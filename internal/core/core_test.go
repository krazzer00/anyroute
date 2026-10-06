package core

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/mockasa"
	"github.com/krazzer00/anyroute/internal/profiles"
	"github.com/krazzer00/anyroute/internal/rules"
)

type fakePlatform struct {
	mu          sync.Mutex
	nrptApplied []string
	nrptRemoved atomic.Int32
	cleanups    atomic.Int32
}

func (f *fakePlatform) Cleanup(context.Context, *logx.Src, bool) { f.cleanups.Add(1) }
func (f *fakePlatform) Dialer() anyconnect.DialFunc {
	d := &net.Dialer{}
	return d.DialContext
}
func (f *fakePlatform) LocalNets() []netip.Prefix    { return nil }
func (f *fakePlatform) PhysicalNets() []netip.Prefix { return nil }
func (f *fakePlatform) LocalDNS() []netip.Addr       { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }
func (f *fakePlatform) PickTunPrefix([]netip.Prefix) (netip.Prefix, error) {
	return netip.MustParsePrefix("172.29.254.1/30"), nil
}
func (f *fakePlatform) ApplyNRPT(_ context.Context, ns []string, _ netip.Addr) error {
	f.mu.Lock()
	f.nrptApplied = ns
	f.mu.Unlock()
	return nil
}
func (f *fakePlatform) RemoveNRPT(context.Context) error { f.nrptRemoved.Add(1); return nil }
func (f *fakePlatform) HostRoutes(netip.Addr, func(netip.Addr) bool, func(error)) HostRouter {
	return &fakeHosts{}
}
func (f *fakePlatform) NoTun() bool { return true }

func (f *fakePlatform) applied() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.nrptApplied, ",")
}

type fakeHosts struct{ n atomic.Int32 }

func (h *fakeHosts) Add(ips []netip.Addr)                    { h.n.Add(int32(len(ips))) }
func (h *fakeHosts) Reset(netip.Addr, func(netip.Addr) bool) {}
func (h *fakeHosts) Count() int                              { return int(h.n.Load()) }

func newMock(t *testing.T) *mockasa.Server {
	t.Helper()
	srv, err := mockasa.New(mockasa.Config{
		Groups:       []string{"Main", "MFA"},
		TwoFAGroups:  map[string]string{"MFA": "123456"},
		Users:        map[string]string{"ivan": "secret"},
		VPNAddress:   "10.10.0.5",
		HostIP:       "10.10.0.1",
		SplitInclude: []string{"10.10.0.0/255.255.255.0"},
		SplitDNS:     []string{"corp.example"},
		ASAChallenge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func waitState(t *testing.T, c *Core, want State, timeout time.Duration) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s := c.Status(); s.State == want {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	s := c.Status()
	t.Fatalf("не дождались состояния %s, текущее %s (шаг %q, ошибка %q)", want, s.State, s.Step, s.Error)
	return s
}

func req(srv *mockasa.Server, group string) ConnectRequest {
	return ConnectRequest{ServerID: "s1", ServerName: "Мок", Host: srv.Addr(), Group: group,
		Username: "ivan", Password: "secret", InsecureTLS: true, Profile: profiles.DefaultRouting()}
}

func newCore(t *testing.T) (*Core, *fakePlatform) {
	f := &fakePlatform{}
	c := New(logx.New(500, nil), f, "test")
	t.Cleanup(func() { c.Disconnect(); c.Wait(10 * time.Second) })
	return c, f
}

func TestConnectWith2FAAndDisconnect(t *testing.T) {
	srv := newMock(t)
	c, f := newCore(t)
	if err := c.Connect(req(srv, "MFA")); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, c, State2FA, 10*time.Second)
	if st.Challenge == nil || st.Challenge.Message != "Введите OTP-код" {
		t.Fatalf("challenge %+v", st.Challenge)
	}
	if err := c.Connect(req(srv, "MFA")); err == nil {
		t.Fatal("второе подключение должно быть отклонено")
	}
	if err := c.Submit2FA("999999"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st = c.Status()
		if st.State == State2FA && st.Challenge != nil && st.Challenge.Retry {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("после неверного кода ожидался повторный запрос: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := c.Submit2FA("123456"); err != nil {
		t.Fatal(err)
	}
	st = waitState(t, c, StateConnected, 15*time.Second)
	if st.Address != "10.10.0.5/24" || len(st.SplitInclude) != 1 {
		t.Fatalf("статус %+v", st)
	}
	if ns := f.applied(); ns != ".corp.example" {
		t.Fatalf("NRPT %q", ns)
	}

	start := time.Now()
	c.Disconnect()
	st = waitState(t, c, StateIdle, 8*time.Second)
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("отключение заняло %s", d)
	}
	if st.Error != "" {
		t.Fatalf("штатное отключение с ошибкой %q", st.Error)
	}
	if f.nrptRemoved.Load() == 0 {
		t.Fatal("NRPT не снят при отключении")
	}
	if f.cleanups.Load() == 0 {
		t.Fatal("очистка остатков не выполнялась")
	}
	deadline = time.Now().Add(3 * time.Second)
	for srv.Disconnects() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Disconnects() == 0 {
		t.Fatal("шлюз не получил DISCONNECT")
	}
	// Повторное подключение после отключения.
	if err := c.Connect(req(srv, "Main")); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, StateConnected, 15*time.Second)
}

func TestCancelDuring2FA(t *testing.T) {
	srv := newMock(t)
	c, _ := newCore(t)
	_ = c.Connect(req(srv, "MFA"))
	waitState(t, c, State2FA, 10*time.Second)
	start := time.Now()
	c.Disconnect()
	st := waitState(t, c, StateIdle, 5*time.Second)
	if time.Since(start) > 3*time.Second || st.Error != "" {
		t.Fatalf("отмена во время 2FA: %s, ошибка %q", time.Since(start), st.Error)
	}
}

func TestWrongPasswordGoesIdleWithError(t *testing.T) {
	srv := newMock(t)
	c, _ := newCore(t)
	r := req(srv, "Main")
	r.Password = "bad"
	_ = c.Connect(r)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := c.Status(); st.State == StateIdle && st.Error != "" {
			if !strings.Contains(st.Error, "Login failed") {
				t.Fatalf("ошибка %q", st.Error)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("нет ошибки входа: %+v", c.Status())
}

func TestSwitchProfileWhileConnected(t *testing.T) {
	srv := newMock(t)
	c, f := newCore(t)
	_ = c.Connect(req(srv, "Main"))
	waitState(t, c, StateConnected, 15*time.Second)
	p := profiles.Routing{ID: "work", Name: "Работа", DefaultOutbound: "vpn", ServerRoutesToVPN: true}
	if err := c.SetProfile(p); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for f.applied() != "." && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if ns := f.applied(); ns != "." {
		t.Fatalf("после смены профиля NRPT %q", ns)
	}
	if st := c.Status(); st.State != StateConnected || st.ProfileName != "Работа" {
		t.Fatalf("статус после смены профиля: %s %s", st.State, st.ProfileName)
	}
}

func TestServerDropGoesIdle(t *testing.T) {
	srv := newMock(t)
	c, _ := newCore(t)
	_ = c.Connect(req(srv, "Main"))
	waitState(t, c, StateConnected, 15*time.Second)
	srv.Close()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st := c.Status(); st.State == StateIdle {
			if !strings.Contains(st.Error, "соединение с VPN") {
				t.Fatalf("ошибка при обрыве: %q", st.Error)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("после обрыва состояние %+v", c.Status())
}

func TestHostRoutesOnlyForVPNListDomains(t *testing.T) {
	h := &fakeHosts{}
	lc := &liveConn{hosts: h}
	v, _, _, _ := profiles.Routing{VPN: "domain:jira.example.net"}.Compile()
	lc.matcher = rules.NewDomainMatcher(v)
	lc.onDNSReply("www.astralinux.example.", []netip.Addr{netip.MustParseAddr("51.250.40.209")})
	if h.Count() != 0 {
		t.Fatal("host-маршрут для домена вне списка VPN")
	}
	lc.onDNSReply("jira.example.net.", []netip.Addr{netip.MustParseAddr("198.51.100.7")})
	if h.Count() != 1 {
		t.Fatal("нет host-маршрута для домена из списка VPN")
	}
}
