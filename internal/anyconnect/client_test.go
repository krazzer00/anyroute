package anyconnect_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/mockasa"
	"github.com/krazzer00/anyroute/internal/vpnstack"
)

const (
	hostIP = "10.10.0.1"
	vpnIP  = "10.10.0.5"
)

func newASA(t *testing.T, mod func(*mockasa.Config)) *mockasa.Server {
	t.Helper()
	cfg := mockasa.Config{
		Groups:       []string{"Основная", "Двухфакторная"},
		TwoFAGroups:  map[string]string{"Двухфакторная": "123456"},
		Users:        map[string]string{"ivan": "p<&>ss"},
		VPNAddress:   vpnIP,
		HostIP:       hostIP,
		SplitInclude: []string{"10.10.0.0/255.255.255.0", "172.20.0.0/16"},
		SplitDNS:     []string{"corp.example"},
		DNS:          map[string]string{"intranet.corp.example": "10.10.0.42"},
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := mockasa.New(cfg)
	if err != nil {
		t.Fatalf("запуск мок-шлюза: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	if err := srv.StartEcho(7); err != nil {
		t.Fatal(err)
	}
	if err := srv.StartDNS(); err != nil {
		t.Fatal(err)
	}
	return srv
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func client(t *testing.T, srv *mockasa.Server, group string) *anyconnect.Client {
	c := anyconnect.NewClient(anyconnect.Config{
		Host: srv.Addr(), Group: group, Username: "ivan", Password: "p<&>ss",
		InsecureSkipVerify: true,
	})
	// Регистрируется после сервера — выполняется раньше его Close, который
	// ждёт завершения всех соединений.
	t.Cleanup(func() { c.Close() })
	return c
}

// connect проходит весь путь и возвращает туннель со стеком.
func connect(t *testing.T, c *anyconnect.Client) (*anyconnect.Tunnel, *vpnstack.Stack) {
	t.Helper()
	tun, err := c.Connect(ctx(t))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { tun.Close() })
	st, err := vpnstack.New(tun, tun.Info().Address.Addr(), tun.Info().MTU)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return tun, st
}

func echo(t *testing.T, st *vpnstack.Stack) {
	t.Helper()
	conn, err := st.DialTCP(ctx(t), netip.MustParseAddrPort(hostIP+":7"))
	if err != nil {
		t.Fatalf("TCP внутрь VPN: %v", err)
	}
	defer conn.Close()
	msg := strings.Repeat("привет через туннель ", 500) // больше одного сегмента
	go func() { _, _ = conn.Write([]byte(msg)) }()
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("эхо: %v", err)
	}
	if string(buf) != msg {
		t.Fatal("эхо вернуло другие данные")
	}
}

func TestPasswordLoginTunnelEcho(t *testing.T) {
	srv := newASA(t, nil)
	c := client(t, srv, "Основная")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if got := c.ServerGroups(); len(got) != 2 {
		t.Fatalf("группы сервера: %v", got)
	}
	ch, err := c.PasswordAuth(ctx(t))
	if err != nil || ch != nil {
		t.Fatalf("PasswordAuth: challenge=%v err=%v", ch, err)
	}
	tun, st := connect(t, c)

	info := tun.Info()
	if info.Address != netip.MustParsePrefix(vpnIP+"/24") {
		t.Errorf("адрес клиента %s", info.Address)
	}
	wantRoutes := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24"), netip.MustParsePrefix("172.20.0.0/16")}
	if len(info.SplitInclude) != 2 || info.SplitInclude[0] != wantRoutes[0] || info.SplitInclude[1] != wantRoutes[1] {
		t.Errorf("split-include %v", info.SplitInclude)
	}
	if len(info.SplitDNS) != 1 || info.SplitDNS[0] != "corp.example" {
		t.Errorf("split-dns %v", info.SplitDNS)
	}
	if len(info.DNS) != 1 || info.DNS[0].String() != hostIP {
		t.Errorf("dns %v", info.DNS)
	}
	echo(t, st)
}

func TestTwoFactorRetryThenSuccess(t *testing.T) {
	srv := newASA(t, nil)
	c := client(t, srv, "Двухфакторная")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	ch, err := c.PasswordAuth(ctx(t))
	if err != nil || ch == nil {
		t.Fatalf("ожидался challenge: %v %v", ch, err)
	}
	ch, err = c.Submit2FA(ctx(t), "000000")
	if err != nil || ch == nil || !ch.Retry {
		t.Fatalf("неверный код должен дать повторный challenge: %+v %v", ch, err)
	}
	ch, err = c.Submit2FA(ctx(t), " 123456 ")
	if err != nil || ch != nil {
		t.Fatalf("верный код: %+v %v", ch, err)
	}
	_, st := connect(t, c)
	echo(t, st)
}

// TestASAStyleChallenge — форма как у живой ASA: поле answer, код в
// <password>, auth-handle в <opaque>, без <username> и <group-select>.
func TestASAStyleChallenge(t *testing.T) {
	srv := newASA(t, func(c *mockasa.Config) { c.ASAChallenge = true })
	c := client(t, srv, "Двухфакторная")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	ch, err := c.PasswordAuth(ctx(t))
	if err != nil || ch == nil {
		t.Fatalf("ожидался challenge: %v", err)
	}
	if ch.Message != "Введите OTP-код" {
		t.Errorf("сообщение challenge %q — подстановка param1 не сработала", ch.Message)
	}
	ch, err = c.Submit2FA(ctx(t), "111111")
	if err != nil || ch == nil || !ch.Retry {
		t.Fatalf("неверный код: %+v %v", ch, err)
	}
	if ch, err = c.Submit2FA(ctx(t), "123456"); err != nil || ch != nil {
		t.Fatalf("верный код отклонён: %+v %v", ch, err)
	}
	_, st := connect(t, c)
	echo(t, st)
}

func TestWrongPassword(t *testing.T) {
	srv := newASA(t, nil)
	c := anyconnect.NewClient(anyconnect.Config{Host: srv.Addr(), Group: "Основная", Username: "ivan", Password: "bad", InsecureSkipVerify: true})
	t.Cleanup(func() { c.Close() })
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_, err := c.PasswordAuth(ctx(t))
	var ae *anyconnect.AuthError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "Login failed") {
		t.Fatalf("ожидалась AuthError, получено %v", err)
	}
}

func TestUnknownGroup(t *testing.T) {
	srv := newASA(t, nil)
	c := client(t, srv, "Нет такой")
	err := c.InitAuth(ctx(t))
	if err == nil || !strings.Contains(err.Error(), "Основная") {
		t.Fatalf("ожидалась ошибка со списком групп, получено %v", err)
	}
}

func TestNoGroupSelectServer(t *testing.T) {
	srv := newASA(t, func(c *mockasa.Config) { c.NoGroupSelect = true; c.Groups = nil })
	c := client(t, srv, "")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if ch, err := c.PasswordAuth(ctx(t)); err != nil || ch != nil {
		t.Fatalf("PasswordAuth: %v %v", ch, err)
	}
}

func TestDisconnectNotifiesServer(t *testing.T) {
	srv := newASA(t, nil)
	c := client(t, srv, "Основная")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PasswordAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	tun, err := c.Connect(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = tun.Close()
	if time.Since(start) > 3*time.Second {
		t.Fatalf("Close занял %s", time.Since(start))
	}
	select {
	case <-tun.Done():
	default:
		t.Fatal("Done не закрыт после Close")
	}
	deadline := time.Now().Add(3 * time.Second)
	for srv.Disconnects() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Disconnects() != 1 {
		t.Fatalf("сервер не получил DISCONNECT")
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("повторный Close: %v", err)
	}
}

func TestDNSThroughTunnel(t *testing.T) {
	srv := newASA(t, nil)
	c := client(t, srv, "Основная")
	if err := c.InitAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PasswordAuth(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_, st := connect(t, c)
	conn, err := st.DialUDP(netip.MustParseAddrPort(hostIP + ":53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"intranet", "corp", "example"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("ответ DNS: %v", err)
	}
	if n < 4 || netip.AddrFrom4([4]byte(buf[n-4:n])).String() != "10.10.0.42" {
		t.Fatalf("неверный ответ DNS: %x", buf[:n])
	}
}

func TestFetchGroupsFollowsRedirect(t *testing.T) {
	srv := newASA(t, nil)
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://"+srv.Addr()+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer front.Close()
	groups, def, err := anyconnect.FetchGroups(ctx(t), anyconnect.Config{
		Host: strings.TrimPrefix(front.URL, "https://"), InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("FetchGroups: %v", err)
	}
	if len(groups) != 2 || groups[0] != "Основная" {
		t.Fatalf("группы %v", groups)
	}
	_ = def
}

func TestRedirectToHTTPRefused(t *testing.T) {
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://evil.example/")
		w.WriteHeader(http.StatusFound)
	}))
	defer front.Close()
	_, _, err := anyconnect.FetchGroups(ctx(t), anyconnect.Config{
		Host: strings.TrimPrefix(front.URL, "https://"), InsecureSkipVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("ожидался отказ от http-редиректа, получено %v", err)
	}
}
