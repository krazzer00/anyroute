package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/core"
	"github.com/krazzer00/anyroute/internal/ipc"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/mockasa"
	"github.com/krazzer00/anyroute/internal/profiles"
)

type fakePlat struct{}

func (fakePlat) Cleanup(context.Context, *logx.Src, bool) {}
func (fakePlat) Dialer() anyconnect.DialFunc {
	d := &net.Dialer{}
	return d.DialContext
}
func (fakePlat) LocalNets() []netip.Prefix    { return nil }
func (fakePlat) PhysicalNets() []netip.Prefix { return nil }
func (fakePlat) LocalDNS() []netip.Addr       { return nil }
func (fakePlat) PickTunPrefix([]netip.Prefix) (netip.Prefix, error) {
	return netip.MustParsePrefix("172.29.254.1/30"), nil
}
func (fakePlat) ApplyNRPT(context.Context, []string, netip.Addr) error { return nil }
func (fakePlat) RemoveNRPT(context.Context) error                      { return nil }
func (fakePlat) HostRoutes(netip.Addr, func(netip.Addr) bool, func(error)) core.HostRouter {
	return nopHosts{}
}
func (fakePlat) NoTun() bool { return true }

type nopHosts struct{}

func (nopHosts) Add([]netip.Addr)                          {}
func (nopHosts) Reapply(netip.Addr, func(netip.Addr) bool) {}
func (nopHosts) Count() int                                { return 0 }

func TestServiceOverPipe(t *testing.T) {
	srv, err := mockasa.New(mockasa.Config{
		Groups: []string{"MFA"}, TwoFAGroups: map[string]string{"MFA": "123456"},
		Users: map[string]string{"ivan": "pw"}, VPNAddress: "10.10.0.5", HostIP: "10.10.0.1",
		ASAChallenge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	pipe := fmt.Sprintf(`\\.\pipe\anyroute-svc-test-%d`, time.Now().UnixNano())
	s, err := Start("test", fakePlat{}, nil, pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	c, err := ipc.Dial(pipe, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var hello map[string]string
	if err := c.Call("hello", nil, &hello, 0); err != nil || hello["version"] != "test" {
		t.Fatalf("hello: %v %v", hello, err)
	}
	reqd := core.ConnectRequest{ServerID: "a", ServerName: "Мок", Host: srv.Addr(), Group: "MFA",
		Username: "ivan", Password: "pw", InsecureTLS: true, Profile: profiles.DefaultRouting()}
	if err := c.Call("connect", reqd, nil, 0); err != nil {
		t.Fatal(err)
	}

	waitFor := func(want core.State) core.Status {
		deadline := time.After(15 * time.Second)
		for {
			select {
			case f, ok := <-c.Events():
				if !ok {
					t.Fatal("канал событий закрыт")
				}
				if f.Event != "state" {
					continue
				}
				var st core.Status
				_ = json.Unmarshal(f.Data, &st)
				if st.State == want {
					return st
				}
			case <-deadline:
				var st core.Status
				_ = c.Call("status", nil, &st, 0)
				t.Fatalf("не дождались %s, статус %+v", want, st)
			}
		}
	}
	waitFor(core.State2FA)
	if err := c.Call("submit2fa", map[string]string{"code": "123456"}, nil, 0); err != nil {
		t.Fatal(err)
	}
	st := waitFor(core.StateConnected)
	if st.Address == "" {
		t.Fatalf("нет адреса: %+v", st)
	}
	var logs []logx.Entry
	if err := c.Call("logs", map[string]uint64{"after": 0}, &logs, 0); err != nil || len(logs) == 0 {
		t.Fatalf("logs: %d %v", len(logs), err)
	}
	for _, e := range logs {
		if e.Message == "pw" {
			t.Fatal("пароль в журнале")
		}
	}
	if err := c.Call("disconnect", nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(core.StateIdle)
}
