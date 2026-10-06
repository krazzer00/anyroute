package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/mockasa"
	"github.com/krazzer00/anyroute/internal/rules"
	"github.com/krazzer00/anyroute/internal/vpnstack"
)

func testPlan() rules.Plan {
	vpn, _ := rules.Parse("domain:googleapis.com\nprocessName:chrome.exe\nip:198.51.100.0/24")
	direct, _ := rules.Parse("processName:Telegram.exe\nport:22")
	return rules.Compile(rules.Input{
		DefaultOutbound: rules.OutDirect, ServerRoutesToVPN: true, VPN: vpn, Direct: direct,
		Server: rules.Server{
			Gateway:      netip.MustParseAddr("203.0.113.1"),
			SplitInclude: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
			SplitDNS:     []string{"corp.example"},
			DNS:          []netip.Addr{netip.MustParseAddr("10.10.0.1")},
		},
	})
}

func TestBuildConfig(t *testing.T) {
	raw, err := Build(Params{TunPrefix: netip.MustParsePrefix("172.29.254.1/30"), Plan: testPlan(),
		LocalDNS: []netip.Addr{netip.MustParseAddr("192.168.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
		DNS struct {
			Final string `json:"final"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	tun := cfg.Inbounds[0]
	if tun["strict_route"] != false || tun["dns_mode"] != "disabled" {
		t.Errorf("TUN должен быть без strict_route и DNS на интерфейсе: %v", tun)
	}
	ra, _ := json.Marshal(tun["route_address"])
	if strings.Contains(string(ra), "0.0.0.0/1") || !strings.Contains(string(ra), "10.10.0.0/24") {
		t.Errorf("route_address %s", ra)
	}
	// процесс и адрес — разными правилами (в sing-box группы полей — «И»)
	for _, r := range cfg.Route.Rules {
		if _, p := r["process_name"]; p {
			if _, ip := r["ip_cidr"]; ip {
				t.Errorf("process_name и ip_cidr в одном правиле: %v", r)
			}
		}
	}
	first := cfg.Route.Rules[0]
	if first["action"] != "hijack-dns" {
		t.Errorf("первое правило должно перехватывать DNS AnyRoute: %v", first)
	}
	if cfg.Route.Final != "direct" || cfg.DNS.Final != "local" {
		t.Errorf("final %s / dns %s", cfg.Route.Final, cfg.DNS.Final)
	}
}

// TestEngineVPNOutbound поднимает sing-box (без TUN) поверх сессии к мок-шлюзу
// и проверяет outbound «vpn» и DNS шлюза.
func TestEngineVPNOutbound(t *testing.T) {
	srv, err := mockasa.New(mockasa.Config{
		Groups: []string{"g"}, Users: map[string]string{"u": "p"},
		VPNAddress: "10.10.0.5", HostIP: "10.10.0.1",
		DNS: map[string]string{"intranet.corp.example": "10.10.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_ = srv.StartEcho(7)
	_ = srv.StartDNS()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := anyconnect.NewClient(anyconnect.Config{Host: srv.Addr(), Group: "g", Username: "u", Password: "p", InsecureSkipVerify: true})
	if err := c.InitAuth(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PasswordAuth(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := c.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	st, err := vpnstack.New(tun, tun.Info().Address.Addr(), tun.Info().MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sess := NewSession(st, tun.Info().DNS)
	var mu sync.Mutex
	var seen []netip.Addr
	sess.OnDNSReply(func(_ string, ips []netip.Addr) { mu.Lock(); seen = append(seen, ips...); mu.Unlock() })

	log := logx.New(100, nil)
	eng := New(log.Source("engine"), sess)
	if err := eng.Start(Params{NoTun: true, Plan: testPlan(), LogLevel: "warn"}); err != nil {
		t.Fatalf("запуск sing-box: %v", err)
	}
	defer eng.Stop()

	ob, ok := eng.box.Outbound().Outbound("vpn")
	if !ok {
		t.Fatal("нет outbound vpn")
	}
	conn, err := ob.DialContext(ctx, "tcp", M.ParseSocksaddr("10.10.0.1:7"))
	if err != nil {
		t.Fatalf("dial через outbound vpn: %v", err)
	}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("эхо через outbound: %q %v", buf, err)
	}
	conn.Close()

	// Домен вместо адреса — outbound разрешает его DNS шлюза.
	conn, err = ob.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("intranet.corp.example", 7))
	if err != nil {
		t.Fatalf("dial по имени: %v", err)
	}
	conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || seen[0].String() != "10.10.0.1" {
		t.Fatalf("обработчик ответов DNS не вызван: %v", seen)
	}

	start := time.Now()
	eng.Stop()
	if time.Since(start) > 6*time.Second {
		t.Fatalf("остановка заняла %s", time.Since(start))
	}
}
