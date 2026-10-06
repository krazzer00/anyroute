package rules

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	text := `
# комментарий
processName:vpnagent.exe
processName:Telegram.exe   # хвостовой комментарий
processPath:C:\Program Files\App\app.exe
domain:corp.example
domain:*.googleapis.com
example.org
full:host.example.net
keyword:intra
regexp:^git\..*\.example$
ip:10.0.0.0/8
192.168.50.7
172.16.0.0/12
port:443
port:1000-2000
processName:vpnagent.exe
`
	l, errs := Parse(text)
	if len(errs) != 0 {
		t.Fatalf("ошибки разбора: %v", errs)
	}
	want := List{
		ProcessName:  []string{"vpnagent.exe", "Telegram.exe"},
		ProcessPath:  []string{`C:\Program Files\App\app.exe`},
		DomainSuffix: []string{"corp.example", "googleapis.com", "example.org"},
		Domain:       []string{"host.example.net"},
		Keyword:      []string{"intra"},
		Regex:        []string{`^git\..*\.example$`},
		CIDR: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.50.7/32"),
			netip.MustParsePrefix("172.16.0.0/12")},
		Port:      []uint16{443},
		PortRange: []string{"1000:2000"},
	}
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("разбор:\n got %+v\nwant %+v", l, want)
	}
}

func TestParseErrors(t *testing.T) {
	_, errs := Parse("domain:\nprocessPath:app.exe\nip:999.1.1.1/8\nport:70000\nregexp:([\ndomain:a*b.com\nfoo:bar baz\nip:fe80::1")
	if len(errs) != 8 {
		for _, e := range errs {
			t.Log(e)
		}
		t.Fatalf("ожидалось 8 ошибок, получено %d", len(errs))
	}
	if errs[0].Line != 1 || errs[3].Line != 4 {
		t.Fatalf("номера строк: %+v", errs)
	}
}

func srv() Server {
	return Server{
		Gateway:      netip.MustParseAddr("203.0.113.10"),
		SplitInclude: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.20.0.0/16")},
		SplitDNS:     []string{"corp.example", "dev.corp.example"},
		DNS:          []netip.Addr{netip.MustParseAddr("10.0.0.53")},
	}
}

func names(p Plan) []string {
	var out []string
	for _, r := range p.Rules {
		out = append(out, r.Name+"→"+r.Outbound)
	}
	return out
}

func TestCompileDirectDefault(t *testing.T) {
	vpn, _ := Parse("domain:googleapis.com\nip:198.51.100.0/24\nfull:jira.example.net\nkeyword:git")
	direct, _ := Parse("processName:Telegram.exe\ndomain:public.corp.example")
	block, _ := Parse("domain:ads.example\nip:192.0.2.66")
	p := Compile(Input{
		DefaultOutbound: OutDirect, ServerRoutesToVPN: true, LANDirect: true,
		LocalNets: []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")},
		VPN:       vpn, Direct: direct, Block: block, Server: srv(),
	})
	wantOrder := []string{"шлюз VPN→direct", "Блокировать→block", "Напрямую→direct", "VPN→vpn", "сети сервера→vpn", "локальная сеть→direct"}
	if !reflect.DeepEqual(names(p), wantOrder) {
		t.Fatalf("порядок правил %v", names(p))
	}
	if p.Final != OutDirect || p.DNSFinal != OutDirect {
		t.Fatalf("final %s/%s", p.Final, p.DNSFinal)
	}
	wantRoute := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.66/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	if !reflect.DeepEqual(p.RouteAddress, wantRoute) {
		t.Fatalf("route_address %v", p.RouteAddress)
	}
	if !Covers(p.RouteExclude, netip.MustParseAddr("203.0.113.10")) || !Covers(p.RouteExclude, netip.MustParseAddr("192.168.2.7")) {
		t.Fatalf("route_exclude %v", p.RouteExclude)
	}
	wantNRPT := []string{".ads.example", ".corp.example", ".googleapis.com", "jira.example.net"}
	if !reflect.DeepEqual(p.NRPT, wantNRPT) {
		t.Fatalf("NRPT %v", p.NRPT)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "keyword") {
		t.Fatalf("нет предупреждения про keyword: %v", p.Warnings)
	}
	if len(p.DNSRules) != 3 || p.DNSRules[0].Server != OutBlock || p.DNSRules[1].Server != OutDirect || p.DNSRules[2].Server != OutVPN {
		t.Fatalf("DNS-правила %+v", p.DNSRules)
	}
}

func TestCompileVPNDefault(t *testing.T) {
	direct, _ := Parse("ip:192.0.2.0/24")
	p := Compile(Input{DefaultOutbound: OutVPN, Direct: direct, Server: srv()})
	if p.Final != OutVPN || p.DNSFinal != OutVPN {
		t.Fatal("final должен быть vpn")
	}
	if !reflect.DeepEqual(p.NRPT, []string{"."}) {
		t.Fatalf("NRPT %v", p.NRPT)
	}
	if !Covers(p.RouteAddress, netip.MustParseAddr("8.8.8.8")) || !Covers(p.RouteAddress, netip.MustParseAddr("200.1.1.1")) {
		t.Fatalf("полный захват %v", p.RouteAddress)
	}
	if !Covers(p.RouteExclude, netip.MustParseAddr("192.0.2.1")) {
		t.Fatalf("исключение direct CIDR %v", p.RouteExclude)
	}
}

func TestCompileNoServerRoutes(t *testing.T) {
	p := Compile(Input{DefaultOutbound: OutDirect, ServerRoutesToVPN: false, Server: srv()})
	if Covers(p.RouteAddress, netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("сети сервера не должны захватываться")
	}
	if len(p.NRPT) != 0 {
		t.Fatalf("NRPT %v", p.NRPT)
	}
	// DNS шлюза всё равно маршрутизируется в туннель.
	if !Covers(p.RouteAddress, netip.MustParseAddr("10.0.0.53")) {
		t.Fatalf("DNS шлюза не в маршрутах: %v", p.RouteAddress)
	}
}

func TestNRPTNestedZones(t *testing.T) {
	got := nrptNamespaces([]string{"corp.example", "dev.corp.example", ".Corp.Example.", "=a.corp.example", "=b.other"})
	want := []string{".corp.example", "b.other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

// Зоны split-DNS сервера — только для DNS: маршрут определяют адреса.
// Имя из зоны с публичным адресом вне split-include должно идти напрямую.
func TestSplitDNSIsNotRouting(t *testing.T) {
	vpn, _ := Parse("domain:jira.example.net")
	p := Compile(Input{DefaultOutbound: OutDirect, ServerRoutesToVPN: true, VPN: vpn, Server: srv()})
	for _, r := range p.Rules {
		if r.Name == "сети сервера" && len(r.Match.DomainSuffix) > 0 {
			t.Fatalf("зоны сервера попали в правило маршрутизации: %+v", r.Match)
		}
	}
	m := p.HostRouteDomains
	if m.Match("www.corp.example") || m.Match("corp.example") {
		t.Fatal("host-маршрут для имени из зоны сервера")
	}
	if !m.Match("jira.example.net") || !m.Match("a.jira.example.net.") || m.Match("xjira.example.net") {
		t.Fatal("сопоставление доменов из списка VPN")
	}
	if Covers(p.RouteAddress, netip.MustParseAddr("51.250.40.209")) {
		t.Fatal("публичный адрес вне split-include захвачен")
	}
	// DNS зоны сервера по-прежнему спрашивается у шлюза.
	if len(p.NRPT) == 0 || p.NRPT[0] != ".corp.example" {
		t.Fatalf("NRPT %v", p.NRPT)
	}
}

func TestDomainMatcherKinds(t *testing.T) {
	l, _ := Parse("full:a.example\nkeyword:intra\n" + `regexp:^git\.`)
	m := NewDomainMatcher(l)
	for name, want := range map[string]bool{"a.example": true, "b.a.example": false, "my-intra.ru": true, "git.corp": true, "gitlab.corp": false} {
		if m.Match(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
	var nilm *DomainMatcher
	if nilm.Match("x") {
		t.Fatal("nil matcher")
	}
}
