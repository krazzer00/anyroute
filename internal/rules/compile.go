package rules

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Назначения трафика.
const (
	OutVPN    = "vpn"
	OutDirect = "direct"
	OutBlock  = "block"
)

// Server — данные, выданные шлюзом при подключении.
type Server struct {
	Gateway      netip.Addr
	SplitInclude []netip.Prefix
	SplitExclude []netip.Prefix
	SplitDNS     []string
	DNS          []netip.Addr
	DefaultRoute bool // шлюз не выдал split-include (ждёт весь трафик)
}

// Input — всё, из чего собирается решение.
type Input struct {
	DefaultOutbound   string // OutVPN | OutDirect
	ServerRoutesToVPN bool
	LANDirect         bool
	LocalNets         []netip.Prefix // подсети локальных интерфейсов (для LANDirect)
	VPN, Direct       List
	Block             List
	Server            Server
}

// Rule — одно правило маршрутизации в порядке проверки.
type Rule struct {
	Name     string `json:"name"` // для журнала и UI
	Outbound string `json:"outbound"`
	Match    List   `json:"match"`
}

// DNSRule — правило выбора DNS-сервера.
type DNSRule struct {
	Server string // OutVPN | OutDirect | OutBlock
	Match  List   // используются только доменные поля
}

// Plan — итоговое решение для движка.
type Plan struct {
	Rules        []Rule
	Final        string
	RouteAddress []netip.Prefix // что заворачивается в TUN AnyRoute
	RouteExclude []netip.Prefix // что исключается из захвата
	NRPT         []string       // пространства имён NRPT → DNS AnyRoute ("." — все)
	DNSRules     []DNSRule
	DNSFinal     string
	Warnings     []string
	// HostRouteDomains — для каких имён ответ DNS превращается в /32-маршрут
	// в TUN (домены из списка «Через VPN»).
	HostRouteDomains *DomainMatcher `json:"-"`
}

// DomainMatcher проверяет имя по доменным правилам списка.
type DomainMatcher struct {
	suffix  []string
	full    map[string]bool
	keyword []string
	regex   []*regexp.Regexp
}

// NewDomainMatcher строит сопоставитель по доменным полям списка.
func NewDomainMatcher(l List) *DomainMatcher {
	m := &DomainMatcher{suffix: l.DomainSuffix, keyword: l.Keyword, full: map[string]bool{}}
	for _, d := range l.Domain {
		m.full[d] = true
	}
	for _, r := range l.Regex {
		if re, err := regexp.Compile(r); err == nil {
			m.regex = append(m.regex, re)
		}
	}
	return m
}

// Match — подходит ли имя (без завершающей точки, регистр не важен).
func (m *DomainMatcher) Match(name string) bool {
	if m == nil {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if m.full[name] {
		return true
	}
	for _, s := range m.suffix {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	for _, k := range m.keyword {
		if strings.Contains(name, k) {
			return true
		}
	}
	for _, re := range m.regex {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

var (
	halfA = netip.MustParsePrefix("0.0.0.0/1")
	halfB = netip.MustParsePrefix("128.0.0.0/1")
	// Всегда вне захвата: link-local, multicast, broadcast.
	alwaysExclude = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
)

// Compile собирает план.
func Compile(in Input) Plan {
	var p Plan
	def := in.DefaultOutbound
	if def != OutVPN {
		def = OutDirect
	}
	p.Final = def

	// Шлюз — всегда напрямую.
	if in.Server.Gateway.IsValid() {
		gw := netip.PrefixFrom(in.Server.Gateway.Unmap(), 32)
		p.Rules = append(p.Rules, Rule{Name: "шлюз VPN", Outbound: OutDirect, Match: List{CIDR: []netip.Prefix{gw}}})
		p.RouteExclude = append(p.RouteExclude, gw)
	}
	if !in.Block.Empty() {
		p.Rules = append(p.Rules, Rule{Name: "Блокировать", Outbound: OutBlock, Match: in.Block})
	}
	if !in.Direct.Empty() {
		p.Rules = append(p.Rules, Rule{Name: "Напрямую", Outbound: OutDirect, Match: in.Direct})
	}
	if !in.VPN.Empty() {
		p.Rules = append(p.Rules, Rule{Name: "VPN", Outbound: OutVPN, Match: in.VPN})
	}
	if in.ServerRoutesToVPN {
		if len(in.Server.SplitExclude) > 0 {
			p.Rules = append(p.Rules, Rule{Name: "исключения сервера", Outbound: OutDirect, Match: List{CIDR: in.Server.SplitExclude}})
		}
		// Только адреса: зоны split-DNS определяют, какой DNS спрашивать, а не
		// маршрут. Как у AnyConnect: имя из зоны с публичным адресом вне
		// split-include идёт напрямую — шлюз такой трафик не пропускает.
		if len(in.Server.SplitInclude) > 0 {
			p.Rules = append(p.Rules, Rule{Name: "сети сервера", Outbound: OutVPN, Match: List{CIDR: in.Server.SplitInclude}})
		}
	}
	// Host-маршруты (/32 в TUN по ответам DNS) — только для доменов из
	// списка «Через VPN»: иначе адрес уже определён маршрутами выше.
	p.HostRouteDomains = NewDomainMatcher(in.VPN)
	if in.LANDirect {
		lan := append([]netip.Prefix(nil), in.LocalNets...)
		if len(lan) > 0 {
			p.Rules = append(p.Rules, Rule{Name: "локальная сеть", Outbound: OutDirect, Match: List{CIDR: lan}})
			p.RouteExclude = append(p.RouteExclude, lan...)
		}
	}

	// Что заворачивать в TUN: только то, что может пойти в VPN или должно
	// быть заблокировано, — иначе AnyRoute отбирал бы трафик у Throne.
	var route []netip.Prefix
	if def == OutVPN {
		route = append(route, halfA, halfB)
		if len(in.Server.SplitInclude) > 0 {
			p.Warnings = append(p.Warnings, "шлюз пропускает через VPN только свои сети — при «по умолчанию: через VPN» остальной трафик, скорее всего, не пройдёт")
		}
	} else {
		route = append(route, in.VPN.CIDR...)
		route = append(route, in.Block.CIDR...)
		if in.ServerRoutesToVPN {
			route = append(route, in.Server.SplitInclude...)
			if in.Server.DefaultRoute {
				p.Warnings = append(p.Warnings, "шлюз не выдал список сетей (ожидает весь трафик) — при «по умолчанию: напрямую» в VPN пойдёт только то, что указано в правилах")
			}
		}
	}
	for _, d := range in.Server.DNS {
		route = append(route, netip.PrefixFrom(d.Unmap(), 32))
	}
	p.RouteAddress = normalize(route)
	p.RouteExclude = normalize(append(p.RouteExclude, alwaysExclude...))
	if len(in.Direct.CIDR) > 0 && def == OutVPN {
		p.RouteExclude = normalize(append(p.RouteExclude, in.Direct.CIDR...))
	}

	// NRPT: какие имена Windows спрашивает у DNS AnyRoute.
	if def == OutVPN {
		p.NRPT = []string{"."}
	} else {
		var ns []string
		if in.ServerRoutesToVPN {
			ns = append(ns, in.Server.SplitDNS...)
		}
		ns = append(ns, in.VPN.DomainSuffix...)
		ns = append(ns, in.Block.DomainSuffix...)
		for _, d := range append(append([]string(nil), in.VPN.Domain...), in.Block.Domain...) {
			ns = append(ns, "="+d)
		}
		p.NRPT = nrptNamespaces(ns)
		if len(in.VPN.Keyword)+len(in.VPN.Regex) > 0 {
			p.Warnings = append(p.Warnings, "правила keyword:/regexp: в списке VPN работают только для трафика, уже попавшего в туннель: Windows не умеет направлять DNS по ключевым словам")
		}
	}

	// DNS: блок → отказ, напрямую → системный DNS, VPN и зоны сервера → DNS шлюза.
	if in.Block.HasDomains() {
		p.DNSRules = append(p.DNSRules, DNSRule{Server: OutBlock, Match: domainsOnly(in.Block)})
	}
	if in.Direct.HasDomains() {
		p.DNSRules = append(p.DNSRules, DNSRule{Server: OutDirect, Match: domainsOnly(in.Direct)})
	}
	vpnDNS := domainsOnly(in.VPN)
	if in.ServerRoutesToVPN {
		vpnDNS.DomainSuffix = append(vpnDNS.DomainSuffix, in.Server.SplitDNS...)
	}
	if vpnDNS.HasDomains() {
		p.DNSRules = append(p.DNSRules, DNSRule{Server: OutVPN, Match: vpnDNS})
	}
	p.DNSFinal = OutDirect
	if def == OutVPN {
		p.DNSFinal = OutVPN
	}
	if len(in.Server.DNS) == 0 {
		p.Warnings = append(p.Warnings, "шлюз не выдал DNS-серверов — имена разрешаются системным DNS")
		p.DNSFinal = OutDirect
		var kept []DNSRule
		for _, r := range p.DNSRules {
			if r.Server != OutVPN {
				kept = append(kept, r)
			}
		}
		p.DNSRules = kept
	}
	return p
}

func domainsOnly(l List) List {
	return List{DomainSuffix: l.DomainSuffix, Domain: l.Domain, Keyword: l.Keyword, Regex: l.Regex}
}

// nrptNamespaces: суффикс "corp.example" → ".corp.example" (зона целиком),
// "=host" → "host" (одно имя); дубли и вложенные зоны убираются.
func nrptNamespaces(in []string) []string {
	set := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" || d == "=" {
			continue
		}
		if strings.HasPrefix(d, "=") {
			set[strings.TrimPrefix(d, "=")] = true
		} else {
			set["."+d] = true
		}
	}
	var out []string
	for ns := range set {
		covered := false
		for other := range set {
			if other != ns && strings.HasPrefix(other, ".") && strings.HasSuffix(ns, other) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// normalize убирает дубли и подсети, вложенные в другие из того же списка.
func normalize(in []netip.Prefix) []netip.Prefix {
	var ps []netip.Prefix
	for _, p := range in {
		if p.IsValid() && p.Addr().Is4() {
			ps = append(ps, p.Masked())
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Bits() != ps[j].Bits() {
			return ps[i].Bits() < ps[j].Bits()
		}
		return ps[i].Addr().Less(ps[j].Addr())
	})
	var out []netip.Prefix
	for _, p := range ps {
		dup := false
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// Covers сообщает, попадает ли адрес в один из префиксов.
func Covers(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
