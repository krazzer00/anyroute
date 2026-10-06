package engine

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/krazzer00/anyroute/internal/rules"
)

// Тэги outbound'ов и DNS-серверов в конфигурации sing-box.
const (
	tagVPN    = "vpn"
	tagDirect = "direct"
	tagBlock  = "block"
	tagLocal  = "local"
	tagTun    = "tun-in"
)

// Params — всё, что нужно для конфигурации sing-box.
type Params struct {
	TunName   string       // имя адаптера ("anyroute-tun")
	TunPrefix netip.Prefix // адрес TUN, например 172.29.254.1/30
	MTU       int
	Plan      rules.Plan
	// LocalDNS — DNS-серверы физического интерфейса для имён, идущих
	// напрямую. Пусто — DNS системы (тип local).
	LocalDNS []netip.Addr
	LogLevel string // trace|debug|info|warn|error
	NoTun    bool   // без TUN-инбаунда (тесты)
	// CachePath — файл кэша sing-box. sing-box включает его сам, когда
	// задан обработчик журнала; без пути он писал бы cache.db в текущий
	// каталог (у службы — System32).
	CachePath string
}

// DNSAddress — адрес DNS AnyRoute внутри подсети TUN (следующий за адресом
// интерфейса). На него указывает NRPT, пакеты перехватываются sing-box.
func (p Params) DNSAddress() netip.Addr { return p.TunPrefix.Addr().Next() }

// Build собирает JSON-конфигурацию sing-box.
func Build(p Params) ([]byte, error) {
	cfg := map[string]any{
		"log": map[string]any{"level": orDefault(p.LogLevel, "info"), "timestamp": false},
		"dns": buildDNS(p),
		"outbounds": []any{
			map[string]any{"type": TypeAnyConnect, "tag": tagVPN},
			map[string]any{"type": "direct", "tag": tagDirect},
			map[string]any{"type": "block", "tag": tagBlock},
		},
		"route": buildRoute(p),
		"experimental": map[string]any{
			"cache_file": map[string]any{"enabled": true, "path": cachePath(p.CachePath)},
		},
	}
	if !p.NoTun {
		tun := map[string]any{
			"type":           "tun",
			"tag":            tagTun,
			"interface_name": orDefault(p.TunName, "anyroute-tun"),
			"address":        []string{p.TunPrefix.String()},
			"mtu":            mtu(p.MTU),
			"auto_route":     true,
			"strict_route":   false,
			"stack":          "mixed",
			"dns_mode":       "disabled",
		}
		if len(p.Plan.RouteAddress) > 0 {
			tun["route_address"] = prefixes(p.Plan.RouteAddress)
		} else {
			// Пустой route_address в sing-box означает «весь трафик» —
			// захватываем только адрес DNS AnyRoute, чтобы не отбирать
			// трафик у Throne.
			tun["route_address"] = []string{netip.PrefixFrom(p.DNSAddress(), 32).String()}
		}
		if len(p.Plan.RouteExclude) > 0 {
			tun["route_exclude_address"] = prefixes(p.Plan.RouteExclude)
		}
		cfg["inbounds"] = []any{tun}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func buildRoute(p Params) map[string]any {
	var rs []any
	if p.TunPrefix.IsValid() {
		rs = append(rs, map[string]any{
			"ip_cidr": []string{netip.PrefixFrom(p.DNSAddress(), 32).String()},
			"port":    53,
			"action":  "hijack-dns",
		})
	}
	rs = append(rs,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	)
	for _, r := range p.Plan.Rules {
		for _, m := range matchRules(r.Match, true) {
			m["outbound"] = outboundTag(r.Outbound)
			rs = append(rs, m)
		}
	}
	return map[string]any{
		"rules":                   rs,
		"final":                   outboundTag(p.Plan.Final),
		"auto_detect_interface":   true,
		"find_process":            true,
		"default_domain_resolver": tagLocal,
	}
}

func buildDNS(p Params) map[string]any {
	servers := []any{map[string]any{"type": TypeVPNDNS, "tag": tagVPN}}
	if len(p.LocalDNS) > 0 {
		servers = append(servers, map[string]any{"type": "udp", "tag": tagLocal, "server": p.LocalDNS[0].String()})
	} else {
		servers = append(servers, map[string]any{"type": "local", "tag": tagLocal})
	}
	var rs []any
	for _, r := range p.Plan.DNSRules {
		for _, m := range matchRules(r.Match, false) {
			switch r.Server {
			case rules.OutBlock:
				m["action"] = "predefined"
				m["rcode"] = "NXDOMAIN"
			case rules.OutVPN:
				m["server"] = tagVPN
			default:
				m["server"] = tagLocal
			}
			rs = append(rs, m)
		}
	}
	final := tagLocal
	if p.Plan.DNSFinal == rules.OutVPN {
		final = tagVPN
	}
	return map[string]any{
		"servers":         servers,
		"rules":           rs,
		"final":           final,
		"strategy":        "ipv4_only",
		"reverse_mapping": true,
	}
}

// matchRules переводит список в правила sing-box. Внутри одного правила
// sing-box группы полей (адрес, порт, процесс) объединяются по «И», а
// элементы списка должны срабатывать по «ИЛИ» — поэтому каждая группа идёт
// отдельным правилом. Домены и подсети — одна группа (адрес назначения).
func matchRules(l rules.List, withNonDomain bool) []map[string]any {
	var out []map[string]any
	dst := map[string]any{}
	if len(l.DomainSuffix) > 0 {
		dst["domain_suffix"] = l.DomainSuffix
	}
	if len(l.Domain) > 0 {
		dst["domain"] = l.Domain
	}
	if len(l.Keyword) > 0 {
		dst["domain_keyword"] = l.Keyword
	}
	if len(l.Regex) > 0 {
		dst["domain_regex"] = l.Regex
	}
	if withNonDomain && len(l.CIDR) > 0 {
		dst["ip_cidr"] = prefixes(l.CIDR)
	}
	if len(dst) > 0 {
		out = append(out, dst)
	}
	if !withNonDomain {
		return out
	}
	if len(l.ProcessName) > 0 {
		out = append(out, map[string]any{"process_name": l.ProcessName})
	}
	if len(l.ProcessPath) > 0 {
		out = append(out, map[string]any{"process_path": l.ProcessPath})
	}
	if len(l.Port)+len(l.PortRange) > 0 {
		ports := map[string]any{}
		if len(l.Port) > 0 {
			ports["port"] = l.Port
		}
		if len(l.PortRange) > 0 {
			ports["port_range"] = l.PortRange
		}
		out = append(out, ports)
	}
	return out
}

func outboundTag(out string) string {
	switch out {
	case rules.OutVPN:
		return tagVPN
	case rules.OutBlock:
		return tagBlock
	}
	return tagDirect
}

func prefixes(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func cachePath(p string) string {
	if p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "anyroute-cache-"+strconv.Itoa(os.Getpid())+".db")
}

func mtu(n int) int {
	if n <= 0 || n > 1500 {
		return 1400
	}
	return n
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
