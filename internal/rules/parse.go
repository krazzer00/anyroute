// Package rules — правила маршрутизации в стиле Throne: разбор текстовых
// списков и сборка итогового решения (что заворачивать в TUN AnyRoute,
// какие зоны отдавать DNS AnyRoute через NRPT, в каком порядке проверять).
//
// Пакет не зависит от sing-box: результат — нейтральные структуры, которые
// движок переводит в опции sing-box.
package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// List — разобранный список правил одного назначения.
type List struct {
	ProcessName  []string       `json:"processName,omitempty"`
	ProcessPath  []string       `json:"processPath,omitempty"`
	DomainSuffix []string       `json:"domainSuffix,omitempty"` // domain: и голые домены
	Domain       []string       `json:"domain,omitempty"`       // full:
	Keyword      []string       `json:"keyword,omitempty"`
	Regex        []string       `json:"regex,omitempty"`
	CIDR         []netip.Prefix `json:"cidr,omitempty"`
	Port         []uint16       `json:"port,omitempty"`
	PortRange    []string       `json:"portRange,omitempty"` // "1000:2000" (формат sing-box)
}

// Empty сообщает, что список пуст.
func (l List) Empty() bool {
	return len(l.ProcessName)+len(l.ProcessPath)+len(l.DomainSuffix)+len(l.Domain)+
		len(l.Keyword)+len(l.Regex)+len(l.CIDR)+len(l.Port)+len(l.PortRange) == 0
}

// HasDomains — есть ли доменные правила.
func (l List) HasDomains() bool {
	return len(l.DomainSuffix)+len(l.Domain)+len(l.Keyword)+len(l.Regex) > 0
}

// LineError — ошибка в конкретной строке списка.
type LineError struct {
	Line int    `json:"line"`
	Text string `json:"text"`
	Err  string `json:"error"`
}

func (e LineError) Error() string {
	return fmt.Sprintf("строка %d «%s»: %s", e.Line, e.Text, e.Err)
}

var (
	domainRe  = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)
	processRe = regexp.MustCompile(`^[^\\/:*?"<>|\x00-\x1f]{1,255}$`)
)

// Parse разбирает текст списка (по правилу в строке, # — комментарий).
func Parse(text string) (List, []LineError) {
	var l List
	var errs []LineError
	seen := map[string]bool{}
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := raw
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := l.add(line, seen); err != nil {
			errs = append(errs, LineError{Line: i + 1, Text: strings.TrimSpace(raw), Err: err.Error()})
		}
	}
	return l, errs
}

func (l *List) add(line string, seen map[string]bool) error {
	key, val, hasPrefix := strings.Cut(line, ":")
	prefix := strings.ToLower(strings.TrimSpace(key))
	val = strings.TrimSpace(val)
	if !hasPrefix || !knownPrefix(prefix) {
		// Без префикса: адрес/подсеть или домен.
		prefix, val = "", line
		if _, err := netip.ParsePrefix(line); err == nil {
			prefix = "ip"
		} else if _, err := netip.ParseAddr(line); err == nil {
			prefix = "ip"
		} else {
			prefix = "domain"
		}
	}
	if val == "" {
		return fmt.Errorf("пустое значение после %q", prefix+":")
	}
	dedup := prefix + ":" + strings.ToLower(val)
	if seen[dedup] {
		return nil
	}
	seen[dedup] = true

	switch prefix {
	case "processname", "process_name", "process":
		if !processRe.MatchString(val) {
			return fmt.Errorf("недопустимое имя процесса")
		}
		l.ProcessName = append(l.ProcessName, val)
	case "processpath", "process_path":
		if !strings.Contains(val, `\`) && !strings.Contains(val, "/") {
			return fmt.Errorf("нужен полный путь к exe, например C:\\Program Files\\App\\app.exe")
		}
		l.ProcessPath = append(l.ProcessPath, val)
	case "domain", "domain_suffix", "suffix":
		d, err := normDomain(strings.TrimPrefix(strings.TrimPrefix(val, "*."), "."))
		if err != nil {
			return err
		}
		l.DomainSuffix = append(l.DomainSuffix, d)
	case "full":
		d, err := normDomain(val)
		if err != nil {
			return err
		}
		l.Domain = append(l.Domain, d)
	case "keyword":
		l.Keyword = append(l.Keyword, strings.ToLower(val))
	case "regexp", "regex":
		if _, err := regexp.Compile(val); err != nil {
			return fmt.Errorf("ошибка в регулярном выражении: %v", err)
		}
		l.Regex = append(l.Regex, val)
	case "ip", "ip_cidr", "cidr":
		p, err := parseCIDR(val)
		if err != nil {
			return err
		}
		l.CIDR = append(l.CIDR, p)
	case "port":
		if a, b, isRange := strings.Cut(val, "-"); isRange {
			lo, err1 := parsePort(a)
			hi, err2 := parsePort(b)
			if err1 != nil || err2 != nil || lo > hi {
				return fmt.Errorf("диапазон портов должен быть вида 1000-2000")
			}
			l.PortRange = append(l.PortRange, fmt.Sprintf("%d:%d", lo, hi))
			return nil
		}
		p, err := parsePort(val)
		if err != nil {
			return err
		}
		l.Port = append(l.Port, p)
	default:
		return fmt.Errorf("неизвестный тип правила %q", prefix)
	}
	return nil
}

func knownPrefix(p string) bool {
	switch p {
	case "processname", "process_name", "process", "processpath", "process_path",
		"domain", "domain_suffix", "suffix", "full", "keyword", "regexp", "regex",
		"ip", "ip_cidr", "cidr", "port":
		return true
	}
	return false
}

func normDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if strings.Contains(d, "*") {
		return "", fmt.Errorf("звёздочка допустима только в начале: *.example.com")
	}
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("некорректный домен %q", d)
	}
	return d, nil
}

func parseCIDR(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("поддерживаются только IPv4-адреса")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("некорректный адрес или подсеть %q", s)
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("поддерживаются только IPv4-адреса")
	}
	return netip.PrefixFrom(a, 32), nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("порт должен быть числом 1–65535")
	}
	return uint16(n), nil
}
