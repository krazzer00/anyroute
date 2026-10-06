package nrpt

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/krazzer00/anyroute/internal/execx"
)

const policyKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

// psTimeout — PowerShell с модулем DnsClient стартует несколько секунд.
const psTimeout = 45 * time.Second

// Apply ставит одно правило: зоны namespaces → DNS-сервер server. Старые
// правила AnyRoute снимаются тем же вызовом.
func Apply(ctx context.Context, namespaces []string, server netip.Addr) error {
	if len(namespaces) == 0 {
		return Remove(ctx, Comment)
	}
	quoted := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		if !validNamespace(ns) {
			return fmt.Errorf("nrpt: недопустимое пространство имён %q", ns)
		}
		quoted = append(quoted, execx.PSQuote(ns))
	}
	script := removeScript(Comment) + "; " + fmt.Sprintf(
		"Add-DnsClientNrptRule -Namespace @(%s) -NameServers %s -Comment %s -ErrorAction Stop | Out-Null; Clear-DnsClientCache",
		strings.Join(quoted, ","), execx.PSQuote(server.String()), execx.PSQuote(Comment))
	if _, err := execx.PowerShell(ctx, psTimeout, script); err != nil {
		return fmt.Errorf("установка правил DNS (NRPT): %w", err)
	}
	return nil
}

// Remove снимает все правила, комментарий которых начинается с одного из
// префиксов. Если по реестру снимать нечего, PowerShell не запускается.
func Remove(ctx context.Context, prefixes ...string) error {
	left, err := Leftovers(prefixes...)
	if err == nil && len(left) == 0 {
		return nil
	}
	if _, err := execx.PowerShell(ctx, psTimeout, removeScript(prefixes...)+"; Clear-DnsClientCache"); err != nil {
		return fmt.Errorf("снятие правил DNS (NRPT): %w", err)
	}
	return nil
}

func removeScript(prefixes ...string) string {
	var conds []string
	for _, p := range prefixes {
		conds = append(conds, "$_.Comment -like "+execx.PSQuote(p+"*"))
	}
	return "Get-DnsClientNrptRule | Where-Object { " + strings.Join(conds, " -or ") +
		" } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }"
}

// Leftovers читает правила NRPT из реестра (без PowerShell, без прав
// администратора) и возвращает те, чей комментарий начинается с префикса.
func Leftovers(prefixes ...string) ([]Entry, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, n := range names {
		k, err := registry.OpenKey(root, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		comment, _, _ := k.GetStringValue("Comment")
		ns, _, _ := k.GetStringsValue("Name")
		servers, _, _ := k.GetStringValue("GenericDNSServers")
		k.Close()
		for _, p := range prefixes {
			if strings.HasPrefix(comment, p) {
				out = append(out, Entry{Key: n, Namespaces: ns, Servers: servers, Comment: comment})
				break
			}
		}
	}
	return out, nil
}

func validNamespace(ns string) bool {
	if ns == "." {
		return true
	}
	if ns == "" || len(ns) > 255 {
		return false
	}
	for _, r := range ns {
		if !(r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
