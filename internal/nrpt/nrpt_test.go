//go:build windows

package nrpt

import (
	"strings"
	"testing"
)

func TestValidNamespace(t *testing.T) {
	for _, ok := range []string{".", ".corp.example", "host.example.net", ".a-b_c.ru"} {
		if !validNamespace(ok) {
			t.Errorf("%q должен быть допустим", ok)
		}
	}
	for _, bad := range []string{"", "a b", "x';calc;'", "$(evil)", "a|b"} {
		if validNamespace(bad) {
			t.Errorf("%q не должен быть допустим", bad)
		}
	}
}

func TestRemoveScript(t *testing.T) {
	s := removeScript("AnyRoute", "Dual'VPN:")
	if !strings.Contains(s, "$_.Comment -like 'AnyRoute*' -or $_.Comment -like 'Dual''VPN:*'") {
		t.Fatalf("скрипт: %s", s)
	}
}

// TestLeftoversReadsRegistry — чтение реестра работает без прав администратора.
func TestLeftoversReadsRegistry(t *testing.T) {
	if _, err := Leftovers(LegacyPrefixes...); err != nil {
		t.Fatalf("чтение NRPT из реестра: %v", err)
	}
}
