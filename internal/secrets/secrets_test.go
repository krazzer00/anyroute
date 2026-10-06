package secrets

import (
	"encoding/base32"
	"testing"
	"time"
)

// Векторы RFC 6238 (SHA1, ключ "12345678901234567890"), последние 6 цифр.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for ts, want := range cases {
		got, err := TOTP(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %s (%v), want %s", ts, got, err, want)
		}
	}
}

func TestNormalizeSecret(t *testing.T) {
	for in, want := range map[string]string{
		"jbsw y3dp ehpk 3pxp": "JBSWY3DPEHPK3PXP",
		"JBSW-Y3DP-EHPK-3PXP": "JBSWY3DPEHPK3PXP",
		"otpauth://totp/Corp:ivan?secret=JBSWY3DPEHPK3PXP&issuer=Corp": "JBSWY3DPEHPK3PXP",
	} {
		got, err := NormalizeTOTPSecret(in)
		if err != nil || got != want {
			t.Errorf("%q → %q (%v)", in, got, err)
		}
	}
	if _, err := NormalizeTOTPSecret("не base32!"); err == nil {
		t.Error("ожидалась ошибка")
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	id := "test-" + time.Now().Format("150405.000000")
	if err := Save(id, Password, "ivan", "p@ss"); err != nil {
		t.Skipf("диспетчер учётных данных недоступен: %v", err)
	}
	defer DeleteAll(id)
	got, err := Load(id, Password)
	if err != nil || got != "p@ss" {
		t.Fatalf("Load: %q %v", got, err)
	}
	DeleteAll(id)
	if _, err := Load(id, Password); err != ErrNotFound {
		t.Fatalf("после удаления: %v", err)
	}
}
