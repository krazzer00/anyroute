package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func signed(t *testing.T, version string, data []byte) (*Manifest, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	m := &Manifest{
		Version:   version,
		URL:       downloadPrefix + "v" + version + "/AnyRoute-Setup-" + version + ".exe",
		SHA256:    h,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SignedMessage(version, h))),
	}
	return m, pub, priv
}

func TestVerify(t *testing.T) {
	data := []byte("установщик")
	m, pub, priv := signed(t, "1.2.3", data)
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, data, pub); err != nil {
		t.Fatalf("валидный установщик отклонён: %v", err)
	}
	if err := Verify(m, []byte("подмена"), pub); err == nil {
		t.Fatal("подменённый файл принят")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(m, data, other); err == nil {
		t.Fatal("чужой ключ принят")
	}
	// Подпись привязана к версии: старый подписанный файл под новой версией не проходит.
	m2 := *m
	m2.Version = "9.9.9"
	if err := Verify(&m2, data, pub); err == nil {
		t.Fatal("подпись не привязана к версии")
	}
	_ = priv
}

func TestManifestURLRestricted(t *testing.T) {
	m, _, _ := signed(t, "1.2.3", []byte("x"))
	m.URL = "https://evil.example/AnyRoute-Setup.exe"
	if err := m.Validate(); err == nil {
		t.Fatal("чужой адрес принят")
	}
	m, _, _ = signed(t, "1.2.3", []byte("x"))
	m.URL = downloadPrefix + "v1.0.0/AnyRoute-Setup-1.0.0.exe"
	if err := m.Validate(); err == nil {
		t.Fatal("адрес другой версии принят")
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.1", "1.0.0", true},
		{"v1.10.0", "1.9.9", true},
		{"1.0.0", "1.0.0", false},
		{"0.9.0", "1.0.0", false},
		{"1.0.0", "dev", false},
		{"2.0.0-rc1", "1.9.0", true},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s,%s)=%v", c.a, c.b, got)
		}
	}
}
