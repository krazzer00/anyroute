// Package update — автообновление из GitHub Releases.
//
// Релиз содержит установщик и latest.json:
//
//	{"version":"1.2.3","notes":"…","url":"https://github.com/krazzer00/anyroute/releases/download/v1.2.3/AnyRoute-Setup-1.2.3.exe",
//	 "sha256":"…","signature":"base64(ed25519)"}
//
// Подпись ed25519 ставится в CI закрытым ключом из секретов репозитория над
// строкой "anyroute|<version>|<sha256>" — она связывает файл с версией, и
// подменить установщик или подсунуть старый подписанный нельзя. Открытый
// ключ встроен в программу (PublicKey).
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Repo — репозиторий релизов.
const Repo = "krazzer00/anyroute"

// Адреса.
const (
	latestURL      = "https://github.com/" + Repo + "/releases/latest/download/latest.json"
	downloadPrefix = "https://github.com/" + Repo + "/releases/download/"
)

// Manifest — описание релиза.
type Manifest struct {
	Version   string `json:"version"`
	Notes     string `json:"notes"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Published string `json:"published,omitempty"`
}

// SignedMessage — что подписывается.
func SignedMessage(version, sha256hex string) []byte {
	return []byte("anyroute|" + strings.TrimPrefix(version, "v") + "|" + strings.ToLower(sha256hex))
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

// FetchManifest скачивает latest.json последнего релиза (version == "") или
// указанной версии.
func FetchManifest(ctx context.Context, version string) (*Manifest, error) {
	u := latestURL
	if version != "" {
		u = downloadPrefix + "v" + strings.TrimPrefix(version, "v") + "/latest.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AnyRoute-Updater")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("проверка обновлений: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("релизы ещё не опубликованы")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("проверка обновлений: %s", resp.Status)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("latest.json: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate проверяет поля манифеста (без подписи).
func (m *Manifest) Validate() error {
	m.Version = strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if _, ok := parseVersion(m.Version); !ok {
		return fmt.Errorf("некорректная версия в манифесте: %q", m.Version)
	}
	if !strings.HasPrefix(m.URL, downloadPrefix+"v"+m.Version+"/") {
		return fmt.Errorf("адрес установщика вне релизов %s: %q", Repo, m.URL)
	}
	if b, err := hex.DecodeString(m.SHA256); err != nil || len(b) != sha256.Size {
		return errors.New("некорректная контрольная сумма в манифесте")
	}
	if sig, err := base64.StdEncoding.DecodeString(m.Signature); err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("некорректная подпись в манифесте")
	}
	return nil
}

// Verify проверяет установщик: SHA-256 и подпись ed25519 открытым ключом.
func Verify(m *Manifest, data []byte, pub ed25519.PublicKey) error {
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m.SHA256) {
		return errors.New("контрольная сумма установщика не совпадает — файл повреждён или подменён")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, SignedMessage(m.Version, m.SHA256), sig) {
		return errors.New("подпись установщика недействительна — обновление отклонено")
	}
	return nil
}

// Newer сообщает, новее ли версия a, чем b ("dev" считается старше всех
// релизов только для проверки — обновление dev-сборки не предлагается).
func Newer(a, b string) bool {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Download скачивает установщик (не больше limit байт).
func Download(ctx context.Context, url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, downloadPrefix) {
		return nil, fmt.Errorf("загрузка разрешена только из релизов %s", Repo)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AnyRoute-Updater")
	c := &http.Client{Timeout: 10 * time.Minute}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("загрузка установщика: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("установщик слишком большой")
	}
	return data, nil
}
