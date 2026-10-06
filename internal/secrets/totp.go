// Package secrets — хранение паролей и TOTP-секретов в диспетчере учётных
// данных Windows (только у пользователя, никогда в файлах AnyRoute) и
// генерация TOTP-кодов по RFC 6238.
package secrets

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 по умолчанию использует HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// NormalizeTOTPSecret принимает секрет в base32 (с пробелами/дефисами в
// любом регистре) или ссылку otpauth://… и возвращает чистый base32.
func NormalizeTOTPSecret(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "otpauth://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("некорректная ссылка otpauth: %w", err)
		}
		s = u.Query().Get("secret")
	}
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	if s == "" {
		return "", errors.New("пустой TOTP-секрет")
	}
	if _, err := decodeSecret(s); err != nil {
		return "", errors.New("TOTP-секрет должен быть в base32 (буквы A–Z и цифры 2–7)")
	}
	return s, nil
}

func decodeSecret(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// TOTP возвращает 6-значный код для момента t (шаг 30 с, HMAC-SHA1).
func TOTP(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(strings.ToUpper(secret))
	if err != nil {
		return "", errors.New("некорректный TOTP-секрет")
	}
	return hotp(key, uint64(t.Unix()/30), 6), nil
}

// TOTPRemaining — сколько секунд действует текущий код.
func TOTPRemaining(t time.Time) int { return 30 - int(t.Unix()%30) }

func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}
