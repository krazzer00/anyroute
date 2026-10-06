package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// publicKeyB64 — открытый ключ подписи обновлений. Закрытый ключ хранится
// только в секретах репозитория (UPDATE_SIGNING_KEY) и у владельца.
const publicKeyB64 = "/n9f5tEHwTvOsu3C57InV/zYc9XKu9dM5jZM6wewPn0="

// PublicKey — ключ проверки установщиков.
func PublicKey() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
