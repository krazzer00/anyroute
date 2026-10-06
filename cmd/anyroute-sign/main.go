// anyroute-sign — подпись установщика для latest.json (используется в CI).
//
//	anyroute-sign -version 1.2.3 -file AnyRoute-Setup-1.2.3.exe -notes notes.md > latest.json
//
// Закрытый ключ (base64 seed ed25519) берётся из переменной окружения
// UPDATE_SIGNING_KEY и нигде не печатается.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/krazzer00/anyroute/internal/update"
)

func main() {
	version := flag.String("version", "", "версия без v")
	file := flag.String("file", "", "установщик")
	notes := flag.String("notes", "", "файл с описанием изменений (необязательно)")
	flag.Parse()
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("UPDATE_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("UPDATE_SIGNING_KEY не задан или некорректен")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(update.PublicKey()) {
		fail("ключ не соответствует открытому ключу в internal/update/pubkey.go")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fail(err.Error())
	}
	v := strings.TrimPrefix(*version, "v")
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	m := update.Manifest{
		Version:   v,
		URL:       "https://github.com/" + update.Repo + "/releases/download/v" + v + "/" + filepath.Base(*file),
		SHA256:    h,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, update.SignedMessage(v, h))),
		Published: time.Now().UTC().Format(time.RFC3339),
	}
	if *notes != "" {
		if b, err := os.ReadFile(*notes); err == nil {
			m.Notes = strings.TrimSpace(string(b))
		}
	}
	if err := m.Validate(); err != nil {
		fail(err.Error())
	}
	if err := update.Verify(&m, data, update.PublicKey()); err != nil {
		fail(err.Error())
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(m)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "anyroute-sign:", msg)
	os.Exit(1)
}
