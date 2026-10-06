package secrets

import (
	"errors"
	"strings"

	"github.com/danieljoos/wincred"
)

const prefix = "AnyRoute/"

// Kind — тип секрета профиля сервера.
type Kind string

const (
	Password Kind = "password"
	TOTPKey  Kind = "totp"
)

func target(serverID string, kind Kind) string { return prefix + serverID + "/" + string(kind) }

// ErrNotFound — секрет не сохранён.
var ErrNotFound = errors.New("секрет не сохранён")

// Save сохраняет секрет в диспетчере учётных данных текущего пользователя.
func Save(serverID string, kind Kind, user, value string) error {
	c := wincred.NewGenericCredential(target(serverID, kind))
	c.UserName = user
	c.CredentialBlob = []byte(value)
	c.Persist = wincred.PersistLocalMachine
	c.Comment = "AnyRoute"
	return c.Write()
}

// Load читает секрет.
func Load(serverID string, kind Kind) (string, error) {
	c, err := wincred.GetGenericCredential(target(serverID, kind))
	if err != nil {
		if errors.Is(err, wincred.ErrElementNotFound) || strings.Contains(err.Error(), "not found") {
			return "", ErrNotFound
		}
		return "", err
	}
	return string(c.CredentialBlob), nil
}

// Has сообщает, сохранён ли секрет.
func Has(serverID string, kind Kind) bool {
	_, err := Load(serverID, kind)
	return err == nil
}

// Delete удаляет секрет (отсутствие — не ошибка).
func Delete(serverID string, kind Kind) error {
	c, err := wincred.GetGenericCredential(target(serverID, kind))
	if err != nil {
		return nil
	}
	return c.Delete()
}

// DeleteAll удаляет все секреты профиля сервера.
func DeleteAll(serverID string) {
	_ = Delete(serverID, Password)
	_ = Delete(serverID, TOTPKey)
}
