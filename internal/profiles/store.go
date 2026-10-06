// Package profiles — профили серверов, профили маршрутизации и настройки
// интерфейса. Хранятся в %APPDATA%\AnyRoute (у пользователя). Секретов здесь
// нет: пароли и TOTP-секреты — в диспетчере учётных данных (internal/secrets).
package profiles

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/krazzer00/anyroute/internal/rules"
)

// Server — профиль VPN-сервера.
type Server struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Host             string `json:"host"`
	Group            string `json:"group"`
	Username         string `json:"username"`
	SavePassword     bool   `json:"savePassword"`
	RoutingProfileID string `json:"routingProfileId"`
	InsecureTLS      bool   `json:"insecureTls,omitempty"`
}

// Routing — профиль маршрутизации. Списки хранятся текстом, как в редакторе.
type Routing struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	DefaultOutbound   string `json:"defaultOutbound"` // vpn | direct
	ServerRoutesToVPN bool   `json:"serverRoutesToVpn"`
	LANDirect         bool   `json:"lanDirect"`
	VPN               string `json:"vpn"`
	Direct            string `json:"direct"`
	Block             string `json:"block"`
}

// Settings — настройки приложения.
type Settings struct {
	Autostart        bool   `json:"autostart"`
	CheckUpdates     bool   `json:"checkUpdates"`
	LogLevel         string `json:"logLevel"`
	Effects          bool   `json:"effects"`
	LastServerID     string `json:"lastServerId"`
	ConfirmOnExit    bool   `json:"confirmOnExit"`
	DisconnectOnExit bool   `json:"disconnectOnExit"`
}

// DefaultSettings — настройки по умолчанию.
func DefaultSettings() Settings {
	return Settings{CheckUpdates: true, LogLevel: "info", Effects: true, ConfirmOnExit: true, DisconnectOnExit: true}
}

// DefaultRouting — профиль «Default»: как обычный AnyConnect — в VPN только
// сети и зоны сервера, остальное напрямую.
func DefaultRouting() Routing {
	return Routing{
		ID: "default", Name: "Default", DefaultOutbound: rules.OutDirect,
		ServerRoutesToVPN: true, LANDirect: true,
		Direct: "# Например:\n# processName:Telegram.exe\n# domain:example.com\n",
	}
}

// Compile разбирает списки профиля.
func (r Routing) Compile() (vpn, direct, block rules.List, errs map[string][]rules.LineError) {
	errs = map[string][]rules.LineError{}
	var e []rules.LineError
	if vpn, e = rules.Parse(r.VPN); len(e) > 0 {
		errs["vpn"] = e
	}
	if direct, e = rules.Parse(r.Direct); len(e) > 0 {
		errs["direct"] = e
	}
	if block, e = rules.Parse(r.Block); len(e) > 0 {
		errs["block"] = e
	}
	return vpn, direct, block, errs
}

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._\-/]*)?$`)
	idRe   = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
)

// Validate проверяет профиль сервера.
func (s *Server) Validate() error {
	s.Name = strings.TrimSpace(s.Name)
	s.Host = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s.Host), "https://"), "http://"))
	s.Host = strings.TrimSuffix(s.Host, "/")
	s.Username = strings.TrimSpace(s.Username)
	if s.Name == "" {
		return errors.New("укажите название сервера")
	}
	if len(s.Name) > 80 || strings.ContainsAny(s.Name, "\x00\r\n") {
		return errors.New("недопустимое название сервера")
	}
	if !hostRe.MatchString(s.Host) {
		return errors.New("адрес сервера: имя или IP, например vpn.example.com или vpn.example.com:8443")
	}
	if len(s.Group) > 200 || len(s.Username) > 200 || strings.ContainsAny(s.Group+s.Username, "\x00\r\n") {
		return errors.New("недопустимая группа или логин")
	}
	return nil
}

// Validate проверяет профиль маршрутизации, включая синтаксис правил.
func (r *Routing) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > 80 {
		return errors.New("укажите название профиля (до 80 символов)")
	}
	if r.DefaultOutbound != rules.OutVPN {
		r.DefaultOutbound = rules.OutDirect
	}
	if len(r.VPN)+len(r.Direct)+len(r.Block) > 1<<20 {
		return errors.New("слишком большие списки правил")
	}
	_, _, _, errs := r.Compile()
	if len(errs) > 0 {
		return &RuleErrors{Errors: errs}
	}
	return nil
}

// RuleErrors — ошибки в списках правил (по спискам).
type RuleErrors struct {
	Errors map[string][]rules.LineError
}

func (e *RuleErrors) Error() string {
	names := map[string]string{"vpn": "VPN", "direct": "Напрямую", "block": "Блокировать"}
	var parts []string
	for _, k := range []string{"vpn", "direct", "block"} {
		for _, le := range e.Errors[k] {
			parts = append(parts, names[k]+", "+le.Error())
		}
	}
	return strings.Join(parts, "; ")
}

// NewID генерирует идентификатор.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Store — хранилище в каталоге dir.
type Store struct {
	mu  sync.Mutex
	dir string
}

// DefaultDir — %APPDATA%\AnyRoute.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "AnyRoute"), nil
}

// Open открывает (создаёт) хранилище и профиль Default.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	rs, err := s.Routings()
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		if err := s.SaveRouting(DefaultRouting()); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Dir — каталог хранилища.
func (s *Store) Dir() string { return s.dir }

// Servers — список серверов.
func (s *Store) Servers() ([]Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []Server
	if err := readJSON(filepath.Join(s.dir, "servers.json"), &list); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return list, nil
}

// Server — сервер по id.
func (s *Store) Server(id string) (Server, error) {
	list, err := s.Servers()
	if err != nil {
		return Server{}, err
	}
	for _, sv := range list {
		if sv.ID == id {
			return sv, nil
		}
	}
	return Server{}, fmt.Errorf("сервер %q не найден", id)
}

// SaveServer добавляет или обновляет сервер (пустой ID — новый).
func (s *Store) SaveServer(sv Server) (Server, error) {
	if err := sv.Validate(); err != nil {
		return sv, err
	}
	list, err := s.Servers()
	if err != nil {
		return sv, err
	}
	if sv.ID == "" {
		sv.ID = NewID()
	} else if !idRe.MatchString(sv.ID) {
		return sv, errors.New("недопустимый идентификатор")
	}
	found := false
	for i := range list {
		if list[i].ID == sv.ID {
			list[i], found = sv, true
		}
	}
	if !found {
		list = append(list, sv)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return sv, writeJSON(filepath.Join(s.dir, "servers.json"), list)
}

// DeleteServer удаляет сервер.
func (s *Store) DeleteServer(id string) error {
	list, err := s.Servers()
	if err != nil {
		return err
	}
	out := list[:0]
	for _, sv := range list {
		if sv.ID != id {
			out = append(out, sv)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.dir, "servers.json"), out)
}

// Routings — профили маршрутизации (по имени).
func (s *Store) Routings() ([]Routing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := filepath.Glob(filepath.Join(s.dir, "profiles", "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Routing
	for _, f := range files {
		var r Routing
		if err := readJSON(f, &r); err != nil || r.ID == "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == "default" || out[j].ID == "default" {
			return out[i].ID == "default"
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Routing — профиль по id (неизвестный id — Default).
func (s *Store) Routing(id string) (Routing, error) {
	rs, err := s.Routings()
	if err != nil {
		return Routing{}, err
	}
	for _, r := range rs {
		if r.ID == id {
			return r, nil
		}
	}
	for _, r := range rs {
		if r.ID == "default" {
			return r, nil
		}
	}
	return DefaultRouting(), nil
}

// SaveRouting сохраняет профиль (пустой ID — новый).
func (s *Store) SaveRouting(r Routing) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = NewID()
	} else if !idRe.MatchString(r.ID) {
		return errors.New("недопустимый идентификатор профиля")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.dir, "profiles", r.ID+".json"), r)
}

// DeleteRouting удаляет профиль (Default удалить нельзя).
func (s *Store) DeleteRouting(id string) error {
	if id == "default" {
		return errors.New("профиль Default удалить нельзя")
	}
	if !idRe.MatchString(id) {
		return errors.New("недопустимый идентификатор профиля")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, "profiles", id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Settings — настройки.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := DefaultSettings()
	_ = readJSON(filepath.Join(s.dir, "settings.json"), &st)
	return st
}

// SaveSettings сохраняет настройки.
func (s *Store) SaveSettings(st Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.dir, "settings.json"), st)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeJSON пишет атомарно: во временный файл и переименованием, чтобы
// аварийное завершение не оставило полуфайл.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
