// Package gui — интерфейс AnyRoute (Wails v2). Работает с правами
// пользователя: хранит профили и учётные данные, туннелем управляет служба.
//
// Правило пакета: ни один вызов из JS и ни один пункт трея не блокирует
// надолго. Обращения к службе ограничены по времени (ipc), долгие действия
// (подключение) асинхронны — результат приходит событием состояния.
package gui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/api"
	"github.com/krazzer00/anyroute/internal/ipc"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/profiles"
	"github.com/krazzer00/anyroute/internal/secrets"
	"github.com/krazzer00/anyroute/internal/update"
)

var errServiceDown = errors.New("служба AnyRoute не запущена — нажмите «Перезапустить службу» или переустановите приложение")

// App — объект, методы которого доступны JS (window.go.gui.App).
type App struct {
	version string
	store   *profiles.Store
	link    *svcLink
	tray    *tray
	ctx     context.Context

	mu        sync.Mutex
	status    api.Status
	quitting  bool
	lastTOTP  int // номер challenge, на который уже отправлен автокод
	pendingUp *update.Manifest
	startHide bool
}

// NewApp создаёт приложение.
func NewApp(version string, startHidden bool) (*App, error) {
	dir, err := profiles.DefaultDir()
	if err != nil {
		return nil, err
	}
	st, err := profiles.Open(dir)
	if err != nil {
		return nil, err
	}
	return &App{version: version, store: st, startHide: startHidden, status: api.Status{State: api.StateIdle}}, nil
}

// startup — Wails OnStartup.
func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	a.tray = newTray(a)
	a.tray.start()
	a.link = newSvcLink(a.onServiceEvent, a.onServiceState)
	if a.store.Settings().CheckUpdates {
		go a.updateLoop()
	}
}

func (a *App) emit(name string, data any) {
	a.mu.Lock()
	ctx := a.ctx
	a.mu.Unlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, data)
	}
}

func (a *App) onServiceState(up bool) {
	a.emit("service", up)
	if up {
		var st api.Status
		if err := a.link.call("status", nil, &st, 0); err == nil {
			a.applyStatus(st)
		}
		lvl := a.store.Settings().LogLevel
		_ = a.link.call("setLogLevel", map[string]string{"level": lvl}, nil, 0)
	} else {
		a.applyStatus(api.Status{State: api.StateIdle, Error: "нет связи со службой AnyRoute"})
	}
}

func (a *App) onServiceEvent(f ipc.Frame) {
	switch f.Event {
	case "state":
		var st api.Status
		if decodeInto(f.Data, &st) {
			a.applyStatus(st)
		}
	case "log":
		var e logx.Entry
		if decodeInto(f.Data, &e) {
			a.emit("log", e)
		}
	case "sample":
		var s api.Sample
		if decodeInto(f.Data, &s) {
			a.emit("sample", s)
		}
	case "update":
		a.emit("update", f.Data)
	}
}

// applyStatus обновляет состояние, трей и при необходимости отвечает на
// запрос второго фактора кодом TOTP.
func (a *App) applyStatus(st api.Status) {
	a.mu.Lock()
	a.status = st
	a.mu.Unlock()
	a.emit("status", st)
	if a.tray != nil {
		a.tray.update(st)
	}
	if st.State == api.State2FA && st.Challenge != nil {
		a.autoTOTP(st)
	}
}

// autoTOTP отправляет код по сохранённому секрету — один раз на challenge.
// Если сервер код отклонил (Retry), решает пользователь: окно ввода.
func (a *App) autoTOTP(st api.Status) {
	if st.Challenge.Retry || st.ServerID == "" {
		return
	}
	a.mu.Lock()
	if a.lastTOTP == st.Challenge.Seq {
		a.mu.Unlock()
		return
	}
	a.lastTOTP = st.Challenge.Seq
	a.mu.Unlock()
	secret, err := secrets.Load(st.ServerID, secrets.TOTPKey)
	if err != nil {
		return
	}
	go func() {
		// Если до смены кода осталось мало, ждём новый — иначе сервер
		// может получить уже устаревший код.
		if secrets.TOTPRemaining(time.Now()) < 3 {
			time.Sleep(time.Duration(secrets.TOTPRemaining(time.Now())+1) * time.Second)
		}
		code, err := secrets.TOTP(secret, time.Now())
		if err != nil {
			a.emit("toast", map[string]string{"kind": "error", "text": "TOTP-секрет повреждён: " + err.Error()})
			return
		}
		a.emit("toast", map[string]string{"kind": "info", "text": "Код подтверждения сгенерирован и отправлен автоматически"})
		if err := a.link.call("submit2fa", map[string]string{"code": code}, nil, 0); err != nil {
			a.emit("toast", map[string]string{"kind": "error", "text": err.Error()})
		}
	}()
}

// ---------- Методы для JS ----------

// Bootstrap — начальные данные интерфейса.
type Bootstrap struct {
	Version   string             `json:"version"`
	Servers   []ServerView       `json:"servers"`
	Profiles  []profiles.Routing `json:"profiles"`
	Settings  profiles.Settings  `json:"settings"`
	Status    api.Status         `json:"status"`
	ServiceUp bool               `json:"serviceUp"`
	Logs      []logx.Entry       `json:"logs"`
	Samples   []api.Sample       `json:"samples"`
}

// ServerView — сервер для интерфейса (без секретов, с флагами их наличия).
type ServerView struct {
	profiles.Server
	HasPassword bool `json:"hasPassword"`
	HasTOTP     bool `json:"hasTotp"`
}

func (a *App) serverViews() []ServerView {
	list, _ := a.store.Servers()
	out := make([]ServerView, 0, len(list))
	for _, s := range list {
		out = append(out, ServerView{Server: s, HasPassword: secrets.Has(s.ID, secrets.Password), HasTOTP: secrets.Has(s.ID, secrets.TOTPKey)})
	}
	return out
}

// Init возвращает всё, что нужно для первой отрисовки.
func (a *App) Init() Bootstrap {
	rs, _ := a.store.Routings()
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	b := Bootstrap{Version: a.version, Servers: a.serverViews(), Profiles: rs, Settings: a.store.Settings(), Status: st}
	if a.link != nil && a.link.up() {
		b.ServiceUp = true
		_ = a.link.call("logs", map[string]uint64{"after": 0}, &b.Logs, 0)
		_ = a.link.call("samples", nil, &b.Samples, 0)
	}
	return b
}

// Servers — список серверов.
func (a *App) Servers() []ServerView { return a.serverViews() }

// ServerForm — данные формы сервера.
type ServerForm struct {
	Server     profiles.Server `json:"server"`
	Password   string          `json:"password"`   // "" — не менять
	TOTPSecret string          `json:"totpSecret"` // "" — не менять
	ClearTOTP  bool            `json:"clearTotp"`
}

// SaveServer сохраняет сервер и его секреты.
func (a *App) SaveServer(f ServerForm) (ServerView, error) {
	sv, err := a.store.SaveServer(f.Server)
	if err != nil {
		return ServerView{}, err
	}
	if !sv.SavePassword {
		_ = secrets.Delete(sv.ID, secrets.Password)
	} else if f.Password != "" {
		if err := secrets.Save(sv.ID, secrets.Password, sv.Username, f.Password); err != nil {
			return ServerView{}, fmt.Errorf("пароль не сохранён: %w", err)
		}
	}
	if f.ClearTOTP {
		_ = secrets.Delete(sv.ID, secrets.TOTPKey)
	} else if strings.TrimSpace(f.TOTPSecret) != "" {
		norm, err := secrets.NormalizeTOTPSecret(f.TOTPSecret)
		if err != nil {
			return ServerView{}, err
		}
		if err := secrets.Save(sv.ID, secrets.TOTPKey, sv.Username, norm); err != nil {
			return ServerView{}, fmt.Errorf("TOTP-секрет не сохранён: %w", err)
		}
	}
	a.tray.refreshMenus()
	return ServerView{Server: sv, HasPassword: secrets.Has(sv.ID, secrets.Password), HasTOTP: secrets.Has(sv.ID, secrets.TOTPKey)}, nil
}

// DeleteServer удаляет сервер и его секреты.
func (a *App) DeleteServer(id string) error {
	secrets.DeleteAll(id)
	err := a.store.DeleteServer(id)
	a.tray.refreshMenus()
	return err
}

// TOTPPreview — текущий код по секрету (проверка правильности секрета в форме).
func (a *App) TOTPPreview(secret string) (string, error) {
	norm, err := secrets.NormalizeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return secrets.TOTP(norm, time.Now())
}

// FetchGroups запрашивает группы у сервера (из процесса интерфейса).
func (a *App) FetchGroups(host string, insecure bool) (map[string]any, error) {
	sv := profiles.Server{Name: "x", Host: host}
	if err := sv.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	groups, def, err := anyconnect.FetchGroups(ctx, anyconnect.Config{Host: sv.Host, InsecureSkipVerify: insecure})
	if err != nil {
		return nil, err
	}
	return map[string]any{"groups": groups, "default": def}, nil
}

// Profiles — профили маршрутизации.
func (a *App) Profiles() []profiles.Routing {
	rs, _ := a.store.Routings()
	return rs
}

// SaveProfile сохраняет профиль; если он активен — применяет на лету.
func (a *App) SaveProfile(r profiles.Routing) (map[string]any, error) {
	if err := r.Validate(); err != nil {
		var re *profiles.RuleErrors
		if errors.As(err, &re) {
			return map[string]any{"ruleErrors": re.Errors}, nil
		}
		return nil, err
	}
	if r.ID == "" {
		r.ID = profiles.NewID()
	}
	if err := a.store.SaveRouting(r); err != nil {
		return nil, err
	}
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	if st.State == api.StateConnected && st.ProfileID == r.ID {
		_ = a.link.call("setProfile", r, nil, 0)
	}
	a.tray.refreshMenus()
	return map[string]any{"profile": r}, nil
}

// DeleteProfile удаляет профиль; серверы с ним переходят на Default.
func (a *App) DeleteProfile(id string) error {
	if err := a.store.DeleteRouting(id); err != nil {
		return err
	}
	list, _ := a.store.Servers()
	for _, s := range list {
		if s.RoutingProfileID == id {
			s.RoutingProfileID = "default"
			_, _ = a.store.SaveServer(s)
		}
	}
	a.tray.refreshMenus()
	return nil
}

// UseProfile назначает серверу профиль и применяет его, если сервер подключён.
func (a *App) UseProfile(serverID, profileID string) error {
	sv, err := a.store.Server(serverID)
	if err != nil {
		return err
	}
	sv.RoutingProfileID = profileID
	if _, err := a.store.SaveServer(sv); err != nil {
		return err
	}
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	if st.ServerID == serverID && (st.State == api.StateConnected || st.State == api.StateConnecting || st.State == api.StateAuth || st.State == api.State2FA) {
		r, err := a.store.Routing(profileID)
		if err != nil {
			return err
		}
		return a.link.call("setProfile", r, nil, 0)
	}
	return nil
}

// Connect подключается к серверу. password — для серверов без
// сохранённого пароля (иначе пусто).
func (a *App) Connect(serverID, password string, remember bool) error {
	sv, err := a.store.Server(serverID)
	if err != nil {
		return err
	}
	if password == "" {
		password, err = secrets.Load(serverID, secrets.Password)
		if err != nil {
			return errors.New("NEED_PASSWORD")
		}
	} else if remember {
		if err := secrets.Save(serverID, secrets.Password, sv.Username, password); err == nil {
			sv.SavePassword = true
			_, _ = a.store.SaveServer(sv)
		}
	}
	r, err := a.store.Routing(sv.RoutingProfileID)
	if err != nil {
		return err
	}
	st := a.store.Settings()
	st.LastServerID = serverID
	_ = a.store.SaveSettings(st)
	req := api.ConnectRequest{ServerID: sv.ID, ServerName: sv.Name, Host: sv.Host, Group: sv.Group,
		Username: sv.Username, Password: password, InsecureTLS: sv.InsecureTLS, Profile: r}
	return a.link.call("connect", req, nil, 0)
}

// Disconnect отключает VPN.
func (a *App) Disconnect() error { return a.link.call("disconnect", nil, nil, 0) }

// Submit2FA отправляет код второго фактора.
func (a *App) Submit2FA(code string) error {
	return a.link.call("submit2fa", map[string]string{"code": code}, nil, 0)
}

// Status — текущее состояние.
func (a *App) Status() api.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// Connections — соединения для вкладки «Приложения».
func (a *App) Connections() ([]api.Conn, error) {
	var out []api.Conn
	err := a.link.call("connections", nil, &out, 0)
	return out, err
}

// Logs — записи журнала службы после номера after.
func (a *App) Logs(after uint64) ([]logx.Entry, error) {
	var out []logx.Entry
	err := a.link.call("logs", map[string]uint64{"after": after}, &out, 0)
	return out, err
}

// Settings — настройки.
func (a *App) Settings() profiles.Settings { return a.store.Settings() }

// SaveSettings сохраняет настройки и применяет их.
func (a *App) SaveSettings(s profiles.Settings) error {
	if err := setAutostart(s.Autostart); err != nil {
		return fmt.Errorf("автозапуск: %w", err)
	}
	if err := a.store.SaveSettings(s); err != nil {
		return err
	}
	_ = a.link.call("setLogLevel", map[string]string{"level": s.LogLevel}, nil, 0)
	return nil
}

// RestartService перезапускает службу (права выдаёт установщик).
func (a *App) RestartService() error { return restartService() }

// ServiceUp — есть ли связь со службой.
func (a *App) ServiceUp() bool { return a.link != nil && a.link.up() }

// ---------- Окно ----------

// WindowMinimise сворачивает окно.
func (a *App) WindowMinimise() { runtime.WindowMinimise(a.ctx) }

// WindowToggleMaximise разворачивает/восстанавливает окно.
func (a *App) WindowToggleMaximise() { runtime.WindowToggleMaximise(a.ctx) }

// WindowHide прячет окно в трей.
func (a *App) WindowHide() { runtime.WindowHide(a.ctx) }

// ShowWindow показывает окно (трей, второй запуск).
func (a *App) ShowWindow() {
	a.mu.Lock()
	ctx := a.ctx
	a.mu.Unlock()
	if ctx == nil {
		return
	}
	runtime.WindowShow(ctx)
	runtime.WindowUnminimise(ctx)
	go applyWindowEffects(a.store.Settings().Effects)
}

// WindowShape — подогнать форму окна (скругления на Windows 10) под размер.
func (a *App) WindowShape() { go applyWindowEffects(a.store.Settings().Effects) }

// Quit — выход. disconnect=true — сначала отключить VPN.
func (a *App) Quit(disconnect bool) {
	a.mu.Lock()
	a.quitting = true
	ctx := a.ctx
	a.mu.Unlock()
	if disconnect && a.link != nil {
		_ = a.link.call("disconnect", nil, nil, 2*time.Second)
	}
	if a.tray != nil {
		a.tray.stop()
	}
	if a.link != nil {
		a.link.close()
	}
	if ctx != nil {
		runtime.Quit(ctx)
	}
}

// beforeClose — крестик окна прячет в трей.
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	q := a.quitting
	a.mu.Unlock()
	if q {
		return false
	}
	runtime.WindowHide(ctx)
	return true
}

// ---------- Обновления ----------

// UpdateInfo — сведения о доступном обновлении.
type UpdateInfo struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
	Notes     string `json:"notes"`
	Current   string `json:"current"`
	Error     string `json:"error,omitempty"`
}

// CheckUpdate проверяет наличие новой версии.
func (a *App) CheckUpdate() UpdateInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	info := UpdateInfo{Current: a.version}
	m, err := update.FetchManifest(ctx, "")
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Version, info.Notes = m.Version, m.Notes
	info.Available = update.Newer(m.Version, a.version)
	if info.Available {
		a.mu.Lock()
		a.pendingUp = m
		a.mu.Unlock()
	}
	return info
}

// ApplyUpdate просит службу установить обновление.
func (a *App) ApplyUpdate(version string) error {
	return a.link.call("update", map[string]string{"version": version}, nil, 10*time.Second)
}

func (a *App) updateLoop() {
	time.Sleep(10 * time.Second)
	for {
		if info := a.CheckUpdate(); info.Available {
			a.emit("updateAvailable", info)
			if a.tray != nil {
				a.tray.notifyUpdate(info.Version)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}
