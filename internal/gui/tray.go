package gui

import (
	"context"
	"fmt"
	"sync"

	"fyne.io/systray"

	"github.com/krazzer00/anyroute/internal/api"
	"github.com/krazzer00/anyroute/internal/icon"
)

// tray — значок в области уведомлений. Каждый пункт меню обрабатывается в
// отдельной горутине: долгий вызов (подключение, выход) не блокирует меню,
// и «Показать AnyRoute» срабатывает всегда — в DualVPN единый цикл трея
// вставал на время отключения.
type tray struct {
	app *App

	mu       sync.Mutex
	ready    bool
	status   *systray.MenuItem
	disc     *systray.MenuItem
	srvMenu  *systray.MenuItem
	profMenu *systray.MenuItem
	updItem  *systray.MenuItem
	cancel   context.CancelFunc
	icons    map[string][]byte
	last     api.Status
}

func newTray(a *App) *tray {
	return &tray{app: a, icons: map[string][]byte{
		"idle":       icon.Tray(icon.Grey),
		"connecting": icon.Tray(icon.Amber),
		"connected":  icon.Tray(icon.Cyan),
		"error":      icon.Tray(icon.Red),
	}}
}

func (t *tray) start() { go systray.Run(t.onReady, func() {}) }

func (t *tray) stop() { systray.Quit() }

func (t *tray) onReady() {
	systray.SetIcon(t.icons["idle"])
	systray.SetTooltip("AnyRoute — отключено")
	systray.SetOnTapped(func() { go t.app.ShowWindow() })
	t.mu.Lock()
	t.ready = true
	t.mu.Unlock()
	t.refreshMenus()
	t.mu.Lock()
	st := t.last
	t.mu.Unlock()
	t.update(st)
}

// refreshMenus перестраивает меню (список серверов и профилей изменился).
func (t *tray) refreshMenus() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if !t.ready {
		t.mu.Unlock()
		return
	}
	if t.cancel != nil {
		t.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.mu.Unlock()

	systray.ResetMenu()
	status := systray.AddMenuItem("Отключено", "")
	status.Disable()
	systray.AddSeparator()

	srvMenu := systray.AddMenuItem("Подключить", "Подключиться к серверу")
	for _, s := range t.app.serverViews() {
		id := s.ID
		it := srvMenu.AddSubMenuItem(s.Name, s.Host)
		t.on(ctx, it, func() {
			if err := t.app.Connect(id, "", false); err != nil {
				// Нужен пароль или ошибка — показываем окно, там всё видно.
				t.app.ShowWindow()
				t.app.emit("connectFailed", map[string]string{"serverId": id, "error": err.Error()})
			}
		})
	}
	disc := systray.AddMenuItem("Отключить", "Отключить VPN")
	t.on(ctx, disc, func() { _ = t.app.Disconnect() })

	profMenu := systray.AddMenuItem("Профиль маршрутизации", "")
	for _, p := range t.app.Profiles() {
		pid, name := p.ID, p.Name
		it := profMenu.AddSubMenuItemCheckbox(name, "", false)
		t.on(ctx, it, func() {
			st := t.app.Status()
			srv := st.ServerID
			if srv == "" {
				srv = t.app.store.Settings().LastServerID
			}
			if srv != "" {
				_ = t.app.UseProfile(srv, pid)
				t.app.emit("profileChanged", map[string]string{"serverId": srv, "profileId": pid})
			}
		})
	}
	systray.AddSeparator()
	upd := systray.AddMenuItem("Доступно обновление", "")
	upd.Hide()
	t.on(ctx, upd, func() { t.app.ShowWindow(); t.app.emit("showUpdate", nil) })
	show := systray.AddMenuItem("Показать AnyRoute", "")
	t.on(ctx, show, func() { t.app.ShowWindow() })
	quit := systray.AddMenuItem("Выход", "Отключить VPN и закрыть AnyRoute")
	t.on(ctx, quit, func() { t.app.Quit(t.app.store.Settings().DisconnectOnExit) })

	t.mu.Lock()
	t.status, t.disc, t.srvMenu, t.profMenu, t.updItem = status, disc, srvMenu, profMenu, upd
	st := t.last
	t.mu.Unlock()
	t.update(st)
}

func (t *tray) on(ctx context.Context, it *systray.MenuItem, fn func()) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-it.ClickedCh:
				go fn()
			}
		}
	}()
}

// update отражает состояние в значке, подсказке и меню.
func (t *tray) update(st api.Status) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.last = st
	ready := t.ready
	status, disc := t.status, t.disc
	t.mu.Unlock()
	if !ready {
		return
	}
	key, text := "idle", "Отключено"
	switch st.State {
	case api.StateConnected:
		key, text = "connected", "Подключено: "+st.ServerName
	case api.StateConnecting, api.StateAuth:
		key, text = "connecting", "Подключение: "+st.ServerName
	case api.State2FA:
		key, text = "connecting", "Ждёт код подтверждения"
	case api.StateDisconnecting:
		key, text = "connecting", "Отключение…"
	default:
		if st.Error != "" {
			key, text = "error", "Ошибка: "+trim(st.Error, 60)
		}
	}
	systray.SetIcon(t.icons[key])
	systray.SetTooltip(fmt.Sprintf("AnyRoute — %s", trim(text, 100)))
	if status != nil {
		status.SetTitle(text)
	}
	if disc != nil {
		if st.State == api.StateIdle {
			disc.Disable()
		} else {
			disc.Enable()
		}
	}
}

func (t *tray) notifyUpdate(version string) {
	t.mu.Lock()
	it := t.updItem
	t.mu.Unlock()
	if it != nil {
		it.SetTitle("Доступно обновление " + version)
		it.Show()
	}
}

func trim(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
