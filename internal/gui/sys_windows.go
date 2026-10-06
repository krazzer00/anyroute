package gui

import (
	"errors"
	"fmt"
	"os"

	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// setAutostart включает/выключает запуск при входе в Windows (свёрнутым в трей).
func setAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue("AnyRoute")
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue("AnyRoute", `"`+exe+`" --tray`)
}

// restartService перезапускает службу AnyRoute от имени пользователя
// (установщик выдаёт интерактивным пользователям права start/stop).
func restartService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	m := &mgr.Mgr{Handle: scm}
	defer m.Disconnect()
	name, _ := windows.UTF16PtrFromString("AnyRoute")
	h, err := windows.OpenService(scm, name, windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("служба AnyRoute не найдена или нет прав: %w", err)
	}
	s := &mgr.Service{Name: "AnyRoute", Handle: h}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	return s.Start()
}

var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	dwmapi                       = windows.NewLazySystemDLL("dwmapi.dll")
	procFindWindowW              = user32.NewProc("FindWindowW")
	procSetWindowCompositionAttr = user32.NewProc("SetWindowCompositionAttribute")
	procSetWindowRgn             = user32.NewProc("SetWindowRgn")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procIsZoomed                 = user32.NewProc("IsZoomed")
	gdi32                        = windows.NewLazySystemDLL("gdi32.dll")
	procCreateRoundRectRgn       = gdi32.NewProc("CreateRoundRectRgn")
	procDwmSetWindowAttribute    = dwmapi.NewProc("DwmSetWindowAttribute")
)

const windowClass = "AnyRouteWindow"

func findWindow() windows.HWND {
	cls, _ := windows.UTF16PtrFromString(windowClass)
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
	return windows.HWND(h)
}

// isWin11 — сборка 22000 и новее.
func isWin11() bool {
	maj, _, build := windows.RtlGetNtVersionNumbers()
	return maj >= 10 && build >= 22000
}

// supportsBackdrop — системный Acrylic (Windows 11 22621+).
func supportsBackdrop() bool {
	_, _, build := windows.RtlGetNtVersionNumbers()
	return build >= 22621
}

type accentPolicy struct {
	AccentState   uint32
	AccentFlags   uint32
	GradientColor uint32
	AnimationID   uint32
}

type winCompAttrData struct {
	Attrib uint32
	PvData unsafe.Pointer
	CbData uintptr
}

// applyWindowEffects — скругления и стекло там, где Wails их не даёт.
// Windows 11: скругление через DWM (Acrylic даёт сам Wails). Windows 10:
// acrylic blur-behind с тёмной тонировкой и форма окна со скруглениями.
// effects=false — без прозрачности (слабые машины, удалённый рабочий стол).
func applyWindowEffects(effects bool) {
	var hwnd windows.HWND
	for i := 0; i < 50 && hwnd == 0; i++ {
		hwnd = findWindow()
		if hwnd == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if hwnd == 0 {
		return
	}
	if isWin11() {
		pref := uint32(2) // DWMWCP_ROUND
		procDwmSetWindowAttribute.Call(uintptr(hwnd), 33, uintptr(unsafe.Pointer(&pref)), 4)
		return
	}
	// Windows 10.
	if effects {
		// ACCENT_ENABLE_ACRYLICBLURBEHIND (4); цвет ABGR: тёмно-синяя тонировка.
		acc := accentPolicy{AccentState: 4, AccentFlags: 2, GradientColor: 0xB0140A07}
		data := winCompAttrData{Attrib: 19, PvData: unsafe.Pointer(&acc), CbData: unsafe.Sizeof(acc)}
		procSetWindowCompositionAttr.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&data)))
	}
	roundWindow(hwnd)
}

// roundWindow задаёт форму окна со скруглёнными углами (Windows 10).
// Развёрнутое окно — без скруглений.
func roundWindow(hwnd windows.HWND) {
	if z, _, _ := procIsZoomed.Call(uintptr(hwnd)); z != 0 {
		procSetWindowRgn.Call(uintptr(hwnd), 0, 1)
		return
	}
	var r struct{ Left, Top, Right, Bottom int32 }
	if ok, _, _ := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r))); ok == 0 {
		return
	}
	w, h := r.Right-r.Left, r.Bottom-r.Top
	rgn, _, _ := procCreateRoundRectRgn.Call(0, 0, uintptr(w+1), uintptr(h+1), 24, 24)
	if rgn != 0 {
		procSetWindowRgn.Call(uintptr(hwnd), rgn, 1)
	}
}
