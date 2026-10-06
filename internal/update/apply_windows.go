package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/krazzer00/anyroute/internal/logx"
)

// maxInstaller — предел размера установщика.
const maxInstaller = 300 << 20

// Applier — установка обновлений из службы (LocalSystem).
type Applier struct {
	Current string // текущая версия
	DataDir string // %ProgramData%\AnyRoute
	// BeforeInstall вызывается перед запуском установщика (отключение VPN).
	BeforeInstall func()
}

// secureDirSDDL — каталог загрузок: писать могут только SYSTEM и
// администраторы, иначе пользователь подменил бы установщик, который служба
// запустит с правами системы.
const secureDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(secureDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// relaunchMarker — файл-флаг: после обновления новая служба запускает
// интерфейс в сеансе пользователя.
func (a *Applier) relaunchMarker() string {
	return filepath.Join(a.DataDir, "updates", "relaunch.json")
}

// Apply скачивает, проверяет и запускает установщик версии version.
func (a *Applier) Apply(ctx context.Context, version string, log *logx.Src) error {
	m, err := FetchManifest(ctx, version)
	if err != nil {
		return err
	}
	if !Newer(m.Version, a.Current) {
		return fmt.Errorf("версия %s не новее установленной %s", m.Version, a.Current)
	}
	log.Infof("загрузка обновления %s…", m.Version)
	data, err := Download(ctx, m.URL, maxInstaller)
	if err != nil {
		return err
	}
	if err := Verify(m, data, PublicKey()); err != nil {
		return err
	}
	log.OKf("обновление %s загружено, подпись проверена", m.Version)

	dir := filepath.Join(a.DataDir, "updates")
	if err := secureDir(dir); err != nil {
		return fmt.Errorf("каталог обновлений: %w", err)
	}
	path := filepath.Join(dir, "AnyRoute-Setup-"+m.Version+".exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	session := windows.WTSGetActiveConsoleSessionId()
	marker, _ := json.Marshal(map[string]any{"session": session, "version": m.Version})
	_ = os.WriteFile(a.relaunchMarker(), marker, 0o644)

	if a.BeforeInstall != nil {
		a.BeforeInstall()
	}
	log.Infof("запуск установщика %s", m.Version)
	cmd := exec.Command(path, "/S", "/UPDATE")
	cmd.Dir = dir
	// Установщик остановит службу — он не должен умереть вместе с ней.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS | windows.CREATE_BREAKAWAY_FROM_JOB,
	}
	if err := cmd.Start(); err != nil {
		// CREATE_BREAKAWAY_FROM_JOB недопустим вне job — повтор без него.
		cmd = exec.Command(path, "/S", "/UPDATE")
		cmd.Dir = dir
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("запуск установщика: %w", err)
		}
	}
	_ = cmd.Process.Release()
	return nil
}

// RelaunchAfterUpdate запускает интерфейс в сеансе пользователя, если
// служба стартовала после автообновления. Возвращает true, если запустила.
func (a *Applier) RelaunchAfterUpdate(guiPath string, log *logx.Src) bool {
	raw, err := os.ReadFile(a.relaunchMarker())
	if err != nil {
		return false
	}
	_ = os.Remove(a.relaunchMarker())
	var mk struct {
		Session uint32 `json:"session"`
	}
	_ = json.Unmarshal(raw, &mk)
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return false
	}
	if err := runInSession(session, guiPath, "--updated"); err != nil {
		log.Warnf("не удалось запустить интерфейс после обновления: %v", err)
		return false
	}
	log.OKf("интерфейс перезапущен после обновления")
	// Удаляем загруженные установщики.
	files, _ := filepath.Glob(filepath.Join(a.DataDir, "updates", "AnyRoute-Setup-*.exe"))
	for _, f := range files {
		_ = os.Remove(f)
	}
	return true
}

// runInSession запускает программу от имени пользователя сеанса session.
func runInSession(session uint32, path string, args ...string) error {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer token.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	cmdline := syscall.EscapeArg(path)
	for _, a := range args {
		cmdline += " " + syscall.EscapeArg(a)
	}
	cmd16, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return err
	}
	dir16, _ := windows.UTF16PtrFromString(filepath.Dir(path))
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := &windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(*si))
	pi := &windows.ProcessInformation{}
	if err := windows.CreateProcessAsUser(token, nil, cmd16, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_PROCESS_GROUP, env, dir16, si, pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
