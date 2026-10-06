// anyroute-service — служба Windows AnyRoute (LocalSystem).
//
//	anyroute-service install    регистрирует и запускает службу
//	anyroute-service uninstall  останавливает и удаляет службу
//	anyroute-service run        консольный режим для отладки (от администратора)
//
// Без аргументов запускается диспетчером служб.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/krazzer00/anyroute/internal/core"
	"github.com/krazzer00/anyroute/internal/ipc"
	"github.com/krazzer00/anyroute/internal/service"
	"github.com/krazzer00/anyroute/internal/update"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		var err error
		switch strings.ToLower(os.Args[1]) {
		case "install":
			err = install()
		case "uninstall":
			err = uninstall()
		case "run":
			err = runConsole()
		case "version":
			fmt.Println(version)
		default:
			err = fmt.Errorf("неизвестная команда %q (install | uninstall | run | version)", os.Args[1])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "anyroute-service:", err)
			os.Exit(1)
		}
		return
	}
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		if err := svc.Run(service.Name, &handler{}); err != nil {
			os.Exit(1)
		}
		return
	}
	fmt.Println("Это служба AnyRoute. Команды: install | uninstall | run | version")
}

func newApplier(s **service.Service) *update.Applier {
	return &update.Applier{
		Current: version,
		DataDir: service.DataDir(),
		BeforeInstall: func() {
			if *s != nil {
				(*s).Core.Disconnect()
				(*s).Core.Wait(20 * time.Second)
			}
		},
	}
}

func start(console bool) (*service.Service, error) {
	var s *service.Service
	app := newApplier(&s)
	var out *os.File
	if console {
		out = os.Stdout
	}
	var err error
	if out != nil {
		s, err = service.Start(version, core.WindowsPlatform{}, app, ipc.PipeName, out)
	} else {
		s, err = service.Start(version, core.WindowsPlatform{}, app, ipc.PipeName, nil)
	}
	if err != nil {
		return nil, err
	}
	exe, _ := os.Executable()
	go app.RelaunchAfterUpdate(filepath.Join(filepath.Dir(exe), "AnyRoute.exe"), s.Log.Source("update"))
	return s, nil
}

func runConsole() error {
	s, err := start(true)
	if err != nil {
		return err
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	s.Stop()
	return nil
}

type handler struct{}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	s, err := start(false)
	if err != nil {
		return true, 1
	}
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
			s.Stop()
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

// serviceSDDL — права на управление службой: интерактивные пользователи
// (IU) могут её запускать и останавливать (кнопка «Перезапустить службу» в
// интерфейсе), но не менять конфигурацию.
const serviceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

func install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("нужны права администратора: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(service.Name); err == nil {
		s.Close()
		if err := uninstall(); err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
	s, err := m.CreateService(service.Name, exe, mgr.Config{
		DisplayName:  "AnyRoute VPN",
		Description:  "Клиент Cisco AnyConnect с маршрутизацией по правилам (TUN). Держит VPN-туннель, чтобы интерфейс работал без прав администратора.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return fmt.Errorf("создание службы: %w", err)
	}
	defer s.Close()
	// Автоперезапуск при сбое: 5 с, 5 с, затем 30 с; счётчик сбрасывается за сутки.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	if err := setServiceSDDL(); err != nil {
		fmt.Fprintln(os.Stderr, "предупреждение: права на перезапуск службы пользователем не установлены:", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("запуск службы: %w", err)
	}
	fmt.Println("служба AnyRoute установлена и запущена")
	return nil
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("нужны права администратора: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service.Name)
	if err != nil {
		return nil // уже удалена
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("удаление службы: %w", err)
	}
	fmt.Println("служба AnyRoute удалена")
	return nil
}
