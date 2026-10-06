// Package service — содержимое службы AnyRoute: ядро, канал для интерфейса,
// журнал в файл, установка обновлений. Используется и службой Windows, и
// консольным режимом (anyroute-service run) для отладки.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/krazzer00/anyroute/internal/cleanup"
	"github.com/krazzer00/anyroute/internal/core"
	"github.com/krazzer00/anyroute/internal/ipc"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/profiles"
)

// Name — имя службы Windows.
const Name = "AnyRoute"

// Updater — установка обновлений (internal/update).
type Updater interface {
	Apply(ctx context.Context, version string, log *logx.Src) error
}

// Service — запущенная служба.
type Service struct {
	Log     *logx.Logger
	Core    *core.Core
	srv     *ipc.Server
	ln      net.Listener
	logFile io.Closer
	upd     Updater
	version string
	updMu   sync.Mutex
}

// DataDir — %ProgramData%\AnyRoute.
func DataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "AnyRoute")
}

// openLog открывает файл журнала службы; большой файл начинается заново.
func openLog(dataDir string) (*os.File, error) {
	dir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "service.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
		_ = os.Rename(path, path+".old")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
}

// Start поднимает службу: журнал, ядро, очистку остатков, канал.
// dataDir — каталог журнала и кэша ("" — DataDir()).
func Start(version string, plat core.Platform, upd Updater, pipeName string, console io.Writer, dataDir string) (*Service, error) {
	if dataDir == "" {
		dataDir = DataDir()
	}
	var out io.Writer = console
	var closer io.Closer
	if f, err := openLog(dataDir); err == nil {
		closer = f
		if console != nil {
			out = io.MultiWriter(f, console)
		} else {
			out = f
		}
	}
	log := logx.New(5000, out)
	s := &Service{Log: log, logFile: closer, upd: upd, version: version}
	src := log.Source("service")
	src.Infof("служба AnyRoute %s запускается", version)

	s.Core = core.New(log, plat, version)
	if err := os.MkdirAll(dataDir, 0o755); err == nil {
		s.Core.CachePath = filepath.Join(dataDir, "cache.db")
	}
	// Остатки прошлого аварийного завершения убираются сразу при старте
	// службы — до того, как пользователь нажмёт «Подключить».
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cleanup.Run(ctx, log.Source("cleanup"), false)
	}()

	s.srv = ipc.NewServer(func(err error) { src.Warnf("канал: %v", err) })
	s.register()
	s.Core.Subscribe(func(e core.Event) { s.srv.Broadcast(e.Type, e.Data) })

	ln, err := ipc.Listen(pipeName)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			src.Warnf("канал закрыт: %v", err)
		}
	}()
	src.OKf("служба готова, канал %s", pipeName)
	return s, nil
}

// Stop отключает VPN (с ожиданием) и закрывает канал.
func (s *Service) Stop() {
	src := s.Log.Source("service")
	src.Infof("остановка службы")
	s.Core.Disconnect()
	if !s.Core.Wait(25 * time.Second) {
		src.Warnf("подключение не завершилось за 25 с")
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	src.Infof("служба остановлена")
	if s.logFile != nil {
		_ = s.logFile.Close()
	}
}

func decode[T any](p json.RawMessage) (T, error) {
	var v T
	if len(p) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(p, &v); err != nil {
		return v, fmt.Errorf("некорректные параметры: %w", err)
	}
	return v, nil
}

func (s *Service) register() {
	h := s.srv.Handle
	h("hello", func(context.Context, json.RawMessage) (any, error) {
		return map[string]string{"version": s.version}, nil
	})
	h("status", func(context.Context, json.RawMessage) (any, error) { return s.Core.Status(), nil })
	h("connect", func(_ context.Context, p json.RawMessage) (any, error) {
		req, err := decode[core.ConnectRequest](p)
		if err != nil {
			return nil, err
		}
		return nil, s.Core.Connect(req)
	})
	h("disconnect", func(context.Context, json.RawMessage) (any, error) {
		s.Core.Disconnect()
		return nil, nil
	})
	h("submit2fa", func(_ context.Context, p json.RawMessage) (any, error) {
		v, err := decode[struct {
			Code string `json:"code"`
		}](p)
		if err != nil {
			return nil, err
		}
		return nil, s.Core.Submit2FA(v.Code)
	})
	h("setProfile", func(_ context.Context, p json.RawMessage) (any, error) {
		v, err := decode[profiles.Routing](p)
		if err != nil {
			return nil, err
		}
		return nil, s.Core.SetProfile(v)
	})
	h("connections", func(context.Context, json.RawMessage) (any, error) { return s.Core.Connections(), nil })
	h("samples", func(context.Context, json.RawMessage) (any, error) { return s.Core.Samples(), nil })
	h("logs", func(_ context.Context, p json.RawMessage) (any, error) {
		v, err := decode[struct {
			After uint64 `json:"after"`
		}](p)
		if err != nil {
			return nil, err
		}
		return s.Log.Entries(v.After), nil
	})
	h("setLogLevel", func(_ context.Context, p json.RawMessage) (any, error) {
		v, err := decode[struct {
			Level string `json:"level"`
		}](p)
		if err != nil {
			return nil, err
		}
		switch logx.Level(v.Level) {
		case logx.Debug:
			s.Log.SetLevel(logx.Debug)
			s.Core.SetDebugXML(true)
		default:
			s.Log.SetLevel(logx.Info)
			s.Core.SetDebugXML(false)
		}
		return nil, nil
	})
	h("update", func(_ context.Context, p json.RawMessage) (any, error) {
		v, err := decode[struct {
			Version string `json:"version"`
		}](p)
		if err != nil {
			return nil, err
		}
		if s.upd == nil {
			return nil, errors.New("обновление недоступно в этой сборке")
		}
		if !s.updMu.TryLock() {
			return nil, errors.New("обновление уже выполняется")
		}
		// Загрузка и проверка — в фоне, ответ сразу: ход виден в журнале.
		go func() {
			defer s.updMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			src := s.Log.Source("update")
			if err := s.upd.Apply(ctx, v.Version, src); err != nil {
				src.Errorf("обновление не установлено: %v", err)
				s.srv.Broadcast("update", map[string]string{"state": "error", "error": err.Error()})
				return
			}
			s.srv.Broadcast("update", map[string]string{"state": "installing"})
		}()
		return nil, nil
	})
}
