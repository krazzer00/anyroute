package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	adapterservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/dns"
	dnstransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/krazzer00/anyroute/internal/logx"
)

// Engine — экземпляр sing-box поверх VPN-сессии. Перезапускается при смене
// профиля маршрутизации; сессия при этом не трогается.
type Engine struct {
	log  *logx.Src
	sess *Session

	mu      sync.Mutex
	box     *box.Box
	cancel  context.CancelFunc
	traffic *trafficcontrol.Manager
}

// New создаёт движок для сессии.
func New(l *logx.Src, sess *Session) *Engine { return &Engine{log: l, sess: sess} }

// Start поднимает sing-box с параметрами p. Если движок уже запущен, старый
// экземпляр сначала останавливается.
func (e *Engine) Start(p Params) error {
	e.Stop()

	raw, err := Build(p)
	if err != nil {
		return err
	}
	e.log.Debugf("конфигурация sing-box:\n%s", raw)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = service.ContextWith[*Session](ctx, e.sess)
	ctx = registryContext(ctx)

	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		cancel()
		return fmt.Errorf("конфигурация sing-box: %w", err)
	}
	b, err := box.New(box.Options{Context: ctx, Options: opts, PlatformLogWriter: logWriter{e.log}})
	if err != nil {
		cancel()
		return fmt.Errorf("создание sing-box: %w", err)
	}
	tm := trafficcontrol.NewManager(b.Outbound())
	_ = tm.Start(0)
	b.Router().AppendTracker(tm)

	errCh := make(chan error, 1)
	go func() { errCh <- b.Start() }()
	select {
	case err = <-errCh:
	case <-time.After(30 * time.Second):
		err = errors.New("sing-box не запустился за 30 с")
	}
	if err != nil {
		closeWithTimeout(b, 5*time.Second)
		cancel()
		return fmt.Errorf("запуск sing-box: %w", err)
	}

	e.mu.Lock()
	e.box, e.cancel, e.traffic = b, cancel, tm
	e.mu.Unlock()
	return nil
}

// Stop останавливает sing-box. Укладывается в 5 с: если box не закрылся,
// он бросается (адаптер и маршруты всё равно снимаются при выходе процесса,
// а cleanup при следующем подключении уберёт остатки).
func (e *Engine) Stop() {
	e.mu.Lock()
	b, cancel, tm := e.box, e.cancel, e.traffic
	e.box, e.cancel, e.traffic = nil, nil, nil
	e.mu.Unlock()
	if b == nil {
		return
	}
	if tm != nil {
		tm.CloseAllConnections()
		_ = tm.Close()
	}
	if !closeWithTimeout(b, 5*time.Second) {
		e.log.Warnf("sing-box не остановился за 5 с — продолжаю без ожидания")
	}
	cancel()
}

// Running сообщает, запущен ли sing-box.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.box != nil
}

func closeWithTimeout(b *box.Box, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = b.Close()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// registryContext регистрирует только нужные типы sing-box и наши:
// без десятков прокси-протоколов бинарь заметно меньше.
func registryContext(ctx context.Context) context.Context {
	inbounds := inbound.NewRegistry()
	tun.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	block.RegisterOutbound(outbounds)
	outbound.Register[AnyConnectOptions](outbounds, TypeAnyConnect, newVPNOutbound)

	transports := dns.NewTransportRegistry()
	dnstransport.RegisterUDP(transports)
	dnstransport.RegisterTCP(transports)
	local.RegisterTransport(transports)
	dns.RegisterTransport[VPNDNSOptions](transports, TypeVPNDNS, newVPNDNS)

	return box.Context(ctx, inbounds, outbounds, endpoint.NewRegistry(),
		transports, adapterservice.NewRegistry(), certificate.NewRegistry())
}

// logWriter перенаправляет журнал sing-box в журнал AnyRoute.
type logWriter struct{ l *logx.Src }

func (w logWriter) WriteMessage(level log.Level, message string) {
	message = strings.TrimSpace(message)
	switch {
	case level <= log.LevelError:
		w.l.Errorf("%s", message)
	case level == log.LevelWarn:
		w.l.Warnf("%s", message)
	case level == log.LevelInfo:
		w.l.Debugf("%s", message) // соединения — только в отладке, иначе журнал тонет
	default:
		w.l.Debugf("%s", message)
	}
}
