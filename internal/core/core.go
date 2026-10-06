package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/engine"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/profiles"
	"github.com/krazzer00/anyroute/internal/rules"
	"github.com/krazzer00/anyroute/internal/vpnstack"
)

// Platform — системные операции, подменяемые в тестах.
type Platform interface {
	Cleanup(ctx context.Context, log *logx.Src, tunActive bool)
	Dialer() anyconnect.DialFunc
	LocalNets() []netip.Prefix    // все подсети (для выбора адреса TUN)
	PhysicalNets() []netip.Prefix // подсети физических интерфейсов (LAN)
	LocalDNS() []netip.Addr       // DNS физического интерфейса
	PickTunPrefix(avoid []netip.Prefix) (netip.Prefix, error)
	ApplyNRPT(ctx context.Context, namespaces []string, server netip.Addr) error
	RemoveNRPT(ctx context.Context) error
	HostRoutes(nextHop netip.Addr, skip func(netip.Addr) bool, onErr func(error)) HostRouter
	NoTun() bool // тесты: sing-box без TUN
}

// HostRouter — host-маршруты в TUN.
type HostRouter interface {
	Add(ips []netip.Addr)
	Reapply(nextHop netip.Addr, skip func(netip.Addr) bool)
	Count() int
}

// Тайминги.
const (
	twoFATimeout       = 5 * time.Minute
	teardownStep       = 5 * time.Second
	nrptTimeout        = 30 * time.Second
	connectTimeout     = 90 * time.Second
	sampleInterval     = time.Second
	samplesKept        = 300
	disconnectWatchdog = 40 * time.Second
)

// Core — ядро службы.
type Core struct {
	log      *logx.Logger
	src      *logx.Src
	plat     Platform
	version  string
	debugXML atomic.Bool

	status atomic.Pointer[Status]

	mu       sync.Mutex
	cancel   context.CancelFunc
	runDone  chan struct{}
	codeCh   chan string
	eng      *engine.Engine
	conn     *liveConn
	profile  profiles.Routing
	samples  []Sample
	lastSeen map[string][2]int64
	subs     map[int]func(Event)
	nextSub  int
	chSeq    int
	gen      int // номер текущего подключения; защищает от «опоздавшего» run
}

// liveConn — ресурсы активного подключения.
type liveConn struct {
	tunnel    *anyconnect.Tunnel
	info      anyconnect.TunnelInfo
	stack     *vpnstack.Stack
	sess      *engine.Session
	hosts     HostRouter
	tunPrefix netip.Prefix
	plan      rules.Plan
	nrptOn    bool
}

// New создаёт ядро.
func New(log *logx.Logger, plat Platform, version string) *Core {
	c := &Core{log: log, src: log.Source("core"), plat: plat, version: version, subs: map[int]func(Event){}, lastSeen: map[string][2]int64{}}
	c.status.Store(&Status{State: StateIdle, Version: version})
	log.Subscribe(func(e logx.Entry) { c.emit(Event{Type: "log", Data: e}) })
	go c.sampler()
	return c
}

// SetDebugXML включает журнал XML-обмена с шлюзом (секреты маскируются).
func (c *Core) SetDebugXML(on bool) { c.debugXML.Store(on) }

// Subscribe подписывает fn на события. fn не должна блокироваться.
func (c *Core) Subscribe(fn func(Event)) func() {
	c.mu.Lock()
	id := c.nextSub
	c.nextSub++
	c.subs[id] = fn
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
	}
}

func (c *Core) emit(e Event) {
	c.mu.Lock()
	fns := make([]func(Event), 0, len(c.subs))
	for _, fn := range c.subs {
		fns = append(fns, fn)
	}
	c.mu.Unlock()
	for _, fn := range fns {
		fn(e)
	}
}

// Status — текущий снимок (без блокировок).
func (c *Core) Status() Status {
	s := *c.status.Load()
	return s
}

func (c *Core) update(fn func(s *Status)) {
	for {
		old := c.status.Load()
		next := *old
		fn(&next)
		if c.status.CompareAndSwap(old, &next) {
			c.emit(Event{Type: "state", Data: next})
			return
		}
	}
}

func (c *Core) setStep(state State, step string) {
	c.update(func(s *Status) { s.State, s.Step = state, step })
	if step != "" {
		c.src.Infof("%s", step)
	}
}

// Connect начинает подключение. Возвращается сразу.
func (c *Core) Connect(req ConnectRequest) error {
	if err := validateConnect(&req); err != nil {
		return err
	}
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		st := c.Status()
		if st.State == StateDisconnecting {
			return errors.New("идёт отключение — подождите несколько секунд")
		}
		return errors.New("уже подключено или идёт подключение — сначала отключитесь")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.gen++
	gen := c.gen
	c.cancel = cancel
	c.runDone = make(chan struct{})
	c.codeCh = make(chan string, 1)
	c.profile = req.Profile
	done := c.runDone
	c.mu.Unlock()

	c.status.Store(&Status{State: StateConnecting, ServerID: req.ServerID, ServerName: req.ServerName,
		Host: req.Host, ProfileID: req.Profile.ID, ProfileName: req.Profile.Name, Version: c.version, Step: "Подготовка…"})
	c.emit(Event{Type: "state", Data: c.Status()})
	go func() {
		defer close(done)
		c.run(ctx, gen, req)
	}()
	return nil
}

func validateConnect(r *ConnectRequest) error {
	sv := profiles.Server{Name: r.ServerName, Host: r.Host, Group: r.Group, Username: r.Username}
	if strings.TrimSpace(sv.Name) == "" {
		sv.Name = r.Host
	}
	if err := sv.Validate(); err != nil {
		return err
	}
	r.Host, r.ServerName = sv.Host, sv.Name
	if r.Username == "" || r.Password == "" {
		return errors.New("не указаны логин или пароль")
	}
	if len(r.Password) > 1024 {
		return errors.New("слишком длинный пароль")
	}
	if err := r.Profile.Validate(); err != nil {
		return fmt.Errorf("профиль маршрутизации: %w", err)
	}
	return nil
}

// Submit2FA передаёт код второго фактора ожидающему подключению.
func (c *Core) Submit2FA(code string) error {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return errors.New("введите код")
	}
	if c.Status().State != State2FA {
		return errors.New("сервер сейчас не ждёт код")
	}
	c.mu.Lock()
	ch := c.codeCh
	c.mu.Unlock()
	select {
	case ch <- code:
		return nil
	default:
		return errors.New("код уже отправлен, дождитесь ответа сервера")
	}
}

// Disconnect начинает отключение. Возвращается сразу.
func (c *Core) Disconnect() {
	c.mu.Lock()
	cancel := c.cancel
	done := c.runDone
	gen := c.gen
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	if st := c.Status(); st.State != StateDisconnecting {
		c.setStep(StateDisconnecting, "Отключение…")
	}
	cancel()
	// Сторож: если отключение по какой-то причине повисло, состояние всё
	// равно не должно остаться «отключение» навсегда.
	go func() {
		select {
		case <-done:
		case <-time.After(disconnectWatchdog):
			c.src.Errorf("отключение не завершилось за %s — состояние сброшено; при проблемах с сетью перезапустите службу", disconnectWatchdog)
			c.finish(gen, "отключение не завершилось вовремя")
		}
	}()
}

// Wait ждёт завершения текущего подключения (для остановки службы).
func (c *Core) Wait(timeout time.Duration) bool {
	c.mu.Lock()
	done := c.runDone
	c.mu.Unlock()
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// SetProfile применяет профиль маршрутизации к активному подключению
// (перезапускается только sing-box; CSTP-сессия и 2FA сохраняются).
func (c *Core) SetProfile(p profiles.Routing) error {
	if err := p.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	c.profile = p
	lc := c.conn
	eng := c.eng
	c.mu.Unlock()
	c.update(func(s *Status) { s.ProfileID, s.ProfileName = p.ID, p.Name })
	if lc == nil || eng == nil {
		return nil
	}
	go func() {
		c.src.Infof("применяю профиль маршрутизации «%s»", p.Name)
		if err := c.applyRouting(context.Background(), lc, eng, p); err != nil {
			c.src.Errorf("профиль «%s» не применён: %v", p.Name, err)
			return
		}
		c.src.OKf("профиль «%s» применён", p.Name)
	}()
	return nil
}

// run — полный цикл подключения.
func (c *Core) run(ctx context.Context, gen int, req ConnectRequest) {
	var lc *liveConn
	var client *anyconnect.Client
	var eng *engine.Engine
	errMsg := ""

	defer func() {
		if r := recover(); r != nil {
			c.src.Errorf("внутренняя ошибка подключения: %v", r)
			errMsg = fmt.Sprint("внутренняя ошибка: ", r)
		}
		c.teardown(gen, client, lc, eng)
		c.finish(gen, errMsg)
	}()

	cctx, ccancel := context.WithTimeout(ctx, connectTimeout)
	defer ccancel()

	c.setStep(StateConnecting, "Проверка остатков прошлых подключений…")
	c.plat.Cleanup(cctx, c.log.Source("cleanup"), false)

	c.setStep(StateConnecting, "Подключение к "+req.Host+"…")
	client = anyconnect.NewClient(anyconnect.Config{
		Host: req.Host, Group: req.Group, Username: req.Username, Password: req.Password,
		InsecureSkipVerify: req.InsecureTLS, Dial: c.plat.Dialer(),
		Log: c.log.Source("anyconnect"), DebugXML: c.debugXML.Load(),
	})
	if err := client.InitAuth(cctx); err != nil {
		errMsg = humanErr(ctx, err)
		return
	}
	c.update(func(s *Status) { s.Host = client.Host() })

	c.setStep(StateAuth, "Аутентификация…")
	ch, err := client.PasswordAuth(cctx)
	if err != nil {
		errMsg = humanErr(ctx, err)
		return
	}
	for ch != nil {
		// Ждём код второго фактора: таймаут подключения на это время снят.
		c.mu.Lock()
		c.chSeq++
		info := &Challenge{Message: ch.Message, Label: ch.Label, Retry: ch.Retry, Seq: c.chSeq}
		codeCh := c.codeCh
		c.mu.Unlock()
		if info.Message == "" {
			info.Message = "Введите код подтверждения"
		}
		c.update(func(s *Status) {
			s.State, s.Step, s.Challenge = State2FA, "Ожидание кода подтверждения", info
		})
		c.src.Infof("сервер запросил второй фактор: %s", info.Message)
		var code string
		select {
		case code = <-codeCh:
		case <-ctx.Done():
			errMsg = ""
			return
		case <-time.After(twoFATimeout):
			errMsg = "код подтверждения не введён за 5 минут"
			return
		}
		c.update(func(s *Status) { s.State, s.Step, s.Challenge = StateAuth, "Проверка кода…", nil })
		sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
		ch, err = client.Submit2FA(sctx, code)
		scancel()
		if err != nil {
			errMsg = humanErr(ctx, err)
			return
		}
		if ch != nil {
			c.src.Warnf("сервер отклонил код: %s", ch.Message)
		}
	}
	c.src.OKf("аутентификация пройдена")

	tctx, tcancel := context.WithTimeout(ctx, 30*time.Second)
	c.setStep(StateConnecting, "Установка туннеля…")
	tunnel, err := client.Connect(tctx)
	tcancel()
	if err != nil {
		errMsg = humanErr(ctx, err)
		return
	}
	client = nil // соединение теперь принадлежит туннелю
	info := tunnel.Info()
	lc = &liveConn{tunnel: tunnel, info: info}
	c.src.OKf("туннель установлен: адрес %s, шлюз %s, сетей сервера %d, DNS %v", info.Address, info.Server, len(info.SplitInclude), info.DNS)
	if info.Banner != "" {
		c.src.Infof("баннер сервера: %s", info.Banner)
	}

	st, err := vpnstack.New(tunnel, info.Address.Addr(), info.MTU)
	if err != nil {
		errMsg = err.Error()
		return
	}
	lc.stack = st
	lc.sess = engine.NewSession(st, info.DNS)

	avoid := append(c.plat.LocalNets(), info.SplitInclude...)
	lc.tunPrefix, err = c.plat.PickTunPrefix(avoid)
	if err != nil {
		errMsg = err.Error()
		return
	}

	eng = engine.New(c.log.Source("sing-box"), lc.sess)
	c.mu.Lock()
	profile := c.profile
	c.mu.Unlock()
	c.setStep(StateConnecting, "Настройка маршрутизации…")
	if err := c.applyRouting(ctx, lc, eng, profile); err != nil {
		errMsg = humanErr(ctx, err)
		return
	}

	c.mu.Lock()
	if c.gen != gen {
		c.mu.Unlock()
		return
	}
	c.conn, c.eng = lc, eng
	c.mu.Unlock()
	c.update(func(s *Status) {
		s.State, s.Step, s.Since = StateConnected, "", time.Now()
		s.Address = info.Address.String()
		s.Gateway = info.Server.String()
		s.DNS = addrs(info.DNS)
		s.SplitInclude = pfx(info.SplitInclude)
		s.SplitDNS = info.SplitDNS
		s.TunPrefix = lc.tunPrefix.String()
		s.Banner = info.Banner
		s.Error = ""
	})
	c.src.OKf("подключено к %s (профиль «%s»)", req.ServerName, profile.Name)

	dtlsTick := time.NewTicker(2 * time.Second)
	defer dtlsTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tunnel.Done():
			if e := tunnel.Err(); e != nil {
				errMsg = "соединение с VPN потеряно: " + e.Error()
			} else {
				errMsg = "соединение с VPN закрыто"
			}
			c.src.Errorf("%s", errMsg)
			return
		case <-dtlsTick.C:
			d := tunnel.DTLS()
			n := lc.hosts.Count()
			if s := c.Status(); s.DTLS != d || s.HostRoutes != n {
				c.update(func(s *Status) { s.DTLS, s.HostRoutes = d, n })
			}
		}
	}
}

// applyRouting собирает план и (пере)запускает sing-box, NRPT и host-маршруты.
func (c *Core) applyRouting(ctx context.Context, lc *liveConn, eng *engine.Engine, p profiles.Routing) error {
	vpn, direct, block, errs := p.Compile()
	if len(errs) > 0 {
		return &profiles.RuleErrors{Errors: errs}
	}
	in := rules.Input{
		DefaultOutbound: p.DefaultOutbound, ServerRoutesToVPN: p.ServerRoutesToVPN, LANDirect: p.LANDirect,
		LocalNets: c.plat.PhysicalNets(), VPN: vpn, Direct: direct, Block: block,
		Server: rules.Server{
			Gateway: lc.info.Server, SplitInclude: lc.info.SplitInclude, SplitExclude: lc.info.SplitExclude,
			SplitDNS: lc.info.SplitDNS, DNS: lc.info.DNS, DefaultRoute: lc.info.DefaultRoute,
		},
	}
	plan := rules.Compile(in)
	for _, w := range plan.Warnings {
		c.src.Warnf("%s", w)
	}
	params := engine.Params{
		TunName: "anyroute-tun", TunPrefix: lc.tunPrefix, MTU: lc.info.MTU, Plan: plan,
		LocalDNS: c.plat.LocalDNS(), LogLevel: "info", NoTun: c.plat.NoTun(),
	}
	dnsAddr := params.DNSAddress()
	skip := func(a netip.Addr) bool { return rules.Covers(plan.RouteAddress, a) }
	if lc.hosts == nil {
		lc.hosts = c.plat.HostRoutes(dnsAddr, skip, func(err error) { c.src.Warnf("host-маршрут: %v", err) })
		lc.sess.OnDNSReply(func(_ string, ips []netip.Addr) { lc.hosts.Add(ips) })
	}
	if err := eng.Start(params); err != nil {
		return err
	}
	lc.hosts.Reapply(dnsAddr, skip)
	lc.plan = plan

	nctx, ncancel := context.WithTimeout(ctx, nrptTimeout)
	defer ncancel()
	if len(plan.NRPT) > 0 {
		if err := c.plat.ApplyNRPT(nctx, plan.NRPT, dnsAddr); err != nil {
			c.src.Errorf("%v — имена из зон VPN могут не разрешаться", err)
		} else {
			lc.nrptOn = true
			c.src.Infof("DNS-зоны через VPN: %s", strings.Join(plan.NRPT, ", "))
		}
	} else if lc.nrptOn {
		_ = c.plat.RemoveNRPT(nctx)
		lc.nrptOn = false
	}
	c.update(func(s *Status) { s.Warnings = plan.Warnings })
	return nil
}

// teardown освобождает ресурсы подключения. Каждый шаг ограничен по
// времени; NRPT снимается параллельно с остановкой движка.
func (c *Core) teardown(gen int, client *anyconnect.Client, lc *liveConn, eng *engine.Engine) {
	c.mu.Lock()
	current := c.gen == gen
	if current {
		c.conn, c.eng = nil, nil
	}
	c.mu.Unlock()
	if current && (lc != nil || eng != nil) {
		c.setStep(StateDisconnecting, "Отключение…")
	}

	var wg sync.WaitGroup
	if lc != nil && lc.nrptOn {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), nrptTimeout)
			defer cancel()
			if err := c.plat.RemoveNRPT(ctx); err != nil {
				c.src.Errorf("%v (будет повторено при следующем подключении)", err)
			}
		}()
	}
	if eng != nil {
		stepWithTimeout("остановка sing-box", c.src, eng.Stop)
	}
	if lc != nil {
		if lc.tunnel != nil {
			stepWithTimeout("закрытие туннеля", c.src, func() { _ = lc.tunnel.Close() })
		}
		if lc.stack != nil {
			_ = lc.stack.Close()
		}
	}
	if client != nil {
		_ = client.Close()
	}
	wg.Wait()
}

func stepWithTimeout(name string, log *logx.Src, fn func()) {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(teardownStep):
		log.Warnf("%s: не завершилось за %s, продолжаю", name, teardownStep)
	}
}

// finish переводит ядро в idle, если подключение gen всё ещё текущее
// (сторож мог уже завершить его, а пользователь — начать новое).
func (c *Core) finish(gen int, errMsg string) {
	c.mu.Lock()
	if c.gen != gen || c.cancel == nil {
		c.mu.Unlock()
		return
	}
	c.cancel()
	c.cancel = nil
	c.mu.Unlock()
	c.update(func(s *Status) {
		prev := *s
		*s = Status{State: StateIdle, Version: c.version, ServerID: prev.ServerID, ServerName: prev.ServerName,
			Host: prev.Host, ProfileID: prev.ProfileID, ProfileName: prev.ProfileName, Error: errMsg}
	})
	if errMsg != "" {
		c.src.Errorf("подключение завершено: %s", errMsg)
	} else {
		c.src.Infof("отключено")
	}
}

// humanErr — текст ошибки для пользователя; отмена — не ошибка.
func humanErr(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return ""
	}
	var ae *anyconnect.AuthError
	if errors.As(err, &ae) {
		return "сервер отклонил вход: " + ae.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "превышено время ожидания ответа сервера"
	}
	return err.Error()
}

// Connections — соединения для вкладки «Приложения».
func (c *Core) Connections() []Conn {
	c.mu.Lock()
	eng := c.eng
	c.mu.Unlock()
	if eng == nil {
		return nil
	}
	infos := eng.Connections()
	out := make([]Conn, 0, len(infos))
	for _, ci := range infos {
		out = append(out, Conn{ID: ci.ID, Process: ci.Process, Path: ci.Path, PID: ci.PID, Network: ci.Network,
			Dest: ci.Dest, Domain: ci.Domain, Outbound: ci.Outbound, Rule: ci.Rule, Up: ci.Up, Down: ci.Down,
			Start: ci.Start, Closed: ci.Closed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start > out[j].Start })
	return out
}

// Samples — точки графика за последние 5 минут.
func (c *Core) Samples() []Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Sample(nil), c.samples...)
}

// sampler раз в секунду считает скорость по соединениям.
func (c *Core) sampler() {
	t := time.NewTicker(sampleInterval)
	defer t.Stop()
	for now := range t.C {
		c.mu.Lock()
		eng := c.eng
		c.mu.Unlock()
		if eng == nil {
			continue
		}
		s := Sample{T: now.UnixMilli()}
		seen := make(map[string][2]int64)
		for _, ci := range eng.Connections() {
			prev := c.lastSeen[ci.ID]
			du, dd := ci.Up-prev[0], ci.Down-prev[1]
			seen[ci.ID] = [2]int64{ci.Up, ci.Down}
			if du < 0 || dd < 0 {
				continue
			}
			switch ci.Outbound {
			case "vpn":
				s.VPNUp += du
				s.VPNDown += dd
			case "direct":
				s.DirectUp += du
				s.DirectDown += dd
			}
		}
		c.mu.Lock()
		c.lastSeen = seen
		c.samples = append(c.samples, s)
		if len(c.samples) > samplesKept {
			c.samples = append(c.samples[:0:0], c.samples[len(c.samples)-samplesKept:]...)
		}
		c.mu.Unlock()
		c.emit(Event{Type: "sample", Data: s})
	}
}

func addrs(a []netip.Addr) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, x.String())
	}
	return out
}

func pfx(a []netip.Prefix) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, x.String())
	}
	return out
}
