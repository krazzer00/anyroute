package anyconnect

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"
)

// TunnelInfo — конфигурация, выданная шлюзом при CSTP-переговорах.
type TunnelInfo struct {
	Server       netip.Addr     // IP шлюза (конечный, после редиректов)
	ServerHost   string         // имя шлюза
	Address      netip.Prefix   // адрес клиента внутри VPN с маской
	MTU          int            // MTU туннеля
	DNS          []netip.Addr   // DNS-серверы шлюза
	SplitInclude []netip.Prefix // сети, которые шлюз направляет в VPN
	SplitExclude []netip.Prefix // сети, исключённые шлюзом
	SplitDNS     []string       // зоны, обслуживаемые DNS внутри VPN
	TunnelAllDNS bool           // шлюз требует весь DNS через VPN
	DefaultRoute bool           // split-include не выдан — шлюз ждёт весь трафик
	Banner       string
	TLSCipher    string
}

// Tunnel — установленный CSTP-туннель (TLS, при возможности DTLS).
// Потокобезопасен: ReadPacket/WritePacket вызываются из разных горутин.
type Tunnel struct {
	log  Logger
	info TunnelInfo

	tlsConn net.Conn
	br      *bufio.Reader
	tlsWMu  sync.Mutex // записи в TLS-канал из нескольких горутин

	dtlsMu   sync.Mutex
	dtlsConn net.Conn // nil — DTLS не поднят
	dtlsUp   atomic.Bool

	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error

	rx atomic.Uint64
	tx atomic.Uint64

	dpd       time.Duration
	keepalive time.Duration
}

// Connect устанавливает CSTP-туннель поверх аутентифицированного соединения.
// После успеха соединение принадлежит туннелю, Client больше не нужен.
func (c *Client) Connect(ctx context.Context) (*Tunnel, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, errors.New("anyconnect: нет TLS-соединения — сначала аутентификация")
	}
	if c.sessionToken == "" {
		return nil, errors.New("anyconnect: нет сессионного токена — сначала аутентификация")
	}

	masterSecret := make([]byte, 48)
	masterSecret[0], masterSecret[1] = 0x03, 0x03 // DTLS 1.2 (legacy-переговоры)
	if _, err := rand.Read(masterSecret[2:]); err != nil {
		return nil, err
	}
	localIP, _, _ := net.SplitHostPort(c.conn.LocalAddr().String())

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+c.prof.HostWithPort+"/CSCOSSLC/tunnel", nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	req.Header.Del("Content-Type")
	// Точные имена заголовков: req.Header.Set канонизировал бы регистр.
	exact := map[string]string{
		"X-CSTP-Version":              "1",
		"X-CSTP-Hostname":             c.prof.ComputerName,
		"X-CSTP-Accept-Encoding":      "identity",
		"X-CSTP-Base-MTU":             "1399",
		"X-CSTP-MTU":                  "1399",
		"X-CSTP-Address-Type":         "IPv4",
		"X-CSTP-Local-VPNAddress-IP4": localIP,
		"X-CSTP-Full-IPv6-Capability": "false",
		"Cookie":                      "webvpn=" + c.sessionToken,
		"X-DTLS-Master-Secret":        hex.EncodeToString(masterSecret),
		"X-DTLS12-CipherSuite":        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256",
	}
	for k, v := range exact {
		req.Header[k] = []string{v}
	}

	_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := req.Write(c.conn); err != nil {
		_ = c.closeLocked()
		return nil, err
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		_ = c.closeLocked()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.closeLocked()
		return nil, fmt.Errorf("шлюз отказал в установке туннеля: %s", resp.Status)
	}
	_ = c.conn.SetDeadline(time.Time{})

	if c.cfg.DebugXML {
		var sb strings.Builder
		_ = resp.Header.Write(&sb)
		c.log.Debugf("CONNECT ← %s", sb.String())
	}

	info, err := parseTunnelInfo(resp.Header)
	if err != nil {
		_ = c.closeLocked()
		return nil, err
	}
	if ap, err := netip.ParseAddrPort(c.conn.RemoteAddr().String()); err == nil {
		info.Server = ap.Addr().Unmap()
	}
	info.ServerHost = c.prof.serverName()
	info.Banner = c.banner
	if tc, ok := c.conn.(*tls.Conn); ok {
		info.TLSCipher = tls.CipherSuiteName(tc.ConnectionState().CipherSuite)
	}

	t := &Tunnel{
		log:     c.log,
		info:    info,
		tlsConn: c.conn,
		br:      c.br,
		in:      make(chan []byte, 256),
		done:    make(chan struct{}),
	}
	t.dpd = secondsHeader(resp.Header, "X-CSTP-DPD", 30)
	t.keepalive = secondsHeader(resp.Header, "X-CSTP-Keepalive", 20)
	// Туннель забирает соединение: Client его больше не закрывает.
	c.conn, c.br = nil, nil

	go t.tlsReadLoop()
	go t.timers()

	if !c.cfg.NoDTLS {
		if port := resp.Header.Get("X-DTLS-Port"); port != "" && info.Server.IsValid() {
			sessID := resp.Header.Get("X-DTLS-Session-ID")
			if sessID == "" {
				sessID = resp.Header.Get("X-DTLS-App-ID")
			}
			suite := resp.Header.Get("X-DTLS12-CipherSuite")
			dtlsDPD := secondsHeader(resp.Header, "X-DTLS-DPD", 30)
			go t.dtlsLoop(c.cfg.Dial, net.JoinHostPort(info.Server.String(), port), sessID, suite, masterSecret, dtlsDPD)
		}
	}
	return t, nil
}

func secondsHeader(h http.Header, name string, def int) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get(name)))
	if err != nil || n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}

// parseTunnelInfo разбирает X-CSTP-* ответа на CONNECT.
func parseTunnelInfo(h http.Header) (TunnelInfo, error) {
	var info TunnelInfo
	addr, err := netip.ParseAddr(strings.TrimSpace(h.Get("X-CSTP-Address")))
	if err != nil {
		return info, fmt.Errorf("шлюз не выдал адрес клиента (X-CSTP-Address): %w", err)
	}
	bits := 32
	if m := strings.TrimSpace(h.Get("X-CSTP-Netmask")); m != "" {
		if b, ok := maskBits(m); ok {
			bits = b
		}
	}
	info.Address = netip.PrefixFrom(addr, bits)
	info.MTU, _ = strconv.Atoi(strings.TrimSpace(h.Get("X-CSTP-MTU")))
	if info.MTU <= 0 || info.MTU > 1500 {
		info.MTU = 1399
	}
	for _, v := range h.Values("X-CSTP-DNS") {
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			info.DNS = append(info.DNS, a)
		}
	}
	info.SplitInclude = parseRoutes(h.Values("X-CSTP-Split-Include"))
	info.SplitExclude = parseRoutes(h.Values("X-CSTP-Split-Exclude"))
	info.DefaultRoute = len(info.SplitInclude) == 0
	for _, v := range h.Values("X-CSTP-Split-DNS") {
		for _, d := range strings.Split(v, ",") {
			if d = strings.Trim(strings.TrimSpace(d), "."); d != "" {
				info.SplitDNS = append(info.SplitDNS, strings.ToLower(d))
			}
		}
	}
	// Домены поиска (X-CSTP-Default-Domain) обслуживает тот же DNS шлюза.
	for _, v := range h.Values("X-CSTP-Default-Domain") {
		for _, d := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
			if d = strings.Trim(d, "."); d != "" && !contains(info.SplitDNS, strings.ToLower(d)) {
				info.SplitDNS = append(info.SplitDNS, strings.ToLower(d))
			}
		}
	}
	info.TunnelAllDNS = strings.EqualFold(strings.TrimSpace(h.Get("X-CSTP-Tunnel-All-DNS")), "true")
	return info, nil
}

// parseRoutes переводит "сеть/маска" (или CIDR) в префиксы.
func parseRoutes(values []string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range values {
		v = strings.TrimSpace(v)
		network, mask, ok := strings.Cut(v, "/")
		if !ok {
			continue
		}
		a, err := netip.ParseAddr(network)
		if err != nil || !a.Is4() {
			continue
		}
		bits, err := strconv.Atoi(mask)
		if err != nil {
			var okm bool
			if bits, okm = maskBits(mask); !okm {
				continue
			}
		}
		if p, err := a.Prefix(bits); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func maskBits(mask string) (int, bool) {
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return 0, false
	}
	b := m.As4()
	ones, bits := net.IPv4Mask(b[0], b[1], b[2], b[3]).Size()
	if bits == 0 {
		return 0, false
	}
	return ones, true
}

// Info — конфигурация туннеля.
func (t *Tunnel) Info() TunnelInfo { return t.info }

// DTLS сообщает, идёт ли трафик по DTLS.
func (t *Tunnel) DTLS() bool { return t.dtlsUp.Load() }

// Stats — байты, принятые и отправленные по туннелю.
func (t *Tunnel) Stats() (rx, tx uint64) { return t.rx.Load(), t.tx.Load() }

// Done закрывается при завершении туннеля (сервер, ошибка или Close).
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err — причина завершения туннеля (nil, пока туннель жив или закрыт штатно).
func (t *Tunnel) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

// ErrClosed возвращается из ReadPacket/WritePacket после закрытия туннеля.
var ErrClosed = errors.New("anyconnect: туннель закрыт")

// ReadPacket возвращает следующий IP-пакет из туннеля.
func (t *Tunnel) ReadPacket() ([]byte, error) {
	select {
	case p := <-t.in:
		return p, nil
	case <-t.done:
		return nil, ErrClosed
	}
}

// WritePacket отправляет IP-пакет в туннель (DTLS, если он поднят).
func (t *Tunnel) WritePacket(p []byte) error {
	select {
	case <-t.done:
		return ErrClosed
	default:
	}
	if t.dtlsUp.Load() {
		if err := t.writeDTLS(pktData, p); err == nil {
			return nil
		}
		// DTLS упал — продолжаем по TLS.
	}
	return t.writeTLS(pktData, p)
}

// Close штатно закрывает туннель: отправляет серверу DISCONNECT (иначе ASA
// держит «висящую» сессию до таймаута) и закрывает соединения. Идемпотентна,
// укладывается в ~2 с даже при мёртвом сервере.
func (t *Tunnel) Close() error {
	select {
	case <-t.done:
		return nil
	default:
	}
	if t.dtlsUp.Load() {
		_ = t.writeDTLS(pktDisconnect, nil)
	}
	_ = t.tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	// Как OpenConnect (cstp_bye): код 0xb0 и текст причины.
	_ = t.writeTLS(pktDisconnect, append([]byte{0xb0}, "Client disconnected"...))
	t.shutdown(nil)
	return nil
}

func (t *Tunnel) shutdown(err error) {
	t.closeOnce.Do(func() {
		t.errMu.Lock()
		t.err = err
		t.errMu.Unlock()
		close(t.done)
		_ = t.tlsConn.Close()
		t.dtlsMu.Lock()
		if t.dtlsConn != nil {
			_ = t.dtlsConn.Close()
		}
		t.dtlsMu.Unlock()
		if err != nil {
			t.log.Warnf("туннель завершён: %v", err)
		}
	})
}

// writeTLS отправляет STF-фрейм по TLS.
func (t *Tunnel) writeTLS(typ byte, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("anyconnect: пакет %d байт слишком велик", len(payload))
	}
	frame := make([]byte, stfHeaderLen+len(payload))
	copy(frame, stfMagic[:])
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	frame[6] = typ
	copy(frame[stfHeaderLen:], payload)

	t.tlsWMu.Lock()
	n, err := t.tlsConn.Write(frame)
	t.tlsWMu.Unlock()
	t.tx.Add(uint64(n))
	if err != nil {
		t.shutdown(fmt.Errorf("запись в TLS-канал: %w", err))
		return ErrClosed
	}
	return nil
}

// tlsReadLoop читает STF-фреймы целиком (заголовок, затем ровно длину
// полезной нагрузки). В исходном sslcon фрейм считывался одним Read в
// предположении «одна TLS-запись — один фрейм»; при склейке или разрыве
// записей это теряло пакеты.
func (t *Tunnel) tlsReadLoop() {
	head := make([]byte, stfHeaderLen)
	dead := t.dpd*2 + 10*time.Second
	for {
		_ = t.tlsConn.SetReadDeadline(time.Now().Add(dead))
		if _, err := io.ReadFull(t.br, head); err != nil {
			t.shutdown(readErr("TLS", err))
			return
		}
		if [4]byte(head[:4]) != stfMagic {
			t.shutdown(errors.New("рассинхронизация протокола CSTP"))
			return
		}
		n := int(binary.BigEndian.Uint16(head[4:6]))
		payload := make([]byte, n)
		if _, err := io.ReadFull(t.br, payload); err != nil {
			t.shutdown(readErr("TLS", err))
			return
		}
		t.rx.Add(uint64(stfHeaderLen + n))
		switch head[6] {
		case pktData:
			t.deliver(payload)
		case pktDPDReq:
			_ = t.writeTLS(pktDPDResp, payload)
		case pktDPDResp, pktKeepalive:
		case pktDisconnect:
			reason := "сервер закрыл сессию"
			if len(payload) > 1 {
				reason += ": " + strings.TrimSpace(string(payload[1:]))
			}
			t.shutdown(errors.New(reason))
			return
		case pktTerminate:
			t.shutdown(errors.New("сервер завершает работу"))
			return
		case pktCompressed:
			t.log.Warnf("сервер прислал сжатый пакет, сжатие не согласовывалось — пакет отброшен")
		}
	}
}

func readErr(channel string, err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("шлюз не отвечает (%s)", channel)
	}
	if errors.Is(err, io.EOF) {
		return errors.New("шлюз закрыл соединение")
	}
	return fmt.Errorf("чтение %s-канала: %w", channel, err)
}

func (t *Tunnel) deliver(p []byte) {
	select {
	case t.in <- p:
	case <-t.done:
	}
}

// timers отправляет DPD и keepalive.
func (t *Tunnel) timers() {
	interval := t.keepalive
	if t.dpd > 0 && (interval <= 0 || t.dpd < interval) {
		interval = t.dpd
	}
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			_ = t.writeTLS(pktDPDReq, nil)
			if t.dtlsUp.Load() {
				_ = t.writeDTLS(pktDPDReq, nil)
			}
		}
	}
}

// --- DTLS ---

func (t *Tunnel) writeDTLS(typ byte, payload []byte) error {
	t.dtlsMu.Lock()
	conn := t.dtlsConn
	t.dtlsMu.Unlock()
	if conn == nil {
		return errors.New("DTLS не поднят")
	}
	buf := make([]byte, 1+len(payload))
	buf[0] = typ
	copy(buf[1:], payload)
	n, err := conn.Write(buf)
	t.tx.Add(uint64(n))
	if err != nil {
		t.dropDTLS(err)
		return err
	}
	return nil
}

func (t *Tunnel) dropDTLS(err error) {
	if t.dtlsUp.Swap(false) {
		t.log.Warnf("DTLS-канал закрыт (%v), трафик переведён на TLS", err)
	}
}

func (t *Tunnel) dtlsLoop(dial DialFunc, addr, sessionID, suite string, masterSecret []byte, dpd time.Duration) {
	id, _ := hex.DecodeString(sessionID)
	cfg := &dtls.Config{
		InsecureSkipVerify:   true, //nolint:gosec // DTLS привязан к сессии TLS через master secret
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites:         []dtls.CipherSuiteID{dtlsSuite(suite)},
		SessionStore:         &sessionStore{sess: dtls.Session{ID: id, Secret: masterSecret}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := dial(ctx, "udp4", addr)
	if err != nil {
		t.log.Infof("DTLS недоступен (%v), работаем по TLS", err)
		return
	}
	conn, err := dtls.ClientWithContext(ctx, connectedPacketConn{raw}, raw.RemoteAddr(), cfg)
	if err != nil {
		_ = raw.Close()
		t.log.Infof("DTLS не согласован (%v), работаем по TLS", err)
		return
	}
	select {
	case <-t.done:
		_ = conn.Close()
		return
	default:
	}
	t.dtlsMu.Lock()
	t.dtlsConn = conn
	t.dtlsMu.Unlock()
	t.dtlsUp.Store(true)
	t.log.Infof("DTLS-канал установлен (%s)", dtls.CipherSuiteName(conn.ConnectionState().CipherSuiteID))

	buf := make([]byte, 65535)
	dead := dpd*2 + 10*time.Second
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dead))
		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-t.done:
			default:
				t.dropDTLS(err)
			}
			t.dtlsMu.Lock()
			t.dtlsConn = nil
			t.dtlsMu.Unlock()
			_ = conn.Close()
			return
		}
		if n == 0 {
			continue
		}
		t.rx.Add(uint64(n))
		switch buf[0] {
		case pktData:
			p := make([]byte, n-1)
			copy(p, buf[1:n])
			t.deliver(p)
		case pktDPDReq:
			_ = t.writeDTLS(pktDPDResp, buf[1:n])
		case pktDisconnect:
			t.dropDTLS(errors.New("сервер закрыл DTLS"))
			t.dtlsMu.Lock()
			t.dtlsConn = nil
			t.dtlsMu.Unlock()
			_ = conn.Close()
			return
		}
	}
}

func dtlsSuite(name string) dtls.CipherSuiteID {
	switch name {
	case "ECDHE-RSA-AES128-GCM-SHA256":
		return dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	case "ECDHE-ECDSA-AES256-GCM-SHA384":
		return dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	case "ECDHE-RSA-AES256-GCM-SHA384":
		return dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	default:
		return dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	}
}

// sessionStore отдаёт pion/dtls заранее согласованную legacy-сессию
// (ID + pre-master secret) — так AnyConnect «возобновляет» DTLS.
type sessionStore struct{ sess dtls.Session }

func (s *sessionStore) Set([]byte, dtls.Session) error   { return nil }
func (s *sessionStore) Get([]byte) (dtls.Session, error) { return s.sess, nil }
func (s *sessionStore) Del([]byte) error                 { return nil }

// connectedPacketConn приводит подключённый UDP-сокет (из DialFunc, уже
// привязанный к интерфейсу) к net.PacketConn, которого ждёт pion/dtls.
type connectedPacketConn struct{ net.Conn }

func (c connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.Conn.RemoteAddr(), err
}

func (c connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Conn.Write(p) }
