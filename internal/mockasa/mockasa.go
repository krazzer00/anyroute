// Package mockasa — эмулятор VPN-шлюза Cisco ASA (AnyConnect SSL/TLS)
// для интеграционных тестов и локальной отладки без реальных серверов.
//
// Реализует поднабор протокола, который использует клиент sslcon:
//
//  1. Aggregate authentication (XML config-auth поверх HTTPS):
//     init → auth-request с формой и списком групп;
//     auth-reply → проверка логина/пароля;
//     для 2FA-групп — challenge-форма (auth id="challenge"),
//     повторный auth-reply с кодом второго фактора;
//     успех → type="complete" с session-token.
//  2. CSTP-туннель: CONNECT /CSCOSSLC/tunnel с cookie webvpn → 200 OK
//     с заголовками X-CSTP-* (адрес клиента, маска, MTU, split-маршруты),
//     далее обмен STF-фреймами (DATA, DPD-REQ/RESP, DISCONNECT).
//     DTLS не анонсируется (X-DTLS-Port отсутствует) — клиент работает по TLS.
//  3. «Внутренняя сеть» за шлюзом: gVisor netstack с хостом HostIP,
//     на котором можно поднять echo/HTTP-сервисы (StartEcho, StartHTTP).
//
// Ограничение: один активный CSTP-туннель на экземпляр сервера
// (для двух туннелей DualVPN поднимаются два экземпляра — как в жизни).
package mockasa

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Значения по умолчанию — как у настоящих шлюзов/AnyConnect.
const (
	defaultMTU     = 1399
	defaultMask    = "255.255.255.0"
	cstpDPD        = 30
	cstpKeepalive  = 20
	stfHeaderLen   = 8
	maxAuthBody    = 1 << 20 // защита от бесконечного тела запроса
	authFormAction = "/+webvpn+/index.html"
	twoFAAction    = "/+webvpn+/2fa"
)

// stfMagic — первые 4 байта заголовка STF-фрейма CSTP.
var stfMagic = []byte{0x53, 0x54, 0x46, 0x01}

// Типы STF-фреймов (draft-mavrogiannopoulos-openconnect-03, таблица 3).
const (
	frameData       = 0x00
	frameDPDReq     = 0x03
	frameDPDResp    = 0x04
	frameDisconnect = 0x05
	frameKeepalive  = 0x07
)

// Config — параметры эмулируемого шлюза.
type Config struct {
	Groups       []string          // tunnel-groups, предлагаемые клиенту
	TwoFAGroups  map[string]string // группа → ожидаемый код второго фактора
	Users        map[string]string // username → password
	VPNAddress   string            // X-CSTP-Address: адрес, выдаваемый клиенту
	VPNMask      string            // X-CSTP-Netmask (по умолчанию 255.255.255.0)
	HostIP       string            // адрес виртуального хоста внутренней сети
	SplitInclude []string          // X-CSTP-Split-Include, формат "сеть/маска"
	MTU          int               // X-CSTP-MTU (по умолчанию 1399)

	// NoGroupSelect эмулирует ocserv без select-group: сервер не предлагает
	// список групп в init-форме и отвергает непустой <group-select> в
	// auth-reply (аналог реального 401). Позволяет проверять совместимость
	// клиента, который по конфигу всегда знает свою группу.
	NoGroupSelect bool

	// ASAChallenge эмулирует challenge-форму живой Cisco ASA: поле кода
	// называется answer, а значение ожидается в <password>; в <opaque>
	// лежит <auth-handle>, который клиент обязан вернуть дословно; повторный
	// <group-select> и лишний <username> считаются ошибкой («Login failed.»).
	ASAChallenge bool

	SplitDNS []string          // X-CSTP-Split-DNS
	DNS      map[string]string // имя → IPv4 для DNS-сервера на HostIP:53
}

// Server — экземпляр мок-шлюза.
type Server struct {
	cfg  Config
	ln   net.Listener
	vnet *vnet

	mu         sync.Mutex
	tokens      map[string]bool // выданные session-token
	cstpActive  bool            // уже есть активный CSTP-туннель
	closed      bool
	disconnects int             // получено DISCONNECT-фреймов от клиентов
	authHandle  string          // выданный в challenge auth-handle (ASAChallenge)

	wg sync.WaitGroup
}

// New поднимает мок-шлюз на 127.0.0.1 (порт выбирается автоматически)
// и сразу начинает принимать подключения. Адрес — в Addr().
func New(cfg Config) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("mockasa: не заданы пользователи")
	}
	if len(cfg.Groups) == 0 && !cfg.NoGroupSelect {
		return nil, errors.New("mockasa: не заданы группы")
	}
	if net.ParseIP(cfg.VPNAddress) == nil {
		return nil, fmt.Errorf("mockasa: некорректный VPNAddress %q", cfg.VPNAddress)
	}
	if cfg.VPNMask == "" {
		cfg.VPNMask = defaultMask
	}
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}

	v, err := newVNet(cfg.HostIP, cfg.MTU)
	if err != nil {
		return nil, err
	}

	cert, err := selfSignedCert()
	if err != nil {
		v.close()
		return nil, err
	}
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		v.close()
		return nil, fmt.Errorf("mockasa: запуск listener: %w", err)
	}

	s := &Server{
		cfg:    cfg,
		ln:     ln,
		vnet:   v,
		tokens: make(map[string]bool),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr возвращает адрес шлюза (host:port) — значение для ClientConfig.Host.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Disconnects — сколько DISCONNECT-фреймов получено от клиентов.
func (s *Server) Disconnects() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disconnects
}

// HostIP возвращает адрес виртуального хоста внутренней сети.
func (s *Server) HostIP() string { return s.cfg.HostIP }

// Close останавливает шлюз и внутреннюю сеть.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	err := s.ln.Close()
	s.wg.Wait()
	s.vnet.close()
	return err
}

// StartEcho поднимает TCP-echo-сервис на HostIP:port внутренней сети.
func (s *Server) StartEcho(port uint16) error {
	ln, err := s.vnet.listenTCP(port)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return nil
}

// StartDNS поднимает DNS-сервер (UDP) на HostIP:53 внутренней сети: отвечает
// A-записями из Config.DNS, на остальное — NXDOMAIN.
func (s *Server) StartDNS() error {
	conn, err := s.vnet.listenUDP(53)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := answerDNS(buf[:n], s.cfg.DNS); resp != nil {
				_, _ = conn.WriteTo(resp, from)
			}
		}
	}()
	return nil
}

// StartHTTP поднимает HTTP-сервис на HostIP:port внутренней сети.
// При handler == nil отвечает страницей с именем шлюза — удобно проверять
// доступность через curl --socks5.
func (s *Server) StartHTTP(port uint16, handler http.Handler) error {
	ln, err := s.vnet.listenTCP(port)
	if err != nil {
		return err
	}
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "mockasa: внутренний хост %s, путь %s\n", s.cfg.HostIP, r.URL.Path)
		})
	}
	go func() { _ = http.Serve(ln, handler) }()
	return nil
}

// acceptLoop принимает TLS-подключения клиентов.
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener закрыт
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

// clientMsg — разбираемая часть XML-запросов клиента (config-auth).
type clientMsg struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		Username string `xml:"username"`
		Password string `xml:"password"`
		// Код второго фактора клиент кладёт в элемент, названный так же,
		// как поле в выданной challenge-форме (здесь — secondary_password).
		// Настоящая ASA ведёт себя так же (у неё поле называется answer),
		// поэтому мок обязан требовать именно своё имя, а не <password>.
		SecondaryPassword string `xml:"secondary_password"`
		Answer            string `xml:"answer"`
	} `xml:"auth"`
	GroupSelect string `xml:"group-select"`
	Opaque      struct {
		AuthHandle string `xml:"auth-handle"`
	} `xml:"opaque"`
}

// connState — состояние аутентификации одного TLS-соединения.
type connState struct {
	await2FA bool   // выдана challenge-форма, ждём код
	username string // пользователь, прошедший первичную аутентификацию
	group    string
}

// handleConn обслуживает одно TLS-соединение: цикл HTTP-запросов
// (аутентификация), затем — при CONNECT — CSTP-туннель.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	st := &connState{}

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // клиент закрыл соединение
		}

		switch {
		case req.Method == http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(req.Body, maxAuthBody))
			req.Body.Close()
			if err != nil {
				return
			}
			resp := s.handleAuth(st, body)
			if err := writeXMLResponse(conn, resp); err != nil {
				return
			}
		case req.Method == http.MethodConnect && strings.Contains(req.URL.Path, "/CSCOSSLC/tunnel"):
			if !s.checkCookie(req) {
				_ = writeRawResponse(conn, "HTTP/1.1 401 Unauthorized\r\n\r\n")
				return
			}
			s.serveCSTP(conn, br)
			return
		default:
			_ = writeRawResponse(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
		}
	}
}

// handleAuth — конечный автомат aggregate authentication.
func (s *Server) handleAuth(st *connState, body []byte) string {
	var msg clientMsg
	if err := xml.Unmarshal(body, &msg); err != nil {
		return s.xmlError("malformed request")
	}

	switch {
	case msg.Type == "init":
		st.await2FA = false
		return s.xmlInit()

	case msg.Type == "auth-reply" && st.await2FA && s.cfg.ASAChallenge:
		want := s.cfg.TwoFAGroups[st.group]
		s.mu.Lock()
		handle := s.authHandle
		s.mu.Unlock()
		switch {
		case msg.GroupSelect != "", msg.Auth.Answer != "",
			strings.Contains(string(body), "<username>"),
			msg.Opaque.AuthHandle != handle:
			st.await2FA = false
			return s.xmlError("Login failed.")
		case msg.Auth.Password != want:
			return s.xmlASAChallenge("Неверный код")
		}
		st.await2FA = false
		return s.xmlComplete(s.issueToken())

	case msg.Type == "auth-reply" && st.await2FA:
		// Второй фактор: код приходит в <secondary_password> — так называется
		// поле в challenge-форме, которую выдал мок.
		want := s.cfg.TwoFAGroups[st.group]
		if msg.Auth.SecondaryPassword != want {
			return s.xml2FAChallenge("Неверный код. Введите код ещё раз.")
		}
		st.await2FA = false
		return s.xmlComplete(s.issueToken())

	case msg.Type == "auth-reply" && s.cfg.NoGroupSelect:
		// ocserv-строгий режим: непрошеный group-select отвергается (401).
		if msg.GroupSelect != "" {
			return s.xmlError("unexpected group-select")
		}
		pass, ok := s.cfg.Users[msg.Auth.Username]
		if !ok || pass != msg.Auth.Password {
			return s.xmlError("Login failed")
		}
		st.username = msg.Auth.Username
		st.group = ""
		return s.xmlComplete(s.issueToken())

	case msg.Type == "auth-reply":
		group := msg.GroupSelect
		if !inList(s.cfg.Groups, group) {
			return s.xmlError("unknown tunnel-group")
		}
		pass, ok := s.cfg.Users[msg.Auth.Username]
		if !ok || pass != msg.Auth.Password {
			return s.xmlError("Login failed")
		}
		st.username = msg.Auth.Username
		st.group = group
		if _, need2FA := s.cfg.TwoFAGroups[group]; need2FA {
			st.await2FA = true
			if s.cfg.ASAChallenge {
				return s.xmlASAChallenge("")
			}
			return s.xml2FAChallenge("Введите код двухфакторной аутентификации.")
		}
		return s.xmlComplete(s.issueToken())

	default:
		return s.xmlError("unexpected request type " + msg.Type)
	}
}

// issueToken генерирует и регистрирует session-token.
func (s *Server) issueToken() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	s.tokens[token] = true
	s.mu.Unlock()
	return token
}

// checkCookie сверяет cookie webvpn из CONNECT с выданными токенами.
func (s *Server) checkCookie(req *http.Request) bool {
	ck, err := req.Cookie("webvpn")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[ck.Value]
}

// xmlInit — ответ на init: форма логина со списком групп.
// Поля username/password/group_list не считаются клиентом 2FA-формой.
func (s *Server) xmlInit() string {
	if s.cfg.NoGroupSelect {
		return s.xmlInitNoGroups()
	}
	var opts strings.Builder
	for _, g := range s.cfg.Groups {
		opts.WriteString("<option>" + xmlEscape(g) + "</option>")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <opaque is-for="sg">
        <tunnel-group>` + xmlEscape(s.cfg.Groups[0]) + `</tunnel-group>
        <group-alias>` + xmlEscape(s.cfg.Groups[0]) + `</group-alias>
        <config-hash>1234567890</config-hash>
    </opaque>
    <auth id="main">
        <message>Please enter your username and password.</message>
        <form method="post" action="` + authFormAction + `">
            <input type="text" name="username" label="Username:"></input>
            <input type="password" name="password" label="Password:"></input>
            <select name="group_list" label="GROUP:">` + opts.String() + `</select>
        </form>
    </auth>
</config-auth>`
}

// xmlInitNoGroups — init-форма в стиле ocserv без select-group: только
// username/password, без <select name="group_list"> и без opaque с группой.
// Клиент увидит пустой список групп и не станет слать <group-select>.
func (s *Server) xmlInitNoGroups() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <auth id="main">
        <message>Please enter your username and password.</message>
        <form method="post" action="` + authFormAction + `">
            <input type="text" name="username" label="Username:"></input>
            <input type="password" name="password" label="Password:"></input>
        </form>
    </auth>
</config-auth>`
}

// xml2FAChallenge — challenge-форма второго фактора
// (auth id="challenge" + input secondary_password).
func (s *Server) xml2FAChallenge(message string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <auth id="challenge">
        <message>` + xmlEscape(message) + `</message>
        <form method="post" action="` + twoFAAction + `">
            <input type="password" name="secondary_password" label="Response:"></input>
        </form>
    </auth>
</config-auth>`
}

// xmlASAChallenge — challenge-форма в стиле живой ASA: шаблон сообщения с
// подстановкой в param1, поле answer, auth-handle в opaque.
func (s *Server) xmlASAChallenge(errText string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	handle := hex.EncodeToString(buf)
	s.mu.Lock()
	s.authHandle = handle
	s.mu.Unlock()
	errXML := ""
	if errText != "" {
		errXML = `<error id="51" param1="" param2="">` + xmlEscape(errText) + `</error>`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <opaque is-for="sg">
        <tunnel-group>` + xmlEscape(s.cfg.Groups[0]) + `</tunnel-group>
        <auth-handle>` + handle + `</auth-handle>
        <config-hash>1234567890</config-hash>
    </opaque>
    <auth id="challenge">
        <message id="2" param1="Введите OTP-код" param2="">%s</message>` + errXML + `
        <form>
            <input type="password" name="answer" label="OTP:"></input>
        </form>
    </auth>
</config-auth>`
}

// xmlComplete — успешное завершение аутентификации с session-token.
func (s *Server) xmlComplete(token string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-token>` + token + `</session-token>
    <auth id="success">
        <message>Connected</message>
    </auth>
</config-auth>`
}

// xmlError — отказ в аутентификации (auth-request с <error>).
func (s *Server) xmlError(message string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <auth id="failure">
        <message>` + xmlEscape(message) + `</message>
        <error param1="">` + xmlEscape(message) + `</error>
    </auth>
</config-auth>`
}

// serveCSTP обслуживает CSTP-туннель: отдаёт конфигурацию X-CSTP-*
// и переливает STF-фреймы между клиентом и внутренней сетью (vnet).
func (s *Server) serveCSTP(conn net.Conn, br *bufio.Reader) {
	s.mu.Lock()
	if s.cstpActive {
		s.mu.Unlock()
		_ = writeRawResponse(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		return
	}
	s.cstpActive = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cstpActive = false
		s.mu.Unlock()
	}()

	var hdr strings.Builder
	hdr.WriteString("HTTP/1.1 200 OK\r\n")
	hdr.WriteString("Server: mockasa\r\n")
	hdr.WriteString("X-CSTP-Version: 1\r\n")
	hdr.WriteString("X-CSTP-Address: " + s.cfg.VPNAddress + "\r\n")
	hdr.WriteString("X-CSTP-Netmask: " + s.cfg.VPNMask + "\r\n")
	hdr.WriteString(fmt.Sprintf("X-CSTP-MTU: %d\r\n", s.cfg.MTU))
	hdr.WriteString("X-CSTP-DNS: " + s.cfg.HostIP + "\r\n")
	for _, inc := range s.cfg.SplitInclude {
		hdr.WriteString("X-CSTP-Split-Include: " + inc + "\r\n")
	}
	for _, d := range s.cfg.SplitDNS {
		hdr.WriteString("X-CSTP-Split-DNS: " + d + "\r\n")
	}
	hdr.WriteString(fmt.Sprintf("X-CSTP-DPD: %d\r\n", cstpDPD))
	hdr.WriteString(fmt.Sprintf("X-CSTP-Keepalive: %d\r\n", cstpKeepalive))
	hdr.WriteString("\r\n")
	if err := writeRawResponse(conn, hdr.String()); err != nil {
		return
	}

	// Все записи в conn — под мьютексом: egress-горутина и DPD-RESP
	// не должны перемешивать фреймы
	var wmu sync.Mutex
	writeFrame := func(typ byte, payload []byte) error {
		frame := make([]byte, stfHeaderLen+len(payload))
		copy(frame, stfMagic)
		binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
		frame[6] = typ
		copy(frame[stfHeaderLen:], payload)
		wmu.Lock()
		defer wmu.Unlock()
		// Один фрейм — одна запись (одна TLS-запись): клиент читает
		// фрейм за один Read
		_, err := conn.Write(frame)
		return err
	}

	// Исходящие пакеты внутренней сети → клиенту
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case pkt, ok := <-s.vnet.egress:
				if !ok {
					return
				}
				if err := writeFrame(frameData, pkt); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	// Входящие фреймы клиента
	head := make([]byte, stfHeaderLen)
	for {
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		if !bytes.Equal(head[:4], stfMagic) {
			return // рассинхронизация протокола
		}
		payloadLen := binary.BigEndian.Uint16(head[4:6])
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		switch head[6] {
		case frameData:
			s.vnet.inject(payload)
		case frameDPDReq:
			if err := writeFrame(frameDPDResp, payload); err != nil {
				return
			}
		case frameDPDResp, frameKeepalive:
			// подтверждения — игнорируем
		case frameDisconnect:
			s.mu.Lock()
			s.disconnects++
			s.mu.Unlock()
			return
		}
	}
}

// writeXMLResponse отправляет XML-ответ аутентификации.
func writeXMLResponse(conn net.Conn, body string) error {
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
	_, err := conn.Write([]byte(resp))
	return err
}

// writeRawResponse отправляет сырой HTTP-ответ.
func writeRawResponse(conn net.Conn, raw string) error {
	_, err := conn.Write([]byte(raw))
	return err
}

func inList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// xmlEscape экранирует спецсимволы для подстановки в XML.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
