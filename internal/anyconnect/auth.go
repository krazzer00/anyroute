package anyconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"
)

// Logger — журнал клиента. Реализуется logx.Src; nil допустим.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// DialFunc открывает соединение к шлюзу. Служба подставляет диалер,
// привязанный к физическому интерфейсу: соединение с VPN-шлюзом не должно
// уходить ни в собственный TUN, ни в чужой (Throne).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config — параметры подключения.
type Config struct {
	Host     string
	Group    string // алиас группы ровно как его отдаёт сервер; "" — по умолчанию
	Username string
	Password string

	InsecureSkipVerify bool
	NoDTLS             bool
	AgentVersion       string // "" — DefaultAgentVersion

	Dial     DialFunc
	Log      Logger
	DebugXML bool // писать XML обмена в журнал (секреты маскируются журналом)
}

// Ошибки уровня протокола.
var (
	ErrNotInitialized = errors.New("anyconnect: сначала InitAuth")
	ErrNo2FAPending   = errors.New("anyconnect: сервер не запрашивал код второго фактора")
)

// AuthError — отказ сервера в аутентификации с текстом от сервера.
type AuthError struct {
	ID      string
	Message string
}

func (e *AuthError) Error() string { return e.Message }

// Client — состояние одной попытки подключения (одно TLS-соединение).
type Client struct {
	cfg  Config
	prof *profile
	log  Logger

	mu           sync.Mutex
	conn         net.Conn
	br           *bufio.Reader
	initialized  bool
	serverGroups []string
	defaultGroup string
	sessionToken string
	webvpnCookie string
	lastBody     []byte
	challenge    *Challenge
	banner       string
}

// NewClient создаёт клиента. Сеть не трогает.
func NewClient(cfg Config) *Client {
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		cfg.Dial = d.DialContext
	}
	l := cfg.Log
	if l == nil {
		l = nopLogger{}
	}
	return &Client{cfg: cfg, prof: newProfile(cfg), log: l}
}

// Host — текущий адрес шлюза (после возможных редиректов).
func (c *Client) Host() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prof.Host
}

// ServerGroups — алиасы групп, предложенные сервером на init.
func (c *Client) ServerGroups() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.serverGroups...)
}

// DefaultGroup — группа, которую сервер отмечает выбранной по умолчанию.
func (c *Client) DefaultGroup() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.defaultGroup
}

// Banner — баннер сервера (если был).
func (c *Client) Banner() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.banner
}

const maxRedirects = 5

// InitAuth открывает TLS-соединение, следует редиректам и получает форму
// логина со списком групп.
func (c *Client) InitAuth(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.webvpnCookie = ""
	for attempt := 0; ; attempt++ {
		if err := c.dialLocked(ctx); err != nil {
			return fmt.Errorf("подключение к %s: %w", c.prof.HostWithPort, err)
		}
		dtd := new(DTD)
		err := c.postLocked(ctx, tplInit, "/", dtd)
		if err == nil {
			c.applyInitLocked(dtd)
			break
		}
		var redirect *redirectError
		if !errors.As(err, &redirect) {
			return err
		}
		if attempt >= maxRedirects {
			return fmt.Errorf("слишком много перенаправлений (%d), последнее — на %s", maxRedirects, redirect.Location)
		}
		host, herr := redirectHost(redirect.Location)
		if herr != nil {
			return herr
		}
		if host == c.prof.HostWithPort || host == c.prof.Host {
			return fmt.Errorf("сервер перенаправляет сам на себя (%s)", redirect.Location)
		}
		c.log.Infof("сервер перенаправил %s на %s", c.prof.Host, host)
		c.prof.setHost(host)
	}

	if len(c.serverGroups) > 0 && c.prof.Group != "" && !contains(c.serverGroups, c.prof.Group) {
		return fmt.Errorf("группа %q не найдена на сервере; доступные группы: %s",
			c.prof.Group, strings.Join(c.serverGroups, ", "))
	}
	c.prof.SendGroupSelect = len(c.serverGroups) > 0 && c.prof.Group != ""
	c.initialized = true
	return nil
}

func (c *Client) applyInitLocked(dtd *DTD) {
	c.prof.AuthPath = dtd.Auth.Form.Action
	if c.prof.AuthPath == "" {
		c.prof.AuthPath = "/"
	}
	c.prof.TunnelGroup = dtd.Opaque.TunnelGroup
	c.prof.GroupAlias = dtd.Opaque.GroupAlias
	c.prof.ConfigHash = dtd.Opaque.ConfigHash
	c.serverGroups = dtd.Auth.Form.Groups
	c.defaultGroup = selectedOption(c.lastBody)
	if dtd.Auth.Banner != "" {
		c.banner = strings.TrimSpace(dtd.Auth.Banner)
	}
}

// selectedOption ищет <option selected="true"> в форме init.
func selectedOption(body []byte) string {
	var f struct {
		Options []struct {
			Selected string `xml:"selected,attr"`
			Value    string `xml:",chardata"`
		} `xml:"auth>form>select>option"`
	}
	if xml.Unmarshal(body, &f) != nil {
		return ""
	}
	for _, o := range f.Options {
		if strings.EqualFold(o.Selected, "true") {
			return strings.TrimSpace(o.Value)
		}
	}
	return ""
}

// PasswordAuth отправляет логин и пароль. Если сервер запросил второй
// фактор, возвращает Challenge (и nil-ошибку): код передаётся в Submit2FA.
func (c *Client) PasswordAuth(ctx context.Context) (*Challenge, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return nil, ErrNotInitialized
	}

	dtd := new(DTD)
	if err := c.postLocked(ctx, tplAuthReply, c.prof.AuthPath, dtd); err != nil {
		return nil, err
	}
	if ch := c.checkChallengeLocked(dtd); ch != nil {
		return ch, nil
	}
	// Совместимость с двухшаговым логином (ocserv): форма без ошибки —
	// отправляем ещё раз.
	if dtd.Type == "auth-request" && dtd.Auth.Error.Value == "" {
		dtd = new(DTD)
		if err := c.postLocked(ctx, tplAuthReply, c.prof.AuthPath, dtd); err != nil {
			return nil, err
		}
		if ch := c.checkChallengeLocked(dtd); ch != nil {
			return ch, nil
		}
	}
	return nil, c.completeLocked(dtd)
}

// Submit2FA отправляет код второго фактора. Возвращает новый Challenge
// (Retry=true), если сервер отклонил код и выдал новую форму; ошибку — если
// сервер отказал окончательно; (nil, nil) — при успехе.
func (c *Client) Submit2FA(ctx context.Context, code string) (*Challenge, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.challenge == nil {
		return nil, ErrNo2FAPending
	}
	code = strings.TrimSpace(code)
	dtd := new(DTD)
	err := c.postCodeLocked(ctx, code, dtd)
	if err != nil {
		c.challenge = nil
		return nil, err
	}
	if dtd.Type == "auth-request" {
		if ch, ok := detectChallenge(c.lastBody); ok {
			c.challenge = ch
			ch.Retry = true
			if ch.Message == "" {
				ch.Message = "Сервер отклонил код. Введите код ещё раз."
			}
			return ch, nil
		}
	}
	c.challenge = nil
	return nil, c.completeLocked(dtd)
}

// checkChallengeLocked запоминает challenge-форму второго фактора.
func (c *Client) checkChallengeLocked(dtd *DTD) *Challenge {
	if dtd.Type != "auth-request" || dtd.Auth.Error.Value != "" {
		return nil
	}
	ch, ok := detectChallenge(c.lastBody)
	if !ok {
		return nil
	}
	c.challenge = ch
	return ch
}

// completeLocked разбирает финальный ответ: успех (complete + токен) или
// отказ с сообщением сервера.
func (c *Client) completeLocked(dtd *DTD) error {
	if dtd.Type == "auth-request" {
		if dtd.Auth.Error.Value != "" {
			return &AuthError{ID: dtd.Auth.Error.ID, Message: formatServerMessage(dtd.Auth.Error.Value, dtd.Auth.Error.Param1, dtd.Auth.Error.Param2)}
		}
		msg := strings.TrimSpace(dtd.Auth.Message)
		if msg == "" {
			msg = "сервер отклонил аутентификацию"
		}
		return &AuthError{Message: msg}
	}
	if dtd.Type != "complete" {
		return fmt.Errorf("неожиданный ответ сервера: %q", dtd.Type)
	}
	if dtd.Auth.Banner != "" {
		c.banner = strings.TrimSpace(dtd.Auth.Banner)
	}
	c.sessionToken = dtd.SessionToken
	if c.webvpnCookie != "" {
		c.sessionToken = c.webvpnCookie
	}
	if c.sessionToken == "" {
		return errors.New("сервер не выдал сессионный токен")
	}
	return nil
}

// Close закрывает TLS-соединение. Идемпотентна.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.br = nil
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// dialLocked открывает TLS-соединение к текущему адресу профиля.
func (c *Client) dialLocked(ctx context.Context) error {
	_ = c.closeLocked()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := c.cfg.Dial(dctx, "tcp4", c.prof.HostWithPort)
	if err != nil {
		return err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         c.prof.serverName(),
		InsecureSkipVerify: c.cfg.InsecureSkipVerify, //nolint:gosec // только по явной настройке профиля
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(dctx); err != nil {
		_ = raw.Close()
		return err
	}
	c.conn = tc
	c.br = bufio.NewReader(tc)
	return nil
}

// Типы XML-шаблонов.
const (
	tplInit = iota
	tplAuthReply
	tpl2FAReply
)

var (
	templates = map[int]*template.Template{
		tplInit:      template.Must(template.New("init").Parse(templateInit)),
		tplAuthReply: template.Must(template.New("auth").Parse(templateAuthReply)),
		tpl2FAReply:  template.Must(template.New("2fa").Parse(template2FAReply)),
	}
	xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
)

// esc экранирует значение для подстановки в XML-шаблон: text/template этого
// не делает, а пароль с символом '<' или '&' ломал бы весь запрос.
func esc(s string) string { return xmlEscaper.Replace(s) }

func (c *Client) templateData(code string) map[string]any {
	p := c.prof
	d := map[string]any{
		"AppVersion":      esc(p.AppVersion),
		"ComputerName":    esc(p.ComputerName),
		"DeviceType":      esc(p.DeviceType),
		"PlatformVersion": esc(p.PlatformVersion),
		"UniqueID":        esc(p.UniqueID),
		"Platform":        esc(p.Platform),
		"TunnelGroup":     esc(p.TunnelGroup),
		"GroupAlias":      esc(p.GroupAlias),
		"ConfigHash":      esc(p.ConfigHash),
		"MacAddress":      esc(p.MacAddress),
		"Username":        esc(p.Username),
		"Password":        esc(p.Password),
		"Group":           esc(p.Group),
		"SendGroupSelect": p.SendGroupSelect,
	}
	if ch := c.challenge; ch != nil {
		d["Code"] = esc(code)
		d["CodeField"] = codeElement(ch.field)
		d["OpaqueXML"] = ch.opaque // возвращается дословно — это XML сервера
		d["HasOpaque"] = ch.opaque != ""
		d["SendUsername"] = ch.hasUsername
	}
	return d
}

func (c *Client) postCodeLocked(ctx context.Context, code string, dtd *DTD) error {
	path := c.prof.AuthPath
	if c.challenge.action != "" {
		path = c.challenge.action
	}
	return c.postWithDataLocked(ctx, tpl2FAReply, path, c.templateData(code), dtd)
}

func (c *Client) postLocked(ctx context.Context, typ int, path string, dtd *DTD) error {
	return c.postWithDataLocked(ctx, typ, path, c.templateData(""), dtd)
}

// postWithDataLocked рендерит XML и отправляет его по открытому соединению.
func (c *Client) postWithDataLocked(ctx context.Context, typ int, path string, data map[string]any, dtd *DTD) error {
	if c.conn == nil {
		return errors.New("anyconnect: нет TLS-соединения с сервером")
	}
	var body bytes.Buffer
	if err := templates[typ].Execute(&body, data); err != nil {
		return err
	}
	if c.cfg.DebugXML {
		c.log.Debugf("→ %s", body.String())
	}

	if path == "" {
		path = "/"
	}
	u := "https://" + c.prof.HostWithPort + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body.Bytes()))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("X-Transcend-Version", "1")
	req.Header.Set("X-Aggregate-Auth", "1")

	// Дедлайн на обмен: зависший сервер не должен вешать подключение.
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()

	if err := req.Write(c.conn); err != nil {
		_ = c.closeLocked()
		return err
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		_ = c.closeLocked()
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		_ = c.closeLocked()
		return err
	}
	if c.cfg.DebugXML {
		c.log.Debugf("← %s", string(respBody))
	}
	c.lastBody = respBody

	if resp.StatusCode == http.StatusOK {
		for _, ck := range resp.Cookies() {
			if ck.Name == "webvpn" && ck.Value != "" {
				c.webvpnCookie = ck.Value
			}
		}
		return xml.Unmarshal(respBody, dtd)
	}
	if loc := redirectTarget(resp); loc != "" {
		_ = c.closeLocked()
		return &redirectError{Location: loc, Status: resp.Status}
	}
	_ = c.closeLocked()
	return fmt.Errorf("ошибка аутентификации: %s", resp.Status)
}

// setHeaders — общие заголовки для auth-запросов и CONNECT.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", c.prof.userAgent())
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
}

// FetchGroups запрашивает у сервера список групп. Учётные данные не нужны.
func FetchGroups(ctx context.Context, cfg Config) (groups []string, def string, err error) {
	cfg.Group = ""
	c := NewClient(cfg)
	defer c.Close() //nolint:errcheck // соединение открывалось ради списка групп
	if err := c.InitAuth(ctx); err != nil {
		return nil, "", err
	}
	return c.ServerGroups(), c.DefaultGroup(), nil
}

type redirectError struct {
	Location string
	Status   string
}

func (e *redirectError) Error() string {
	return fmt.Sprintf("перенаправление (%s) на %s", e.Status, e.Location)
}

func redirectTarget(resp *http.Response) string {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return resp.Header.Get("Location")
	}
	return ""
}

// redirectHost разбирает Location. Понижение до http запрещено.
func redirectHost(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("некорректный адрес перенаправления %q: %w", location, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("сервер перенаправляет на %q — похоже, это веб-портал, а не адрес VPN-шлюза", location)
	}
	if u.Scheme != "" && u.Scheme != "https" {
		return "", fmt.Errorf("перенаправление на %q: поддерживается только https", location)
	}
	return u.Host, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

const templateInit = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id computer-name="{{.ComputerName}}" device-type="{{.DeviceType}}" platform-version="{{.PlatformVersion}}" unique-id="{{.UniqueID}}">{{.Platform}}</device-id>
</config-auth>`

const templateAuthReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id computer-name="{{.ComputerName}}" device-type="{{.DeviceType}}" platform-version="{{.PlatformVersion}}" unique-id="{{.UniqueID}}">{{.Platform}}</device-id>
    <opaque is-for="sg">
        <tunnel-group>{{.TunnelGroup}}</tunnel-group>
        <group-alias>{{.GroupAlias}}</group-alias>
        <config-hash>{{.ConfigHash}}</config-hash>
    </opaque>
    <mac-address-list>
        <mac-address public-interface="true">{{.MacAddress}}</mac-address>
    </mac-address-list>
    <auth>
        <username>{{.Username}}</username>
        <password>{{.Password}}</password>
    </auth>
{{if .SendGroupSelect}}    <group-select>{{.Group}}</group-select>
{{end}}</config-auth>`

// Ответ на challenge-форму повторяет ровно её поля (как OpenConnect):
// без <username> (если форма его не просит), без <group-select>, с <opaque>
// из challenge-ответа дословно. Нарушение любого пункта даёт на живой ASA
// «Login failed.» на верный код.
const template2FAReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id computer-name="{{.ComputerName}}" device-type="{{.DeviceType}}" platform-version="{{.PlatformVersion}}" unique-id="{{.UniqueID}}">{{.Platform}}</device-id>
    <opaque is-for="sg">{{if .HasOpaque}}{{.OpaqueXML}}{{else}}
        <tunnel-group>{{.TunnelGroup}}</tunnel-group>
        <group-alias>{{.GroupAlias}}</group-alias>
        <config-hash>{{.ConfigHash}}</config-hash>
    {{end}}</opaque>
    <auth>
{{if .SendUsername}}        <username>{{.Username}}</username>
{{end}}        <{{.CodeField}}>{{.Code}}</{{.CodeField}}>
    </auth>
</config-auth>`
