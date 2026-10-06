// Package logx — журнал AnyRoute: уровни, кольцевой буфер для интерфейса,
// подписчики (поток событий в GUI) и обязательное маскирование секретов.
//
// Любая строка проходит через Mask до попадания в буфер или файл: пароли,
// коды второго фактора, cookie webvpn и session token не должны оказаться
// ни в журнале на экране, ни в файле, который пользователь пришлёт в отчёте.
package logx

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level — уровень записи.
type Level string

const (
	Debug Level = "debug"
	Info  Level = "info"
	OK    Level = "ok"
	Warn  Level = "warn"
	Error Level = "error"
)

func (l Level) rank() int {
	switch l {
	case Debug:
		return 0
	case Info, OK:
		return 1
	case Warn:
		return 2
	case Error:
		return 3
	}
	return 1
}

// Entry — одна запись журнала.
type Entry struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Level   Level     `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

// Logger — журнал с кольцевым буфером. Потокобезопасен.
type Logger struct {
	mu       sync.Mutex
	min      Level
	buf      []Entry
	size     int
	seq      uint64
	out      io.Writer
	subs     map[int]func(Entry)
	nextSub  int
	debugXML bool
}

// New создаёт журнал на size записей. out — необязательный файл/консоль.
func New(size int, out io.Writer) *Logger {
	if size <= 0 {
		size = 5000
	}
	return &Logger{min: Info, size: size, out: out, subs: map[int]func(Entry){}}
}

// SetLevel задаёт минимальный уровень записей.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.min = level
	l.mu.Unlock()
}

// Subscribe подписывает fn на новые записи; возвращает функцию отписки.
// fn вызывается вне блокировки журнала и не должна блокироваться надолго.
func (l *Logger) Subscribe(fn func(Entry)) func() {
	l.mu.Lock()
	id := l.nextSub
	l.nextSub++
	l.subs[id] = fn
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		delete(l.subs, id)
		l.mu.Unlock()
	}
}

// Entries возвращает записи с номером больше after (0 — все).
func (l *Logger) Entries(after uint64) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, len(l.buf))
	for _, e := range l.buf {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

// Log добавляет запись.
func (l *Logger) Log(level Level, source, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	msg = Mask(msg)

	l.mu.Lock()
	if level.rank() < l.min.rank() {
		l.mu.Unlock()
		return
	}
	l.seq++
	e := Entry{Seq: l.seq, Time: time.Now(), Level: level, Source: source, Message: msg}
	l.buf = append(l.buf, e)
	if len(l.buf) > l.size {
		l.buf = append(l.buf[:0:0], l.buf[len(l.buf)-l.size:]...)
	}
	subs := make([]func(Entry), 0, len(l.subs))
	for _, fn := range l.subs {
		subs = append(subs, fn)
	}
	out := l.out
	l.mu.Unlock()

	if out != nil {
		fmt.Fprintf(out, "%s [%s] %s: %s\n", e.Time.Format("2006-01-02 15:04:05.000"), strings.ToUpper(string(level)), source, msg)
	}
	for _, fn := range subs {
		fn(e)
	}
}

// Source возвращает обёртку журнала с фиксированным источником.
func (l *Logger) Source(name string) *Src { return &Src{l: l, name: name} }

// Src — журнал с фиксированным источником; реализует anyconnect.Logger.
type Src struct {
	l    *Logger
	name string
}

func (s *Src) Debugf(format string, args ...any) { s.log(Debug, format, args...) }
func (s *Src) Infof(format string, args ...any)  { s.log(Info, format, args...) }
func (s *Src) OKf(format string, args ...any)    { s.log(OK, format, args...) }
func (s *Src) Warnf(format string, args ...any)  { s.log(Warn, format, args...) }
func (s *Src) Errorf(format string, args ...any) { s.log(Error, format, args...) }

func (s *Src) log(level Level, format string, args ...any) {
	if s == nil || s.l == nil {
		return
	}
	s.l.Log(level, s.name, format, args...)
}

// Правила маскирования. Значения заменяются на ***, имена остаются — по
// журналу должно быть видно, в каком элементе ушёл код, но не сам код.
var maskRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// XML-элементы с секретами (aggregate auth).
	{regexp.MustCompile(`(?is)<(password|answer|secondary_password|otp|code|passwd|session-token|session-id)>.*?</(?:password|answer|secondary_password|otp|code|passwd|session-token|session-id)>`), "<$1>***</$1>"},
	// Cookie webvpn и прочие токены в заголовках.
	{regexp.MustCompile(`(?i)(webvpn(?:c|context)?=)[^;\s"]+`), "${1}***"},
	{regexp.MustCompile(`(?i)(X-DTLS-Master-Secret:\s*)\S+`), "${1}***"},
	{regexp.MustCompile(`(?i)(X-DTLS-Session-ID:\s*)\S+`), "${1}***"},
	{regexp.MustCompile(`(?i)("?(?:password|secret|totp|token|code)"?\s*[:=]\s*"?)[^"\s,}]+`), "${1}***"},
}

// Mask прячет секреты в строке.
func Mask(s string) string {
	for _, r := range maskRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
