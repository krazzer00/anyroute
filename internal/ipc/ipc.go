// Package ipc — канал между интерфейсом (права пользователя) и службой
// (LocalSystem): именованный канал \\.\pipe\anyroute, JSON по строке на кадр.
//
// Кадр-запрос: {"id":1,"method":"status","params":{…}}; ответ:
// {"id":1,"result":…} или {"id":1,"error":"…"}; событие службы:
// {"event":"state","data":…}. Каждый вызов клиента ограничен по времени —
// зависшая служба не может повесить интерфейс.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PipeName — имя канала службы.
const PipeName = `\\.\pipe\anyroute`

// maxFrame — предел размера кадра (защита службы от мусора).
const maxFrame = 4 << 20

// DefaultTimeout — таймаут вызова по умолчанию.
const DefaultTimeout = 5 * time.Second

// Frame — кадр протокола.
type Frame struct {
	ID     uint64          `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// HandlerFunc обрабатывает запрос.
type HandlerFunc func(ctx context.Context, params json.RawMessage) (any, error)

// Server — сервер канала.
type Server struct {
	mu       sync.Mutex
	handlers map[string]HandlerFunc
	conns    map[*srvConn]struct{}
	onErr    func(error)
}

// NewServer создаёт сервер.
func NewServer(onErr func(error)) *Server {
	return &Server{handlers: map[string]HandlerFunc{}, conns: map[*srvConn]struct{}{}, onErr: onErr}
}

// Handle регистрирует обработчик метода.
func (s *Server) Handle(method string, h HandlerFunc) {
	s.mu.Lock()
	s.handlers[method] = h
	s.mu.Unlock()
}

type srvConn struct {
	c    net.Conn
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func (c *srvConn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.c.Close()
	})
}

// send ставит кадр в очередь. Ответы ждут места (с таймаутом), события при
// переполнении отбрасываются: медленный клиент не тормозит службу.
func (c *srvConn) send(b []byte, isEvent bool) {
	if isEvent {
		select {
		case c.out <- b:
		default:
		}
		return
	}
	select {
	case c.out <- b:
	case <-c.done:
	case <-time.After(5 * time.Second):
		c.close()
	}
}

// Serve принимает подключения до закрытия ln.
func (s *Server) Serve(ln net.Listener) error {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		c := &srvConn{c: nc, out: make(chan []byte, 512), done: make(chan struct{})}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.writer(c)
		go s.reader(c)
	}
}

func (s *Server) writer(c *srvConn) {
	defer c.close()
	for {
		select {
		case b := <-c.out:
			_ = c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.c.Write(b); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (s *Server) reader(c *srvConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		c.close()
	}()
	sc := bufio.NewScanner(c.c)
	sc.Buffer(make([]byte, 64<<10), maxFrame)
	for sc.Scan() {
		var f Frame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil || f.Method == "" {
			continue
		}
		go s.dispatch(c, f)
	}
}

func (s *Server) dispatch(c *srvConn, f Frame) {
	s.mu.Lock()
	h := s.handlers[f.Method]
	s.mu.Unlock()
	resp := Frame{ID: f.ID}
	if h == nil {
		resp.Error = "неизвестный метод " + f.Method
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := safeCall(ctx, h, f.Params)
		cancel()
		if err != nil {
			resp.Error = err.Error()
		} else if res != nil {
			resp.Result, _ = json.Marshal(res)
		}
	}
	b, _ := json.Marshal(resp)
	c.send(append(b, '\n'), false)
}

func safeCall(ctx context.Context, h HandlerFunc, p json.RawMessage) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("внутренняя ошибка службы: %v", r)
		}
	}()
	return h(ctx, p)
}

// Broadcast рассылает событие всем подключённым клиентам.
func (s *Server) Broadcast(event string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b, _ := json.Marshal(Frame{Event: event, Data: raw})
	b = append(b, '\n')
	s.mu.Lock()
	conns := make([]*srvConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.send(b, true)
	}
}

// Client — клиент канала.
type Client struct {
	c       net.Conn
	nextID  atomic.Uint64
	mu      sync.Mutex
	wmu     sync.Mutex
	pending map[uint64]chan Frame
	events  chan Frame
	done    chan struct{}
	once    sync.Once
	err     error
}

// ErrClosed — соединение со службой потеряно.
var ErrClosed = errors.New("связь со службой AnyRoute потеряна")

// NewClient оборачивает соединение.
func NewClient(c net.Conn) *Client {
	cl := &Client{c: c, pending: map[uint64]chan Frame{}, events: make(chan Frame, 1024), done: make(chan struct{})}
	go cl.readLoop()
	return cl
}

// Events — поток событий службы (закрывается при обрыве).
func (c *Client) Events() <-chan Frame { return c.events }

// Done закрывается при обрыве соединения.
func (c *Client) Done() <-chan struct{} { return c.done }

// Close закрывает соединение.
func (c *Client) Close() error {
	c.fail(ErrClosed)
	return nil
}

func (c *Client) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.done)
		_ = c.c.Close()
	})
}

func (c *Client) readLoop() {
	defer close(c.events)
	sc := bufio.NewScanner(c.c)
	sc.Buffer(make([]byte, 64<<10), maxFrame)
	for sc.Scan() {
		var f Frame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			continue
		}
		if f.Event != "" {
			select {
			case c.events <- f:
			default: // интерфейс не успевает — событие теряется, статус дочитается запросом
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[f.ID]
		delete(c.pending, f.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- f
		}
	}
	err := sc.Err()
	if err == nil {
		err = io.EOF
	}
	c.fail(fmt.Errorf("%w: %v", ErrClosed, err))
}

// Call вызывает метод службы. timeout <= 0 — DefaultTimeout.
func (c *Client) Call(method string, params, result any, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	id := c.nextID.Add(1)
	f := Frame{ID: id, Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		f.Params = raw
	}
	b, _ := json.Marshal(f)
	ch := make(chan Frame, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return c.err
	}
	c.pending[id] = ch
	c.mu.Unlock()

	c.wmu.Lock()
	_ = c.c.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.c.Write(append(b, '\n'))
	c.wmu.Unlock()
	if err != nil {
		c.fail(err)
		return ErrClosed
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		if result != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	case <-time.After(timeout):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("служба AnyRoute не ответила за %s (%s)", timeout, method)
	}
}
