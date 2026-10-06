package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newPair(t *testing.T) (*Server, *Client) {
	t.Helper()
	name := fmt.Sprintf(`\\.\pipe\anyroute-test-%d`, time.Now().UnixNano())
	ln, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := NewServer(nil)
	go s.Serve(ln)
	c, err := Dial(name, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return s, c
}

func TestCallAndEvents(t *testing.T) {
	s, c := newPair(t)
	s.Handle("echo", func(_ context.Context, p json.RawMessage) (any, error) {
		var v map[string]string
		_ = json.Unmarshal(p, &v)
		return map[string]string{"got": v["msg"]}, nil
	})
	s.Handle("fail", func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("плохо") })
	s.Handle("panic", func(context.Context, json.RawMessage) (any, error) { panic("бум") })
	s.Handle("slow", func(context.Context, json.RawMessage) (any, error) { time.Sleep(2 * time.Second); return nil, nil })

	var out map[string]string
	if err := c.Call("echo", map[string]string{"msg": "привет"}, &out, 0); err != nil || out["got"] != "привет" {
		t.Fatalf("echo: %v %v", out, err)
	}
	if err := c.Call("fail", nil, nil, 0); err == nil || err.Error() != "плохо" {
		t.Fatalf("fail: %v", err)
	}
	if err := c.Call("panic", nil, nil, 0); err == nil || !strings.Contains(err.Error(), "внутренняя ошибка") {
		t.Fatalf("panic: %v", err)
	}
	if err := c.Call("nope", nil, nil, 0); err == nil {
		t.Fatal("неизвестный метод должен давать ошибку")
	}
	start := time.Now()
	if err := c.Call("slow", nil, nil, 300*time.Millisecond); err == nil || time.Since(start) > time.Second {
		t.Fatalf("таймаут вызова не сработал: %v за %s", err, time.Since(start))
	}
	// Канал продолжает работать после таймаута.
	if err := c.Call("echo", map[string]string{"msg": "ещё"}, &out, 0); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	s.Broadcast("state", map[string]string{"state": "connected"})
	select {
	case f := <-c.Events():
		if f.Event != "state" || !strings.Contains(string(f.Data), "connected") {
			t.Fatalf("событие %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("событие не пришло")
	}
}

func TestClientDetectsServerGone(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\anyroute-test-gone-%d`, time.Now().UnixNano())
	ln, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil)
	accepted := make(chan struct{})
	go func() {
		nc, err := ln.Accept()
		if err == nil {
			close(accepted)
			time.Sleep(100 * time.Millisecond)
			nc.Close()
		}
	}()
	_ = s
	c, err := Dial(name, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	<-accepted
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("обрыв не обнаружен")
	}
	if err := c.Call("status", nil, nil, time.Second); !errors.Is(err, ErrClosed) {
		t.Fatalf("после обрыва: %v", err)
	}
	ln.Close()
}
