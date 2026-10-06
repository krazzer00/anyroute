package gui

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/krazzer00/anyroute/internal/ipc"
)

// svcLink — соединение со службой с автоматическим переподключением.
// Все вызовы ограничены по времени: если служба не отвечает, интерфейс
// показывает это, а не зависает.
type svcLink struct {
	mu      sync.Mutex
	client  *ipc.Client
	onEvent func(ipc.Frame)
	onState func(up bool)
	stop    chan struct{}
}

func newSvcLink(onEvent func(ipc.Frame), onState func(up bool)) *svcLink {
	l := &svcLink{onEvent: onEvent, onState: onState, stop: make(chan struct{})}
	go l.loop()
	return l
}

func (l *svcLink) loop() {
	wasUp := false
	for {
		c, err := ipc.Dial(ipc.PipeName, 2*time.Second)
		if err == nil {
			l.mu.Lock()
			l.client = c
			l.mu.Unlock()
			wasUp = true
			l.onState(true)
			for f := range c.Events() {
				l.onEvent(f)
			}
			l.mu.Lock()
			l.client = nil
			l.mu.Unlock()
			l.onState(false)
		} else if wasUp {
			wasUp = false
			l.onState(false)
		}
		select {
		case <-l.stop:
			return
		case <-time.After(1500 * time.Millisecond):
		}
	}
}

// up сообщает, есть ли связь со службой.
func (l *svcLink) up() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.client != nil
}

// call вызывает метод службы.
func (l *svcLink) call(method string, params, result any, timeout time.Duration) error {
	l.mu.Lock()
	c := l.client
	l.mu.Unlock()
	if c == nil {
		return errServiceDown
	}
	return c.Call(method, params, result, timeout)
}

func (l *svcLink) close() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	l.mu.Lock()
	if l.client != nil {
		_ = l.client.Close()
	}
	l.mu.Unlock()
}

func decodeInto(raw json.RawMessage, v any) bool { return json.Unmarshal(raw, v) == nil }
