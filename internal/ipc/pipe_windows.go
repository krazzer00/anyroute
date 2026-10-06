package ipc

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// pipeSDDL: SYSTEM и администраторы — полный доступ, интерактивно вошедшие
// пользователи — чтение и запись. Сетевым сеансам и службам канал закрыт.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen открывает канал name (PipeName — для службы).
func Listen(name string) (net.Listener, error) {
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("канал %s: %w", name, err)
	}
	return ln, nil
}

// Dial подключается к каналу службы.
func Dial(name string, timeout time.Duration) (*Client, error) {
	c, err := winio.DialPipe(name, &timeout)
	if err != nil {
		return nil, fmt.Errorf("служба AnyRoute недоступна: %w", err)
	}
	return NewClient(c), nil
}
