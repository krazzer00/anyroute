// Package core — ядро службы AnyRoute: одно подключение, его состояние,
// ожидание второго фактора, профиль маршрутизации, статистика.
//
// Все методы Core возвращаются быстро: долгие операции идут в отдельной
// горутине, статус читается из атомарного снимка без блокировок. Поэтому
// ни интерфейс, ни трей не могут «зависнуть» на запросе к службе.
package core

import "github.com/krazzer00/anyroute/internal/api"

// Типы протокола (см. internal/api).
type (
	State          = api.State
	Challenge      = api.Challenge
	Status         = api.Status
	ConnectRequest = api.ConnectRequest
	Sample         = api.Sample
	Conn           = api.Conn
	Event          = api.Event
)

// Состояния.
const (
	StateIdle          = api.StateIdle
	StateConnecting    = api.StateConnecting
	StateAuth          = api.StateAuth
	State2FA           = api.State2FA
	StateConnected     = api.StateConnected
	StateDisconnecting = api.StateDisconnecting
)
