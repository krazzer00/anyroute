// Package core — ядро службы AnyRoute: одно подключение, его состояние,
// ожидание второго фактора, профиль маршрутизации, статистика.
//
// Все методы Core возвращаются быстро: долгие операции идут в отдельной
// горутине, статус читается из атомарного снимка без блокировок. Поэтому
// ни интерфейс, ни трей не могут «зависнуть» на запросе к службе.
package core

import (
	"time"

	"github.com/krazzer00/anyroute/internal/profiles"
)

// State — состояние подключения.
type State string

const (
	StateIdle          State = "idle"
	StateConnecting    State = "connecting"
	StateAuth          State = "auth"
	State2FA           State = "2fa"
	StateConnected     State = "connected"
	StateDisconnecting State = "disconnecting"
)

// Challenge — запрос второго фактора для интерфейса.
type Challenge struct {
	Message string `json:"message"`
	Label   string `json:"label"`
	Retry   bool   `json:"retry"`
	Seq     int    `json:"seq"` // растёт с каждым новым запросом кода
}

// Status — снимок состояния.
type Status struct {
	State        State      `json:"state"`
	ServerID     string     `json:"serverId,omitempty"`
	ServerName   string     `json:"serverName,omitempty"`
	Host         string     `json:"host,omitempty"`
	ProfileID    string     `json:"profileId,omitempty"`
	ProfileName  string     `json:"profileName,omitempty"`
	Step         string     `json:"step,omitempty"`
	Since        time.Time  `json:"since,omitempty"`
	Address      string     `json:"address,omitempty"`
	Gateway      string     `json:"gateway,omitempty"`
	DNS          []string   `json:"dns,omitempty"`
	SplitInclude []string   `json:"splitInclude,omitempty"`
	SplitDNS     []string   `json:"splitDns,omitempty"`
	TunPrefix    string     `json:"tunPrefix,omitempty"`
	DTLS         bool       `json:"dtls"`
	Banner       string     `json:"banner,omitempty"`
	Challenge    *Challenge `json:"challenge,omitempty"`
	Warnings     []string   `json:"warnings,omitempty"`
	HostRoutes   int        `json:"hostRoutes"`
	Error        string     `json:"error,omitempty"`
	Version      string     `json:"version"`
}

// ConnectRequest — параметры подключения от интерфейса. Учётные данные
// живут только на время сеанса.
type ConnectRequest struct {
	ServerID    string           `json:"serverId"`
	ServerName  string           `json:"serverName"`
	Host        string           `json:"host"`
	Group       string           `json:"group"`
	Username    string           `json:"username"`
	Password    string           `json:"password"`
	InsecureTLS bool             `json:"insecureTls"`
	Profile     profiles.Routing `json:"profile"`
}

// Sample — точка графика: скорость за секунду, байт/с.
type Sample struct {
	T          int64 `json:"t"` // unix ms
	VPNUp      int64 `json:"vu"`
	VPNDown    int64 `json:"vd"`
	DirectUp   int64 `json:"du"`
	DirectDown int64 `json:"dd"`
}

// Conn — активное или недавно закрытое соединение.
type Conn struct {
	ID       string `json:"id"`
	Process  string `json:"process"`
	Path     string `json:"path"`
	PID      uint32 `json:"pid"`
	Network  string `json:"network"`
	Dest     string `json:"dest"`
	Domain   string `json:"domain"`
	Outbound string `json:"outbound"`
	Rule     string `json:"rule"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	Start    int64  `json:"start"`
	Closed   bool   `json:"closed"`
}

// Event — событие для подписчиков (IPC).
type Event struct {
	Type string `json:"type"` // state | log | sample
	Data any    `json:"data"`
}
