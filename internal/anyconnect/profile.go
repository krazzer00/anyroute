package anyconnect

import (
	"net"
	"runtime"
	"strings"

	"github.com/elastic/go-sysinfo"
)

// DefaultAgentVersion — версия клиента, сообщаемая серверу (как у AnyConnect 4.10).
const DefaultAgentVersion = "4.10.07062"

// profile — параметры подключения и данные, полученные от шлюза в ходе
// аутентификации. Поля экспортируются: они подставляются в XML-шаблоны.
type profile struct {
	Host         string
	HostWithPort string
	Username     string
	Password     string
	Group        string
	AppVersion   string
	AuthPath     string

	MacAddress  string
	TunnelGroup string
	GroupAlias  string
	ConfigHash  string

	// SendGroupSelect — слать ли <group-select>: только если сервер предложил
	// список групп и группа выбрана. ocserv без select-group отвергает
	// непрошеный group-select (401), а пустая группа означает «группа сервера
	// по умолчанию».
	SendGroupSelect bool

	ComputerName    string
	DeviceType      string
	PlatformVersion string
	UniqueID        string
	// Platform — тело <device-id> ("win"). С пустым телом живая ASA отвечает
	// <error id="96">VPN Server internal error.</error> уже на init.
	Platform string
}

func newProfile(cfg Config) *profile {
	p := &profile{
		Username:   cfg.Username,
		Password:   cfg.Password,
		Group:      cfg.Group,
		AppVersion: cfg.AgentVersion,
	}
	if p.AppVersion == "" {
		p.AppVersion = DefaultAgentVersion
	}
	p.setHost(cfg.Host)
	p.fillDeviceInfo()
	return p
}

// setHost переводит профиль на другой адрес (редирект шлюза).
func (p *profile) setHost(host string) {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	p.Host = host
	if _, _, err := net.SplitHostPort(host); err == nil {
		p.HostWithPort = host
	} else {
		p.HostWithPort = net.JoinHostPort(host, "443")
	}
}

// serverName — имя для SNI и проверки сертификата (без порта).
func (p *profile) serverName() string {
	if h, _, err := net.SplitHostPort(p.HostWithPort); err == nil {
		return h
	}
	return p.Host
}

// platformID — тело <device-id> в терминах AnyConnect.
func platformID() string {
	switch runtime.GOOS {
	case "windows":
		return "win"
	case "darwin":
		return "mac-intel"
	default:
		return "linux-64"
	}
}

// osName — имя ОС в User-Agent: настоящий клиент шлёт
// "AnyConnect Windows 4.10.07062" — без архитектуры и подчёркивания.
func osName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "Mac OS X"
	default:
		return "Linux"
	}
}

func (p *profile) userAgent() string {
	return "AnyConnect " + osName() + " " + p.AppVersion
}

func (p *profile) fillDeviceInfo() {
	p.Platform = platformID()
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	info := host.Info()
	p.ComputerName = info.Hostname
	p.UniqueID = info.UniqueID
	p.DeviceType = info.OS.Name
	if runtime.GOOS == "windows" {
		p.PlatformVersion = info.OS.Build
	} else {
		p.PlatformVersion = strings.Split(info.OS.Version, " ")[0]
	}
	p.MacAddress = primaryMAC()
}

// primaryMAC — MAC первого активного физического интерфейса (для
// <mac-address-list>). Пустое значение допустимо.
func primaryMAC() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		return strings.ReplaceAll(ifc.HardwareAddr.String(), ":", "-")
	}
	return ""
}
