// Package netx — сетевые сведения Windows для службы: физический интерфейс
// маршрута по умолчанию, локальные подсети, выбор подсети TUN, привязка
// сокетов к интерфейсу и host-маршруты в TUN AnyRoute.
package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TunName — имя адаптера AnyRoute.
const TunName = "anyroute-tun"

// Iface — сетевой интерфейс.
type Iface struct {
	Index   uint32
	LUID    winipcfg.LUID
	Name    string
	Gateway netip.Addr
	DNS     []netip.Addr
	Addrs   []netip.Prefix
}

// isVirtualTunnel — адаптеры VPN/TUN (наш, Throne, Wintun, TAP), которые
// нельзя считать «физическим» выходом в сеть.
func isVirtualTunnel(a *winipcfg.IPAdapterAddresses) bool {
	name := strings.ToLower(a.FriendlyName() + " " + a.Description())
	for _, marker := range []string{"anyroute", "throne", "sing-tun", "wintun", "wireguard", "tap-windows", "anyconnect", "openvpn", "nekoray", "tun"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return a.IfType == winipcfg.IfTypePropVirtual && strings.Contains(name, "tunnel")
}

func adapters() ([]*winipcfg.IPAdapterAddresses, error) {
	return winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways|winipcfg.GAAFlagIncludePrefix)
}

func toIface(a *winipcfg.IPAdapterAddresses) Iface {
	ifc := Iface{Index: a.IfIndex, LUID: a.LUID, Name: a.FriendlyName()}
	for u := a.FirstUnicastAddress; u != nil; u = u.Next {
		if ip, ok := sockaddrAddr(u.Address); ok && ip.Is4() {
			if p, err := ip.Prefix(int(u.OnLinkPrefixLength)); err == nil {
				ifc.Addrs = append(ifc.Addrs, netip.PrefixFrom(ip, p.Bits()))
			}
		}
	}
	for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
		if ip, ok := sockaddrAddr(d.Address); ok && ip.Is4() {
			ifc.DNS = append(ifc.DNS, ip)
		}
	}
	for g := a.FirstGatewayAddress; g != nil; g = g.Next {
		if ip, ok := sockaddrAddr(g.Address); ok && ip.Is4() {
			ifc.Gateway = ip
			break
		}
	}
	return ifc
}

func sockaddrAddr(sa windows.SocketAddress) (netip.Addr, bool) {
	if sa.Sockaddr == nil {
		return netip.Addr{}, false
	}
	raw := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(sa.Sockaddr))
	a := raw.Addr()
	return a.Unmap(), a.IsValid()
}

// DefaultIface — физический интерфейс маршрута 0.0.0.0/0 с наименьшей
// метрикой (без учёта TUN-адаптеров).
func DefaultIface() (Iface, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return Iface{}, err
	}
	ads, err := adapters()
	if err != nil {
		return Iface{}, err
	}
	byIndex := map[uint32]*winipcfg.IPAdapterAddresses{}
	for _, a := range ads {
		byIndex[a.IfIndex] = a
	}
	best, bestMetric := (*winipcfg.IPAdapterAddresses)(nil), ^uint32(0)
	for i := range routes {
		r := &routes[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		a := byIndex[r.InterfaceIndex]
		if a == nil || a.OperStatus != winipcfg.IfOperStatusUp || isVirtualTunnel(a) {
			continue
		}
		if m := r.Metric + a.Ipv4Metric; m < bestMetric {
			best, bestMetric = a, m
		}
	}
	if best == nil {
		return Iface{}, errors.New("не найден физический интерфейс с маршрутом по умолчанию — нет сети?")
	}
	return toIface(best), nil
}

// LocalNets — подсети всех активных интерфейсов (кроме loopback и TUN
// AnyRoute). Нужны, чтобы адрес TUN не пересёкся ни с чем, в том числе с
// подсетью Throne.
func LocalNets() ([]netip.Prefix, error) {
	ads, err := adapters()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range ads {
		if a.OperStatus != winipcfg.IfOperStatusUp || a.IfType == winipcfg.IfTypeSoftwareLoopback || strings.EqualFold(a.FriendlyName(), TunName) {
			continue
		}
		for _, p := range toIface(a).Addrs {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// PhysicalNets — подсети физических интерфейсов (для «локальная сеть напрямую»).
func PhysicalNets() []netip.Prefix {
	ads, err := adapters()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range ads {
		if a.OperStatus != winipcfg.IfOperStatusUp || a.IfType == winipcfg.IfTypeSoftwareLoopback || isVirtualTunnel(a) {
			continue
		}
		for _, p := range toIface(a).Addrs {
			if p.Bits() >= 8 { // не исключаем «всё» из-за странных масок
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

// TunCandidates — подсети /30 для TUN AnyRoute в порядке предпочтения.
// 172.19.0.0/24 занята Throne по умолчанию, её среди кандидатов нет.
var TunCandidates = []netip.Prefix{
	netip.MustParsePrefix("172.29.254.1/30"),
	netip.MustParsePrefix("100.127.254.1/30"),
	netip.MustParsePrefix("198.18.254.1/30"),
	netip.MustParsePrefix("10.255.254.1/30"),
}

// PickTunPrefix выбирает подсеть TUN, не пересекающуюся с avoid.
func PickTunPrefix(avoid []netip.Prefix) (netip.Prefix, error) {
	for _, c := range TunCandidates {
		if !overlapsAny(c.Masked(), avoid) {
			return c, nil
		}
	}
	return netip.Prefix{}, errors.New("не удалось подобрать подсеть для TUN: все кандидаты заняты")
}

func overlapsAny(p netip.Prefix, list []netip.Prefix) bool {
	for _, q := range list {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}

// ipUnicastIf — IP_UNICAST_IF: сокет отправляет пакеты только через
// указанный интерфейс независимо от таблицы маршрутов.
const ipUnicastIf = 31

// BindControl возвращает Control для net.Dialer, привязывающий сокет к
// интерфейсу с индексом index.
func BindControl(index uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			// Для IPv4 индекс передаётся в сетевом порядке байт.
			v := int(htonl(index))
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, v)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func htonl(v uint32) uint32 {
	return (v&0xff)<<24 | (v&0xff00)<<8 | (v&0xff0000)>>8 | (v&0xff000000)>>24
}

// BoundDialer — DialContext, привязанный к текущему физическому интерфейсу.
// Интерфейс определяется на каждый вызов: сеть могла смениться (Wi-Fi →
// Ethernet).
func BoundDialer() func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ifc, err := DefaultIface()
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{Timeout: 15 * time.Second, Control: BindControl(ifc.Index)}
		return d.DialContext(ctx, network, address)
	}
}

// HostRoutes — /32-маршруты в TUN AnyRoute для адресов доменов, идущих в
// VPN. Добавленные адреса запоминаются: после пересоздания TUN (смена
// профиля) они применяются заново.
type HostRoutes struct {
	mu      sync.Mutex
	nextHop netip.Addr
	skip    func(netip.Addr) bool
	added   map[netip.Addr]bool
	errFn   func(error)
}

// maxHostRoutes ограничивает рост таблицы маршрутов.
const maxHostRoutes = 4096

// NewHostRoutes создаёт менеджер. skip — адреса, уже покрытые маршрутами TUN.
func NewHostRoutes(nextHop netip.Addr, skip func(netip.Addr) bool, onErr func(error)) *HostRoutes {
	return &HostRoutes{nextHop: nextHop, skip: skip, added: map[netip.Addr]bool{}, errFn: onErr}
}

func tunLUID() (winipcfg.LUID, error) {
	ifc, err := net.InterfaceByName(TunName)
	if err != nil {
		return 0, fmt.Errorf("адаптер %s не найден: %w", TunName, err)
	}
	return winipcfg.LUIDFromIndex(uint32(ifc.Index))
}

// Add добавляет маршруты для новых адресов.
func (h *HostRoutes) Add(ips []netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var fresh []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.Is4() || h.added[ip] || (h.skip != nil && h.skip(ip)) || len(h.added) >= maxHostRoutes {
			continue
		}
		fresh = append(fresh, ip)
	}
	if len(fresh) == 0 {
		return
	}
	luid, err := tunLUID()
	if err != nil {
		h.report(err)
		return
	}
	for _, ip := range fresh {
		err := luid.AddRoute(netip.PrefixFrom(ip, 32), h.nextHop, 0)
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			h.report(fmt.Errorf("маршрут %s: %w", ip, err))
			continue
		}
		h.added[ip] = true
	}
}

// Reapply повторно добавляет все запомненные маршруты (TUN пересоздан).
func (h *HostRoutes) Reapply(nextHop netip.Addr, skip func(netip.Addr) bool) {
	h.mu.Lock()
	ips := make([]netip.Addr, 0, len(h.added))
	for ip := range h.added {
		ips = append(ips, ip)
	}
	h.added = map[netip.Addr]bool{}
	h.nextHop, h.skip = nextHop, skip
	h.mu.Unlock()
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	h.Add(ips)
}

// Count — сколько маршрутов добавлено.
func (h *HostRoutes) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.added)
}

func (h *HostRoutes) report(err error) {
	if h.errFn != nil {
		h.errFn(err)
	}
}

// TunExists сообщает, есть ли в системе адаптер AnyRoute.
func TunExists() bool {
	_, err := net.InterfaceByName(TunName)
	return err == nil
}
