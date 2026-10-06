// Виртуальная «внутренняя сеть» мок-шлюза на gVisor netstack.
//
// IP-пакеты, пришедшие от VPN-клиента по CSTP-туннелю, инжектируются в
// netstack; сервисы (echo, HTTP) слушают внутри netstack на адресе HostIP
// через gonet — с точки зрения клиента это настоящие хосты за шлюзом.
// Исходящие пакеты netstack уходят обратно в туннель через канал egress.
package mockasa

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

const (
	vnetNICID       = tcpip.NICID(1)
	vnetChannelSize = 512
)

// vnet — netstack-хост внутренней сети шлюза.
type vnet struct {
	stack  *stack.Stack
	linkEP *channel.Endpoint
	hostIP tcpip.Address

	egress chan []byte // исходящие IP-пакеты netstack → CSTP-туннель

	cancel context.CancelFunc
}

// newVNet создаёт netstack с одним NIC и адресом hostIP.
func newVNet(hostIP string, mtu int) (*vnet, error) {
	parsed := net.ParseIP(hostIP)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("mockasa: некорректный IPv4-адрес хоста %q", hostIP)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(vnetChannelSize, uint32(mtu), "")
	if tcpipErr := s.CreateNIC(vnetNICID, linkEP); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("mockasa: создание NIC: %s", tcpipErr)
	}

	addr := tcpip.AddrFromSlice(parsed.To4())
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24},
	}
	if tcpipErr := s.AddProtocolAddress(vnetNICID, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		s.Close()
		return nil, fmt.Errorf("mockasa: назначение адреса NIC: %s", tcpipErr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: vnetNICID},
	})

	v := &vnet{
		stack:  s,
		linkEP: linkEP,
		hostIP: addr,
		egress: make(chan []byte, 64),
	}

	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	go v.readLoop(ctx)
	return v, nil
}

// inject подаёт IP-пакет из туннеля в netstack (трафик клиента → хосты).
func (v *vnet) inject(pkt []byte) {
	if len(pkt) == 0 || header.IPVersion(pkt) != header.IPv4Version {
		return // мок поддерживает только IPv4
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	v.linkEP.InjectInbound(header.IPv4ProtocolNumber, pkb)
	pkb.DecRef()
}

// readLoop переливает исходящие пакеты netstack в egress-канал.
func (v *vnet) readLoop(ctx context.Context) {
	defer close(v.egress)
	for {
		pkb := v.linkEP.ReadContext(ctx)
		if pkb == nil {
			return // vnet закрыт
		}
		buf := pkb.ToBuffer()
		data := buf.Flatten()
		buf.Release()
		pkb.DecRef()

		select {
		case v.egress <- data:
		case <-ctx.Done():
			return
		}
	}
}

// listenTCP открывает TCP-listener внутри netstack на HostIP:port.
func (v *vnet) listenTCP(port uint16) (net.Listener, error) {
	ln, err := gonet.ListenTCP(v.stack, tcpip.FullAddress{
		NIC:  vnetNICID,
		Addr: v.hostIP,
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("mockasa: listen внутри netstack: %w", err)
	}
	return ln, nil
}

// listenUDP открывает UDP-сокет внутри netstack на HostIP:port.
func (v *vnet) listenUDP(port uint16) (net.PacketConn, error) {
	conn, err := gonet.DialUDP(v.stack, &tcpip.FullAddress{
		NIC:  vnetNICID,
		Addr: v.hostIP,
		Port: port,
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("mockasa: udp внутри netstack: %w", err)
	}
	return conn, nil
}

// close останавливает netstack и перекачку пакетов.
func (v *vnet) close() {
	v.cancel()
	v.stack.Close()
	v.linkEP.Close()
}
