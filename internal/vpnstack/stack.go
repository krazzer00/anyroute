// Package vpnstack — userspace TCP/IP (gVisor) поверх потока IP-пакетов
// AnyConnect-туннеля. Через него outbound «vpn» sing-box и DNS-транспорт
// открывают соединения внутрь VPN, не трогая таблицу маршрутов системы.
package vpnstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	nicID       = tcpip.NICID(1)
	channelSize = 1024
)

// PacketIO — поток IP-пакетов туннеля (anyconnect.Tunnel).
type PacketIO interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

// Stack — сетевой стек одного подключения.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	io     PacketIO
	local  tcpip.Address
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// New создаёт стек с адресом клиента addr (выдан шлюзом) и MTU туннеля.
func New(io PacketIO, addr netip.Addr, mtu int) (*Stack, error) {
	if io == nil {
		return nil, errors.New("vpnstack: нет потока пакетов")
	}
	if !addr.Is4() {
		return nil, fmt.Errorf("vpnstack: нужен IPv4-адрес, получен %s", addr)
	}
	if mtu <= 0 {
		mtu = 1399
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	ep := channel.New(channelSize, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("vpnstack: создание NIC: %s", err)
	}
	local := tcpip.AddrFrom4(addr.As4())
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: local, PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("vpnstack: адрес NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, io: io, local: local, cancel: cancel}
	st.wg.Add(2)
	go st.inject(ctx)
	go st.extract(ctx)
	return st, nil
}

// inject переносит пакеты из туннеля в стек.
func (st *Stack) inject(ctx context.Context) {
	defer st.wg.Done()
	for {
		pkt, err := st.io.ReadPacket()
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if len(pkt) == 0 || header.IPVersion(pkt) != header.IPv4Version {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		st.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		pkb.DecRef()
	}
}

// extract переносит исходящие пакеты стека в туннель.
func (st *Stack) extract(ctx context.Context) {
	defer st.wg.Done()
	for {
		pkb := st.ep.ReadContext(ctx)
		if pkb == nil {
			return
		}
		buf := pkb.ToBuffer()
		data := buf.Flatten()
		buf.Release()
		pkb.DecRef()
		if err := st.io.WritePacket(data); err != nil {
			return
		}
	}
}

func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, error) {
	a := ap.Addr().Unmap()
	if !a.Is4() {
		return tcpip.FullAddress{}, fmt.Errorf("vpnstack: IPv6 через туннель не поддерживается (%s)", a)
	}
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(a.As4()), Port: ap.Port()}, nil
}

// DialTCP открывает TCP-соединение внутрь VPN.
func (st *Stack) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	fa, err := fullAddr(dst)
	if err != nil {
		return nil, err
	}
	return gonet.DialContextTCP(ctx, st.s, fa, ipv4.ProtocolNumber)
}

// DialUDP открывает «подключённый» UDP-сокет внутрь VPN.
func (st *Stack) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	fa, err := fullAddr(dst)
	if err != nil {
		return nil, err
	}
	return gonet.DialUDP(st.s, nil, &fa, ipv4.ProtocolNumber)
}

// ListenUDP открывает неподключённый UDP-сокет (ReadFrom/WriteTo) внутри VPN.
func (st *Stack) ListenUDP() (net.PacketConn, error) {
	laddr := tcpip.FullAddress{NIC: nicID, Addr: st.local}
	return gonet.DialUDP(st.s, &laddr, nil, ipv4.ProtocolNumber)
}

// Close останавливает стек. Идемпотентна; не закрывает сам туннель.
func (st *Stack) Close() error {
	st.once.Do(func() {
		st.cancel()
		st.s.Close()
		st.ep.Close()
	})
	return nil
}
