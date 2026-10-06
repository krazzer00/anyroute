package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Типы, регистрируемые в sing-box.
const (
	TypeAnyConnect = "anyconnect"
	TypeVPNDNS     = "anyroute-vpn"
)

// AnyConnectOptions — опции outbound (сессия берётся из контекста).
type AnyConnectOptions struct{}

// VPNDNSOptions — опции DNS-транспорта (серверы берутся из сессии).
type VPNDNSOptions struct{}

func sessionFrom(ctx context.Context) (*Session, error) {
	s := service.FromContext[*Session](ctx)
	if s == nil {
		return nil, fmt.Errorf("engine: нет VPN-сессии в контексте")
	}
	return s, nil
}

// vpnOutbound — outbound «anyconnect».
type vpnOutbound struct {
	outbound.Adapter
	sess   *Session
	logger logger.ContextLogger
}

func newVPNOutbound(ctx context.Context, _ adapter.Router, l log.ContextLogger, tag string, _ AnyConnectOptions) (adapter.Outbound, error) {
	s, err := sessionFrom(ctx)
	if err != nil {
		return nil, err
	}
	return &vpnOutbound{
		Adapter: outbound.NewAdapter(TypeAnyConnect, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    s,
		logger:  l,
	}, nil
}

func (o *vpnOutbound) resolve(ctx context.Context, dst M.Socksaddr) (netip.AddrPort, error) {
	if dst.IsIP() {
		return dst.AddrPort(), nil
	}
	ip, err := o.sess.LookupA(ctx, dst.Fqdn)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, dst.Port), nil
}

func (o *vpnOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	st, _ := o.sess.get()
	if st == nil {
		return nil, ErrNoStack
	}
	ap, err := o.resolve(ctx, dst)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return st.DialTCP(ctx, ap)
	case N.NetworkUDP:
		return st.DialUDP(ap)
	}
	return nil, fmt.Errorf("engine: неподдерживаемая сеть %q", network)
}

func (o *vpnOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	st, _ := o.sess.get()
	if st == nil {
		return nil, ErrNoStack
	}
	return st.ListenUDP()
}

// vpnDNS — DNS-транспорт «anyroute-vpn».
type vpnDNS struct {
	dns.TransportAdapter
	sess *Session
}

func newVPNDNS(ctx context.Context, _ log.ContextLogger, tag string, _ VPNDNSOptions) (adapter.DNSTransport, error) {
	s, err := sessionFrom(ctx)
	if err != nil {
		return nil, err
	}
	return &vpnDNS{TransportAdapter: dns.NewTransportAdapter(TypeVPNDNS, tag, nil), sess: s}, nil
}

func (t *vpnDNS) Start(adapter.StartStage) error { return nil }
func (t *vpnDNS) Close() error                   { return nil }
func (t *vpnDNS) Reset()                         {}

func (t *vpnDNS) Exchange(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	return t.sess.Exchange(ctx, msg)
}

func (t *vpnDNS) ExchangeAsync(ctx context.Context, msg *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.sess.Exchange(ctx, msg)) }()
}
