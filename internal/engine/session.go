// Package engine встраивает sing-box: TUN AnyRoute, маршрутизация по
// правилам, DNS. Собственные части — outbound «anyconnect» (соединения через
// gVisor-стек поверх CSTP-туннеля) и DNS-транспорт «anyroute-vpn» (запросы к
// DNS шлюза через туннель + host-маршруты для ответов).
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"

	"github.com/krazzer00/anyroute/internal/vpnstack"
)

// Session — общее для движка состояние подключения: стек VPN и DNS шлюза.
// Живёт дольше экземпляра sing-box: смена профиля пересоздаёт box, а
// сессия (и пройденная 2FA) остаётся.
type Session struct {
	mu      sync.RWMutex
	stack   *vpnstack.Stack
	dns     []netip.Addr
	onReply func(domain string, ips []netip.Addr)
}

// NewSession создаёт сессию.
func NewSession(stack *vpnstack.Stack, dns []netip.Addr) *Session {
	return &Session{stack: stack, dns: dns}
}

// OnDNSReply задаёт обработчик ответов DNS шлюза (host-маршруты).
func (s *Session) OnDNSReply(fn func(domain string, ips []netip.Addr)) {
	s.mu.Lock()
	s.onReply = fn
	s.mu.Unlock()
}

func (s *Session) get() (*vpnstack.Stack, []netip.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stack, s.dns
}

func (s *Session) notify(msg *mDNS.Msg) {
	if msg == nil || len(msg.Question) == 0 {
		return
	}
	s.mu.RLock()
	fn := s.onReply
	s.mu.RUnlock()
	if fn == nil {
		return
	}
	var ips []netip.Addr
	for _, rr := range msg.Answer {
		if a, ok := rr.(*mDNS.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) > 0 {
		fn(mDNS.CanonicalName(msg.Question[0].Name), ips)
	}
}

// ErrNoStack — туннель ещё не поднят или уже закрыт.
var ErrNoStack = errors.New("engine: VPN-туннель не активен")

// Exchange отправляет DNS-запрос серверам шлюза через туннель: UDP, при
// усечении ответа — TCP. Перебирает серверы по очереди.
func (s *Session) Exchange(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
	st, servers := s.get()
	if st == nil {
		return nil, ErrNoStack
	}
	if len(servers) == 0 {
		return nil, errors.New("шлюз не выдал DNS-серверов")
	}
	var lastErr error
	for _, srv := range servers {
		resp, err := exchangeOne(ctx, st, netip.AddrPortFrom(srv, 53), q)
		if err == nil {
			s.notify(resp)
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("DNS шлюза не ответил: %w", lastErr)
}

func exchangeOne(ctx context.Context, st *vpnstack.Stack, server netip.AddrPort, q *mDNS.Msg) (*mDNS.Msg, error) {
	packed, err := q.Pack()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(4 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := st.DialUDP(server)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packed); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil {
		return nil, err
	}
	resp := new(mDNS.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	if !resp.Truncated {
		return resp, nil
	}
	// Усечённый ответ — повтор по TCP.
	tctx, cancel := context.WithDeadline(ctx, deadline.Add(2*time.Second))
	defer cancel()
	tc, err := st.DialTCP(tctx, server)
	if err != nil {
		return resp, nil
	}
	defer tc.Close()
	_ = tc.SetDeadline(deadline.Add(2 * time.Second))
	dc := &mDNS.Conn{Conn: tc}
	if err := dc.WriteMsg(q); err != nil {
		return resp, nil
	}
	full, err := dc.ReadMsg()
	if err != nil {
		return resp, nil
	}
	return full, nil
}

// LookupA разрешает имя через DNS шлюза (для соединений, пришедших в
// outbound с доменом вместо адреса).
func (s *Session) LookupA(ctx context.Context, name string) (netip.Addr, error) {
	q := new(mDNS.Msg)
	q.SetQuestion(mDNS.Fqdn(name), mDNS.TypeA)
	q.RecursionDesired = true
	resp, err := s.Exchange(ctx, q)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*mDNS.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, &net.DNSError{Err: "нет A-записи", Name: name, IsNotFound: true}
}
