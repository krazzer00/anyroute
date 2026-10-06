package core

import (
	"context"
	"net/netip"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/cleanup"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/netx"
	"github.com/krazzer00/anyroute/internal/nrpt"
)

// WindowsPlatform — боевая реализация Platform.
type WindowsPlatform struct{}

func (WindowsPlatform) Cleanup(ctx context.Context, log *logx.Src, tunActive bool) {
	cleanup.Run(ctx, log, tunActive)
}

func (WindowsPlatform) Dialer() anyconnect.DialFunc { return netx.BoundDialer() }

func (WindowsPlatform) LocalNets() []netip.Prefix {
	n, _ := netx.LocalNets()
	return n
}

func (WindowsPlatform) PhysicalNets() []netip.Prefix { return netx.PhysicalNets() }

func (WindowsPlatform) LocalDNS() []netip.Addr {
	ifc, err := netx.DefaultIface()
	if err != nil {
		return nil
	}
	return ifc.DNS
}

func (WindowsPlatform) PickTunPrefix(avoid []netip.Prefix) (netip.Prefix, error) {
	return netx.PickTunPrefix(avoid)
}

func (WindowsPlatform) ApplyNRPT(ctx context.Context, ns []string, server netip.Addr) error {
	return nrpt.Apply(ctx, ns, server)
}

func (WindowsPlatform) RemoveNRPT(ctx context.Context) error { return nrpt.Remove(ctx, nrpt.Comment) }

func (WindowsPlatform) HostRoutes(nextHop netip.Addr, skip func(netip.Addr) bool, onErr func(error)) HostRouter {
	return netx.NewHostRoutes(nextHop, skip, onErr)
}

func (WindowsPlatform) NoTun() bool { return false }
