//go:build windows

package netx

import (
	"net/netip"
	"testing"
)

func TestPickTunPrefixAvoidsThrone(t *testing.T) {
	p, err := PickTunPrefix([]netip.Prefix{netip.MustParsePrefix("172.19.0.0/24")})
	if err != nil || p != TunCandidates[0] {
		t.Fatalf("got %v %v", p, err)
	}
	p, err = PickTunPrefix([]netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")})
	if err != nil || p != TunCandidates[1] {
		t.Fatalf("при занятой 172.16/12 got %v %v", p, err)
	}
	var all []netip.Prefix
	for _, c := range TunCandidates {
		all = append(all, c.Masked())
	}
	if _, err := PickTunPrefix(all); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestHtonl(t *testing.T) {
	if htonl(0x01020304) != 0x04030201 {
		t.Fatal("htonl")
	}
}

// TestDefaultIfaceOnThisMachine — на машине с сетью должен находиться
// физический интерфейс, и это не TUN Throne.
func TestDefaultIfaceOnThisMachine(t *testing.T) {
	ifc, err := DefaultIface()
	if err != nil {
		t.Skipf("нет сети: %v", err)
	}
	t.Logf("интерфейс %q index=%d gw=%s dns=%v addrs=%v", ifc.Name, ifc.Index, ifc.Gateway, ifc.DNS, ifc.Addrs)
	if ifc.Name == "throne-tun" || ifc.Name == TunName {
		t.Fatalf("выбран TUN-адаптер %q", ifc.Name)
	}
	nets, err := LocalNets()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("локальные сети %v; физические %v", nets, PhysicalNets())
}
