package mockasa

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// answerDNS строит ответ на простой DNS-запрос (один вопрос, тип A).
// Минимальная реализация для тестов: без сжатия в вопросе, ответ ссылается
// на имя указателем 0xc00c.
func answerDNS(q []byte, records map[string]string) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	// Разбор имени вопроса.
	off := 12
	var labels []string
	for off < len(q) {
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[off:off+l]))
		off += l
	}
	if off+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[off : off+2])
	question := q[12 : off+4]
	name := strings.ToLower(strings.Join(labels, "."))

	resp := make([]byte, 12, 12+len(question)+16)
	copy(resp, q[:2])
	flags := uint16(0x8180) // ответ, RD, RA
	ip, ok := records[name]
	addr, perr := netip.ParseAddr(ip)
	if !ok || perr != nil || !addr.Is4() {
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	resp = append(resp, question...)
	if ok && perr == nil && addr.Is4() && qtype == 1 {
		binary.BigEndian.PutUint16(resp[6:8], 1)
		a := addr.As4()
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, a[:]...)
	}
	return resp
}
