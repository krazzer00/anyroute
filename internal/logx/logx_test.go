package logx

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := []struct{ in, mustNot, must string }{
		{`<auth><username>ivan</username><password>Secr3t!</password></auth>`, "Secr3t!", "<password>***</password>"},
		{`<auth><password>123456</password></auth>`, "123456", "<password>***</password>"},
		{`<secondary_password>654321</secondary_password>`, "654321", "<secondary_password>***</secondary_password>"},
		{`<session-token>ABCDEF0123</session-token>`, "ABCDEF0123", "<session-token>***</session-token>"},
		{`Cookie: webvpn=4A5B6C@123@ABC; path=/`, "4A5B6C@123@ABC", "webvpn=***"},
		{`X-DTLS-Master-Secret: 0011223344`, "0011223344", "X-DTLS-Master-Secret: ***"},
		{`{"password":"hunter2","user":"a"}`, "hunter2", `"password":"***`},
		{`totp=JBSWY3DPEHPK3PXP`, "JBSWY3DPEHPK3PXP", "totp=***"},
	}
	for _, c := range cases {
		got := Mask(c.in)
		if strings.Contains(got, c.mustNot) {
			t.Errorf("Mask(%q) = %q — секрет не скрыт", c.in, got)
		}
		if !strings.Contains(got, c.must) {
			t.Errorf("Mask(%q) = %q — ожидалось %q", c.in, got, c.must)
		}
	}
}

func TestRingAndLevels(t *testing.T) {
	l := New(3, nil)
	var got []Entry
	unsub := l.Subscribe(func(e Entry) { got = append(got, e) })
	src := l.Source("core")
	src.Debugf("скрыто")
	for i := 0; i < 5; i++ {
		src.Infof("запись %d", i)
	}
	unsub()
	src.Infof("после отписки")
	if n := len(l.Entries(0)); n != 3 {
		t.Fatalf("в буфере %d записей, ожидалось 3", n)
	}
	if len(got) != 5 {
		t.Fatalf("подписчик получил %d записей, ожидалось 5", len(got))
	}
	if e := l.Entries(0); e[0].Message != "запись 3" {
		t.Fatalf("первая запись буфера %q", e[0].Message)
	}
	last := l.Entries(0)[2].Seq
	if len(l.Entries(last)) != 0 {
		t.Fatal("Entries(after) вернул старые записи")
	}
}
