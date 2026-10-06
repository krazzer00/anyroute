package profiles

import (
	"strings"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := s.Routings()
	if len(rs) != 1 || rs[0].ID != "default" {
		t.Fatalf("профиль Default не создан: %+v", rs)
	}
	sv, err := s.SaveServer(Server{Name: "Офис", Host: "https://vpn.example.com/", Username: "ivan", RoutingProfileID: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if sv.ID == "" || sv.Host != "vpn.example.com" {
		t.Fatalf("нормализация: %+v", sv)
	}
	got, err := s.Server(sv.ID)
	if err != nil || got.Username != "ivan" {
		t.Fatalf("Server: %+v %v", got, err)
	}
	sv.Name = "Офис 2"
	if _, err := s.SaveServer(sv); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Servers()
	if len(list) != 1 || list[0].Name != "Офис 2" {
		t.Fatalf("обновление: %+v", list)
	}
	if err := s.DeleteServer(sv.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Servers(); len(list) != 0 {
		t.Fatal("сервер не удалён")
	}

	r := Routing{Name: "Работа", DefaultOutbound: "vpn", Direct: "processName:Telegram.exe"}
	if err := s.SaveRouting(r); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.Routings(); len(rs) != 2 || rs[0].ID != "default" {
		t.Fatalf("порядок профилей: %+v", rs)
	}
	if err := s.DeleteRouting("default"); err == nil {
		t.Fatal("Default удалять нельзя")
	}
}

func TestRoutingValidationReportsLines(t *testing.T) {
	r := Routing{Name: "x", VPN: "domain:ok.example\nip:300.1.1.1", Block: "port:0"}
	err := r.Validate()
	re, ok := err.(*RuleErrors)
	if !ok {
		t.Fatalf("ожидались ошибки правил, получено %v", err)
	}
	if len(re.Errors["vpn"]) != 1 || re.Errors["vpn"][0].Line != 2 || len(re.Errors["block"]) != 1 {
		t.Fatalf("ошибки: %+v", re.Errors)
	}
	if !strings.Contains(err.Error(), "VPN, строка 2") {
		t.Fatalf("текст: %s", err)
	}
}

func TestServerValidation(t *testing.T) {
	for _, bad := range []Server{{Name: "", Host: "a.example"}, {Name: "x", Host: "a b"}, {Name: "x", Host: "a.example;calc"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("ожидалась ошибка для %+v", bad)
		}
	}
}
