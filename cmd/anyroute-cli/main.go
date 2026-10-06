// anyroute-cli — диагностика без интерфейса и службы.
//
//	anyroute-cli -host vpn.example.com -groups
//	anyroute-cli -host vpn.example.com -group "Remote" -user ivan -hold 60s
//
// Пароль спрашивается в консоли (или -pass), код 2FA — тоже (или -otp,
// -totp-secret). Подключение поднимает TUN, поэтому нужны права
// администратора; служба AnyRoute на это время должна быть отключена от VPN.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/krazzer00/anyroute/internal/anyconnect"
	"github.com/krazzer00/anyroute/internal/core"
	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/netx"
	"github.com/krazzer00/anyroute/internal/profiles"
	"github.com/krazzer00/anyroute/internal/secrets"
)

var version = "dev"

func main() {
	host := flag.String("host", "", "адрес VPN-шлюза")
	group := flag.String("group", "", "алиас группы (пусто — по умолчанию)")
	user := flag.String("user", "", "логин")
	pass := flag.String("pass", "", "пароль (лучше не указывать — спросит)")
	otp := flag.String("otp", "", "код 2FA")
	totp := flag.String("totp-secret", "", "TOTP-секрет base32 для автокода")
	groups := flag.Bool("groups", false, "показать группы сервера и выйти")
	insecure := flag.Bool("insecure", false, "не проверять сертификат шлюза")
	profile := flag.String("profile", "", "файл профиля маршрутизации (JSON из %APPDATA%\\AnyRoute\\profiles)")
	hold := flag.Duration("hold", 0, "держать подключение (0 — до Ctrl+C)")
	debug := flag.Bool("debug", false, "журнал XML-обмена (секреты маскируются)")
	flag.Parse()

	if *host == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *groups {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		list, def, err := anyconnect.FetchGroups(ctx, anyconnect.Config{Host: *host, InsecureSkipVerify: *insecure, Dial: netx.BoundDialer()})
		if err != nil {
			fail(err)
		}
		for _, g := range list {
			mark := ""
			if g == def {
				mark = "  (по умолчанию)"
			}
			fmt.Printf("%s%s\n", g, mark)
		}
		return
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		s, _ := in.ReadString('\n')
		return strings.TrimSpace(s)
	}
	if *user == "" {
		*user = ask("Логин: ")
	}
	if *pass == "" {
		*pass = ask("Пароль: ")
	}
	rp := profiles.DefaultRouting()
	if *profile != "" {
		data, err := os.ReadFile(*profile)
		if err != nil {
			fail(err)
		}
		if err := jsonUnmarshal(data, &rp); err != nil {
			fail(err)
		}
	}

	log := logx.New(2000, os.Stdout)
	if *debug {
		log.SetLevel(logx.Debug)
	}
	c := core.New(log, core.WindowsPlatform{}, version)
	c.SetDebugXML(*debug)
	if err := c.Connect(core.ConnectRequest{ServerName: *host, Host: *host, Group: *group, Username: *user,
		Password: *pass, InsecureTLS: *insecure, Profile: rp}); err != nil {
		fail(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	lastSeq := 0
	var connectedAt time.Time
	for {
		select {
		case <-sig:
			fmt.Println("отключение…")
			c.Disconnect()
			c.Wait(30 * time.Second)
			return
		case <-time.After(200 * time.Millisecond):
		}
		st := c.Status()
		switch st.State {
		case core.State2FA:
			if st.Challenge != nil && st.Challenge.Seq != lastSeq {
				lastSeq = st.Challenge.Seq
				code := *otp
				*otp = ""
				if code == "" && *totp != "" && !st.Challenge.Retry {
					code, _ = secrets.TOTP(*totp, time.Now())
				}
				if code == "" {
					code = ask(st.Challenge.Message + ": ")
				}
				if err := c.Submit2FA(code); err != nil {
					fmt.Println(err)
				}
			}
		case core.StateConnected:
			if connectedAt.IsZero() {
				connectedAt = time.Now()
				fmt.Printf("\nПОДКЛЮЧЕНО: адрес %s, шлюз %s, DNS %v\nсети сервера: %v\nзоны: %v\nTUN: %s\n\n",
					st.Address, st.Gateway, st.DNS, st.SplitInclude, st.SplitDNS, st.TunPrefix)
			}
			if *hold > 0 && time.Since(connectedAt) > *hold {
				c.Disconnect()
				c.Wait(30 * time.Second)
				return
			}
		case core.StateIdle:
			if st.Error != "" {
				fail(fmt.Errorf("%s", st.Error))
			}
			if !connectedAt.IsZero() {
				return
			}
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ошибка:", err)
	os.Exit(1)
}
