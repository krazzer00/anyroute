// AnyRoute — клиент Cisco AnyConnect с маршрутизацией по правилам.
// Интерфейс работает с правами пользователя; туннель держит служба
// anyroute-service.
package main

import (
	"os"

	"github.com/krazzer00/anyroute/internal/gui"
)

var version = "dev"

func main() {
	hidden := false
	for _, a := range os.Args[1:] {
		if a == "--tray" {
			hidden = true
		}
	}
	if err := gui.Run(version, hidden); err != nil {
		gui.Fatal(err)
	}
}
