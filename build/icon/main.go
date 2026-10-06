// Генерация иконок: go run ./build/icon
package main

import (
	"os"

	"github.com/krazzer00/anyroute/internal/icon"
)

func main() {
	must(os.WriteFile("build/appicon.png", icon.PNG(icon.Render(512, icon.Cyan, true)), 0o644))
	must(os.WriteFile("build/windows/icon.ico", icon.App(), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
