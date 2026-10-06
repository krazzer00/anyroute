package gui

import (
	"context"
	"embed"
	"io/fs"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend
var assets embed.FS

// Run запускает интерфейс. startHidden — запуск в трей (автозапуск).
func Run(version string, startHidden bool) error {
	app, err := NewApp(version, startHidden)
	if err != nil {
		return err
	}
	effects := app.store.Settings().Effects
	front, _ := fs.Sub(assets, "frontend")
	winOpts := &windows.Options{
		WebviewIsTransparent: true,
		WindowIsTranslucent:  effects,
		BackdropType:         windows.Acrylic,
		Theme:                windows.Dark,
		WindowClassName:      windowClass,
		DisablePinchZoom:     true,
		ResizeDebounceMS:     16,
	}
	if !effects {
		winOpts.WebviewIsTransparent = false
	}
	bg := &options.RGBA{R: 7, G: 11, B: 20, A: 0}
	if !effects {
		bg.A = 255
	}
	return wails.Run(&options.App{
		Title:            "AnyRoute",
		Width:            1120,
		Height:           760,
		MinWidth:         920,
		MinHeight:        660,
		Frameless:        true,
		StartHidden:      startHidden,
		BackgroundColour: bg,
		AssetServer:      &assetserver.Options{Assets: front},
		OnStartup:        app.startup,
		OnDomReady:       func(context.Context) { go applyWindowEffects(effects) },
		OnBeforeClose:    app.beforeClose,
		Bind:             []interface{}{app},
		Windows:          winOpts,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "anyroute-6b1f2c7e-gui",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				go app.ShowWindow()
			},
		},
	})
}
