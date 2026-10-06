// Package cleanup убирает остатки аварийного завершения: правила NRPT
// AnyRoute и DualVPN. Вызывается при старте службы и перед каждым
// подключением — пользователю больше не нужно снимать их вручную через
// PowerShell.
package cleanup

import (
	"context"
	"strings"

	"github.com/krazzer00/anyroute/internal/logx"
	"github.com/krazzer00/anyroute/internal/netx"
	"github.com/krazzer00/anyroute/internal/nrpt"
)

// Run проверяет и убирает остатки. Быстрый путь (ничего не осталось) не
// запускает PowerShell: проверка идёт по реестру.
func Run(ctx context.Context, log *logx.Src, tunActive bool) {
	left, err := nrpt.Leftovers(nrpt.LegacyPrefixes...)
	if err != nil {
		log.Warnf("не удалось проверить правила DNS (NRPT): %v", err)
	}
	if len(left) > 0 {
		var ns []string
		for _, e := range left {
			ns = append(ns, strings.Join(e.Namespaces, ","))
		}
		log.Warnf("найдены оставшиеся после сбоя правила DNS (%d): %s — удаляю", len(left), strings.Join(ns, "; "))
		if err := nrpt.Remove(ctx, nrpt.LegacyPrefixes...); err != nil {
			log.Errorf("%v", err)
		} else {
			log.OKf("оставшиеся правила DNS удалены")
		}
	}
	if !tunActive && netx.TunExists() {
		log.Warnf("в системе остался адаптер %s от прошлого запуска — он будет переиспользован", netx.TunName)
	}
}
