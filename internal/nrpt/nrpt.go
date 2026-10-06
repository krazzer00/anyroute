// Package nrpt — правила NRPT (Name Resolution Policy Table) Windows:
// направляют запросы к выбранным зонам на DNS AnyRoute.
//
// Правила AnyRoute помечаются комментарием Comment. Снятие и поиск остатков
// работают по префиксам комментария, в том числе для правил DualVPN
// ("DualVPN:*"), которые оставались в системе после аварийного завершения.
package nrpt

// Comment — метка правил AnyRoute.
const Comment = "AnyRoute"

// LegacyPrefixes — метки правил, которые нужно снимать как мусор.
var LegacyPrefixes = []string{"AnyRoute", "DualVPN:"}

// Entry — правило NRPT из реестра.
type Entry struct {
	Key        string
	Namespaces []string
	Servers    string
	Comment    string
}
