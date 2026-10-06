# CLAUDE.md

Подсказки для работы с репозиторием. Комментарии и сообщения в коде — на русском.

## Команды

```bash
go test -tags with_gvisor ./...                 # все тесты (мок ASA, без прав админа)
go vet -tags "with_gvisor,desktop,production" ./...
powershell -ExecutionPolicy Bypass -File build/build.ps1 -Version 0.1.0   # dist/: 3 exe + установщик (если есть NSIS)
```

- Тег `with_gvisor` обязателен для службы и cli: TUN sing-box работает со `stack: mixed`.
- Интерфейс собирается тегами `desktop,production` с `-H=windowsgui`; Wails CLI не нужен.
- Тесты `internal/netx`, `internal/nrpt`, `internal/secrets` читают систему (интерфейсы, реестр, Credential Manager) и не требуют прав.
- Настоящий TUN в тестах не поднимается (`Platform.NoTun()`): sing-box стартует без инбаунда, outbound «vpn» проверяется напрямую.

## Архитектура

`cmd/anyroute` (GUI, Wails v2) ⇄ `\\.\pipe\anyroute` (`internal/ipc`) ⇄ `cmd/anyroute-service` (LocalSystem) → `internal/core` → `internal/anyconnect` (протокол) + `internal/vpnstack` (gVisor) + `internal/engine` (sing-box).

- `internal/api` — типы протокола; GUI импортирует только его, чтобы не тянуть sing-box (GUI ~13 МБ).
- `internal/core` — одно подключение. Все методы возвращаются сразу; статус — атомарный снимок. Номер поколения `gen` защищает от «опоздавшего» `run()` после сторожа отключения.
- `internal/engine` — минимальный набор типов sing-box (tun, direct, block, udp/tcp/local DNS) плюс свои: outbound `anyconnect` и DNS-транспорт `anyroute-vpn`; сессия передаётся через `service.ContextWith[*Session]`.
- `internal/rules` — разбор правил и план: `route_address`, `route_exclude_address`, NRPT, DNS-правила. ⚠️ В sing-box внутри одного правила группы полей (адрес/порт/процесс) объединяются по «И», поэтому `engine.matchRules` выдаёт отдельное правило на группу.

## Совместная работа с Throne — ключевое ограничение

У пользователя постоянно включён Throne (`throne-tun`, 172.19.0.0/24, широкие маршруты /3…/8, без strict_route). Поэтому:

- AnyRoute **никогда** не захватывает весь трафик сам: `route_address` содержит только сети сервера, CIDR из правил, DNS шлюза и `/32` для доменов из правил (`netx.HostRoutes`, по ответам DNS). Узкие маршруты выигрывают по longest prefix match.
- `strict_route: false`, `dns_mode: disabled` — нельзя трогать DNS системы целиком; DNS приходит только через NRPT.
- Соединения к шлюзу и outbound `direct` привязаны к физическому интерфейсу (`IP_UNICAST_IF`, `netx.BindControl`).
- Подсеть TUN выбирается из `netx.TunCandidates` без пересечения с локальными сетями (172.19.0.0/24 занята Throne).

## Протокол Cisco ASA (выверено на живых серверах в DualVPN)

- `<device-id>` с телом (`win`); User-Agent `AnyConnect Windows 4.10.07062` для всех запросов, включая CONNECT.
- Ответ на challenge: код в `<password>` (поле формы `answer`), без `<group-select>`, `<username>` — только если есть в форме, `<opaque>` дословно (auth-handle).
- Значения в XML экранируются (`esc`): пароль с `<`/`&` ломал запрос.
- CSTP-фреймы читаются по длине из заголовка (не «одна TLS-запись = фрейм»); при закрытии шлюзу шлётся DISCONNECT.
- Мок `internal/mockasa` с `ASAChallenge: true` воспроизводит требования живой ASA.

## Надёжность

- NRPT: одно правило с комментарием `AnyRoute`; остатки (`AnyRoute*`, `DualVPN:*`) ищутся по реестру и снимаются при старте службы и перед подключением (`internal/cleanup`).
- Внешние утилиты — только через `internal/execx` (таймаут + `WaitDelay` + `CREATE_NO_WINDOW`).
- Трей: каждый пункт меню — в своей горутине; вызовы службы из GUI — с таймаутом 5 с.

## Обновления и релиз

- Тег `vX.Y.Z` → `.github/workflows/release.yml`: тесты, сборка, NSIS, `cmd/anyroute-sign` (секрет `UPDATE_SIGNING_KEY`, base64 seed ed25519) → `latest.json`, GitHub Release.
- Подпись над строкой `anyroute|<version>|<sha256>`; открытый ключ — `internal/update/pubkey.go`. Загрузка только из `github.com/krazzer00/anyroute/releases/download/`.
- Служба скачивает, проверяет, кладёт установщик в `%ProgramData%\AnyRoute\updates` (ACL: только SYSTEM/админы), запускает `/S /UPDATE`; после рестарта новая служба запускает GUI в сеансе пользователя (`RelaunchAfterUpdate`).
- `installer.nsi` — UTF-8 **с BOM** (иначе кириллица искажается), CRLF.

## Секреты

- Никаких реальных адресов серверов, логинов и внутренних зон в репозитории — только `vpn.example.com`, `corp.example`.
- Пароли и TOTP-секреты — только в Windows Credential Manager (`AnyRoute/<id>/password|totp`), служба их не хранит.
- Журнал маскирует секреты (`logx.Mask`) на всех уровнях.
- gitleaks: CI (`.github/workflows/gitleaks.yml`) и pre-commit хук (`build/hooks/pre-commit`).

## Подводный камень инструментов

Bash-инструмент агента схлопывает `\\` в heredoc: Python-скрипты с обратными слэшами в heredoc портят файлы. Для правок с `\` используйте редактор или `chr(92)`.
