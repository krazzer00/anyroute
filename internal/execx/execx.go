// Package execx — запуск внешних утилит (PowerShell, sc) с общими
// гарантиями: жёсткий таймаут, WaitDelay (иначе Wait висит, пока дочерние
// процессы держат pipe открытым — одна из причин зависаний DualVPN) и
// CREATE_NO_WINDOW, чтобы не мигали окна консоли.
package execx

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Run выполняет команду и возвращает объединённый вывод.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	hide(cmd)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return text, fmt.Errorf("%s: превышено время ожидания %s", name, timeout)
	}
	if err != nil {
		return text, fmt.Errorf("%s: %w: %s", name, err, text)
	}
	return text, nil
}

// PowerShell выполняет скрипт PowerShell без профиля.
func PowerShell(ctx context.Context, timeout time.Duration, script string) (string, error) {
	return Run(ctx, timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// PSQuote экранирует строку для одинарных кавычек PowerShell.
func PSQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
