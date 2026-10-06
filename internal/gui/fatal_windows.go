package gui

import (
	"golang.org/x/sys/windows"
)

// Fatal показывает ошибку запуска в окне сообщения (у GUI-сборки нет консоли).
func Fatal(err error) {
	title, _ := windows.UTF16PtrFromString("AnyRoute")
	text, _ := windows.UTF16PtrFromString("Не удалось запустить AnyRoute:\n\n" + err.Error())
	windows.MessageBox(0, text, title, windows.MB_ICONERROR|windows.MB_OK)
}
