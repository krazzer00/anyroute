; AnyRoute — установщик (NSIS 3, Unicode).
; Сборка: makensis /DVERSION=1.2.3 /DSRC=<корень репозитория> build\windows\installer.nsi
; Тихое обновление из службы: AnyRoute-Setup.exe /S /UPDATE
;
; Файл должен быть в UTF-8 с BOM — иначе makensis прочтёт кириллицу как ANSI.

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SRC
  !define SRC "..\.."
!endif

!define APP "AnyRoute"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AnyRoute"

Name "${APP} ${VERSION}"
OutFile "${SRC}\dist\AnyRoute-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\AnyRoute"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
BrandingText "AnyRoute ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "AnyRoute"
VIAddVersionKey "FileDescription" "Установщик AnyRoute"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "GPL-3.0"

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!define MUI_ICON "${SRC}\build\windows\icon.ico"
!define MUI_UNICON "${SRC}\build\windows\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Запустить AnyRoute"
!define MUI_FINISHPAGE_RUN_FUNCTION RunAsUser

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SRC}\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

Var IsUpdate

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "AnyRoute работает только в 64-разрядной Windows."
    Abort
  ${EndIf}
  SetRegView 64
  StrCpy $IsUpdate "0"
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/UPDATE" $1
  ${IfNot} ${Errors}
    StrCpy $IsUpdate "1"
  ${EndIf}
FunctionEnd

; Запуск интерфейса от имени пользователя (не от администратора):
; explorer.exe открывает программу с обычными правами.
Function RunAsUser
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\AnyRoute.exe"'
FunctionEnd

!macro StopAll
  ; Остановка и снятие службы: она отключает VPN и снимает свои правила DNS.
  IfFileExists "$INSTDIR\anyroute-service.exe" 0 +3
    nsExec::ExecToLog '"$INSTDIR\anyroute-service.exe" uninstall'
    Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /F /IM AnyRoute.exe'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /F /IM anyroute-service.exe'
  Pop $0
  Sleep 800
!macroend

Section "AnyRoute" SecMain
  SectionIn RO
  SetShellVarContext all
  !insertmacro StopAll

  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "${SRC}\dist\AnyRoute.exe"
  File "${SRC}\dist\anyroute-service.exe"
  File "${SRC}\dist\anyroute-cli.exe"
  File "${SRC}\LICENSE"
  File "${SRC}\NOTICE"

  ; Регистрация и запуск службы (переустанавливает, если уже есть).
  nsExec::ExecToLog '"$INSTDIR\anyroute-service.exe" install'
  Pop $0
  ${If} $0 != 0
    ${If} $IsUpdate == "0"
      MessageBox MB_ICONEXCLAMATION "Не удалось зарегистрировать службу AnyRoute (код $0). Подробности — в журнале установки."
    ${EndIf}
  ${EndIf}

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ${If} $IsUpdate == "0"
    CreateDirectory "$SMPROGRAMS\AnyRoute"
    CreateShortcut "$SMPROGRAMS\AnyRoute\AnyRoute.lnk" "$INSTDIR\AnyRoute.exe"
    CreateShortcut "$SMPROGRAMS\AnyRoute\Удалить AnyRoute.lnk" "$INSTDIR\Uninstall.exe"
    CreateShortcut "$DESKTOP\AnyRoute.lnk" "$INSTDIR\AnyRoute.exe"
  ${EndIf}

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "AnyRoute"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "krazzer00"
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "https://github.com/krazzer00/anyroute"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\AnyRoute.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  !insertmacro StopAll
  nsExec::ExecToLog '"$INSTDIR\anyroute-service.exe" uninstall'
  Pop $0
  ; Подстраховка: правила DNS AnyRoute не должны пережить удаление.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -Command "Get-DnsClientNrptRule | Where-Object { $$_.Comment -like ''AnyRoute*'' } | ForEach-Object { Remove-DnsClientNrptRule -Name $$_.Name -Force }"'
  Pop $0
  Delete "$INSTDIR\AnyRoute.exe"
  Delete "$INSTDIR\anyroute-service.exe"
  Delete "$INSTDIR\anyroute-cli.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\AnyRoute\AnyRoute.lnk"
  Delete "$SMPROGRAMS\AnyRoute\Удалить AnyRoute.lnk"
  RMDir "$SMPROGRAMS\AnyRoute"
  Delete "$DESKTOP\AnyRoute.lnk"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "AnyRoute"
  RMDir /r "$COMMONAPPDATA\AnyRoute\updates"
SectionEnd
