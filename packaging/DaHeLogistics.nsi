Unicode True
RequestExecutionLevel user
SetCompressor /SOLID lzma

!ifndef APP_VERSION
  !error "APP_VERSION is required"
!endif
!ifndef PAYLOAD_ROOT
  !error "PAYLOAD_ROOT is required"
!endif
!ifndef OUTPUT_ROOT
  !error "OUTPUT_ROOT is required"
!endif

Name "大禾物流自动化平台"
OutFile "${OUTPUT_ROOT}\DaHe-Logistics-Automation-Tool-${APP_VERSION}-Setup.exe"
InstallDir "$LOCALAPPDATA\Programs\DaHeLogisticsAutomationTool"
InstallDirRegKey HKCU "Software\DaHeLogisticsAutomationTool" "InstallLocation"
ShowInstDetails show
ShowUninstDetails show

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD_ROOT}\*"
  nsExec::ExecToLog /TIMEOUT=900000 '"$INSTDIR\DaHeUpdater.exe" bootstrap-cpu-runtime --archive "$INSTDIR\runtimes\ocr-cpu.zip" --manifest "$INSTDIR\runtimes\cpu-runtime-manifest.json" --target "$INSTDIR\runtimes\ocr-cpu"'
  Pop $0
  StrCmp $0 "0" cpu_runtime_ready
  Sleep 2000
  nsExec::ExecToLog /TIMEOUT=900000 '"$INSTDIR\DaHeUpdater.exe" bootstrap-cpu-runtime --archive "$INSTDIR\runtimes\ocr-cpu.zip" --manifest "$INSTDIR\runtimes\cpu-runtime-manifest.json" --target "$INSTDIR\runtimes\ocr-cpu"'
  Pop $0
  StrCmp $0 "0" cpu_runtime_ready
  Abort "CPU OCR 运行环境安装失败。用户数据未被删除。"
  cpu_runtime_ready:
  Delete "$INSTDIR\runtimes\ocr-cpu.zip"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\DaHeLogisticsAutomationTool" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "DisplayName" "大禾物流自动化平台"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool" "NoRepair" 1
  Delete "$DESKTOP\大禾物流.lnk"
  Delete "$DESKTOP\大禾物流自动化平台.lnk"
  CreateShortcut "$DESKTOP\大禾物流自动化平台.lnk" "$INSTDIR\DaHeLauncher.exe"
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\大禾物流自动化平台.lnk"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DaHeLogisticsAutomationTool"
  DeleteRegKey HKCU "Software\DaHeLogisticsAutomationTool"
  IfFileExists "$INSTDIR\runtimes\ocr-cpu\active-composition.json" 0 cpu_runtime_removed
  IfFileExists "$INSTDIR\DaHeUpdater.exe" 0 cpu_runtime_remove_failed
  nsExec::ExecToLog /TIMEOUT=900000 '"$INSTDIR\DaHeUpdater.exe" remove-cpu-runtime'
  Pop $0
  StrCmp $0 "0" cpu_runtime_removed
  cpu_runtime_remove_failed:
  Abort "CPU OCR 运行环境未能完整删除。用户数据未被删除。"
  cpu_runtime_removed:
  RMDir /r "$INSTDIR"
  ; User data under $LOCALAPPDATA\DaHeLogisticsAutomationTool is intentionally retained.
SectionEnd
