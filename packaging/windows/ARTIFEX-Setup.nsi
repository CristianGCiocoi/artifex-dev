Unicode true
RequestExecutionLevel admin
SetCompressor /SOLID lzma
CRCCheck force

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef ARTIFEX_BUNDLE
  !error "ARTIFEX_BUNDLE is required"
!endif
!ifndef ARTIFEX_OUTPUT
  !error "ARTIFEX_OUTPUT is required"
!endif

Name "ARTIFEX"
Caption "ARTIFEX Setup"
OutFile "${ARTIFEX_OUTPUT}"
InstallDir "$PROGRAMFILES64\ARTIFEX"
InstallDirRegKey HKLM "Software\ARTIFEX" "InstallDir"
BrandingText "ARTIFEX"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "1.0.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "ARTIFEX"
VIAddVersionKey /LANG=1033 "FileDescription" "ARTIFEX Setup"
VIAddVersionKey /LANG=1033 "CompanyName" "ARTIFEX Contributors"
VIAddVersionKey /LANG=1033 "FileVersion" "1.0.0"
VIAddVersionKey /LANG=1033 "ProductVersion" "1.0.0"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Apache-2.0"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "ARTIFEX" section_core
  SectionIn RO
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\artifex"
  File /r "${ARTIFEX_BUNDLE}\*"

  DetailPrint "Installing ARTIFEX and starting its managed service..."
  nsExec::ExecToStack '"$PLUGINSDIR\artifex\artifex.exe" _installer-lifecycle install --install-root "$INSTDIR" --source-executable "$PLUGINSDIR\artifex\artifex.exe" --service-state-root "$LOCALAPPDATA\ARTIFEX\runtime" --consent'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX could not be installed. No incomplete installation will be retained."
    SetErrorLevel $0
    Abort
  ${EndIf}

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\ARTIFEX" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayName" "ARTIFEX"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayVersion" "1.0.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "Publisher" "ARTIFEX Contributors"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "NoRepair" 1
SectionEnd

Section "Uninstall"
  DetailPrint "Stopping the ARTIFEX managed service and removing ARTIFEX..."
  nsExec::ExecToStack '"$INSTDIR\artifex.exe" _installer-lifecycle uninstall --install-root "$INSTDIR" --consent'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX could not be removed safely. The installation has been preserved."
    SetErrorLevel $0
    Abort
  ${EndIf}

  StrCpy $2 0
  wait_for_lifecycle:
    IfFileExists "$INSTDIR\artifex-install-manifest.json" 0 lifecycle_complete
    Sleep 500
    IntOp $2 $2 + 1
    IntCmp $2 120 lifecycle_timeout wait_for_lifecycle wait_for_lifecycle
  lifecycle_timeout:
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX removal did not complete within 60 seconds. The uninstaller has been preserved."
    SetErrorLevel 1
    Abort
  lifecycle_complete:
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX"
  DeleteRegKey HKLM "Software\ARTIFEX"
  Delete /REBOOTOK "$INSTDIR\Uninstall.exe"
  RMDir /REBOOTOK "$INSTDIR"
SectionEnd
