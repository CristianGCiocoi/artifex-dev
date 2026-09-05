Unicode true
RequestExecutionLevel admin
SetCompressor zlib
CRCCheck force

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!ifndef ARTIFEX_BUNDLE
  !error "ARTIFEX_BUNDLE is required"
!endif
!ifndef ARTIFEX_OUTPUT
  !error "ARTIFEX_OUTPUT is required"
!endif
!ifndef ARTIFEX_ICON
  !error "ARTIFEX_ICON is required"
!endif
!ifndef ARTIFEX_VERSION
  !define ARTIFEX_VERSION "2.0.2"
!endif

!define ARTIFEX_START_MENU "$SMPROGRAMS\ARTIFEX"
!define MUI_ICON "${ARTIFEX_ICON}"
!define MUI_UNICON "${ARTIFEX_ICON}"

Name "ARTIFEX"
Caption "ARTIFEX Setup"
OutFile "${ARTIFEX_OUTPUT}"
InstallDir "$PROGRAMFILES64\ARTIFEX"
InstallDirRegKey HKLM "Software\ARTIFEX" "InstallDir"
BrandingText "ARTIFEX"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${ARTIFEX_VERSION}.0"
VIAddVersionKey /LANG=1033 "ProductName" "ARTIFEX"
VIAddVersionKey /LANG=1033 "FileDescription" "ARTIFEX Setup"
VIAddVersionKey /LANG=1033 "CompanyName" "ARTIFEX Contributors"
VIAddVersionKey /LANG=1033 "FileVersion" "${ARTIFEX_VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${ARTIFEX_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Apache-2.0"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_RUN "$INSTDIR\artifex.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "dashboard"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ARTIFEX"
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
  nsExec::ExecToStack '"$PLUGINSDIR\artifex\artifex.exe" _installer-lifecycle install --install-root "$INSTDIR" --source-executable "$PLUGINSDIR\artifex\artifex.exe" --service-state-root "$LOCALAPPDATA\ARTIFEX\state" --consent'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX could not become ready. Installer-owned incomplete files were rolled back and diagnostics were preserved under the ARTIFEX state folder." /SD IDOK
    SetErrorLevel $0
    Abort
  ${EndIf}

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "${ARTIFEX_START_MENU}"
  CreateShortcut "${ARTIFEX_START_MENU}\ARTIFEX.lnk" "$INSTDIR\artifex.exe" "dashboard" "$INSTDIR\artifex.exe" 0 SW_SHOWNORMAL
  CreateShortcut "${ARTIFEX_START_MENU}\Uninstall ARTIFEX.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\ARTIFEX" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\ARTIFEX" "StateRoot" "$LOCALAPPDATA\ARTIFEX\state"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayName" "ARTIFEX"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayVersion" "${ARTIFEX_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "Publisher" "ARTIFEX Contributors"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayIcon" '"$INSTDIR\artifex.exe",0'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ${GetParent} "$INSTDIR" $5
  IfFileExists "$INSTDIR\.artifex-uninstall-cleanup.active" resume_lifecycle start_lifecycle

  start_lifecycle:
  DetailPrint "Stopping the ARTIFEX managed service and removing ARTIFEX..."
  nsExec::ExecToStack '"$INSTDIR\artifex.exe" _installer-lifecycle uninstall --install-root "$INSTDIR" --consent'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX removal did not complete safely. Diagnostics and any remaining installer resources have been preserved." /SD IDOK
    SetErrorLevel $0
    Abort
  ${EndIf}

  resume_lifecycle:
  ClearErrors
  FileOpen $4 "$INSTDIR\.artifex-uninstall-cleanup.active" r
  IfErrors lifecycle_claim_invalid 0
  FileRead $4 $3
  FileClose $4
  StrLen $4 $3
  IntCmp $4 32 lifecycle_claim_ready lifecycle_claim_invalid lifecycle_claim_invalid

  lifecycle_claim_ready:
  StrCpy $2 0
  wait_for_lifecycle:
    IfFileExists "$INSTDIR\.artifex-uninstall-cleanup-$3.failure.json" lifecycle_failure 0
    IfFileExists "$INSTDIR\.artifex-uninstall-cleanup-$3.complete.json" lifecycle_verify_helper lifecycle_wait
  lifecycle_verify_helper:
    IfFileExists "$5\.artifex-lifecycle-*-$3" lifecycle_wait 0
    IfFileExists "$5\.artifex-lifecycle-*-$3.request.json" lifecycle_wait 0
    IfFileExists "$5\.artifex-lifecycle-*-$3.cleanup.ps1" lifecycle_wait lifecycle_complete
  lifecycle_wait:
    Sleep 500
    IntOp $2 $2 + 1
    IntCmp $2 120 lifecycle_timeout wait_for_lifecycle wait_for_lifecycle
  lifecycle_timeout:
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX removal and authenticated helper cleanup did not complete within 60 seconds. The uninstaller and diagnostics have been preserved." /SD IDOK
    SetErrorLevel 1
    Abort
  lifecycle_claim_invalid:
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX found an invalid or incomplete uninstall cleanup claim. No unverified cleanup was performed; diagnostics have been preserved." /SD IDOK
    SetErrorLevel 1
    Abort
  lifecycle_failure:
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX runtime removal completed, but authenticated helper cleanup failed. The uninstaller and diagnostics have been preserved." /SD IDOK
    SetErrorLevel 1
    Abort
  lifecycle_complete:
  DetailPrint "ARTIFEX runtime and project data were retained under $LOCALAPPDATA\ARTIFEX\state."
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX"
  DeleteRegKey HKLM "Software\ARTIFEX"
  Delete "${ARTIFEX_START_MENU}\ARTIFEX.lnk"
  Delete "${ARTIFEX_START_MENU}\Uninstall ARTIFEX.lnk"
  RMDir "${ARTIFEX_START_MENU}"

  ClearErrors
  ReadRegStr $6 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARTIFEX" "DisplayName"
  IfErrors uninstall_product_key_absent lifecycle_metadata_cleanup_failed
  uninstall_product_key_absent:
  ClearErrors
  ReadRegStr $6 HKLM "Software\ARTIFEX" "InstallDir"
  IfErrors uninstall_install_key_absent lifecycle_metadata_cleanup_failed
  uninstall_install_key_absent:
  IfFileExists "${ARTIFEX_START_MENU}\ARTIFEX.lnk" lifecycle_metadata_cleanup_failed 0
  IfFileExists "${ARTIFEX_START_MENU}\Uninstall ARTIFEX.lnk" lifecycle_metadata_cleanup_failed 0
  IfFileExists "${ARTIFEX_START_MENU}" lifecycle_metadata_cleanup_failed 0

  Delete "$INSTDIR\Uninstall.exe"
  IfFileExists "$INSTDIR\Uninstall.exe" lifecycle_metadata_cleanup_failed 0
  Delete "$INSTDIR\.artifex-uninstall-cleanup-$3.complete.json"
  IfFileExists "$INSTDIR\.artifex-uninstall-cleanup-$3.complete.json" lifecycle_metadata_cleanup_failed 0
  Delete "$INSTDIR\.artifex-uninstall-cleanup.active"
  IfFileExists "$INSTDIR\.artifex-uninstall-cleanup.active" lifecycle_metadata_cleanup_failed 0
  RMDir "$INSTDIR"
  IfFileExists "$INSTDIR" lifecycle_metadata_cleanup_failed lifecycle_done

  lifecycle_metadata_cleanup_failed:
    MessageBox MB_ICONSTOP|MB_OK "ARTIFEX runtime removal succeeded, but final installer metadata could not be removed immediately. No reboot-delayed success was reported; diagnostics have been preserved." /SD IDOK
    SetErrorLevel 1
    Abort
  lifecycle_done:
SectionEnd
