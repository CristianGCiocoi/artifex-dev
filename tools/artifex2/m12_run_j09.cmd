@echo off
"C:\Program Files\Python312\python.exe" "C:\ARTIFEX-M12-Media\qualify_m9_black_box.py" --artifex-executable "C:\Program Files\ARTIFEX\artifex.exe" --candidate-artifact "C:\ARTIFEX-M12-Media\ARTIFEX-Setup.exe" --expected-artifact-sha256 0a094ab12420f0fe18092dd834801f4b2463ba39837e4ae0b2d0e2881ae81778 --expected-source-commit 5b5750fcee0eddc74a223334be07224c6ff4b930 --v1-repository "C:\ARTIFEX-M9-Qualification\v1-project" --qualification-root "C:\ARTIFEX-M12-J09-Qualification-V2" --output "C:\ARTIFEX-M12-J09-PASS.json" > "C:\ARTIFEX-M12-J09.log" 2>&1
set "ARTIFEX_M12_J09_EXIT=%ERRORLEVEL%"
echo %ARTIFEX_M12_J09_EXIT%>"C:\ARTIFEX-M12-J09.exit.txt"
exit /b %ARTIFEX_M12_J09_EXIT%
