@echo off
setlocal
chcp 65001 >nul
set "SCRIPT_DIR=%~dp0"
set "LOG=%SCRIPT_DIR%updater_menu_last_run.log"

echo [%date% %time%] Lanzando PowerShell >"%LOG%"
:: Mantén la ventana abierta si PowerShell devuelve error
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%updater_menu.ps1" 1>>"%LOG%" 2>&1
if errorlevel 1 (
  echo.
  echo Hubo un error. Revisa "%LOG%"
  echo (Dejo la ventana pausada para que puedas leer)
  exit
)
endlocal
