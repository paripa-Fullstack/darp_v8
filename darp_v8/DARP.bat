@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

:: Запуск через VBS — без CMD-окна
if exist "%~dp0DARP.vbs" (
    cscript //nologo "%~dp0DARP.vbs"
    exit /b
)

:: Fallback: прямой запуск
where pythonw >nul 2>&1
if %errorlevel% equ 0 (
    start "" pythonw "%~dp0run.py"
    exit /b
)
where python >nul 2>&1
if %errorlevel% equ 0 (
    python "%~dp0run.py"
    exit /b
)
echo Python не найден. Установите Python 3.10+ с https://python.org
pause
