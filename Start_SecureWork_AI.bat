
@echo off
cd /d "C:\Users\sriha\Desktop\SecureWork AI"

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Project Python environment was not found.
    echo Please check the .venv folder.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m app.main

if errorlevel 1 (
    echo.
    echo SecureWork AI closed with an error.
    pause
)
