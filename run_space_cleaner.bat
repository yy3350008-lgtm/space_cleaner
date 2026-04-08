@echo off
setlocal
cd /d "%~dp0"

set PYEXE=C:/Users/25082/AppData/Local/Programs/Python/Python313/python.exe
if not exist "%PYEXE%" (
  echo [ERROR] 未找到 Python 解释器: %PYEXE%
  echo 请修改 run_space_cleaner.bat 中的 PYEXE 路径。
  exit /b 1
)

"%PYEXE%" main.py
exit /b %errorlevel%
