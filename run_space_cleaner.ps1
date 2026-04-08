$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$pythonExe = "C:/Users/25082/AppData/Local/Programs/Python/Python313/python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "未找到 Python 解释器: $pythonExe" -ForegroundColor Red
    Write-Host "请修改 run_space_cleaner.ps1 中的 pythonExe 路径。" -ForegroundColor Yellow
    exit 1
}

& $pythonExe main.py
exit $LASTEXITCODE
