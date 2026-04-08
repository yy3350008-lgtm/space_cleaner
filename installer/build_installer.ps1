$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$issFile = Join-Path $scriptDir "SpaceCleaner.iss"
if (-not (Test-Path $issFile)) {
    Write-Host "未找到安装脚本: $issFile" -ForegroundColor Red
    exit 1
}

$iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
$isccPath = $null

if ($iscc) {
    $isccPath = $iscc.Source
}

if (-not $isccPath) {
    $candidates = @(
        "$env:LOCALAPPDATA\\Programs\\Inno Setup 6\\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            $isccPath = $p
            break
        }
    }
}

if (-not $isccPath) {
    Write-Host "未检测到 Inno Setup 编译器 ISCC.exe。" -ForegroundColor Yellow
    Write-Host "请安装 Inno Setup 后重试此脚本。" -ForegroundColor Yellow
    Write-Host "下载: https://jrsoftware.org/isdl.php" -ForegroundColor Cyan
    exit 2
}

& $isccPath $issFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "安装包编译失败，退出码: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "安装包编译成功。输出目录: ..\\release\\installer" -ForegroundColor Green
