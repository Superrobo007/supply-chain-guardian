# One-time setup for Windows 10/11 (PowerShell).
# Run:  powershell -ExecutionPolicy Bypass -File .\setup.ps1
# Needs: Python 3.10+ (python.org or `winget install Python.Python.3.12`),
#        Node.js 18+ (`winget install OpenJS.NodeJS.LTS`), Git (`winget install Git.Git`)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Host "Missing '$cmd'. Install: $hint"; exit 1 }
}
# Prefer a stable 3.10-3.14 via the py launcher (pre-releases break pip/wheels)
$py = $null; $pyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
  foreach ($v in "3.13","3.12","3.14","3.11","3.10") {
    & py "-$v" -c "import sys" 2>$null
    if ($LASTEXITCODE -eq 0) { $py = "py"; $pyArgs = @("-$v"); break }
  }
}
if (-not $py) { $py = "python" }
Need $py   "winget install Python.Python.3.12"
Need "npm" "winget install OpenJS.NodeJS.LTS   (then open a new terminal)"
Need "git" "winget install Git.Git"
& $py @pyArgs -c "import sys; v=sys.version_info; assert (3,10)<=v[:2]<=(3,14) and v.releaselevel=='final', 'Need stable Python 3.10-3.14: winget install Python.Python.3.12'"
if ($LASTEXITCODE -ne 0) { exit 1 }

if ((Test-Path .venv) -and -not (Test-Path .venv\Scripts\pip.exe)) { Remove-Item -Recurse -Force .venv }
& $py @pyArgs -m venv .venv
$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $vpy -m pip install -q --upgrade pip
& $vpy -m pip install -q -r requirements.txt

New-Item -ItemType Directory -Force -Path targets | Out-Null
if (-not (Test-Path "targets\juice-shop")) {
  git -c core.longpaths=true clone --depth 1 https://github.com/juice-shop/juice-shop.git targets\juice-shop
}
# Juice Shop doesn't commit lockfiles: resolve them WITHOUT running any install scripts
Push-Location targets\juice-shop
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
Pop-Location
Push-Location targets\juice-shop\frontend
npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps
Pop-Location

Write-Host ""
Write-Host "Setup done. Next:  .\.venv\Scripts\Activate.ps1 ; .\run_demo.ps1"
