# Day 1 + Day 2 planning + the "what changed?" tamper scenario (Windows PowerShell).
# Run:  powershell -ExecutionPolicy Bypass -File .\run_demo.ps1
# Brain selection (optional):  $env:ANTHROPIC_API_KEY="sk-ant-..."   or   $env:GUARDIAN_LLM="ollama"
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
# $env:PYTHONUTF8 = "1"

$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $vpy)) { $vpy = "python" }

function G { & $vpy -m guardian.cli @args; if ($LASTEXITCODE -ne 0) { throw "guardian $args failed" } }

if (-not $env:ANTHROPIC_API_KEY -and $env:GUARDIAN_LLM -ne "ollama") {
  Write-Host "(no ANTHROPIC_API_KEY and GUARDIAN_LLM != ollama -> agents run in offline deterministic mode)"
}
G day1 --target targets\juice-shop --investigate 8
G plan --top 6
G plan --ids F-018
G report
G verify-ledger
& $vpy scenarios\tamper_lockfile.py targets\juice-shop targets\juice-shop-tampered
G --out out-tampered day1 --target targets\juice-shop-tampered --base-lock targets\juice-shop.base-package-lock.json --investigate 3

Write-Host ""
Write-Host "Reports: out\report.html  out-tampered\report.html   (open with: start out\report.html)"
Write-Host "Now approve + validate (you are the human in the loop):"
Write-Host "  .\.venv\Scripts\python.exe -m guardian.cli approve F-018 --by <your-name>"
Write-Host "  .\.venv\Scripts\python.exe -m guardian.cli validate F-018"
Write-Host ""
Write-Host "Or do it all in the web console:  .\.venv\Scripts\python.exe -m guardian.cli dashboard"
