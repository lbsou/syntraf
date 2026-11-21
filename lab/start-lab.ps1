# Démarre le lab de robustesse SYNTRAF (cible du raccourci « SYNTRAF Lab »).
# Lance Docker Desktop au besoin, attend le moteur, démarre le lab, affiche l'état.
param(
    [int]$TimeoutSec = 180,
    [switch]$WaitOnly   # n'attend que le moteur Docker (sert à tester l'attente)
)

$ErrorActionPreference = 'Stop'

function Test-DockerWait {
    param([int]$TimeoutSec = 180)
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { return $true }

    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path $exe) {
        Write-Host 'Docker Desktop ne répond pas : démarrage…'
        Start-Process -FilePath $exe | Out-Null
    } else {
        Write-Host "Docker Desktop introuvable ($exe)."
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { return $true }
        Write-Host '  … moteur Docker pas encore prêt'
    }
    return $false
}

if (-not (Test-DockerWait -TimeoutSec $TimeoutSec)) {
    $minutes = [math]::Round($TimeoutSec / 60, 1)
    Write-Host "Docker Desktop n'a pas démarré en $minutes minute(s). Lance-le à la main puis réessaie." -ForegroundColor Red
    exit 1
}
if ($WaitOnly) { Write-Host 'Moteur Docker prêt.'; exit 0 }

$labctl = Join-Path $PSScriptRoot 'labctl.py'
python $labctl up
$code = $LASTEXITCODE
python $labctl status
Write-Host ''
Write-Host 'Grafana  : http://127.0.0.1:18300  (tableau de bord SYNTRAF)'
Write-Host 'Webui    : http://127.0.0.1:18080'
Write-Host "Commandes : python `"$labctl`" --help"
exit $code
