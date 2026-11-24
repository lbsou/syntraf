<#
Installation hors ligne de SYNTRAF (serveur ou sonde) sous Windows. PowerShell en administrateur :

    .\install.ps1 -Server 10.0.0.5 -Token <jeton>      # sonde
    .\install.ps1                                      # serveur + VictoriaMetrics + Grafana, reliés

Réinstaller par-dessus une installation existante la met à jour : la configuration et les données sont gardées.
Chaque service est une tâche planifiée (« SYNTRAF <rôle> », et pour le serveur « SYNTRAF victoriametrics » et
« SYNTRAF grafana ») lancée au démarrage sous le compte SYSTEM et relancée si elle s'arrête.
#>
param(
    [string]$Server = "", [string]$Token = "", [string]$Uid = "",
    [int]$ServerPort = 6531, [int]$WebuiPort = 5000, [int]$GrafanaPort = 3000, [int]$RetentionMonths = 12,
    [string]$Prefix = "", [string]$DataDir = "", [switch]$NoService, [switch]$NoStack
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$role = (Get-Content "$here\payload\ROLE" -Raw).Trim()
$version = (Get-Content "$here\payload\VERSION" -Raw).Trim()
if (-not $Prefix) { $Prefix = Join-Path $env:ProgramFiles "SYNTRAF\$role" }
if (-not $DataDir) { $DataDir = Join-Path $env:ProgramData "SYNTRAF\$role" }
$conf = Join-Path $DataDir "config.toml"
$logDir = Join-Path $DataDir "log"
$dataSub = Join-Path $DataDir "data"
$task = "SYNTRAF $role"
$stack = ($role -eq "server") -and (Test-Path "$here\payload\stack\victoria-metrics.zip") -and -not $NoStack
$tasks = @($task)
if ($stack) { $tasks = @("SYNTRAF victoriametrics", "SYNTRAF grafana", $task) }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $NoService -and -not $admin) { throw "Lancer PowerShell en administrateur, ou utiliser -NoService." }
if ($Token -and ($Token.Length -lt 5 -or $Token.Length -gt 255)) { throw "Le jeton doit faire de 5 à 255 caractères." }
if ($role -eq "probe" -and -not (Test-Path $conf) -and (-not $Server -or -not $Token)) {
    throw "Première installation d'une sonde : -Server et -Token sont nécessaires."
}

Write-Host "SYNTRAF $role $version -> $Prefix"
if (-not $NoService) {
    foreach ($t in $tasks) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }
    }
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$Prefix\*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
New-Item -ItemType Directory -Force $Prefix, $DataDir, $logDir, $dataSub | Out-Null

# Python portable, puis les dépendances depuis les wheels du package (aucun accès réseau)
if (Test-Path "$Prefix\python") { Remove-Item -Recurse -Force "$Prefix\python" }
tar -xzf "$here\payload\python.tar.gz" -C "$Prefix"
if ($LASTEXITCODE) { throw "Extraction de Python impossible" }
$py = Join-Path $Prefix "python\python.exe"
& $py -m pip install --no-index --find-links "$here\payload\wheels" --disable-pip-version-check --quiet --no-warn-script-location -r "$here\payload\requirements.txt"
if ($LASTEXITCODE) { throw "Installation des dépendances impossible" }

# Code et iperf3v
if (Test-Path "$Prefix\app") { Remove-Item -Recurse -Force "$Prefix\app" }
Copy-Item -Recurse "$here\payload\app" "$Prefix\app"
New-Item -ItemType Directory -Force "$Prefix\bin" | Out-Null
Copy-Item "$here\payload\bin\*" "$Prefix\bin\" -Force
$iperf = Join-Path $Prefix "bin\iperf3v.exe"

function Write-Utf8($path, $text) { [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $false)) }
function New-Secret($n) {
    $b = New-Object byte[] $n
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [Convert]::ToBase64String($b).Replace("+", "-").Replace("/", "_").TrimEnd("=")
}

# VictoriaMetrics (écoute en local seulement) et Grafana, provisionné : source de données et tableaux de bord SYNTRAF
if ($stack) {
    foreach ($d in "victoriametrics", "grafana", "grafana-dashboards") {
        if (Test-Path "$Prefix\$d") { Remove-Item -Recurse -Force "$Prefix\$d" }
    }
    $vmDir = Join-Path $Prefix "victoriametrics"; $gfDir = Join-Path $Prefix "grafana"
    $gfData = Join-Path $dataSub "grafana"; $vmData = Join-Path $dataSub "victoriametrics"
    $prov = Join-Path $DataDir "grafana-provisioning"
    New-Item -ItemType Directory -Force $vmDir, $gfDir, $gfData, $vmData, "$logDir\grafana", `
        "$prov\datasources", "$prov\dashboards", "$prov\plugins", "$prov\alerting" | Out-Null
    tar -xf "$here\payload\stack\victoria-metrics.zip" -C $vmDir
    if ($LASTEXITCODE) { throw "Extraction de VictoriaMetrics impossible" }
    tar -xf "$here\payload\stack\grafana.zip" -C $gfDir --strip-components=1
    if ($LASTEXITCODE) { throw "Extraction de Grafana impossible" }
    Copy-Item -Recurse "$here\payload\grafana-dashboards" "$Prefix\grafana-dashboards"
    $fwd = { param($x) $x.Replace("\", "/") }
    Write-Utf8 (Join-Path $DataDir "victoriametrics-scrape.yml") @"
# Santé de SYNTRAF : /metrics du serveur toutes les 15 s (tableau « Santé de SYNTRAF »)
scrape_configs:
  - job_name: syntraf
    scrape_interval: 15s
    scheme: https
    tls_config:
      insecure_skip_verify: true
    static_configs:
      - targets: ["127.0.0.1:$WebuiPort"]
"@
    Write-Utf8 "$prov\datasources\syntraf.yml" @"
apiVersion: 1
datasources:
  - name: VictoriaMetrics
    uid: syntraf-vm
    type: prometheus
    access: proxy
    url: http://127.0.0.1:8428
    isDefault: true
    editable: false
    jsonData: {timeInterval: 1s, httpMethod: POST}
"@
    Write-Utf8 "$prov\dashboards\syntraf.yml" @"
apiVersion: 1
providers:
  - name: syntraf
    folder: SYNTRAF
    type: file
    disableDeletion: true
    allowUiUpdates: false
    options: {path: "$(& $fwd "$Prefix\grafana-dashboards")"}
"@
    $gfIni = Join-Path $DataDir "grafana.ini"
    $gfPassFile = Join-Path $DataDir "grafana-admin-password"
    if (-not (Test-Path $gfIni)) {  # mise à jour : la vôtre est gardée
        $gfPass = New-Secret 18
        Write-Utf8 $gfPassFile "$gfPass`n"
        Write-Utf8 $gfIni @"
# Grafana de SYNTRAF, sans accès à Internet. Mot de passe admin initial : $gfPassFile
[server]
http_port = $GrafanaPort
[paths]
data = $(& $fwd $gfData)
logs = $(& $fwd "$logDir\grafana")
plugins = $(& $fwd "$gfData\plugins")
provisioning = $(& $fwd $prov)
[security]
admin_user = admin
admin_password = $gfPass
[users]
allow_sign_up = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[news]
news_feed_enabled = false
[plugins]
preinstall_disabled = true
[dashboards]
default_home_dashboard_path = $(& $fwd "$Prefix\grafana-dashboards\syntraf.json")
"@
        foreach ($f in $gfIni, $gfPassFile) { icacls $f /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null }
    }
    $vmExe = Get-ChildItem $vmDir -Filter "victoria-metrics*.exe" | Select-Object -First 1
    Set-Content -Path (Join-Path $Prefix "run-victoriametrics.cmd") -Encoding ASCII -Value @"
@echo off
"$($vmExe.FullName)" -storageDataPath="$vmData" -retentionPeriod=$RetentionMonths -httpListenAddr=127.0.0.1:8428 -promscrape.config="$DataDir\victoriametrics-scrape.yml"
"@
    Set-Content -Path (Join-Path $Prefix "run-grafana.cmd") -Encoding ASCII -Value @"
@echo off
cd /d "$gfDir"
"$gfDir\bin\grafana.exe" server --homepath "$gfDir" --config "$gfIni"
"@
}

# Configuration : écrite seulement à la première installation
# Sonde déjà installée et -Server ou -Token donnés : réinscription (serveur réinstallé ou remplacé). L'adresse et le
# jeton sont remplacés ; la clé du serveur mémorisée et le jeton propre donné par l'ancien serveur sont oubliés.
if ($role -eq "probe" -and (Test-Path $conf) -and ($Server -or $Token)) {
    $text = [IO.File]::ReadAllText($conf)
    if ($Server) {
        $text = $text -replace '(?m)^SERVER = .*$', "SERVER = ""$Server""" -replace '(?m)^SERVER_PORT = .*$', "SERVER_PORT = ""$ServerPort"""
    }
    if ($Token) { $text = $text -replace '(?m)^TOKEN = .*$', "TOKEN = ""$Token""" }
    Write-Utf8 $conf $text
    foreach ($f in "syntraf_server_pin", "syntraf_client_token") { Remove-Item -Force (Join-Path $DataDir $f) -ErrorAction SilentlyContinue }
    Write-Host "Réinscription : nouveau serveur ou jeton enregistré ; la clé du serveur sera mémorisée à la prochaine connexion."
}

if (-not (Test-Path $conf)) {
    $iperfToml = $iperf.Replace("\", "/")
    if ($role -eq "probe") {
        if (-not $Uid) { $Uid = ($env:COMPUTERNAME -replace "[^A-Za-z0-9_-]", "_") }
        $text = @"
# Sonde SYNTRAF ($version). Ses flux viennent du serveur ; ici, seulement comment le joindre.
[CLIENT]
CLIENT_UID = "$Uid"
SERVER = "$Server"
SERVER_PORT = "$ServerPort"
TOKEN = "$Token"

[GLOBAL]
IPERF3_BINARY_PATH = "$iperfToml"
LOG_TO = "file"
LOG_LEVEL = "INFO"
"@
    } else {
        $labToken = New-Secret 24
        $today = Get-Date -Format "yyyy-MM-dd"
        $metricsLine = ""; $dbBlock = ""
        if ($stack) {
            $metricsLine = 'METRICS_ALLOW = "127.0.0.1"  # le VictoriaMetrics local lit /metrics'
            $dbBlock = @"
# VictoriaMetrics installé avec SYNTRAF
[[DATABASE]]
DB_UID = "VICTORIAMETRICS"
DB_ENGINE = "VictoriaMetrics"
DB_SERVER = "127.0.0.1"
DB_PORT = "8428"
DB_SERVER_USE_SSL = false
"@
        }
        $text = @"
# Serveur SYNTRAF ($version). Le reste se règle dans l'interface web (https://<ce serveur>:$WebuiPort).
[SERVER]
BIND_ADDRESS = "0.0.0.0"
SERVER_PORT = "$ServerPort"
WEBUI_PORT = "$WebuiPort"
WEBUI_TLS = true
$metricsLine

# Jeton d'enrôlement des sondes (install.ps1 -Token sur chaque sonde) ; gérable ensuite dans Server > Tokens
[SERVER.TOKEN]
$today = "$labToken"

$dbBlock

[GLOBAL]
IPERF3_BINARY_PATH = "$iperfToml"
LOG_TO = "file"
LOG_LEVEL = "INFO"
"@
    }
    Write-Utf8 $conf $text
    # Lisible des seuls administrateurs et de SYSTEM (contient un jeton)
    icacls $conf /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
}

# Lanceur : la tâche planifiée ne sait pas fixer de variable d'environnement
$launcher = Join-Path $Prefix "syntraf-service.cmd"
Set-Content -Path $launcher -Encoding ASCII -Value @"
@echo off
set SYNTRAF_BASE_DIR=$dataSub
cd /d "$dataSub"
"$py" "$Prefix\app\syntraf.py" -c "$conf" -l "$logDir"
"@

if (-not $NoService) {
    $launchers = @{ $task = $launcher }
    if ($stack) {
        $launchers["SYNTRAF victoriametrics"] = Join-Path $Prefix "run-victoriametrics.cmd"
        $launchers["SYNTRAF grafana"] = Join-Path $Prefix "run-grafana.cmd"
    }
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    foreach ($t in $tasks) {
        $action = New-ScheduledTaskAction -Execute $launchers[$t]
        Register-ScheduledTask -TaskName $t -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "SYNTRAF $role $version" -Force | Out-Null
        Start-ScheduledTask -TaskName $t
    }
}

Write-Host ""
Write-Host "SYNTRAF $role $version installé."
Write-Host "  code       : $Prefix"
Write-Host "  config     : $conf"
Write-Host "  données    : $dataSub"
Write-Host "  journaux   : $logDir"
Write-Host "  iperf3     : $iperf"
if ($NoService) { Write-Host "  démarrer   : $((Get-ChildItem $Prefix -Filter *.cmd | ForEach-Object FullName) -join ' ')" }
else { Write-Host "  services   : tâches planifiées $(($tasks | ForEach-Object { "« $_ »" }) -join ', ')" }
if ($role -eq "server") {
    Write-Host "  interface  : https://<ce serveur>:$WebuiPort (mot de passe admin initial : $conf.initial_admin_password)"
    if ($stack) { Write-Host "  grafana    : http://<ce serveur>:$GrafanaPort (admin ; mot de passe : $(Join-Path $DataDir 'grafana-admin-password'))" }
    $tok = (Select-String -Path $conf -Pattern '^\d{4}-\d{2}-\d{2} = "(.+)"' | Select-Object -First 1)
    if ($tok) { Write-Host "  jeton des sondes : $($tok.Matches[0].Groups[1].Value)" }
}
