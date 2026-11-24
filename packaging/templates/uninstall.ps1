<#
Désinstallation de SYNTRAF (serveur ou sonde) sous Windows. -Purge efface aussi la configuration, les données et
les journaux (C:\ProgramData\SYNTRAF\<rôle>).
#>
param([string]$Prefix = "", [string]$DataDir = "", [switch]$Purge)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$role = (Get-Content "$here\payload\ROLE" -Raw).Trim()
if (-not $Prefix) { $Prefix = Join-Path $env:ProgramFiles "SYNTRAF\$role" }
if (-not $DataDir) { $DataDir = Join-Path $env:ProgramData "SYNTRAF\$role" }
foreach ($task in "SYNTRAF $role", "SYNTRAF grafana", "SYNTRAF victoriametrics") {
    if ($role -ne "server" -and $task -ne "SYNTRAF $role") { continue }
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
}
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$Prefix\*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
if ($Purge -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host "SYNTRAF $role désinstallé (configuration, données et journaux effacés)."
} else {
    Write-Host "SYNTRAF $role désinstallé. Gardé : $DataDir (-Purge pour l'effacer)."
}
