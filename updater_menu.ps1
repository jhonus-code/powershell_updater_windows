<# =======================
  Updater Menu (Win Updates + Drivers + Cleanup)
  Version: 2.1 - COM-based (no PSGallery), auto-resume, logging, cleanup
  Works on: Windows 10/11 PowerShell 5.1
======================= #>

# --- Consola / modo estricto ---
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Resolver ruta del script de forma robusta ---
$ScriptPath = $PSCommandPath
if (-not $ScriptPath -or [string]::IsNullOrWhiteSpace($ScriptPath)) {
  try {
    if ($MyInvocation.MyCommand -and ($MyInvocation.MyCommand | Get-Member -Name Path -ErrorAction SilentlyContinue)) {
      $ScriptPath = $MyInvocation.MyCommand.Path
    } elseif ($MyInvocation.MyCommand.Definition -and (Test-Path $MyInvocation.MyCommand.Definition)) {
      $ScriptPath = $MyInvocation.MyCommand.Definition
    } else {
      $ScriptPath = Join-Path (Get-Location) "updater_menu.ps1"
    }
  } catch { $ScriptPath = Join-Path (Get-Location) "updater_menu.ps1" }
}

# --- Rutas / Logs ---
$ScriptDir = Split-Path -Parent $ScriptPath
$LogDir    = Join-Path $ScriptDir "logs"
$StateDir  = Join-Path $ScriptDir "state"
New-Item -ItemType Directory -Path $LogDir,$StateDir -Force | Out-Null

# --- Transcript (log de sesion) ---
$SessionLog = Join-Path $LogDir ("session_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $SessionLog -Append -ErrorAction SilentlyContinue } catch {}

# --- Trap global (asegura cierre de transcript y salida con error) ---
trap {
  Write-Error $_
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}

# --- Elevacion a administrador ---
function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo "powershell"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $psi.Verb = "runas"
    try { [Diagnostics.Process]::Start($psi) | Out-Null } catch { throw "Elevation failed." }
    try { Stop-Transcript | Out-Null } catch {}
    exit
  }
}
Ensure-Admin

# --- Archivos de estado / historial ---
$StateFile   = Join-Path $StateDir "resume_state.json"
$HistoryFile = Join-Path $LogDir "wu_history.json"

function Save-Json($obj, $path) { $obj | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8 }
function Load-Json($path) { if (Test-Path $path) { Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null } }

# --- Reapertura via RunOnce del .bat ---
function Set-RunOnceBatch {
  $batPath = Join-Path $ScriptDir "updater_menu.bat"
  if (-not (Test-Path $batPath)) { return }
  $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  New-Item -Path $key -Force | Out-Null
  New-ItemProperty -Path $key -Name "UpdaterMenuResume" -Value "`"$batPath`"" -PropertyType String -Force | Out-Null
}

function Set-PendingResume($op) {
  $state = @{ pending = $true; operation = $op; timestamp = (Get-Date) }
  Save-Json $state $StateFile
  Set-RunOnceBatch
}
function Clear-PendingResume { if (Test-Path $StateFile) { Remove-Item $StateFile -Force } }

function Append-History($entries) {
  $log = Load-Json $HistoryFile; if (-not $log) { $log = @() }
  $combined = @($log) + @($entries); Save-Json $combined $HistoryFile
}

# --- Visualizacion de estado (ASCII) ---
function Show-Status($title, $status) {
  switch ($status) {
    "Installed"        { Write-Host ("  [OK]   {0}" -f $title) -ForegroundColor Green }
    "AlreadyInstalled" { Write-Host ("  [SKIP] {0}" -f $title) -ForegroundColor Magenta }
    "Failed"           { Write-Host ("  [ERR]  {0}" -f $title) -ForegroundColor Red }
    "Pending"          { Write-Host ("  [..]   {0}" -f $title) -ForegroundColor DarkYellow }
    default            { Write-Host ("  [INFO] {0} ({1})" -f $title,$status) -ForegroundColor DarkGray }
  }
}

# =========================================================
#   A) Motor nativo COM de Windows Update (sin modulos)
# =========================================================

# Registrar Microsoft Update para abarcar drivers/Office/etc.
function Ensure-MicrosoftUpdateService {
  try {
    $sm = New-Object -ComObject "Microsoft.Update.ServiceManager"
    $MU_GUID = "7971f918-a847-4430-9279-4a52d1efe18d"
    $null = $sm.AddService2($MU_GUID, 7, "")
  } catch {
    Write-Host "Could not register Microsoft Update service (continuing)..." -ForegroundColor DarkYellow
  }
}

# Accion COM: buscar, descargar, instalar
function Invoke-UpdateCOM {
  param(
    [Parameter(Mandatory=$true)][string]$Criteria,   # ej: "IsInstalled=0 and IsHidden=0 and Type='Software'"
    [string]$Label = "updates"                       # etiqueta para logs
  )
  Ensure-MicrosoftUpdateService

  $session   = New-Object -ComObject "Microsoft.Update.Session"
  $searcher  = $session.CreateUpdateSearcher()

  Write-Host ""; Write-Host ("Searching {0}..." -f $Label) -ForegroundColor Cyan
  $searchRes = $searcher.Search($Criteria)

  if ($searchRes.Updates.Count -eq 0) {
    Write-Host ("No pending {0}." -f $Label) -ForegroundColor DarkGreen
    return @{
      Items = @(); Installed = 0; Failed = 0; RebootRequired = $false; Entries = @()
    }
  }

  for ($i=0; $i -lt $searchRes.Updates.Count; $i++) {
    $u = $searchRes.Updates.Item($i)
    Show-Status $u.Title "Pending"
  }

  $toInstall = New-Object -ComObject "Microsoft.Update.UpdateColl"
  for ($i=0; $i -lt $searchRes.Updates.Count; $i++) {
    [void]$toInstall.Add($searchRes.Updates.Item($i))
  }

  Set-PendingResume -op $Label

  Write-Host ""; Write-Host "Downloading..." -ForegroundColor Yellow
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $toInstall
  $dres = $downloader.Download()

  $downloaded = New-Object -ComObject "Microsoft.Update.UpdateColl"
  for ($i=0; $i -lt $toInstall.Count; $i++) {
    $u = $toInstall.Item($i)
    if ($u.IsDownloaded) { [void]$downloaded.Add($u) }
  }
  if ($downloaded.Count -eq 0) {
    Write-Host "Nothing downloaded. Aborting." -ForegroundColor Red
    return @{
      Items = @(); Installed = 0; Failed = $toInstall.Count; RebootRequired = $false; Entries = @()
    }
  }

  Write-Host ""; Write-Host "Installing..." -ForegroundColor Yellow
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $downloaded
  $ires = $installer.Install()

  $entries = @()
  $ok = 0; $fail = 0
  for ($i=0; $i -lt $downloaded.Count; $i++) {
    $u = $downloaded.Item($i)
    $ur = $ires.GetUpdateResult($i)
    $code = [string]$ur.ResultCode
    $status = switch ($code) {
      "orcSucceeded"                { "Installed" }
      "orcSucceededWithErrors"      { "Failed" }
      "orcFailed"                   { "Failed" }
      "orcAborted"                  { "Failed" }
      default                       { "Unknown" }
    }
    if ($status -eq "Installed") { $ok++ } elseif ($status -eq "Failed") { $fail++ }
    $entries += [pscustomobject]@{
      Date = (Get-Date)
      KB   = $null
      Title = $u.Title
      Operation = $Label
      Result = $status
    }
  }

  Append-History $entries
  Write-Host ""; Write-Host "Result:" -ForegroundColor Cyan
  foreach ($e in $entries) { Show-Status $e.Title $e.Result }

  if ($ires.RebootRequired) {
    Write-Host ""; Write-Host "Reboot required. Restarting now..." -ForegroundColor Yellow
    Restart-Computer -Force
  } else {
    Clear-PendingResume
  }

  return @{
    Items = $entries
    Installed = $ok
    Failed = $fail
    RebootRequired = [bool]$ires.RebootRequired
    Entries = $entries
  }
}

# =========================================================
#   B) PSWindowsUpdate (solo si ya esta instalado)
# =========================================================
$UsePSWU = $false
try {
  if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate -Force
    $UsePSWU = $true
  }
} catch { $UsePSWU = $false }

function Do-WindowsUpdates {
  if ($UsePSWU) {
    Write-Host ""; Write-Host "Searching Windows Updates (PSWindowsUpdate)..." -ForegroundColor Cyan
    $available = Get-WindowsUpdate -MicrosoftUpdate -ListOnly -IgnoreReboot
    if (-not $available) { Write-Host "No pending updates." -ForegroundColor DarkGreen; return }
    foreach ($a in $available) { Show-Status $a.Title "Pending" }

    Set-PendingResume -op "updates"
    $start = Get-Date
    Write-Host ""; Write-Host "Installing (auto reboot if required)..." -ForegroundColor Yellow
    Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll -AutoReboot

    $entries = @()
    foreach ($h in (Get-WUHistory | Where-Object { $_.Date -ge $start })) {
      $status = if ($h.Result -eq "Succeeded") { "Installed" }
                elseif ($h.Result -eq "Succeeded With Errors") { "Failed" }
                elseif ($h.Result -eq "Failed") { "Failed" }
                else { "Unknown" }
      $entries += [pscustomobject]@{ Date=$h.Date; KB=$h.KB; Title=$h.Title; Operation="updates"; Result=$status }
    }
    Append-History $entries
    Write-Host ""; Write-Host "Result:" -ForegroundColor Cyan
    foreach ($e in $entries) { Show-Status $e.Title $e.Result }
    Clear-PendingResume
  } else {
    $null = Invoke-UpdateCOM -Criteria "IsInstalled=0 and IsHidden=0 and Type='Software'" -Label "updates"
  }
}

function Do-Drivers {
  if ($UsePSWU) {
    Write-Host ""; Write-Host "Searching DRIVERS (PSWindowsUpdate)..." -ForegroundColor Cyan
    $available = Get-WindowsUpdate -MicrosoftUpdate -Category "Drivers" -ListOnly -IgnoreReboot
    if (-not $available) { Write-Host "No pending drivers." -ForegroundColor DarkGreen; return }
    foreach ($a in $available) { Show-Status $a.Title "Pending" }

    Set-PendingResume -op "drivers"
    $start = Get-Date
    Write-Host ""; Write-Host "Installing drivers (auto reboot if required)..." -ForegroundColor Yellow
    Get-WindowsUpdate -MicrosoftUpdate -Category "Drivers" -Install -AcceptAll -AutoReboot

    $entries = @()
    foreach ($h in (Get-WUHistory | Where-Object { $_.Date -ge $start })) {
      $status = if ($h.Result -eq "Succeeded") { "Installed" }
                elseif ($h.Result -eq "Succeeded With Errors") { "Failed" }
                elseif ($h.Result -eq "Failed") { "Failed" }
                else { "Unknown" }
      $entries += [pscustomobject]@{ Date=$h.Date; KB=$h.KB; Title=$h.Title; Operation="drivers"; Result=$status }
    }
    Append-History $entries
    Write-Host ""; Write-Host "Result:" -ForegroundColor Cyan
    foreach ($e in $entries) { Show-Status $e.Title $e.Result }
    Clear-PendingResume
  } else {
    $null = Invoke-UpdateCOM -Criteria "IsInstalled=0 and IsHidden=0 and Type='Driver'" -Label "drivers"
  }
}

# =========================================================
#   C) Limpieza de disco (SAFE / DEEP)
# =========================================================

function Format-Bytes([long]$bytes) {
  if ($bytes -ge 1GB) { '{0:N2} GB' -f ($bytes/1GB) }
  elseif ($bytes -ge 1MB) { '{0:N2} MB' -f ($bytes/1MB) }
  else { '{0:N0} bytes' -f $bytes }
}
function Get-SystemDriveFreeBytes {
  $drive = $env:SystemDrive
  $di = New-Object System.IO.DriveInfo($drive)
  return $di.AvailableFreeSpace
}
function Try-DeletePath([string]$pattern) {
  try {
    Get-ChildItem -LiteralPath $pattern -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
  } catch {}
}

function Do-Cleanup {
  param([switch]$Deep)

  Write-Host ""
  Write-Host ("Starting cleanup: {0}" -f ($(if($Deep){"DEEP (aggressive, irreversible)"} else {"SAFE"}))) -ForegroundColor Cyan

  $before = Get-SystemDriveFreeBytes

  # Parar servicios que bloquean SoftwareDistribution
  $svc = @("wuauserv","bits","dosvc")
  foreach ($s in $svc) { try { Stop-Service $s -Force -ErrorAction SilentlyContinue } catch {} }

  # Caches y temporales
  $paths = @(
    "$env:WINDIR\SoftwareDistribution\Download\*",
    "$env:WINDIR\SoftwareDistribution\DeliveryOptimization\*",
    "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache\*",
    "$env:WINDIR\Temp\*",
    "$env:TEMP\*",
    "$env:LOCALAPPDATA\Temp\*",
    "$env:WINDIR\Logs\CBS\*",
    "$env:WINDIR\Logs\DISM\*"
  )
  foreach ($p in $paths) {
    Write-Host ("  Cleaning {0}" -f $p) -ForegroundColor DarkYellow
    Try-DeletePath $p
  }

  # Papelera
  try {
    Write-Host "  Clearing Recycle Bin" -ForegroundColor DarkYellow
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
  } catch {}

  # Reiniciar servicios
  foreach ($s in $svc) { try { Start-Service $s -ErrorAction SilentlyContinue } catch {} }

  # WinSxS mantenimiento
  Write-Host "  Component Store cleanup (DISM /StartComponentCleanup)" -ForegroundColor DarkYellow
  try {
    Start-Process -FilePath dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup" -Wait -NoNewWindow
  } catch {}

  if ($Deep) {
    Write-Host "  Deep component cleanup (DISM /ResetBase) - irreversible" -ForegroundColor DarkYellow
    try {
      Start-Process -FilePath dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup","/ResetBase" -Wait -NoNewWindow
    } catch {}

    # Borrar Windows.old si existe
    if (Test-Path "C:\Windows.old") {
      Write-Host "  Removing C:\Windows.old (may take time)" -ForegroundColor DarkYellow
      try {
        Start-Process -FilePath takeown.exe -ArgumentList "/F","C:\Windows.old","/R","/D","Y" -Wait -NoNewWindow
        Start-Process -FilePath icacls.exe -ArgumentList "C:\Windows.old","/grant","Administrators:(F)","/T" -Wait -NoNewWindow
        Remove-Item "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
      } catch {}
    }
  }

  $after = Get-SystemDriveFreeBytes
  $freed = $after - $before
  Write-Host ""
  Write-Host ("Cleanup finished. Freed: {0}. Free now: {1}" -f (Format-Bytes $freed), (Format-Bytes $after)) -ForegroundColor Green
}

# =========================================================
#   D) Historial y reanudacion
# =========================================================

function Show-History {
  Write-Host ""; Write-Host "History (last 60 days):" -ForegroundColor Cyan
  $entries = Load-Json $HistoryFile
  if (-not $entries) {
    Write-Host "No history." -ForegroundColor DarkGray
    return
  }
  $since = (Get-Date).AddDays(-60)
  foreach ($e in ($entries | Where-Object { ([datetime]$_.Date) -ge $since } | Sort-Object { [datetime]$_.Date } -Descending)) {
    Show-Status ("[{0:yyyy-MM-dd}] {1}" -f ([datetime]$e.Date), $e.Title) $e.Result
  }
  Write-Host ""; Write-Host ("(Details JSON: {0})" -f $HistoryFile) -ForegroundColor DarkGray
}

function Resume-IfNeeded {
  $state = Load-Json $StateFile
  if ($state -and $state.pending -eq $true) {
    Write-Host ("Resuming after reboot... operation: {0}" -f $state.operation) -ForegroundColor Yellow
    # En ruta COM no podemos reconstruir resultados exactos post-reinicio; limpiamos estado y volvemos al menu
    Clear-PendingResume
    Write-Host ""; Read-Host "Press ENTER to return to menu"
  }
}

# =========================================================
#   E) Menu y bucle principal
# =========================================================

function Show-Menu {
  Clear-Host
  Write-Host "==============================="
  Write-Host "     Windows Updater Menu      "
  Write-Host "==============================="
  Write-Host "1) Windows Updates"
  Write-Host "2) Drivers"
  Write-Host "3) View history"
  Write-Host "4) Cleanup disk (safe)"
  Write-Host "5) Deep Cleanup (aggressive, irreversible)"
  Write-Host "0) Exit"
}

Resume-IfNeeded

while ($true) {
  Show-Menu
  $opt = Read-Host "Choose an option"
  switch ($opt) {
    "1" { Do-WindowsUpdates; Read-Host "`nPress ENTER to continue" }
    "2" { Do-Drivers;        Read-Host "`nPress ENTER to continue" }
    "3" { Show-History;      Read-Host "`nPress ENTER to continue" }
    "4" { Do-Cleanup -Deep:$false; Read-Host "`nPress ENTER to continue" }
    "5" { Do-Cleanup -Deep:$true;  Read-Host "`nPress ENTER to continue" }
    "0" { break }
    default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1 }
  }
}

try { Stop-Transcript | Out-Null } catch {}
