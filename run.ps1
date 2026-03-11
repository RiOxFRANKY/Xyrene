<#
.SYNOPSIS
  XYRENE Run Script
  Starts the Python ML Engine, GUI API Proxy, React GUI, and Java Backend.
  All background servers are gracefully closed when you press Ctrl+C or exit.
#>

$ErrorActionPreference = "Stop"

# Ensure Administrator privileges (needed for Java's packet capture)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[XYRENE] Requesting Administrator privileges..." -ForegroundColor Cyan
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $scriptPath = Join-Path $scriptDir "run.ps1"
    $pwshArgs = "-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"& { `$Host.UI.RawUI.WindowTitle = 'XYRENE Run (Administrator)'; & '$scriptPath' }`""
    Start-Process -FilePath "powershell.exe" -ArgumentList $pwshArgs -Verb RunAs
    exit 0
}

$ORIGINAL_DIR = Get-Location
$ROOT_DIR = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Item -Path ".\").FullName }
$PYTHON_DIR = Join-Path $ROOT_DIR "python-backend"
$JAVA_DIR = Join-Path $ROOT_DIR "java-backend"
$GUI_DIR = Join-Path $ROOT_DIR "gui"
$GUI_API_DIR = Join-Path $ROOT_DIR "gui-api"

$processes = @()

# Cleanup Function
function CleanUp {
    Write-Host "`n[XYRENE] Shutting down all background services..." -ForegroundColor Cyan
    foreach ($p in $processes) {
        if ($p -and -not $p.HasExited) {
            Write-Host "         Stopping process $($p.Id)..." -ForegroundColor Gray
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Set-Location $ORIGINAL_DIR
    Write-Host "[XYRENE] All servers stopped. Returning to root." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

try {
    # 1. Start Python ML Engine
    Write-Host "[XYRENE] Starting Python ML Engine (Port 8000)..." -ForegroundColor Cyan
    Set-Location $PYTHON_DIR
    $pyCmd = "python"
    $activateScript = Join-Path "venv" "bin\activate.ps1"
    if (Test-Path $activateScript) { 
        $pyCmd = (Join-Path "venv" "Scripts\python.exe")
        if (-not (Test-Path $pyCmd)) { $pyCmd = Join-Path "venv" "bin\python.exe" }
    }
    
    $pythonProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"& '$pyCmd' main.py`"" -WindowStyle Hidden -PassThru
    $processes += $pythonProc

    Start-Sleep -Seconds 2

    # To solve port binding collisions, Java now binds to port 0 (random free port).
    # We must start Java FIRST in the background, read its stdout to find the assigned port,
    # and then pass that port to the Node GUI Proxy so it knows where to connect.
    Write-Host "[XYRENE] Starting Java Backend Capture Engine..." -ForegroundColor Cyan
    Set-Location $JAVA_DIR
    $jarFile = Join-Path $JAVA_DIR "target\mitm-ids-2.0.0.jar"
    
    if (-not (Test-Path $jarFile)) {
        Write-Host "[XYRENE] ERROR: Java JAR not found! Run install.ps1 first to build it." -ForegroundColor Red
        throw "JAR not found"
    }

    # Start Java and pipe its output so we can capture the port
    $javaProc = Start-Process -FilePath "java" -ArgumentList "--enable-native-access=ALL-UNNAMED", "-jar", "`"$jarFile`"" -RedirectStandardOutput "java_out.log" -WindowStyle Hidden -PassThru
    $processes += $javaProc

    # Wait for Java to spit out its port
    $javaPort = $null
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Path "java_out.log") {
            $logContent = Get-Content "java_out.log" -Tail 10 -ErrorAction SilentlyContinue
            foreach ($line in $logContent) {
                if ($line -match "\[XYRENE_JAVA_PORT=(\d+)\]") {
                    $javaPort = $matches[1]
                    break
                }
            }
        }
        if ($javaPort) { break }
        Start-Sleep -Milliseconds 500
    }

    if (-not $javaPort) {
        throw "Java API Server failed to bind to a port within 15 seconds."
    }
    Write-Host "[XYRENE] Java proxy bound to dynamic OS port: $javaPort" -ForegroundColor Green

    # 2. Start GUI API Proxy (Pass Java port via Env Var)
    Write-Host "[XYRENE] Starting GUI API Proxy (Port 9876)..." -ForegroundColor Cyan
    Set-Location $GUI_API_DIR
    $env:API_PORT = $javaPort
    $proxyProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"`$env:API_PORT=$javaPort; node server.js`"" -WindowStyle Hidden -PassThru
    $processes += $proxyProc

    # 3. Start React GUI 
    Write-Host "[XYRENE] Starting React GUI Frontend (Port 8080)..." -ForegroundColor Cyan
    Set-Location $GUI_DIR
    $vitePath = Join-Path "node_modules" "vite\bin\vite.js"
    $guiProc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"node `'$vitePath`' serve --port 8080`"" -WindowStyle Hidden -PassThru
    $processes += $guiProc

    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "ALL SERVERS ARE RUNNING IN THE BACKGROUND." -ForegroundColor Yellow
    Write-Host "You can access the GUI at: http://localhost:8080/" -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to stop everything and exit." -ForegroundColor Yellow
    Write-Host "================================================================`n" -ForegroundColor Yellow

    # Continuous loop to dump Java's log to the screen since it's the main driver
    Get-Content "..\java-backend\java_out.log" -Wait

} catch {
    Write-Host "`n[XYRENE] Exiting... Error Encountered:" -ForegroundColor Yellow
    Write-Host $_ -ForegroundColor Red
} finally {
    CleanUp
}
