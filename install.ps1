<#
.SYNOPSIS
  XYRENE Launcher
  Starts the Python ML Engine, builds & runs the Java CLI on Windows
#>

# Requires Administrator privileges for network capturing (WinPcap/Npcap).

# Error handling and strict mode
$ErrorActionPreference = "Stop"

# Save initial directory to restore on exit
$ORIGINAL_DIR = Get-Location

# Hardcoded paths
$ROOT_DIR = (Get-Item -Path ".\").FullName
$PYTHON_DIR = Join-Path $ROOT_DIR "python-backend"
$JAVA_DIR = Join-Path $ROOT_DIR "java-backend"

# ── Colors ───────────────────────────────────────────────────
function Log-Info {
    param([string]$Message)
    Write-Host "[XYRENE] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Log-Success {
    param([string]$Message)
    Write-Host "[XYRENE] " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Log-Error {
    param([string]$Message)
    Write-Host "[XYRENE] " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

# ═══════════════════════════════════════════════════════════════
#  1. Start Python ML Engine
# ═══════════════════════════════════════════════════════════════
Log-Info "Starting Python ML Engine..."

Set-Location -Path $PYTHON_DIR

# Create venv if it doesn't exist
$venvPath = Join-Path $PYTHON_DIR "venv"
if (-not (Test-Path -Path $venvPath)) {
    Log-Info "Creating Python virtual environment..."
    python -m venv venv
    Log-Success "Virtual environment created."
}

# Activate venv for the current PowerShell session
$activateScript = Join-Path $venvPath "bin\activate"
if (Test-Path -Path $activateScript) {
    . $activateScript
    Log-Success "Activated Python venv."
} else {
    Log-Error "Could not find venv activation script at $activateScript"
    exit 1
}

# Install/update dependencies
Log-Info "Installing Python dependencies..."
pip install -r requirements.txt
Log-Success "Dependencies installed."

# Start the Python server hidden in the background
$pythonProcess = Start-Process -FilePath "python" -ArgumentList "main.py" -WindowStyle Hidden -PassThru
Log-Success "Python ML Engine started (PID $($pythonProcess.Id))"

# Setup cleanup hook for when PowerShell exits or script fails
# In PowerShell, we can use a try/finally block for the rest of the script.
try {
    # Wait for the Python server to be ready
    Log-Info "Waiting for ML Engine to be ready..."
    $maxWait = 15
    $ready = $false
    for ($i = 1; $i -le $maxWait; $i++) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Log-Success "ML Engine is online!"
                $ready = $true
                break
            }
        } catch {}

        if ($pythonProcess.HasExited) {
            Log-Error "Python ML Engine failed to start. Check logs."
            exit 1
        }
        
        if ($i -eq $maxWait) {
            Log-Error "ML Engine did not respond within ${maxWait}s. Continuing anyway..."
        }
        Start-Sleep -Seconds 1
    }

    # ═══════════════════════════════════════════════════════════════
    #  2. Build Java Backend
    # ═══════════════════════════════════════════════════════════════
    Set-Location -Path $JAVA_DIR

    $jarFile = Join-Path $JAVA_DIR "target\mitm-ids-2.0.0.jar"

    if (Test-Path -Path $jarFile) {
        Log-Info "Java JAR already exists. Rebuilding with 'mvn clean package'..."
        mvn clean package -q -DskipTests
        Log-Success "Java backend rebuilt."
    } else {
        Log-Info "Building Java backend..."
        mvn package -q -DskipTests
        Log-Success "Java backend built."
    }

    # ═══════════════════════════════════════════════════════════════
    #  3. Launch Java CLI
    # ═══════════════════════════════════════════════════════════════
    # Check for WinPcap/Npcap (required on Windows for Pcap4j)
    $wpcapExists = (Test-Path "C:\Windows\System32\wpcap.dll") -or (Test-Path "C:\Windows\SysWOW64\wpcap.dll")
    if (-not $wpcapExists) {
        Write-Host ""
        Log-Error "CRITICAL: WinPcap or Npcap is not installed on this system!"
        Write-Host "  Pcap4j requires a native packet capture driver (wpcap.dll) to work on Windows."
        Write-Host "  1. Download Npcap from: https://npcap.com/#download"
        Write-Host "  2. Run the installer."
        Write-Host "  3. IMPORTANT: You MUST check the box 'Install Npcap in WinPcap API-compatible Mode' during installation."
        Write-Host "  4. Restart this terminal and run .\install.ps1 again."
        Write-Host ""
        exit 1
    }

    Log-Info "Launching XYRENE CLI..."
    Write-Host ""

    # Launch Java CLI as Administrator in a new PowerShell window
    # We use Start-Process with -Verb RunAs to automatically trigger the UAC prompt
    Log-Info "Waiting for Java CLI to finish..."
    
    # We wrap the java call inside a PowerShell command to ensure it opens in a modern PS console
    $pwshCommand = "`$Host.UI.RawUI.WindowTitle = 'XYRENE - Administrator'; java --enable-native-access=ALL-UNNAMED -jar `"$($jarFile.Replace('\', '\\'))`""
    $pwshArgs = "-NoProfile -Command `"$pwshCommand`""
    
    $javaProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $pwshArgs -Verb RunAs -Wait -PassThru
    
    if ($javaProcess.ExitCode -ne 0) {
        Log-Error "Java CLI exited with code $($javaProcess.ExitCode)"
    } else {
        Log-Success "XYRENE CLI closed successfully."
    }

} finally {
    # ── Cleanup on exit ──────────────────────────────────────────
    if ($pythonProcess -and -not $pythonProcess.HasExited) {
        Log-Info "Stopping Python ML Engine (PID $($pythonProcess.Id))..."
        Stop-Process -Id $pythonProcess.Id -Force -ErrorAction SilentlyContinue
        Log-Success "Python ML Engine stopped."
    }
    
    # Return to original directory
    Set-Location $ORIGINAL_DIR
}
