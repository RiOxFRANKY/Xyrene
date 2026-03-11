#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  XYRENE Launcher
#  Starts the Python ML Engine, builds & runs the Java CLI
# ═══════════════════════════════════════════════════════════════

set -e

# Exit on error
ORIGINAL_DIR="$(pwd)"
ROOT_DIR="$(pwd)"
PYTHON_DIR="$ROOT_DIR/python-backend"
JAVA_DIR="$ROOT_DIR/java-backend"
PYTHON_PID=""

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[XYRENE]${NC} $1"; }
ok()   { echo -e "${GREEN}[XYRENE]${NC} $1"; }
err()  { echo -e "${RED}[XYRENE]${NC} $1"; }

# ── Cleanup on exit ──────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}[XYRENE] Cleaning up...${NC}"
    
    if [ -n "$PYTHON_PID" ]; then
        echo -e "${YELLOW}[XYRENE] Stopping Python ML Engine (PID $PYTHON_PID)...${NC}"
        kill "$PYTHON_PID" 2>/dev/null || true
        echo -e "${GREEN}[XYRENE] Python ML Engine stopped.${NC}"
    fi

    echo -e "${GREEN}[XYRENE] Shutdown complete.${NC}"
    cd "$ORIGINAL_DIR"
}
trap cleanup EXIT INT TERM

# ═══════════════════════════════════════════════════════════════
#  1. Start Python ML Engine
# ═══════════════════════════════════════════════════════════════
log "Starting Python ML Engine..."

cd "$PYTHON_DIR"

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    log "Creating Python virtual environment..."
    python3 -m venv venv
    ok "Virtual environment created."
fi

# Activate venv (Linux/Mac or Git Bash on Windows)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi
ok "Activated Python venv."

# Install/update dependencies
log "Installing Python dependencies..."
pip install -r requirements.txt
ok "Dependencies installed."

python main.py &
PYTHON_PID=$!
ok "Python ML Engine started (PID $PYTHON_PID)"

# Wait for the Python server to be ready
log "Waiting for ML Engine to be ready..."
MAX_WAIT=15
for i in $(seq 1 $MAX_WAIT); do
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        ok "ML Engine is online!"
        break
    fi
    if ! kill -0 "$PYTHON_PID" 2>/dev/null; then
        err "Python ML Engine failed to start. Check logs."
        exit 1
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        err "ML Engine did not respond within ${MAX_WAIT}s. Continuing anyway..."
    fi
    sleep 1
done

# ═══════════════════════════════════════════════════════════════
#  2. Build Java Backend
# ═══════════════════════════════════════════════════════════════
cd "$JAVA_DIR"

JAR_FILE="target/mitm-ids-2.0.0.jar"

if [ -f "$JAR_FILE" ]; then
    log "Java JAR already exists. Rebuilding with 'mvn clean package'..."
    mvn clean package -q -DskipTests
    ok "Java backend rebuilt."
else
    log "Building Java backend..."
    mvn package -q -DskipTests
    ok "Java backend built."
fi

# ═══════════════════════════════════════════════════════════════
#  3. Launch Java CLI
# ═══════════════════════════════════════════════════════════════
log "Launching XYRENE CLI..."
echo ""

sudo java -jar "$JAR_FILE"

# cleanup() runs automatically via trap
