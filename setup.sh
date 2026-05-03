#!/bin/bash
# NightEye one-command setup for SIFT Workstation
# Usage: curl -fsSL https://raw.githubusercontent.com/0xshivangpatel/nighteye/main/setup.sh | bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  NightEye — Autonomous DFIR Agent Setup${NC}"
echo -e "${CYAN}============================================================${NC}"

# --- 0. Check we're on SIFT ---
if [ ! -f /etc/sift-version ] 2>/dev/null && ! grep -qi sift /etc/os-release 2>/dev/null; then
    echo -e "${RED}Warning: This doesn't appear to be a SIFT Workstation.${NC}"
    echo "Setup may fail for missing forensic tools."
fi

# --- 1. System dependencies ---
echo -e "\n${GREEN}[1/6] Installing system packages...${NC}"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    p7zip-full docker.io docker-compose-v2 \
    ewf-tools sleuthkit yara git curl wget

# Start Docker if not running
if ! docker ps >/dev/null 2>&1; then
    sudo systemctl start docker || true
fi

# --- 2. Python virtual environment ---
echo -e "\n${GREEN}[2/6] Setting up Python environment...${NC}"
cd "$(dirname "$0")" 2>/dev/null || cd ~/nighteye
python3 -m venv .venv --clear 2>/dev/null || python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -e ".[dev,parsers]" -q

# --- 3. Hayabusa (Sigma rules for EVTX) ---
echo -e "\n${GREEN}[3/6] Installing Hayabusa + Sigma rules...${NC}"
HAYABUSA_BIN="$HOME/.local/bin/hayabusa"
if [ ! -x "$HAYABUSA_BIN" ]; then
    mkdir -p "$HOME/.local/bin"
    HAYABUSA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v3.1.0/hayabusa-3.1.0-ubuntu-22.04-amd64"
    echo "  Downloading hayabusa..."
    curl -fsSL "$HAYABUSA_URL" -o "$HAYABUSA_BIN"
    chmod +x "$HAYABUSA_BIN"
    # Ensure ~/.local/bin is on PATH
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        export PATH="$HOME/.local/bin:$PATH"
    fi
fi

RULES_DIR="/opt/hayabusa-rules"
if [ ! -d "$RULES_DIR/config" ]; then
    echo "  Cloning hayabusa-rules..."
    sudo rm -rf "$RULES_DIR" 2>/dev/null || true
    sudo git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git "$RULES_DIR"
else
    echo "  Hayabusa rules already present, updating..."
    sudo git -C "$RULES_DIR" pull --ff-only 2>/dev/null || true
fi
# Update hayabusa config
if [ -f "$RULES_DIR/config" ]; then
    sudo "$HAYABUSA_BIN" update-rules -r "$RULES_DIR" 2>/dev/null || true
fi

# --- 4. YARA + signature-base rules ---
echo -e "\n${GREEN}[4/6] Setting up YARA rules...${NC}"
YARA_RULES="/opt/signature-base"
if [ ! -d "$YARA_RULES" ]; then
    echo "  Cloning signature-base (Florian Roth's YARA rules)..."
    sudo rm -rf "$YARA_RULES" 2>/dev/null || true
    sudo git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$YARA_RULES"
else
    echo "  YARA rules already present, updating..."
    sudo git -C "$YARA_RULES" pull --ff-only 2>/dev/null || true
fi

# --- 5. OpenSearch via Docker ---
echo -e "\n${GREEN}[5/6] Starting OpenSearch...${NC}"
# Add user to docker group if needed
if ! groups "$USER" | grep -q docker; then
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    echo "  Added $USER to docker group — log out and back in if needed"
fi

if [ -f docker-compose.yml ]; then
    sudo docker compose up -d 2>/dev/null || docker compose up -d 2>/dev/null || true
    echo "  Waiting for OpenSearch to be ready..."
    for i in $(seq 1 30); do
        if curl -s http://localhost:9200 >/dev/null 2>&1; then
            echo "  OpenSearch is ready!"
            break
        fi
        sleep 2
    done
else
    echo "  No docker-compose.yml found in $(pwd) — start OpenSearch manually."
fi

# --- 6. Verify ---
echo -e "\n${GREEN}[6/6] Verifying installation...${NC}"
echo -n "  nighteye CLI: "
nighteye --version 2>/dev/null && echo "OK" || echo "FAIL"

echo -n "  Hayabusa:    "
hayabusa --version 2>/dev/null && echo "OK" || echo "FAIL (not found)"

echo -n "  YARA:        "
yara --version 2>/dev/null && echo "OK" || echo "FAIL (not found)"

echo -n "  OpenSearch:  "
curl -s http://localhost:9200 >/dev/null 2>&1 && echo "OK" || echo "FAIL (not running)"

echo -n "  Test suite:  "
pytest -q 2>/dev/null && echo "" || echo ""

echo -e "\n${CYAN}============================================================${NC}"
echo -e "${CYAN}  Setup complete. Run:${NC}"
echo -e "    ${GREEN}source .venv/bin/activate${NC}"
echo -e "    ${GREEN}nighteye init --name \"SRL-2015\" --examiner sansforensics --base-dir ~/nighteye/cases${NC}"
echo -e "    ${GREEN}nighteye full-pipeline /path/to/evidence/${NC}"
echo -e "${CYAN}============================================================${NC}"
