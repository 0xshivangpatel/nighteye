#!/bin/bash
# NightEye one-command setup for SIFT / Ubuntu / Debian forensic workstations.
# Installs every parser the pipeline can call:
#   - EZ Tools (.NET): EvtxECmd, MFTECmd, RECmd, AmcacheParser, PECmd
#   - Hayabusa + bundled Sigma rules
#   - Chainsaw + SigmaHQ rules
#   - YARA + Neo23x0/signature-base
#   - Volatility 3 (with writable symbol cache)
#   - Plaso / log2timeline / psort / pinfo
#   - MemProcFS (Linux x64)
#   - libewf-tools (ewfmount), p7zip-full, sleuthkit
# Idempotent. Re-run safely; existing tools are detected and skipped.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[setup]${NC} $*"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
err()  { echo -e "  ${RED}✗${NC} $*"; }

NIGHTEYE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$NIGHTEYE_DIR"

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  NightEye — Autonomous DFIR Agent Setup${NC}"
echo -e "${CYAN}  Installing all forensic parsers and rule packs${NC}"
echo -e "${CYAN}============================================================${NC}"

# ============================================================
# 1. System packages
# ============================================================
log "[1/9] System packages (apt)..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    p7zip-full git curl wget unzip jq \
    docker.io docker-compose-v2 \
    ewf-tools sleuthkit yara \
    python3-venv python3-pip python3-dev build-essential \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    fuse3 dotnet-sdk-9.0 || sudo apt-get install -y -qq dotnet-sdk-8.0 || true
ok "apt packages installed"

if ! groups "$USER" | grep -q docker; then
    sudo usermod -aG docker "$USER" || true
    warn "Added $USER to docker group — log out/in for it to take effect"
fi

if ! docker ps >/dev/null 2>&1; then
    sudo systemctl start docker 2>/dev/null || true
fi

# ============================================================
# 2. Python venv + NightEye package
# ============================================================
log "[2/9] Python venv + nighteye package..."
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install --upgrade pip wheel setuptools -q
pip install -e ".[dev,parsers]" -q
ok "nighteye CLI installed in .venv"

# ============================================================
# 3. Plaso (gives us psort, pinfo, log2timeline)
# ============================================================
log "[3/9] Plaso (psort / pinfo / log2timeline)..."
if .venv/bin/python -c "import plaso" 2>/dev/null; then
    ok "plaso $(.venv/bin/python -c 'import plaso; print(plaso.__version__)') already installed"
else
    pip install plaso -q
    ok "plaso installed"
fi

# ============================================================
# 4. Volatility 3 (with writable symbol cache)
# ============================================================
log "[4/9] Volatility 3 + writable symbol cache..."
if .venv/bin/python -c "import volatility3" 2>/dev/null; then
    ok "volatility3 $(.venv/bin/python -c 'import volatility3; print(volatility3.__version__)')"
else
    pip install volatility3 -q
    ok "volatility3 installed"
fi
# Make the symbol cache writable so Vol3 can download Win10/Win7 PDBs
SYM_PATH=$(.venv/bin/python -c "import volatility3, os; print(os.path.dirname(volatility3.__file__))" 2>/dev/null || true)
if [ -n "$SYM_PATH" ] && [ -d "$SYM_PATH/symbols/windows" ]; then
    sudo chmod -R a+rwX "$SYM_PATH/symbols" "$SYM_PATH/framework/symbols" 2>/dev/null || true
    ok "vol3 symbol cache is writable: $SYM_PATH/symbols/"
fi

# ============================================================
# 5. Hayabusa (binary + bundled Sigma rules)
# ============================================================
log "[5/9] Hayabusa (Sigma rule scanner for EVTX)..."
if command -v hayabusa >/dev/null 2>&1 && hayabusa --help 2>/dev/null | grep -q csv-timeline; then
    ok "hayabusa already installed: $(which hayabusa)"
else
    HAYA_VER=$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
                | jq -r '.tag_name' | sed 's/^v//')
    HAYA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYA_VER}/hayabusa-${HAYA_VER}-lin-x64-gnu.zip"
    log "  downloading hayabusa v${HAYA_VER}..."
    curl -fsSL "$HAYA_URL" -o /tmp/hayabusa.zip
    unzip -oq /tmp/hayabusa.zip -d /tmp/hayabusa-bin
    sudo install -m 0755 "/tmp/hayabusa-bin/hayabusa-${HAYA_VER}-lin-x64-gnu" /usr/local/bin/hayabusa
    sudo mkdir -p /opt/hayabusa
    sudo cp -r /tmp/hayabusa-bin/rules /tmp/hayabusa-bin/config /opt/hayabusa/
    rm -rf /tmp/hayabusa.zip /tmp/hayabusa-bin
    ok "hayabusa v${HAYA_VER} installed at /usr/local/bin/hayabusa"
    ok "hayabusa rules at /opt/hayabusa/rules/ (run from /opt/hayabusa as cwd)"
fi

# ============================================================
# 6. Chainsaw (binary + SigmaHQ rules)
# ============================================================
log "[6/9] Chainsaw + SigmaHQ rules..."
if command -v chainsaw >/dev/null 2>&1; then
    ok "chainsaw already installed: $(which chainsaw)"
else
    CHAIN_VER=$(curl -fsSL https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest \
                | jq -r '.tag_name' | sed 's/^v//')
    CHAIN_URL="https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAIN_VER}/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
    log "  downloading chainsaw v${CHAIN_VER}..."
    curl -fsSL "$CHAIN_URL" -o /tmp/chainsaw.tar.gz
    tar -xzf /tmp/chainsaw.tar.gz -C /tmp/
    sudo install -m 0755 /tmp/chainsaw/chainsaw /usr/local/bin/chainsaw
    sudo mkdir -p /opt/chainsaw
    sudo cp -r /tmp/chainsaw/mappings /opt/chainsaw/
    rm -rf /tmp/chainsaw.tar.gz /tmp/chainsaw
    ok "chainsaw v${CHAIN_VER} installed"
fi
if [ ! -d /opt/chainsaw/sigma ]; then
    log "  cloning SigmaHQ rules..."
    sudo git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/chainsaw/sigma
    ok "sigma rules at /opt/chainsaw/sigma/"
else
    sudo git -C /opt/chainsaw/sigma pull --ff-only -q 2>/dev/null || true
    ok "sigma rules updated"
fi

# ============================================================
# 7. YARA + Neo23x0 signature-base rules
# ============================================================
log "[7/9] YARA + signature-base..."
if ! command -v yara >/dev/null 2>&1; then
    sudo apt-get install -y -qq yara
fi
ok "yara $(yara --version)"
if [ ! -d /opt/yara-rules/signature-base ]; then
    log "  cloning signature-base..."
    sudo mkdir -p /opt/yara-rules
    sudo git clone --depth 1 https://github.com/Neo23x0/signature-base.git /opt/yara-rules/signature-base
    ok "yara rules at /opt/yara-rules/signature-base/yara/"
else
    sudo git -C /opt/yara-rules/signature-base pull --ff-only -q 2>/dev/null || true
    ok "yara rules updated"
fi

# ============================================================
# 8. Eric Zimmerman tools (EvtxECmd / MFTECmd / RECmd / Amcache / PECmd)
# ============================================================
log "[8/9] Eric Zimmerman .NET Tools..."
if command -v EvtxECmd >/dev/null 2>&1 && command -v MFTECmd >/dev/null 2>&1 \
   && command -v RECmd >/dev/null 2>&1 && command -v AmcacheParser >/dev/null 2>&1; then
    ok "EZ Tools already installed: $(which EvtxECmd MFTECmd RECmd AmcacheParser PECmd 2>/dev/null | head -5)"
else
    EZ_DIR=/opt/EZTools
    sudo mkdir -p "$EZ_DIR"
    EZ_URL="https://download.ericzimmermanstools.com/net9/Get-ZimmermanTools.zip"
    log "  downloading Get-ZimmermanTools..."
    curl -fsSL "$EZ_URL" -o /tmp/eztools.zip
    sudo unzip -oq /tmp/eztools.zip -d "$EZ_DIR/"
    rm -f /tmp/eztools.zip
    # Use PowerShell-Core if installed, else manual download script
    if command -v pwsh >/dev/null 2>&1; then
        cd "$EZ_DIR" && sudo pwsh -Command "Get-ZimmermanTools.ps1 -Dest $EZ_DIR -NetVersion 9" || true
        cd "$NIGHTEYE_DIR"
    else
        warn "PowerShell-Core (pwsh) not installed — installing now for EZ Tools downloader"
        sudo apt-get install -y -qq powershell || sudo snap install powershell --classic 2>/dev/null || true
        if command -v pwsh >/dev/null 2>&1; then
            cd "$EZ_DIR" && sudo pwsh -Command "./Get-ZimmermanTools.ps1 -Dest $EZ_DIR -NetVersion 9" || true
            cd "$NIGHTEYE_DIR"
        else
            warn "Unable to install pwsh — falling back to manual EZ Tools download"
            for tool in EvtxeCmd MFTECmd RECmd AmcacheParser PECmd; do
                T_URL="https://download.ericzimmermanstools.com/net9/${tool}.zip"
                curl -fsSL "$T_URL" -o "/tmp/${tool}.zip" || continue
                sudo unzip -oq "/tmp/${tool}.zip" -d "$EZ_DIR/" 2>/dev/null || true
                rm -f "/tmp/${tool}.zip"
            done
        fi
    fi
    # Install thin wrapper scripts to /usr/local/bin
    for tool in EvtxECmd MFTECmd RECmd AmcacheParser PECmd; do
        DLL_PATH=$(find "$EZ_DIR" -iname "${tool}.dll" 2>/dev/null | head -1)
        if [ -n "$DLL_PATH" ]; then
            sudo tee "/usr/local/bin/${tool}" > /dev/null <<EOF
#!/bin/bash
exec dotnet "$DLL_PATH" "\$@"
EOF
            sudo chmod 0755 "/usr/local/bin/${tool}"
            ok "$tool wrapper → $DLL_PATH"
        else
            warn "$tool .dll not found in $EZ_DIR"
        fi
    done
fi

# ============================================================
# 9. MemProcFS (Linux x64)
# ============================================================
log "[9/9] MemProcFS..."
if command -v memprocfs >/dev/null 2>&1; then
    ok "memprocfs already installed"
else
    MPFS_VER=$(curl -fsSL https://api.github.com/repos/ufrisk/MemProcFS/releases/latest \
                | jq -r '.tag_name' | sed 's/^v//')
    MPFS_DATE=$(curl -fsSL https://api.github.com/repos/ufrisk/MemProcFS/releases/latest \
                | jq -r '.assets[] | select(.name | test("linux_x64")) | .name' \
                | head -1 | sed -E 's/.*([0-9]{8}).*/\1/')
    MPFS_URL=$(curl -fsSL https://api.github.com/repos/ufrisk/MemProcFS/releases/latest \
                | jq -r '.assets[] | select(.name | test("linux_x64")) | .browser_download_url' \
                | head -1)
    if [ -n "$MPFS_URL" ]; then
        log "  downloading MemProcFS v${MPFS_VER}..."
        curl -fsSL "$MPFS_URL" -o /tmp/memprocfs.tar.gz
        sudo mkdir -p /opt/memprocfs
        sudo tar -xzf /tmp/memprocfs.tar.gz -C /opt/memprocfs/ --strip-components=0
        rm -f /tmp/memprocfs.tar.gz
        # Find and link the binary
        MPFS_BIN=$(sudo find /opt/memprocfs -name memprocfs -type f -executable 2>/dev/null | head -1)
        if [ -n "$MPFS_BIN" ]; then
            sudo ln -sf "$MPFS_BIN" /usr/local/bin/memprocfs
            ok "memprocfs v${MPFS_VER} installed"
        else
            warn "memprocfs binary not found after extract"
        fi
    else
        warn "could not find linux_x64 release for MemProcFS"
    fi
fi

# ============================================================
# OpenSearch via Docker
# ============================================================
log "[+] OpenSearch (Docker)..."
if [ -f docker-compose.yml ]; then
    sudo docker compose up -d 2>&1 | tail -3
    log "  waiting for OpenSearch to be ready..."
    for i in $(seq 1 60); do
        if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
            ok "OpenSearch is ready"
            break
        fi
        sleep 2
    done
fi

# ============================================================
# Verification
# ============================================================
log ""
log "=== Verification ==="
verify() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        ok "$name"
    else
        err "$name (NOT WORKING — check above)"
    fi
}
verify "nighteye CLI"      .venv/bin/nighteye --version
verify "Plaso"             .venv/bin/python -c "import plaso"
verify "Volatility 3"      .venv/bin/python -c "import volatility3"
verify "Hayabusa"          hayabusa --help
verify "Chainsaw"          chainsaw --version
verify "YARA"              yara --version
verify "EvtxECmd"          which EvtxECmd
verify "MFTECmd"           which MFTECmd
verify "RECmd"             which RECmd
verify "AmcacheParser"     which AmcacheParser
verify "PECmd"             which PECmd
verify "MemProcFS"         which memprocfs
verify "ewfmount"          which ewfmount
verify "OpenSearch"        curl -sf http://localhost:9200/_cluster/health

echo
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Setup complete.${NC}"
echo -e "${CYAN}============================================================${NC}"
echo
echo -e "Next steps:"
echo -e "  ${GREEN}source .venv/bin/activate${NC}"
echo -e "  ${GREEN}nighteye init --name 'My Investigation' --examiner \$USER${NC}"
echo -e "  ${GREEN}nighteye full-pipeline /path/to/evidence/${NC}"
echo
echo -e "Tool paths:"
echo -e "  Hayabusa rules: /opt/hayabusa/rules/  (run from /opt/hayabusa)"
echo -e "  Chainsaw sigma: /opt/chainsaw/sigma/"
echo -e "  YARA rules:     /opt/yara-rules/signature-base/yara/"
echo -e "  EZ Tools:       /opt/EZTools/"
echo -e "  MemProcFS:      /opt/memprocfs/"
echo
