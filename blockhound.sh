#!/usr/bin/env bash
# ============================================================================
# Subnet Scanner — Automated TCP + UDP Network Scanning
# ============================================================================
# Description:
#   Scans sequential /24 subnets for open TCP and UDP ports using naabu 
#   (for fast TCP scanning) and nmap (for UDP scanning). Results are saved 
#   as JSON files for easy parsing and analysis.
#
# Usage:
#   sudo ./subnet_scanner.sh <start_octet>-<end_octet>
#
# Examples:
#   sudo ./subnet_scanner.sh 1-5      # Scans x.x.1.0/24 through x.x.5.0/24
#   sudo ./subnet_scanner.sh 10-10    # Scans only x.x.10.0/24
#
# Requirements:
#   - naabu (https://github.com/projectdiscovery/naabu)
#   - nmap
#   - jq
#   - Python 3 with xmltodict (auto-installed if missing)
#
# Output Structure:
#   results_dir/
#   ├── BASE_NET_<octet>/
#   │   ├── hosts.txt
#   │   ├── naabu_raw.txt
#   │   ├── tcp.json
#   │   ├── udp.xml
#   │   ├── udp.json
#   │   └── combined.json
#   └── all_scans_combined.json
#
# License: MIT
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION — Modify these values for your environment
# ============================================================================

# Base network to scan (first two octets of IPv4 address)
# Example: "192.168" would scan 192.168.x.0/24 subnets
BASE_NET="${BASE_NET:-192.168}"

# Directory to store scan results
RESULTS_DIR="${RESULTS_DIR:-$HOME/scan_results}"

# Scanning parameters (can be overridden via environment variables)
NAABU_RATE="${NAABU_RATE:-8000}"        # TCP scan rate (packets/sec)
NMAP_MIN_RATE="${NMAP_MIN_RATE:-800}"   # UDP scan minimum rate
INITIAL_RTT="${INITIAL_RTT:-215}"       # Initial round-trip timeout (ms)
MAX_RTT="${MAX_RTT:-500}"               # Maximum round-trip timeout (ms)
RETRIES="${RETRIES:-2}"                 # Number of retries for both scans

# ============================================================================
# SETUP — Handle sudo user context and tool discovery
# ============================================================================

# Preserve original user's home directory when running with sudo
if [ -n "${SUDO_USER:-}" ]; then
  HOME_DIR=$(eval echo "~$SUDO_USER")
  RESULTS_DIR="${RESULTS_DIR:-$HOME_DIR/scan_results}"
  OWN_USER="$SUDO_USER"
else
  RESULTS_DIR="${RESULTS_DIR:-$HOME/scan_results}"
  OWN_USER=$(whoami)
fi

# Find naabu binary
NAABU_BIN="${NAABU_BIN:-}"
if [ -z "$NAABU_BIN" ] || ! [ -x "$NAABU_BIN" ]; then
  if command -v naabu >/dev/null; then
    NAABU_BIN=$(command -v naabu)
  else
    echo "!! Naabu not found. Please install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" >&2
    exit 1
  fi
fi

# Check for required tools
if ! command -v jq >/dev/null; then
  echo "!! jq not found. Install with: sudo apt-get install jq" >&2
  exit 1
fi

if ! command -v nmap >/dev/null; then
  echo "!! nmap not found. Install with: sudo apt-get install nmap" >&2
  exit 1
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

# ============================================================================
# PARSE ARGUMENTS
# ============================================================================

RANGE="${1:?Usage: $0 <start_octet>-<end_octet>  (e.g., 1-5)}"
START=$(echo "$RANGE" | cut -d'-' -f1)
END=$(echo "$RANGE" | cut -d'-' -f2)

# Validate input
if ! [[ "$START" =~ ^[0-9]+$ ]] || ! [[ "$END" =~ ^[0-9]+$ ]]; then
  echo "!! Invalid range format. Use: <start>-<end> (e.g., 1-5)" >&2
  exit 1
fi

if [ "$START" -gt "$END" ]; then
  echo "!! Start octet must be less than or equal to end octet" >&2
  exit 1
fi

# ============================================================================
# MAIN SCANNING LOOP
# ============================================================================

echo "Scanning ${BASE_NET}.${START}.0/24 through ${BASE_NET}.${END}.0/24"
echo "Results will be saved to: $RESULTS_DIR"
echo "=============================================================="

for OCT in $(seq "$START" "$END"); do
  CIDR="${BASE_NET}.${OCT}.0/24"
  SUBNET_DIR="${RESULTS_DIR}/${BASE_NET//./_}_${OCT}"
  mkdir -p "$SUBNET_DIR"

  echo -e "\n\033[1;36m==> Starting $CIDR\033[0m"

  # Define output files
  HOSTS_FILE="${SUBNET_DIR}/hosts.txt"
  NAABU_RAW="${SUBNET_DIR}/naabu_raw.txt"
  TCP_JSON="${SUBNET_DIR}/tcp.json"
  UDP_XML="${SUBNET_DIR}/udp.xml"
  UDP_JSON="${SUBNET_DIR}/udp.json"
  COMBINED_JSON="${SUBNET_DIR}/combined.json"

  # Increase file descriptor limit for performance (ignore if not possible)
  ulimit -n 4096 2>/dev/null || true

  # --------------------------------------------------------------------------
  # PARALLEL TCP & UDP SCANS
  # --------------------------------------------------------------------------

  echo -e "\033[1;33m[+] TCP scan (all ports) → $NAABU_RAW\033[0m"

  # TCP scan with naabu (runs in background)
  (
    sudo "$NAABU_BIN" -host "$CIDR" -p 0-65535 \
      -rate "$NAABU_RATE" -retries "$RETRIES" \
      -o "$NAABU_RAW" \
      -silent 2>&1

    sync  # Ensure file is written

    if [ ! -s "$NAABU_RAW" ]; then
      echo "   No open TCP ports found for $CIDR" >&2
      touch "$NAABU_RAW"
    else
      echo "   Naabu found $(wc -l < "$NAABU_RAW") TCP results"
    fi
  ) &
  TCP_PID=$!

  echo -e "\033[1;33m[+] UDP scan (top 1000 ports) → $UDP_XML\033[0m"

  # UDP scan with nmap (runs in background)
  (
    sudo nmap -sU --top-ports 1000 -T4 -n \
      --min-rate "$NMAP_MIN_RATE" \
      --initial-rtt-timeout "${INITIAL_RTT}ms" \
      --max-rtt-timeout "${MAX_RTT}ms" \
      --max-retries "$RETRIES" \
      -oX "$UDP_XML" "$CIDR" >/dev/null 2>&1

    # Convert XML to JSON using Python
    python3 - <<'PY' "$UDP_XML" "$UDP_JSON"
import sys, json, subprocess

try:
    import xmltodict
except ModuleNotFoundError:
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--user", "xmltodict"])
    import xmltodict

xml_file, json_file = sys.argv[1:3]

try:
    with open(xml_file) as f:
        xml = f.read()
    data = xmltodict.parse(xml)
    with open(json_file, "w") as f:
        json.dump(data, f, indent=2)
except Exception as e:
    with open(json_file, "w") as f:
        json.dump({"error": str(e)}, f)
PY
  ) &
  UDP_PID=$!

  # Wait for both scans to complete
  echo "   Waiting for scans to complete..."
  wait "$TCP_PID"
  wait "$UDP_PID"

  # --------------------------------------------------------------------------
  # PROCESS TCP RESULTS
  # --------------------------------------------------------------------------

  # Naabu output format: host:port (e.g., 192.168.1.1:80)
  # Convert to structured JSON grouped by host
  if [ -s "$NAABU_RAW" ]; then
    jq -R -s '
      split("\n")
      | map(select(length > 0))
      | map(split(":") | select(length == 2) | {host: .[0], port: (.[1] | tonumber)})
      | group_by(.host)
      | map({host: .[0].host, ports: map(.port) | sort})
    ' "$NAABU_RAW" > "$TCP_JSON"
  else
    echo "[]" > "$TCP_JSON"
  fi

  # Count results
  TCP_COUNT=$(jq '[.[].ports[]] | length' "$TCP_JSON" 2>/dev/null || echo "0")
  UDP_COUNT=$(jq '.. | .portid? | select(. != null)' "$UDP_JSON" 2>/dev/null | wc -l || echo "0")

  # --------------------------------------------------------------------------
  # MERGE RESULTS
  # --------------------------------------------------------------------------

  jq -n \
    --arg subnet "$CIDR" \
    --slurpfile tcp "$TCP_JSON" \
    --slurpfile udp "$UDP_JSON" \
    '{
      subnet: $subnet,
      scan_time: now | strftime("%Y-%m-%dT%H:%M:%SZ"),
      tcp: $tcp[0],
      udp: $udp[0]
    }' > "$COMBINED_JSON"

  # Fix file ownership if running with sudo
  if [ -n "${SUDO_USER:-}" ]; then
    sudo chown -R "$OWN_USER":"$OWN_USER" "$SUBNET_DIR"
  fi

  # --------------------------------------------------------------------------
  # SUMMARY
  # --------------------------------------------------------------------------

  echo -e "\n\033[1;32m✅ Finished $CIDR\033[0m"
  echo -e "   TCP open ports: \033[1;35m${TCP_COUNT}\033[0m"
  echo -e "   UDP open ports: \033[1;36m${UDP_COUNT}\033[0m"
  echo -e "   Combined JSON:  ${COMBINED_JSON}"
  echo -e "--------------------------------------------------------------"

done

# ============================================================================
# GENERATE MASTER REPORT
# ============================================================================

echo -e "\n\033[1;32mAll scans complete!\033[0m"

# Merge all subnet JSONs into a single master file
MASTER_JSON="$RESULTS_DIR/all_scans_combined.json"
jq -s '.' "$RESULTS_DIR"/*/combined.json > "$MASTER_JSON"

echo -e "\033[1;36m📦 Master JSON:\033[0m $MASTER_JSON"

# Fix ownership of master file
if [ -n "${SUDO_USER:-}" ]; then
  sudo chown "$SUDO_USER:$SUDO_USER" "$MASTER_JSON"
fi

echo -e "\nResults saved to: $RESULTS_DIR"
