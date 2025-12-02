# BlockHound

A fast, parallel network scanner that performs comprehensive TCP and UDP port scanning across multiple /24 subnets. Combines [naabu](https://github.com/projectdiscovery/naabu) for rapid TCP scanning with nmap for UDP scanning, outputting results in JSON format for easy analysis.

## Features

- **Parallel scanning** — TCP and UDP scans run simultaneously for each subnet
- **Full TCP coverage** — Scans all 65,535 TCP ports using naabu
- **UDP top ports** — Scans top 1000 UDP ports with nmap
- **JSON output** — Structured results for easy parsing and integration
- **Configurable** — Adjust scan rates, timeouts, and retries via environment variables
- **Sequential subnet processing** — Scans multiple /24 subnets in sequence

## Requirements

- **naabu** — Install with: `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`
- **nmap** — Install with: `sudo apt-get install nmap`
- **jq** — Install with: `sudo apt-get install jq`
- **Python 3** with `xmltodict` (auto-installed if missing)

## Installation

```bash
git clone https://github.com/KaseyMcGrath/BlockHound-.git
cd BlockHound-
chmod +x blockhound.sh
```

## Usage

```bash
# Basic usage (requires sudo for raw socket access)
sudo ./blockhound.sh <start_octet>-<end_octet>

# Examples
sudo ./blockhound.sh 1-5       # Scans 192.168.1.0/24 through 192.168.5.0/24
sudo ./blockhound.sh 10-10     # Scans only 192.168.10.0/24
sudo ./blockhound.sh 0-255     # Scans entire 192.168.x.0/24 range
```

## Configuration

Set environment variables to customize the scanner:

```bash
# Change target network (default: 192.168)
export BASE_NET="10.0"

# Change output directory (default: ~/scan_results)
export RESULTS_DIR="/path/to/results"

# Adjust scan performance
export NAABU_RATE=5000        # TCP packets/sec (default: 8000)
export NMAP_MIN_RATE=500      # UDP min rate (default: 800)
export RETRIES=3              # Retry count (default: 2)

# Run with custom settings
sudo -E ./blockhound.sh 1-10
```

> **Note:** Use `sudo -E` to preserve environment variables when running with sudo.

## Output Structure

```
scan_results/
├── 192_168_1/
│   ├── naabu_raw.txt      # Raw naabu output (host:port format)
│   ├── tcp.json           # Parsed TCP results
│   ├── udp.xml            # Raw nmap XML output
│   ├── udp.json           # Parsed UDP results
│   └── combined.json      # Merged TCP + UDP results
├── 192_168_2/
│   └── ...
└── all_scans_combined.json  # Master file with all subnets
```

### JSON Output Format

**Per-subnet combined.json:**
```json
{
  "subnet": "192.168.1.0/24",
  "scan_time": "2024-01-15T14:30:00Z",
  "tcp": [
    {
      "host": "192.168.1.1",
      "ports": [22, 80, 443]
    }
  ],
  "udp": { ... }
}
```

## Use Cases

- **Security assessments** — Identify open ports across network segments
- **Asset discovery** — Find active hosts and services
- **Compliance auditing** — Verify expected services and detect unauthorized ports
- **Attack surface mapping** — Document external-facing infrastructure

## Performance Tips

- Start with lower rates on congested networks: `NAABU_RATE=3000`
- Increase retries for unreliable networks: `RETRIES=3`
- The script automatically increases file descriptor limits when possible

## Legal Disclaimer

⚠️ **Only scan networks you own or have explicit written permission to test.** Unauthorized port scanning may violate computer crime laws in your jurisdiction.

## License

MIT License — See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
