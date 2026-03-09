<!-- markdownlint-disable MD033 MD045 -->
<h1 align="center">
  <br>
  <img src="docs/screenshots/banner.png" alt="HeyPort" width="600">
  <br>
  HeyPort
  <br>
</h1>

<h4 align="center">Automated Recon Framework for Bug Bounty Hunters & Penetration Testers</h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-v3.2-0891B2?style=for-the-badge" alt="version v3.2">
  <img src="https://img.shields.io/badge/python-3.8+-3572A5?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/tools-19_integrated-059669?style=for-the-badge" alt="19 tools">
  <img src="https://img.shields.io/badge/license-MIT-DC2626?style=for-the-badge" alt="MIT license">
  <img src="https://img.shields.io/badge/platform-Kali_Linux-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Kali Linux">
</p>

<p align="center">
  <b>One command → Full attack surface map</b><br>
  19 tools · 5 phases · Cross-verified output · Interactive HTML report
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#output">Output</a> •
  <a href="docs/how-it-works.md">How It Works</a> •
  <a href="INSTALL.md">Full Install Guide</a>
</p>
<!-- markdownlint-enable MD033 MD045 -->

---

## The Problem It Solves

Before HeyPort, a recon session looked like this: open 6 terminals, run tools in the wrong order, pipe output manually between them, forget to save something, end up with 15 disconnected text files — **two hours before you even started testing anything.**

HeyPort collapses that entire workflow into one command.

```bash
python3 heyport.py -t target.com
```

---

## Pipeline Overview

| Phase | Name | Mode | What Happens |
| ----- | ---- | ---- | ------------ |
| 1 | Target Overview | Passive | DNS records, WHOIS, IP/ASN/Geo, Shodan passive, org OSINT, breach check |
| 2 | Subdomain Enumeration | Passive + Active | Zone transfer, brute force (3 engines), 10 passive sources, smart mutations |
| 3 | Active Filtering | Active | DNS resolution, HTTP probing (14 ports), tier classification, WAF, takeover scan |
| 4 | Scanning | Active | All 65535 ports via RustScan→nmap, tech detection (webanalyze + whatweb) |
| 5 | Vulnerability Mapping | Active | nuclei (Critical/High + Medium), dalfox XSS hunting |
| — | Report | Output | Self-contained HTML dashboard + recon_map.json |

---

## Features

### Subdomain Enumeration

- 10+ passive sources queried simultaneously (crt.sh, subfinder, assetfinder, BBOT, HackerTarget, AlienVault, RapidDNS, SecurityTrails, Chaos, VirusTotal)
- 3 active brute-force engines with wildcard detection (puredns, gobuster, dnsx)
- Smart mutation engine via alterx — finds subdomains no database has ever seen
- Cross-verification: subdomains found by 2+ independent sources marked **CONFIRMED**

### Smart Filtering

- HTTP probing across 14 ports (catches Grafana:3000, Jenkins:8080, Prometheus:9090, etc.)
- Automatic tier classification — tells you exactly where to start hacking
- Subdomain takeover detection across 50+ third-party services
- WAF fingerprinting with 200+ signatures

### Intelligence

- Cloudflare origin IP bypass (4 passive techniques)
- Year-prefix legacy infrastructure detection (`2017-grafana`, `2019-k8s`)
- Organization OSINT — company profile, GitHub org, IP ranges, breach history
- Shodan passive CVE lookup (zero packets to target)

### Report Output

- Single self-contained HTML report — dark theme, interactive, everything connected
- Structured `recon_map.json` for piping into other tools
- Priority target list (`p3_tier1_priority.txt`) — open and start hacking immediately

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Crypto-void787/heyport.git
cd heyport

# Install Python dependency
pip3 install requests --break-system-packages

# Check all tools are ready
python3 heyport.py --check-tools

# Run recon
python3 heyport.py -t target.com
```

> Full installation guide with every tool: **[INSTALL.md](INSTALL.md)**

---

## Installation

HeyPort requires **19 external tools**. Quick install for Kali Linux:

```bash
# Core dependencies
sudo apt install -y golang-go cargo rustup nmap gobuster dnsrecon whatweb whois dnsutils

# Add Go to PATH (critical)
echo 'export PATH=/root/go/bin:$PATH' >> ~/.zshrc && source ~/.zshrc

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/haccer/subjack@latest
go install github.com/rverton/webanalyze@latest
go install github.com/hahwul/dalfox/v2@latest

# Rust tools
cargo install rustscan

# Python tools
pip3 install bbot wafw00f --break-system-packages

# Update nuclei templates
nuclei -update-templates
```

> Step-by-step guide with PATH setup and verification: **[INSTALL.md](INSTALL.md)**

---

## Usage

```bash
# Full recon — all 5 phases
python3 heyport.py -t target.com

# Custom output directory
python3 heyport.py -t target.com -o /path/to/output

# Run a specific phase only
python3 heyport.py -t target.com --phase 2

# Skip vulnerability scanning (Phase 5)
python3 heyport.py -t target.com --skip-vuln

# Verify all tools are installed
python3 heyport.py --check-tools
```

---

## Output

```text
recon_output/target.com/YYYYMMDD_HHMMSS/
│
├── recon_report.html               ← Open this in browser
├── recon_map.json                  ← All data structured
│
├── p2_all_subdomains.txt           ← Every subdomain found
├── p2_confirmed_subdomains.txt     ← Cross-verified (2+ sources)
│
├── p3_dns_alive.txt                ← Resolving hostnames
├── p3_http_alive.txt               ← HTTP responding URLs
├── p3_tier1_priority.txt           ← ★ Attack these first
├── p3_takeover_risks.txt           ← Critical — subdomain takeovers
├── p3_waf_results.txt              ← WAF detections
│
├── p4_nmap_via_rustscan.txt        ← Full port scan results
│
├── p5_nuclei_pass1_critical_high.txt
├── p5_nuclei_pass2_medium.txt
└── p5_dalfox_xss.txt               ← Confirmed XSS POCs
```

### Tier Classification

| Tier | Label | Criteria |
| ---- | ----- | -------- |
| ★ 1 | HIGH PRIORITY | Juicy keyword hit OR takeover risk OR year-prefix (`2017-x`) OR alive + no WAF |
| 2 | ACTIVE | HTTP responds on any port |
| 3 | DNS ONLY | Resolves but no HTTP response — scan for non-HTTP services |
| 4 | INACTIVE | Does not resolve |

---

## Tested On

- Kali Linux 2024+
- Python 3.8+
- Go 1.21+

---

## Legal Disclaimer

> **For authorized security research only.**
> Only use HeyPort against targets you have explicit written permission to test.
> Running recon against systems without authorization is illegal in most jurisdictions.
> The author is not responsible for any misuse.

---

## Author

Built by **[Crypto-void787](https://github.com/Crypto-void787)** — bug bounty hunter & security researcher.

---

## License

[MIT](LICENSE) — free to use, modify, and distribute with attribution.
