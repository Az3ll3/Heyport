
# HeyPort — Complete Installation Guide

> Tested on Kali Linux 2024+. Most tools are pre-installed or one command away on Kali.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Prepare the Environment](#2-prepare-the-environment)
3. [Configure Go PATH](#3-configure-go-path--most-missed-step)
4. [Configure Cargo PATH](#4-configure-cargo-path)
5. [Install All Tools](#5-install-all-tools)
6. [Verify Everything Works](#6-verify-everything-works)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. System Requirements

| Requirement | Minimum |
| ----------- | ------- |
| OS | Kali Linux 2024+ (recommended), any Debian-based |
| Python | 3.8+ |
| Go | 1.21+ |
| Rust | stable |
| RAM | 4GB |
| Disk | 2GB free (for nuclei templates) |

---

## 2. Prepare the Environment

Always start with a system update. Outdated package lists cause silent installation failures.

```bash
sudo apt update && sudo apt upgrade -y
```

Install core dependencies:

```bash
sudo apt install -y git curl wget unzip build-essential
sudo apt install -y python3 python3-pip
sudo apt install -y golang-go
sudo apt install -y cargo rustup
sudo apt install -y dnsutils whois nmap whatweb gobuster dnsrecon
```

> **Why golang-go and cargo?**
> About 70% of HeyPort's tools are written in Go or Rust.
> Without these runtimes, most tools won't install.

Install Python dependency:

```bash
pip3 install requests --break-system-packages
```

---

## 3. Configure Go PATH — Most Missed Step

Go installs its binaries to `~/go/bin`. If this is not in your `$PATH`, every `go install` will succeed — the binary exists on disk — but the shell returns `command not found` when HeyPort tries to run it.

**This is the #1 reason tools appear installed but don't work.**

For **zsh** (default on Kali):

```bash
echo 'export PATH=/root/go/bin:$PATH' >> ~/.zshrc
source ~/.zshrc
```

For **bash**:

```bash
echo 'export PATH=/root/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

> **Important:** `go/bin` must come BEFORE `/usr/bin` in PATH order.
> Use `/root/go/bin:$PATH` (Go first) — NOT `$PATH:/root/go/bin` (Go last).
> If Go comes last, the system's version of a tool wins over your installed one.

Verify:

```bash
echo $PATH
# Should start with /root/go/bin:...

which subfinder
# Should return /root/go/bin/subfinder after installation
```

---

## 4. Configure Cargo PATH

Same issue for Rust tools — they install to `~/.cargo/bin`.

```bash
echo 'export PATH=$HOME/.cargo/bin:$PATH' >> ~/.zshrc
source ~/.zshrc

rustup default stable
```

---

## 5. Install All Tools

### Go Tools

```bash
# subfinder — aggregates 50+ passive subdomain sources
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# dnsx — DNS resolution, brute force, mass querying
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# httpx — HTTP probing, status codes, tech detection
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei — vulnerability scanner with community templates
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# alterx — smart subdomain mutation and permutation engine
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest

# puredns — wildcard-aware DNS brute force
go install github.com/d3mondev/puredns/v2@latest

# assetfinder — fast passive subdomain discovery
go install github.com/tomnomnom/assetfinder@latest

# subjack — subdomain takeover vulnerability scanner
go install github.com/haccer/subjack@latest

# webanalyze — bulk Wappalyzer tech detection engine
go install github.com/rverton/webanalyze@latest

# dalfox — XSS parameter hunter, confirmed POC output
go install github.com/hahwul/dalfox/v2@latest
```

### Rust Tools

```bash
# rustscan — scans all 65535 ports in seconds via async I/O
cargo install rustscan
```

### Python Tools

```bash
# bbot — recursive subdomain enumeration
pip3 install bbot --break-system-packages

# wafw00f — WAF detection, 200+ signatures
pip3 install wafw00f --break-system-packages
```

### APT Tools

Already installed on Kali, but run this to be safe:

```bash
sudo apt install -y nmap gobuster dnsrecon whatweb whois dnsutils
```

### Post-Install: nuclei Templates

nuclei ships without templates. Download the community template library (~4000 templates):

```bash
nuclei -update-templates
```

This installs to `~/.nuclei-templates/` and takes 1-2 minutes.

---

## 6. Verify Everything Works

HeyPort has a built-in tool checker. Always run this before a scan:

```bash
python3 heyport.py --check-tools
```

You should see a green checkmark for all 19 tools. Fix any red X before running.

Manual spot check for the most critical tools:

```bash
subfinder -version
dnsx -version
httpx -version       # must say ProjectDiscovery, NOT a Python version
nuclei -version
puredns --version
rustscan --version
```

> **httpx version check:**
> There are two tools named `httpx` — a Python HTTP client and ProjectDiscovery's web prober.
> HeyPort needs ProjectDiscovery's version. Run `httpx -version` and confirm it shows:
>
> ```text
> projectdiscovery.io
> Current Version: v1.x.x
> ```
>
> If it says `Usage: httpx [OPTIONS] URL` — you have the Python one.
> Fix: make sure `/root/go/bin` is at the FRONT of your PATH (Step 3).

---

## 7. Troubleshooting

### "command not found" after successful install

Your PATH is wrong. Run:

```bash
ls ~/go/bin/           # list all Go tools — should be there
which subfinder        # returns empty if PATH is wrong
export PATH=/root/go/bin:$PATH   # temporary fix for current session
```

Then go back to Step 3 and fix it permanently.

### dnsx returns 0 results

HeyPort has 4 fallback layers for this:

1. Retry with lower threads
2. Retry without `-resp` flag (changed between versions)  
3. Batch mode — 100 subdomains at a time
4. Python socket fallback — bypasses dnsx entirely

If you still see 0 results, your DNS resolver may be rate-limiting. Try:

```bash
# Test if basic DNS works
dig google.com
nslookup google.com
```

### httpx probing returns 0 HTTP alive

Almost always a PATH issue — system httpx (Python) being called instead of ProjectDiscovery httpx (Go). See the httpx version check above.

### nuclei finds nothing

Update templates first:

```bash
nuclei -update-templates
```

Then test manually:

```bash
nuclei -u https://testphp.vulnweb.com -severity critical,high -silent
```

---

## Test Your Setup

Run against this intentionally vulnerable site — legal, no Cloudflare, all phases fire:

```bash
python3 heyport.py -t testphp.vulnweb.com
```

You should see real HTTP alive targets, real findings from nuclei, and confirmed XSS from dalfox.
