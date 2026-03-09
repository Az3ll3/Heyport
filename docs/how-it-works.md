# How HeyPort Works: Technical Deep Dive

This document covers every phase in detail: what data goes in, what happens to it, what comes out, and how each output helps you find and exploit vulnerabilities.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Phase 1 — Target Overview](#phase-1--target-overview)
3. [Phase 2 — Subdomain Enumeration](#phase-2--subdomain-enumeration)
4. [Phase 3 — Active Filtering](#phase-3--active-filtering)
5. [Phase 4 — Scanning](#phase-4--scanning)
6. [Phase 5 — Vulnerability Mapping](#phase-5--vulnerability-mapping)
7. [The ReconMap](#the-reconmap)
8. [Tier Classification Logic](#tier-classification-logic)
9. [Cross-Verification Logic](#cross-verification-logic)
10. [Severity Criteria](#severity-criteria)

---

## Architecture

HeyPort is a Python orchestration layer. It doesn't do the work itself, it runs 19 best-in-class tools in the right order, feeds output from one into the input of the next, cross-verifies all results, and structures everything into a single data store.

```text
TARGET DOMAIN
     │
     ▼
┌─────────────────────────────────────────────┐
│  PHASE 1 — Passive Intel                    │
│  dig · whois · ipinfo.io · Shodan · crt.sh  │
│  theHarvester · Clearbit · GitHub · BGPView  │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  PHASE 2 — Subdomain Enumeration            │
│  Zone transfer · NSEC walk · Direct DNS     │
│  puredns · gobuster · dnsx (brute)          │
│  subfinder · assetfinder · BBOT             │
│  crt.sh · HackerTarget · AlienVault · more  │
│  alterx mutations                           │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  PHASE 3 — Active Filtering                 │
│  dnsx (resolve) → httpx (14 ports)          │
│  Tier classification · wafw00f · subjack    │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  PHASE 4 — Scanning                         │
│  RustScan → nmap (-sV -O)                   │
│  webanalyze · whatweb                       │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  PHASE 5 — Vulnerability Mapping            │
│  nuclei (Critical/High) · nuclei (Medium)   │
│  dalfox XSS                                 │
└────────────────────┬────────────────────────┘
                     │
                     ▼
            recon_map.json
           recon_report.html
```

Every phase writes to the same `ReconMap` data structure. Nothing is lost between phases. The HTML report reads from this single source of truth.

---

## Phase 1 — Target Overview

### Entry Point

`socket.gethostbyname(target)` resolves the main domain to its primary IP. This IP anchors all Phase 1 lookups.

### DNS Record Analysis

HeyPort queries every DNS record type independently via `dig`:

| Record | Contains | What It Reveals |
| ------ | -------- | --------------- |
| A | IPv4 addresses | If in Cloudflare ranges (104.x, 172.64-67.x) — real server is hidden |
| AAAA | IPv6 addresses | Some targets forget to protect IPv6 — direct origin access |
| MX | Mail servers | Mail often bypasses CDN — MX IP may be the real hosting server |
| TXT | SPF, DKIM, verifications | SPF lists real server IPs. Also reveals third-party integrations |
| NS | Nameservers | Cloudflare NS = CDN+WAF active. Custom NS = self-managed, higher risk |
| CNAME | Aliases | Points to third-party services — takeover candidates |
| SOA | Zone authority | Low TTL = frequent DNS changes = active deployment cycles |

### Cloudflare Origin IP Bypass

When A records resolve to Cloudflare IPs, HeyPort attempts 4 passive bypass techniques:

1. **SPF Record Extraction** — TXT records contain real server IPs for email delivery. Cloudflare never modifies TXT records.
2. **MX Record IP** — Mail servers almost never sit behind Cloudflare. Resolving the MX hostname often reveals the hosting network.
3. **SecurityTrails Historical DNS** — The domain may have pointed directly to the origin before adding Cloudflare.
4. **Shodan Certificate Search** — Shodan indexes SSL certs by IP. If the origin has the domain cert installed, Shodan has its real IP.

### Organization OSINT

Runs in parallel with DNS lookups:

- **Clearbit** — Free company profile from domain (no key required)
- **GitHub API** — Org repos, description, public email, member count
- **Hunter.io** — Professional email addresses and naming pattern
- **BGPView** — All IP ranges the organization owns (CIDR blocks)
- **HIBP** — Known data breach history for the domain
- **Cloud detection** — Maps ASN string to AWS/GCP/Azure/Cloudflare/Hetzner/etc.

---

## Phase 2 — Subdomain Enumeration

Four-step pipeline running sequentially.

### Step A — DNS Recon Tricks

Free techniques that run before any brute force:

**Zone Transfer (AXFR):** Requests a complete copy of the DNS zone from each nameserver. If the nameserver is misconfigured, it hands over every record — every subdomain, every IP, every service — in one response.

**NSEC Walking:** DNSSEC zones using plain NSEC (not NSEC3) create a signed chain linking every hostname. Walking the chain enumerates every subdomain without brute force.

**Direct DNS on 80+ High-Value Names:** Resolves known high-value prefixes in parallel using 80 threads. Names like `admin`, `vpn`, `jenkins`, `grafana`, `cpanel`, `staging`, `k8s`, `kibana`. One real hit here is worth more than 1000 brute-force results.

### Step B — Active Brute Force (3 Engines)

Takes a wordlist and resolves every word against the target domain. Three engines run the same wordlist because they use different algorithms and catch different edge cases:

**puredns** — Wildcard-aware. Detects if `random-uuid.target.com` resolves (wildcard DNS active). If so, identifies the wildcard IP and filters it from all results. Other tools return 5000 false positives. puredns returns 0.

**gobuster dns** — Different DNS resolution algorithm. Catches things puredns misses on rate-limited targets.

**dnsx -w** — Built-in brute mode, outputs IP addresses alongside hostnames.

### Step C — Passive API Sources (10 Sources)

Queried simultaneously, zero packets to target:

| Source | What It Contains |
| ------ | ---------------- |
| crt.sh | Every SSL certificate ever issued — permanent, even for dead subdomains |
| subfinder | 50+ aggregated passive sources |
| assetfinder | CT logs + crawlers — different backend than subfinder |
| HackerTarget | DNS database records |
| AlienVault OTX | Threat intelligence passive DNS — subdomains seen in security incidents |
| RapidDNS | Historical DNS records |
| SecurityTrails | Historical DNS data |
| Chaos (ProjectDiscovery) | Pre-enumerated bug bounty program data |
| VirusTotal | Passive DNS from malware scanning |
| BBOT | Recursive — enumerates subdomains of subdomains |

### Step D — Mutation Engine

`alterx` analyzes all discovered subdomains and learns naming patterns. If it found `dev-api` and `staging-api`, it generates: `prod-api`, `test-api`, `uat-api`, `qa-api`, `v2-api`, `old-api`, `internal-api`, and hundreds more. `dnsx` resolves all candidates.

**Why mutations matter:** `dev-payments.target.com` will never appear in any passive source or wordlist. But if the company uses that naming pattern, alterx generates it and dnsx confirms it exists. These are subdomains nobody else has ever found.

---

## Phase 3 — Active Filtering

### DNS Resolution

`dnsx` resolves all discovered subdomains. Four fallback layers if dnsx returns 0:

1. Normal run (50 threads, -resp flag)
2. Retry without -resp flag (changed behavior in newer versions)
3. Batch mode — 100 subdomains at a time
4. Python socket fallback — bypasses dnsx entirely

**Critical detail:** dnsx outputs `subdomain.com [1.2.3.4]` format. httpx cannot parse hostnames with IPs appended. HeyPort strips the IP and rewrites the file with clean hostnames before httpx reads it. This was the root cause of HTTP Alive = 0 in early versions.

### HTTP Probing — 14 Ports

httpx probes every DNS-alive subdomain across 14 ports simultaneously:

| Port | Common Service |
| ---- | -------------- |
| 80/443 | Standard HTTP/HTTPS |
| 8080 | Jenkins, Tomcat, dev servers |
| 8443 | Internal APIs, admin panels |
| 3000 | Grafana, Node.js, React dev |
| 9090 | Prometheus, Cockpit |
| 8000 | Django/Flask dev servers |
| 8888 | Jupyter notebooks |
| 4443/9443/7443 | Alternate HTTPS |
| 5000 | Flask, Docker registry |
| 3001/8008 | Node.js alternate, IoT admin |

**Why 14 ports:** Development tools never run on standard ports. Probing only 80+443 misses Grafana (3000), Jenkins (8080), Prometheus (9090), and all internal admin panels entirely.

### Tier Classification

See [Tier Classification Logic](#tier-classification-logic) below.

### WAF Detection

`wafw00f` sends specially crafted requests to detect which WAF is protecting the target. Knows 200+ WAF signatures. Runs on first 50 HTTP targets.

### Subdomain Takeover

`subjack` checks CNAME chains against 50+ third-party services. If a CNAME points to an unclaimed destination, that subdomain can be taken over. HeyPort filters `[Not Vulnerable]` lines — the count shown is real findings only.

---

## Phase 4 — Scanning

### RustScan + nmap Pipeline

**RustScan** uses async I/O to scan all 65,535 TCP ports in seconds. It finds which ports are open and hands that list to nmap.

**nmap** runs on the open ports only:

- `-sV` — Service version detection against 5,000+ fingerprints
- `-O` — OS fingerprinting via TCP/IP stack behavior analysis

Result: exact service names and versions on every open port. `Apache 2.4.49` instead of just `port 80 open`.

### Technology Detection — 3 Layers

| Layer | Tool | Scope | Depth |
| ----- | ---- | ----- | ----- |
| 1 | httpx (Phase 3) | All alive hosts | Quick Wappalyzer signatures |
| 2 | webanalyze | All HTTP targets | Full Wappalyzer engine with crawling |
| 3 | whatweb | Tier 1 only (top 20) | 600+ plugins, exact version strings |

All three results merge into one tech list per subdomain, categorized into: Language, Server, CMS, Framework, JS Library, CDN, Cloud, Database, Analytics, Security, OS.

---

## Phase 5 — Vulnerability Mapping

### nuclei — Two Pass System

**Pass 1 (Critical + High):** Templates tagged `cve`, `takeover`, `exposure`, `default-login` at critical or high severity.

**Pass 2 (Medium):** Misconfigurations, information disclosure, weaker findings.

Template categories:

- **CVE templates** — Log4Shell, Spring4Shell, ProxyShell, ProxyLogon — matched by version fingerprint or endpoint behavior
- **Default credentials** — Jenkins, Grafana, phpMyAdmin, Kibana, Elasticsearch
- **Exposed files** — `.env`, `.git`, backup files, `composer.lock`
- **Admin panel exposure** — phpMyAdmin, Adminer, Kibana, cPanel without auth
- **Misconfigurations** — Open redirects, CORS wildcards, debug mode, directory listing

### dalfox — Context-Aware XSS

dalfox crawls targets, discovers parameters, and tests each one with context-aware payloads:

- HTML attribute reflection → attribute-escape payload
- JavaScript string reflection → string-escape payload  
- HTML body reflection → standard tag payload

`--only-poc r` flag — only reports confirmed exploitable XSS with working proof-of-concept. Every entry in `p5_dalfox_xss.txt` is ready to submit to a bug bounty program.

---

## The ReconMap

Central data structure — a Python dictionary serialized to `recon_map.json` after every phase. Structure:

```json
{
  "target": "corvit.com",
  "overview": {
    "ips": [], "dns": {}, "whois": {}, "asn": "",
    "org": "", "cloud": "", "osint": {}
  },
  "subdomains": {
    "sub.domain.com": {
      "sources": ["subfinder", "crt.sh"],
      "confirmed": true,
      "ips": ["1.2.3.4"],
      "tier": 1,
      "http": {"status": 200, "title": "...", "tech": []},
      "waf": "Cloudflare",
      "takeover_risk": false
    }
  },
  "hosts": {
    "1.2.3.4": {
      "ports": [80, 443, 8080],
      "services": {"80": {"service": "http", "version": "Apache 2.4.49"}},
      "os": "Linux 4.x",
      "hostnames": ["sub.domain.com"]
    }
  },
  "findings": [
    {
      "type": "subdomain_takeover",
      "severity": "critical",
      "target": "old.domain.com",
      "detail": "...",
      "source": "subjack"
    }
  ],
  "web": []
}
```

The HTML report reads directly from this structure. All data from all phases is connected — when nuclei finds a CVE on a subdomain, it appears alongside that subdomain's tier, tech stack, and port data in the report.

---

## Tier Classification Logic

```python
TIER1_KEYWORDS = {
    'admin','administrator','panel','dashboard','portal','console',
    'vpn','remote','gateway','citrix','rdp','ssh','bastion',
    'dev','develop','development','staging','stage','test','testing','uat','qa',
    'internal','intranet','corp','corporate','private','secure',
    'api','backend','microservice','service','graphql','rest',
    'jenkins','jira','confluence','gitlab','github','bitbucket',
    'grafana','kibana','prometheus','elastic','splunk','datadog',
    'db','database','mysql','postgres','redis','mongo',
    'mail','smtp','webmail','exchange','owa',
    'ftp','sftp','nas','storage','backup','bak',
    'k8s','kubernetes','docker','rancher','registry',
    'sso','auth','oauth','login','identity','ldap','saml',
    'payment','pay','billing','checkout','stripe',
    'legacy','old','deprecated','archive','v1','v2','v3',
    'phpmyadmin','adminer','cpanel','whm','plesk','webmin',
}

def _classify_tier(subdomain, data):
    parts    = set(re.split(r'[-_.]', subdomain.lower()))
    has_http = bool(data.get('http', {}).get('status'))
    has_ips  = bool(data.get('ips'))
    has_risk = data.get('takeover_risk', False)
    kw_hit   = bool(parts & TIER1_KEYWORDS)
    no_waf   = not data.get('waf')
    year_hit = bool(re.match(r'^20\d{2}[-_]', subdomain))

    if kw_hit or has_risk or year_hit or (has_http and no_waf and has_ips):
        return 1   # HIGH PRIORITY
    elif has_http:
        return 2   # ACTIVE
    elif has_ips:
        return 3   # DNS ONLY
    return 4       # INACTIVE
```

Decision tree:

```text
Does it resolve (has IP)?    NO  → Tier 4
         ↓ YES
Does HTTP respond?           NO  → Tier 3
         ↓ YES
Keyword OR takeover OR      YES  → Tier 1
year-prefix OR (alive+noWAF)?
         ↓ NO
                                 → Tier 2
```

---

## Cross-Verification Logic

Every subdomain is tracked with which tools found it. A subdomain found by 2+ independent sources is marked CONFIRMED.

```python
if len(sources[subdomain]) >= 2:
    confirmed.append(subdomain)
```

Why this matters:

- crt.sh returns permanent CT log data — a subdomain may have been decommissioned years ago
- One passive source may return stale data
- Two independent sources agreeing = subdomain very likely exists right now

---

## Severity Criteria

| Severity | Source | Trigger |
| -------- | ------ | ------- |
| Critical | subjack | CNAME points to unclaimed third-party service |
| High | Shodan InternetDB | Known CVE on target IP |
| High | Year-prefix detection | Subdomain matches `^20\d{2}[-_]` pattern |
| High | dalfox | Confirmed exploitable XSS with POC |
| High | nuclei | Template with `severity: high` fires |
| Medium | httpx | Service on non-standard port (8080/9090/3000/etc.) |
| Medium | httpx tech | Old JavaScript library version detected |
| Medium | whatweb | EOL technology version detected (PHP 7.x, etc.) |
| Medium | nuclei | Template with `severity: medium` fires |
| Info | wafw00f | WAF identified |
| Info | whatweb | Technology version recorded |
