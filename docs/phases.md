# Phases

## HeyPort — Phase by Phase Breakdown

Every phase explained in detail. What runs, what it produces, and what it means for your recon.

---

## Phase 1 — Target Overview

**Mode:** Fully Passive  
**Output:** `recon_map.json` (overview section updated)  
**Time:** ~2-3 minutes

### What Runs

| Tool | Job |
| ---- | --- |
| `dig` | Queries all DNS record types — A, AAAA, MX, NS, TXT, SOA, CNAME |
| `whois` | Registration data — registrar, creation date, expiry, nameservers |
| `ipinfo.io` | Geolocation, ISP, ASN, organization name for the main IP |
| `Shodan InternetDB` | Passive port scan history + CVEs for the main IP (zero packets sent) |
| `crt.sh` | SSL certificate history — how many certs, when issued |
| `theHarvester` | Email addresses and extra hostnames from 30+ public sources |

### OSINT Sub-Phase (runs inside Phase 1)

| Source | What It Returns |
| ------ | --------------- |
| Clearbit | Company name, industry, description |
| GitHub API | Public repos, org description, email, member count |
| Hunter.io | Professional email addresses and naming pattern |
| BGPView | All IP ranges the org owns (CIDR blocks) |
| HIBP | Known data breach history for the domain |
| Cloud detection | Maps ASN to AWS / GCP / Azure / Cloudflare / Hetzner |

### Cloudflare Origin Bypass (triggers automatically if CF detected)

If the A record resolves to Cloudflare IPs, HeyPort attempts 4 passive origin discovery techniques:

1. SPF record extraction — TXT records list real server IPs for email delivery
2. MX record IP resolution — mail servers bypass CDN, often reveal hosting network
3. SecurityTrails historical DNS — may show direct A record before Cloudflare was added
4. Shodan cert search — if origin has the domain cert installed, Shodan has its real IP

### What It Means for You

- ASN reveals cloud provider → tells you which SSRF targets and metadata endpoints to try
- MX IP is often the real server IP hiding behind Cloudflare
- TXT/SPF records contain real server IPs directly — most people miss this
- Breach history means credential stuffing is on the table
- BGP ranges = all fair-game IP space in a full-scope bug bounty program

---

## Phase 2 — Subdomain Enumeration

**Mode:** Passive + Active  
**Output:** `p2_all_subdomains.txt`, `p2_confirmed_subdomains.txt`  
**Time:** ~5-15 minutes depending on target size

### Step A — DNS Recon Tricks

Free techniques that run before brute force:

**Zone Transfer (AXFR)**
Asks each nameserver for a complete copy of the DNS zone. If misconfigured, returns every subdomain, every IP, every service record in one shot. Still works on legacy setups.

**NSEC Walking**
DNSSEC zones using plain NSEC expose a signed chain linking every hostname. Walking the chain enumerates the full zone without brute force. Blocked by NSEC3 (hashed), but some targets still use plain NSEC.

**Direct DNS on 80+ High-Value Names**
Resolves 80+ known attack-surface names in parallel using 80 threads:

```text
admin, vpn, jenkins, grafana, cpanel, staging, dev, api,
k8s, kibana, prometheus, internal, phpmyadmin, adminer,
gitlab, confluence, jira, rdp, citrix, bastion, storage,
backup, db, mysql, redis, mongo, elastic, splunk, datadog...
```

One real hit here is worth more than 1000 random brute-force hits.

### Step B — Active Brute Force (3 Engines)

Takes a wordlist and resolves every word against the target domain.

#### puredns

- Detects wildcard DNS first (`*.target.com = 1.2.3.4`)
- If wildcard active, identifies the wildcard IP and filters ALL matches against it
- Without this: 5000 words = 5000 fake results
- With puredns: 5000 words = only real results
- Uses pool of trusted public resolvers to avoid rate limiting

#### gobuster dns

- Different resolver algorithm, catches things puredns misses
- Different timeout and retry behavior on rate-limited targets

#### dnsx -w

- Built-in brute mode
- Outputs results with IPs already attached

### Step C — Passive API Sources (10 Sources)

All queried simultaneously. Zero packets to target.

| Source | Unique Strength |
| ------ | ---------------- |
| `crt.sh` | Permanent CT logs — finds dead subdomains, historical infra |
| `subfinder` | Broadest coverage — 50+ aggregated sources |
| `assetfinder` | Different backend than subfinder, finds different results |
| `BBOT` | Recursive — runs enumeration on subdomains it finds |
| `HackerTarget` | Clean structured DNS database |
| `AlienVault OTX` | Finds subdomains seen in security incidents |
| `RapidDNS` | Historical DNS — good for old infrastructure |
| `SecurityTrails` | Historical DNS data |
| `Chaos` | Pre-enumerated bug bounty target data (ProjectDiscovery) |
| `VirusTotal` | Passive DNS from malware scanning |

### Step D — Mutation Engine

`alterx` analyzes all subdomains found so far and extracts naming patterns.

Example: found `dev-api.target.com` and `staging-api.target.com`  
alterx learns: `PREFIX-api` is a pattern  
Generates: `prod-api`, `test-api`, `uat-api`, `qa-api`, `v2-api`, `old-api`, `internal-api`...  
dnsx resolves all candidates — only real ones survive.

**Why this matters:** Mutations find subdomains that exist in no database anywhere. First-seen-ever targets with zero monitoring and zero WAF rules.

### Cross-Verification

A subdomain found by 2+ independent sources = **CONFIRMED**

```text
mail.target.com → [subfinder, crt.sh, assetfinder]  → CONFIRMED ✅
xyz.target.com  → [crt.sh only]                      → Single-source
```

CONFIRMED subdomains are high-confidence targets that almost certainly exist right now, not just historically.

---

## Phase 3 — Active Filtering

**Mode:** Active  
**Output:** `p3_dns_alive.txt`, `p3_http_alive.txt`, `p3_tier1_priority.txt`, `p3_takeover_risks.txt`, `p3_waf_results.txt`  
**Time:** ~5-10 minutes

### DNS Resolution (dnsx)

Resolves all discovered subdomains to IPs. Four fallback layers:

```text
1. Normal run — 50 threads, 5s timeout, 2 retries
2. Retry — remove -resp flag (changed in newer dnsx versions)
3. Batch mode — 100 subdomains at a time
4. Python socket fallback — bypasses dnsx entirely
```

**Critical detail:** dnsx outputs `subdomain.com [1.2.3.4]` format. httpx cannot parse that. HeyPort strips IPs and rewrites clean hostnames before httpx reads the file. This is what fixed HTTP Alive = 0.

### HTTP Probing (httpx) — 14 Ports

Every DNS-alive subdomain probed across 14 ports simultaneously:

```text
80, 443           → standard web
8080, 8443        → Jenkins, Tomcat, internal APIs
3000              → Grafana, Node.js dev
9090              → Prometheus, Cockpit
8000, 8888        → Django/Flask, Jupyter notebooks
4443, 9443, 7443  → alternate HTTPS
5000              → Flask, Docker registry
3001, 8008        → Node.js alternate, IoT admin
```

Returns for each host: status code, page title, tech detected, content length, redirect chain.

**Status codes tell a story:**

- `200` → something is serving, go investigate
- `401/403` → protected, try default creds and bypass paths
- `301/302` → follow redirects, Location header sometimes leaks internal hostnames
- `500` → server error, stack traces often leak versions and internal paths

### Tier Classification

Every subdomain automatically classified — see [Tier System](#tier-system) below.

### WAF Detection (wafw00f)

Runs on first 50 HTTP targets. 200+ WAF signatures.

**Why it matters:** Cloudflare WAF blocks standard payloads — need encoded/obfuscated variants. No WAF = go direct with anything.

### Subdomain Takeover (subjack)

Checks CNAME chains against 50+ third-party services:

| Service | Takeover Method |
| ------- | ---------------- |
| GitHub Pages | Register unclaimed `username.github.io` |
| Heroku | Claim unclaimed `appname.herokuapp.com` |
| Amazon S3 | Create unclaimed S3 bucket |
| Shopify | Register unclaimed Shopify store |
| Zendesk | Create unclaimed Zendesk account |
| Fastly | Claim unclaimed Fastly service |

**Impact:** Serve phishing pages under legitimate domain. Steal cookies. Bypass CSP. Typical payout: P1 Critical, $5,000–$20,000.

---

## Tier System

| Tier | Label | How It Qualifies | Action |
| ---- | ----- | ---------------- | ------ |
| ★ 1 | HIGH PRIORITY | Keyword hit OR takeover risk OR year-prefix (`2017-x`) OR alive + no WAF | Attack first |
| 2 | ACTIVE | HTTP responds on any port | Test thoroughly |
| 3 | DNS ONLY | Resolves but no HTTP | Port scan for SSH/FTP/DB |
| 4 | INACTIVE | Does not resolve | Skip |

**Tier 1 Keywords (80+):**

```text
admin, panel, dashboard, portal, console, cpanel, whm, plesk, phpmyadmin,
vpn, rdp, ssh, citrix, bastion, gateway, remote,
dev, staging, test, uat, qa, development,
internal, intranet, corp, corporate, private,
jenkins, grafana, kibana, prometheus, gitlab, splunk, datadog,
db, mysql, postgres, redis, mongo, elastic,
sso, auth, oauth, login, ldap, saml, identity,
pay, billing, checkout, stripe, invoice,
old, legacy, deprecated, archive, backup, v1, v2, v3,
k8s, kubernetes, docker, registry, ftp, storage...
```

**Year-prefix pattern:** `2017-grafana`, `2019-k8s`, `2018-api`
→ Auto Tier 1 + HIGH severity finding
→ Software unpatched since that year, zero monitoring, default credentials likely

---

## Phase 4 — Scanning

**Mode:** Active  
**Output:** `p4_nmap_via_rustscan.txt`, tech data in `recon_map.json`  
**Time:** ~5-20 minutes depending on IP count

### Port Scanning — RustScan → nmap

**RustScan:** Async I/O scans all 65,535 TCP ports in seconds. Identifies open ports only — no service detection.

**nmap (on open ports only):**

- `-sV` — Service version detection (5,000+ fingerprint database)
- `-O` — OS fingerprinting via TCP/IP stack behavior

Why the pipeline beats nmap alone:

```text
nmap alone (all 65535 ports + -sV): 20-40 min per IP
RustScan (find open ports) + nmap (service detect open only): 2-4 min per IP
```

**Versions are everything:**

```text
Port 443 open                 → tells you nothing
Apache 2.4.49 on port 443    → CVE-2021-41773 (path traversal, CVSS 9.8)
OpenSSH 7.4                  → CVE-2018-15473 (user enumeration)
```

**Phase 4 terminal output (per IP):**

```text
[104.21.37.188]  (www.corvit.com)
  OS: Linux 4.x
    80/tcp   http    Apache httpd 2.4.49
    443/tcp  https   Apache httpd 2.4.49
    22/tcp   ssh     OpenSSH 7.4

[66.29.137.10]  (cpanel.corvit.com)
    21/tcp   ftp     vsftpd 3.0.3
    80/tcp   http    cPanel
    2083/tcp https   cPanel SSL
```

### Technology Detection — 3 Layers

**Layer 1 — httpx (Phase 3)**
Quick Wappalyzer pass during HTTP probing. Broad coverage on every alive host.

**Layer 2 — webanalyze**
Full Wappalyzer engine with crawling on all HTTP targets. More accurate, handles JS-heavy SPAs.

**Layer 3 — whatweb (Tier 1 only)**
600+ detection plugins. Extracts exact versions from meta tags, headers, cookies, JavaScript variables. Runs on the 20 most interesting targets.

All three merge into one categorized tech list per subdomain:

```text
Language: PHP 7.2    Server: Apache 2.4    CMS: WordPress 5.8
Framework: Laravel   CDN: Cloudflare       JS: jQuery 1.11
```

---

## Phase 5 — Vulnerability Mapping

**Mode:** Active  
**Output:** `p5_nuclei_pass1_critical_high.txt`, `p5_nuclei_pass2_medium.txt`, `p5_dalfox_xss.txt`  
**Time:** ~10-30 minutes

**Requires:** HTTP-alive targets from Phase 3. If HTTP Alive = 0, Phase 5 skips nuclei and dalfox (nothing to scan).

### nuclei — Pass 1: Critical + High

Templates tagged: `cve`, `takeover`, `exposure`, `default-login`  
Severity filter: `critical,high`

What it finds:

| Category | Examples |
| -------- | -------- |
| CVEs | Log4Shell (CVE-2021-44228), Spring4Shell, ProxyShell, ProxyLogon |
| Default creds | Jenkins admin/admin, Grafana admin/admin, phpMyAdmin blank password |
| Exposed files | `.env` with DB passwords, `.git` with source code, backup zips |
| Admin panels | phpMyAdmin, Kibana, Elasticsearch — unauthenticated |
| Misconfigs | Open redirects, CORS `*`, debug mode on, directory listing |

### nuclei — Pass 2: Medium

Runs after Pass 1 completes. Catches:

- Weaker misconfigurations
- Information disclosure
- Outdated software headers
- Security header absence

### dalfox — XSS Parameter Hunter

Crawls each target, discovers URL parameters and form inputs, tests each one.

**Context-aware payload generation:**

- Reflection in HTML attribute → `'><script>alert(1)</script>`
- Reflection in JS string → `'; alert(1);//`
- Reflection in HTML body → `<script>alert(1)</script>`

`--only-poc r` flag = only reports confirmed exploitable XSS with working POC URL.  
Every line in `p5_dalfox_xss.txt` = real finding, ready to submit.

**Typical bug bounty payout for confirmed XSS: $500–$5,000 (P2 High)**

---

## Report Generation

Runs automatically after Phase 5 (or whichever phase was last).

### recon_map.json

Structured JSON containing everything from every phase:

- Overview, DNS, WHOIS, ASN, OSINT
- All subdomains with sources, tier, IPs, HTTP data, WAF, tech
- All hosts with ports, services, OS
- All findings with severity, target, detail, source

### recon_report.html

Self-contained dark-theme HTML dashboard. No server needed — just open in browser.

Sections:

- **Summary bar** — total subdomains, DNS alive, HTTP alive, unique IPs, findings count
- **Organization Intel** — company profile, cloud, GitHub, emails, breaches
- **Findings & Vulnerabilities** — table sorted by severity (Critical → High → Medium)
- **Subdomains** — full list with tier badges, status codes, tech pills, WAF indicator
- **Hosts & Ports** — per-IP port/service/OS table
- **Tech Stack** — categorized technology breakdown

---

## Recommended Workflow After a Run

```text
1. cat p3_tier1_priority.txt          → open every subdomain in browser manually
2. Open recon_report.html             → check Findings section, Critical first
3. Check p3_takeover_risks.txt        → claim these before anyone else
4. Cross-reference tech versions      → search CVE databases for exact versions found
5. If CF origin IPs found             → curl -H "Host: target.com" https://ORIGIN_IP/
6. Open p5_dalfox_xss.txt POC URLs   → verify in browser, write the report
7. Tier 3 hosts                       → port scan these for SSH/FTP/database services
```
