# Changelog

<!-- markdownlint-disable MD024 -->
All notable changes to HeyPort are documented here.

---

## [v3.2] — 2026-03-09

### Fixed

- **HTTP Alive = 0 (root cause)** — dnsx outputs `hostname [IP]` format. Script parsed clean hostnames into list but never wrote them back to file. httpx was reading the raw file and trying to probe `subdomain.com [1.2.3.4]` as a hostname — fails every time. Fix: `save_lines(dns_alive_file, dns_alive)` added before httpx reads it.
- **Subjack "32 TAKEOVER RISKS" all Not Vulnerable** — subjack with `-v` logs every checked host including clean ones. Script counted all lines as risks. Fix: filter lines containing `[not vulnerable]` (case-insensitive). Only real vulnerable lines counted.
- **Unique IPs wrong count** — `rmap.add_host('', subdomain)` called when IP resolution fails → empty-string key in hosts dict → counted as real IP. Fix: filter empty strings when counting real IPs.
- **Phase 5 "No HTTP targets — run Phase 3 first"** — Phase 5 only read from `p3_http_alive.txt`. If empty, bailed immediately. Fix: fallback to `rmap.data['web']` entries. Better error message explaining Cloudflare as likely cause.
- **Phase 0 header appearing before Phase 1 output** — `_osint_intel()` printed its own `PHASE 0` header mid-Phase 1. Fix: replaced with subsection box inside Phase 1.
- **puredns giving 0 results** — `--resolvers-trusted` flag requires a resolvers file. Without it puredns exits silently. Fix: checks 3 common locations, downloads from janmasarik/resolvers if none found.
- **gobuster giving 0 results** — Script ran gobuster with `-q` (quiet mode) which strips `Found:` prefix. Parser regex never matched quiet output. Fix: removed `-q` flag. Parser now handles both formats.

### Added

- **Port output in terminal** — Phase 4 now prints all open ports per IP directly to terminal with color coding (green=web, red=SSH/RDP, yellow=mail/FTP). Previously results went silently to JSON only.
- **dnsx multi-layer fallback** — 4 attempts before giving up: normal run → retry without `-resp` flag → batch mode (100 at a time) → Python socket fallback.
- **Trailing dot cleanup** — Some tools write `subdomain.com.` with trailing dot. dnsx fails silently on these. Fix: strip trailing dots from input file before dnsx runs.
- **httpx port expansion** — Was: 80, 443 only. Now: 14 ports covering all common dev/admin ports (Grafana:3000, Jenkins:8080, Prometheus:9090, etc.)
- **Cloudflare origin IP bypass** — 4 passive techniques: SPF record extraction, MX record IP, SecurityTrails historical DNS, Shodan cert search. Results shown as amber warning in HTML report.
- **Year-prefix legacy infra detection** — Subdomains matching `^20\d{2}[-_]` auto-promoted to Tier 1 with HIGH severity finding.
- **Non-standard port finding** — httpx finding service on 8080/8443/8000/8888/3000/9090 creates MEDIUM finding automatically.
- **p3_tier1_priority.txt** — Tier 1 subdomains saved to dedicated file. Listed in summary as `★ HIGH PRIORITY — attack these first`.
- **httpx thread + timeout tuning** — Threads: 50 → 100. Explicit 10s timeout per host. Total timeout: 600 → 900s.

---

## [v3.1] — 2026-03-08

### Added

- Smart subdomain tier classification system (Tier 1-4)
- TIER1_KEYWORDS set with 80+ high-value subdomain patterns
- Organization OSINT sub-phase inside Phase 1 (Clearbit, GitHub, Hunter.io, BGPView, HIBP)
- Cloud provider detection from ASN strings
- Tech categorization into 11 labeled groups in HTML report
- ReconMap cross-verification logic (CONFIRMED = 2+ sources)

### Fixed

- dnsrecon output parser missing SRV records
- alterx mutation candidates not feeding into dnsx resolution
- HTML report rendering broken on large subdomain counts

---

## [v3.0] — 2026-03-07

### Added

- Full 5-phase pipeline architecture
- ReconMap data structure (`recon_map.json` + `recon_report.html`)
- Dark theme interactive HTML dashboard
- nuclei two-pass system (Critical/High → Medium)
- dalfox XSS hunting with `--only-poc` flag
- RustScan → nmap pipeline for port scanning
- webanalyze bulk tech detection
- whatweb deep fingerprinting on Tier 1 targets
- wafw00f WAF detection on first 50 HTTP targets
- subjack subdomain takeover scanning

---

## [v2.x] — Prior versions

Early versions — single-phase linear execution, no cross-verification, flat text output only.
