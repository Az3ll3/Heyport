#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗██╗   ██╗██████╗  ██████╗ ██████╗ ████████╗           ║
║  ██║  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝          ║
║  ███████║█████╗   ╚████╔╝ ██████╔╝██║   ██║██████╔╝   ██║              ║
║  ██╔══██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║              ║
║  ██║  ██║███████╗   ██║   ██║     ╚██████╔╝██║  ██║   ██║              ║
║  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   v3.2     ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Ultimate Bug Bounty & Pentest Recon                                     ║
║  Multi-tool | Cross-Verified | Mapped Output | Low Noise                 ║
╚══════════════════════════════════════════════════════════════════════════╝

PHILOSOPHY:
  - Every task uses 2-3 best tools → results cross-verified
  - Subdomains found by multiple tools = CONFIRMED (higher confidence)
  - All output structured into a single ReconMap (JSON + HTML report)
  - Progressive aggression: fully passive → lightly active → scanning
  - Less noise: smart dedup, severity filters, no redundant output

REQUIRED TOOLS:
  subfinder, bbot, assetfinder, puredns, alterx, dnsx, httpx,
  wafw00f, subjack, rustscan, nmap, webanalyze, whatweb, nuclei, dalfox

SUBDOMAIN SOURCES (Phase 2):
  PASSIVE  — subfinder, BBOT, assetfinder, crt.sh, HackerTarget, OTX, RapidDNS, Chaos
  ACTIVE   — puredns (DNS brute-force with wordlist)
  MUTATION — alterx (generates permutations of found subdomains)

USAGE:
  python3 heyport.py -t example.com
  python3 heyport.py -t example.com --phase 2
  python3 heyport.py -t example.com --skip-vuln
  python3 heyport.py --check-tools
"""

import subprocess, sys, os, json, socket, argparse, datetime, re
import concurrent.futures
from pathlib import Path
from collections import defaultdict

try:
    import requests
except ImportError:
    print("[!] Run: pip install requests")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# TERMINAL COLORS
# ═══════════════════════════════════════════════════════════════════════════
class C:
    RED    = '\033[91m';  GREEN  = '\033[92m';  YELLOW = '\033[93m'
    BLUE   = '\033[94m';  CYAN   = '\033[96m';  WHITE  = '\033[97m'
    BOLD   = '\033[1m';   DIM    = '\033[2m';   RESET  = '\033[0m'
    PURPLE = '\033[95m'

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██╗  ██╗███████╗██╗   ██╗██████╗  ██████╗ ██████╗ ████████╗
  ██║  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ███████║█████╗   ╚████╔╝ ██████╔╝██║   ██║██████╔╝   ██║
  ██╔══██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
  ██║  ██║███████╗   ██║   ██║     ╚██████╔╝██║  ██║   ██║
  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝  v3.2
{C.RESET}{C.DIM}  Ultimate Recon  |  Multi-Tool Cross-Verified  |  Mapped Output{C.RESET}
""")

def phase_header(n, title, color=C.CYAN):
    bar = "═" * 68
    print(f"\n{color}{C.BOLD}{bar}{C.RESET}")
    print(f"{color}{C.BOLD}  ◈ PHASE {n}  →  {title}{C.RESET}")
    print(f"{color}{C.BOLD}{bar}{C.RESET}\n")

def info(m):   print(f"{C.CYAN}  [*]{C.RESET} {m}")
def ok(m):     print(f"{C.GREEN}  [+]{C.RESET} {m}")
def warn(m):   print(f"{C.YELLOW}  [!]{C.RESET} {m}")
def err(m):    print(f"{C.RED}  [-]{C.RESET} {m}")
def found(m):  print(f"{C.GREEN}  {C.BOLD}◉{C.RESET} {m}")
def sub(m):    print(f"{C.DIM}      → {m}{C.RESET}")


# ═══════════════════════════════════════════════════════════════════════════
# CORE UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
def run(cmd, timeout=300, silent=False):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        if not silent: warn(f"Timeout: {cmd[:60]}...")
        return "", "TIMEOUT"
    except Exception as e:
        return "", str(e)

def has_tool(name):
    out, _ = run(f"which {name}", silent=True)
    return bool(out)

def read_lines(path):
    p = Path(path)
    if not p.exists(): return []
    return [l.strip() for l in p.read_text().split('\n') if l.strip()]

def save_lines(path, lines):
    Path(path).write_text('\n'.join(sorted(set(lines))))

def ensure_wordlist(out):
    """Download a fast subdomain wordlist if none exists locally."""
    # Check common locations first
    common = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        Path.home() / "wordlists" / "subdomains-5000.txt",
    ]
    for wl in common:
        if Path(wl).exists():
            ok(f"Wordlist found → {wl}")
            return str(wl)
    # Download lightweight one (~5000 words) if nothing found
    wl_path = out / "wordlist_subdomains.txt"
    if wl_path.exists() and wl_path.stat().st_size > 1000:
        return str(wl_path)
    info("Downloading subdomain wordlist (top 5000)...")
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
            "/Discovery/DNS/subdomains-top1million-5000.txt",
            timeout=30, headers={'User-Agent': 'heyport/3.2'}
        )
        if r.status_code == 200:
            wl_path.write_text(r.text)
            ok(f"Wordlist downloaded → {len(r.text.splitlines())} words")
            return str(wl_path)
    except Exception as e:
        warn(f"Wordlist download failed: {e}")
    return None

def resolve_ip(host):
    host = str(host).split()[0].split(',')[0].strip()
    try:
        socket.setdefaulttimeout(3)
        return socket.gethostbyname(host)
    except:
        return None

def save_if_nonempty(path, content):
    """Only write file if it has actual content — no empty files ever."""
    if isinstance(content, list):
        lines = [str(l) for l in content if str(l).strip()]
        content = '\n'.join(lines)
    if content and str(content).strip():
        Path(path).write_text(str(content))
        return True
    return False

# ── Tier classification ────────────────────────────────────────────────────
TIER1_KEYWORDS = {
    'admin','administrator','panel','dashboard','portal','console',
    'vpn','remote','gateway','citrix','rdp','ssh','bastion',
    'dev','develop','development','staging','stage','test','testing','uat','qa',
    'internal','intranet','corp','corporate','private','secure',
    'api','backend','microservice','service','graphql','rest',
    'jenkins','jira','confluence','gitlab','github','bitbucket','bamboo','sonar',
    'grafana','kibana','prometheus','elastic','splunk','datadog','monitor',
    'db','database','mysql','postgres','redis','mongo','cassandra',
    'mail','smtp','webmail','exchange','owa','mta','mx',
    'ftp','sftp','nas','storage','backup','bak',
    'k8s','kubernetes','docker','rancher','registry','harbor',
    'sso','auth','oauth','login','identity','ldap','ad','saml',
    'payment','pay','billing','checkout','stripe','invoice',
    'legacy','old','deprecated','archive','v1','v2','v3',
    'phpmyadmin','adminer','cpanel','whm','plesk','webmin',
}

def _classify_tier(subdomain, data):
    """
    Tier 1 HIGH PRIORITY — juicy keywords, takeover risk, year-prefix (old infra), alive + no WAF
    Tier 2 ACTIVE        — HTTP alive
    Tier 3 DNS ONLY      — resolves but no HTTP response
    Tier 4 INACTIVE      — not resolving at all
    """
    parts     = set(re.split(r'[-_.]', subdomain.lower()))
    has_http  = bool((data.get('http') or {}).get('status'))
    has_ips   = bool(data.get('ips'))
    has_risk  = data.get('takeover_risk', False)
    kw_hit    = bool(parts & TIER1_KEYWORDS)
    no_waf    = not data.get('waf')
    # Year-prefix pattern → old/abandoned infra (2017-grafana, 2019-k8s, etc.)
    year_hit  = bool(re.match(r'^20\d{2}[-_]', subdomain))

    if kw_hit or has_risk or year_hit or (has_http and no_waf and has_ips):
        return 1
    elif has_http:
        return 2
    elif has_ips:
        return 3
    return 4

# ── Tech categorization ────────────────────────────────────────────────────
TECH_CATEGORIES = {
    'Language':  ['PHP','Python','Ruby','Java','Go','Rust','Node.js','ASP.NET','Perl',
                  'Scala','Kotlin','TypeScript','JavaScript','ColdFusion','Elixir'],
    'Server':    ['Apache','nginx','IIS','Tomcat','Gunicorn','Uvicorn','Caddy',
                  'LiteSpeed','OpenResty','Jetty','WildFly','Passenger','lighttpd'],
    'CMS':       ['WordPress','Drupal','Joomla','Magento','Shopify','PrestaShop',
                  'Typo3','Ghost','Strapi','Craft','Squarespace','Wix','Webflow',
                  'HubSpot','Adobe Experience Manager','Sitecore','Kentico'],
    'Framework': ['Laravel','Django','Rails','Spring','Express','FastAPI','Flask',
                  'Symfony','CodeIgniter','CakePHP','Next.js','Nuxt.js','Gatsby',
                  'Angular','React','Vue.js','Svelte','.NET','Blazor','Gin','Echo'],
    'JS Library':['jQuery','Bootstrap','Lodash','Moment.js','D3.js','Three.js',
                  'Chart.js','Leaflet','Underscore.js','Alpine.js','HTMX'],
    'CDN':       ['Cloudflare','Fastly','Akamai','CloudFront','Sucuri','Incapsula',
                  'MaxCDN','BunnyCDN','KeyCDN','jsDelivr','StackPath'],
    'Cloud':     ['AWS','Amazon','Azure','Google Cloud','GCP','DigitalOcean',
                  'Heroku','Vercel','Netlify','Render','Fly.io','Linode','Vultr'],
    'Database':  ['MySQL','PostgreSQL','MariaDB','MongoDB','Redis','Cassandra',
                  'Elasticsearch','SQLite','Oracle','MSSQL','CouchDB','DynamoDB'],
    'Analytics': ['Google Analytics','Google Tag Manager','Hotjar','Mixpanel',
                  'Segment','Amplitude','Heap','FullStory','Matomo','Piwik'],
    'Security':  ['reCAPTCHA','hCaptcha','HSTS','CSP','Imperva','ModSecurity',
                  'Wordfence','Cloudflare Turnstile'],
    'OS':        ['Ubuntu','Debian','CentOS','Red Hat','RHEL','Amazon Linux',
                  'Alpine Linux','FreeBSD','Windows Server'],
}

def _categorize_tech(tech_list):
    """
    Turns a flat tech list into {'Language': ['PHP'], 'CDN': ['Cloudflare'], ...}
    """
    if not tech_list:
        return {}
    result     = {}
    categorized = set()
    for tech in tech_list:
        if not tech:
            continue
        t = tech.strip()
        matched = False
        for cat, keywords in TECH_CATEGORIES.items():
            for kw in keywords:
                if kw.lower() in t.lower():
                    result.setdefault(cat, [])
                    if t not in result[cat]:
                        result[cat].append(t)
                    categorized.add(t)
                    matched = True
                    break
            if matched:
                break
        if not matched:
            result.setdefault('Other', [])
            if t not in result['Other']:
                result['Other'].append(t)
    return result

def check_tools():
    tools = {
        'subfinder':   'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'bbot':        'pip install bbot',
        'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
        'puredns':     'go install github.com/d3mondev/puredns/v2@latest',
        'alterx':      'go install github.com/projectdiscovery/alterx/cmd/alterx@latest',
        'gobuster':    'sudo apt install gobuster  OR  go install github.com/OJ/gobuster/v3@latest',
        'dnsrecon':    'sudo apt install dnsrecon  OR  pip install dnsrecon',
        'dnsx':        'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
        'httpx':       'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'wafw00f':     'pip install wafw00f',
        'subjack':     'go install github.com/haccer/subjack@latest',
        'rustscan':    'cargo install rustscan  OR  https://github.com/RustScan/RustScan/releases',
        'nmap':        'sudo apt install nmap',
        'webanalyze':  'go install github.com/rverton/webanalyze@latest',
        'whatweb':     'sudo apt install whatweb',
        'nuclei':      'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'dalfox':      'go install github.com/hahwul/dalfox/v2@latest',
        'dig':         'sudo apt install dnsutils',
        'whois':       'sudo apt install whois',
    }
    print(f"\n{C.BOLD}  Tool Status:{C.RESET}")
    missing = []
    for tool, install in tools.items():
        if has_tool(tool):
            print(f"    {C.GREEN}✔{C.RESET}  {tool}")
        else:
            print(f"    {C.RED}✘{C.RESET}  {tool:<16} {C.DIM}→ {install}{C.RESET}")
            missing.append(tool)
    print()
    if missing:
        warn(f"{len(missing)} tools missing. Install them for best results.")
    else:
        ok("All tools ready!")
    return missing


# ═══════════════════════════════════════════════════════════════════════════
# RECON MAP — Central data structure
# ═══════════════════════════════════════════════════════════════════════════
class ReconMap:
    def __init__(self, target):
        self.target = target
        self.ts     = datetime.datetime.now().isoformat()
        self.data   = {
            "meta":       {"target": target, "timestamp": self.ts},
            "overview":   {},
            "subdomains": {},   # subdomain → {ips, sources, confirmed, http_info, waf, takeover}
            "hosts":      {},   # ip → {hostnames, ports, services, os, cves}
            "web":        {},   # url → {status, title, tech, waf, findings}
            "findings":   [],   # [{type, severity, target, detail, source}]
            "summary":    {}
        }

    def add_subdomain(self, subdomain, source):
        sub = subdomain.lower().strip().lstrip('*.')
        if not sub or '.' not in sub:
            return
        if sub not in self.data['subdomains']:
            self.data['subdomains'][sub] = {
                'sources': [], 'ips': [], 'confirmed': False,
                'http': None, 'waf': None, 'takeover_risk': False
            }
        if source not in self.data['subdomains'][sub]['sources']:
            self.data['subdomains'][sub]['sources'].append(source)
        # Mark confirmed if found by 2+ independent tools
        sources = self.data['subdomains'][sub]['sources']
        api_sources  = [s for s in sources if s in ['crt.sh','hackertarget','otx','shodan']]
        tool_sources = [s for s in sources if s in ['subfinder','bbot','assetfinder']]
        if len(sources) >= 2 or (len(api_sources) >= 1 and len(tool_sources) >= 1):
            self.data['subdomains'][sub]['confirmed'] = True

    def add_host(self, ip, hostname=None):
        if ip not in self.data['hosts']:
            self.data['hosts'][ip] = {
                'hostnames': [], 'ports': [], 'services': {}, 'os': None, 'cves': []
            }
        if hostname and hostname not in self.data['hosts'][ip]['hostnames']:
            self.data['hosts'][ip]['hostnames'].append(hostname)

    def add_web(self, url, info_dict):
        self.data['web'][url] = info_dict

    def add_finding(self, ftype, severity, target, detail, source=""):
        self.data['findings'].append({
            'type': ftype, 'severity': severity,
            'target': target, 'detail': detail, 'source': source
        })

    def save_json(self, path):
        with open(path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)

    def confirmed_subdomains(self):
        return [s for s, d in self.data['subdomains'].items() if d['confirmed']]

    def all_subdomains(self):
        return list(self.data['subdomains'].keys())

    def get_summary(self):
        subs     = self.data['subdomains']
        findings = self.data['findings']
        # Exclude empty-string keys added when IP resolution fails
        real_ips = [ip for ip in self.data['hosts'] if ip and ip.strip()]
        return {
            'total_subdomains':     len(subs),
            'confirmed_subdomains': len([s for s in subs.values() if s['confirmed']]),
            'dns_alive':            len([s for s in subs.values() if s.get('ips')]),
            'http_alive':           len(self.data['web']),
            'total_ips':            len(real_ips),
            'total_findings':       len(findings),
            'critical':             len([f for f in findings if f['severity']=='critical']),
            'high':                 len([f for f in findings if f['severity']=='high']),
            'medium':               len([f for f in findings if f['severity']=='medium']),
            'takeover_risks':       len([s for s in subs.values() if s.get('takeover_risk')]),
            'wafs_detected':        len([s for s in subs.values() if s.get('waf')]),
        }


# ═══════════════════════════════════════════════════════════════════════════
# OSINT INTELLIGENCE — Company | Cloud | GitHub | Emails | Breach check
# Only stores what's actually found. No links. No guesses.
# ═══════════════════════════════════════════════════════════════════════════
def _osint_intel(target, out, rmap):
    bar = "─" * 68
    print(f"\n{C.PURPLE}{C.BOLD}  ┌── ORGANIZATION INTELLIGENCE  —  OSINT ──────────────────┐{C.RESET}\n")
    H       = {'User-Agent': 'Mozilla/5.0 (compatible; HeyPort/3.2)'}
    osint   = {}
    slug    = target.split('.')[0]

    # ── 1. Clearbit — company name, industry, description ─────────────────
    info("Clearbit — company profile...")
    try:
        r = requests.get(
            f"https://autocomplete.clearbit.com/v1/companies/suggest?query={target}",
            timeout=8, headers=H
        )
        if r.status_code == 200 and r.json():
            best = next(
                (c for c in r.json() if slug in c.get('domain','').lower()),
                r.json()[0]
            )
            if best:
                osint['company_name'] = best.get('name', '')
                ok(f"Company: {C.BOLD}{osint['company_name']}{C.RESET}")
    except:
        pass

    # ── 2. GitHub org — real data from API ────────────────────────────────
    info("GitHub — org intelligence...")
    try:
        r = requests.get(
            f"https://api.github.com/orgs/{slug}",
            timeout=8, headers={**H, 'Accept': 'application/vnd.github.v3+json'}
        )
        if r.status_code == 200:
            gh = r.json()
            osint['github_org']          = gh.get('login', '')
            osint['github_name']         = gh.get('name', '') or gh.get('login', '')
            osint['github_description']  = gh.get('description', '')
            osint['github_location']     = gh.get('location', '')
            osint['github_public_repos'] = gh.get('public_repos', 0)
            osint['github_email']        = gh.get('email', '')
            osint['github_blog']         = gh.get('blog', '')
            osint['github_created']      = gh.get('created_at', '')[:10]
            ok(f"GitHub: {osint['github_name']} — {osint['github_public_repos']} public repos")
        else:
            # Fallback search
            r2 = requests.get(
                f"https://api.github.com/search/users?q={slug}+type:org&per_page=1",
                timeout=8, headers={**H, 'Accept': 'application/vnd.github.v3+json'}
            )
            if r2.status_code == 200 and r2.json().get('items'):
                top = r2.json()['items'][0]
                osint['github_org']  = top.get('login', '')
                osint['github_name'] = top.get('login', '')
    except:
        pass

    # ── 3. Cloud / hosting detection — from ASN + IP info ─────────────────
    info("Cloud provider detection...")
    ipinfo   = rmap.data.get('overview', {}).get('ipinfo', {})
    org_str  = (ipinfo.get('org', '') + ' ' + ipinfo.get('hostname', '')).lower()
    asn_str  = ipinfo.get('asn', {}).get('name', '').lower() if isinstance(ipinfo.get('asn'), dict) else ''
    combined = org_str + ' ' + asn_str

    CLOUD_MAP = {
        'AWS (Amazon Web Services)': ['amazon','aws','amazonaws'],
        'Google Cloud Platform':     ['google','gcp','googlecloud'],
        'Microsoft Azure':           ['microsoft','azure'],
        'Cloudflare':                ['cloudflare'],
        'DigitalOcean':              ['digitalocean'],
        'Hetzner':                   ['hetzner'],
        'Linode / Akamai Cloud':     ['linode','akamai'],
        'Vultr':                     ['vultr'],
        'OVH':                       ['ovh'],
        'Fastly':                    ['fastly'],
        'Oracle Cloud':              ['oracle'],
        'IBM Cloud':                 ['ibm'],
    }
    for provider, kws in CLOUD_MAP.items():
        if any(kw in combined for kw in kws):
            osint['cloud_provider'] = provider
            ok(f"Cloud: {C.BOLD}{provider}{C.RESET}")
            break
    if not osint.get('cloud_provider') and ipinfo.get('org'):
        osint['cloud_provider'] = ipinfo['org']

    # ── 4. Email discovery — theHarvester results + Hunter.io ─────────────
    info("Email discovery...")
    # theHarvester already ran in Phase 1 — pick up what it found
    emails = list(rmap.data.get('overview', {}).get('emails', []))

    try:
        r = requests.get(
            f"https://api.hunter.io/v2/domain-search?domain={target}&limit=10",
            timeout=8, headers=H
        )
        if r.status_code == 200:
            data_h = r.json().get('data', {})
            for e in data_h.get('emails', []):
                v = e.get('value', '')
                if v and v not in emails:
                    emails.append(v)
            # company name fallback
            if data_h.get('organization') and not osint.get('company_name'):
                osint['company_name'] = data_h['organization']
    except:
        pass

    if emails:
        osint['emails'] = list(dict.fromkeys(emails))[:20]
        ok(f"Emails: {C.BOLD}{len(osint['emails'])}{C.RESET} contacts found")

    # ── 5. Have I Been Pwned — breach check for the domain ────────────────
    info("HIBP — checking domain for known breaches...")
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{target}",
            timeout=8,
            headers={**H, 'hibp-api-key': ''}   # works without key for domain check
        )
        # 200 = breached, 404 = not found, 401 = key needed (skip gracefully)
        if r.status_code == 200:
            breaches = r.json() if isinstance(r.json(), list) else []
            osint['breaches']      = [b.get('Name','') for b in breaches[:10]]
            osint['breach_count']  = len(breaches)
            found(f"BREACHES FOUND: {C.RED}{C.BOLD}{len(breaches)}{C.RESET} known data breaches for {target}")
        elif r.status_code == 404:
            osint['breach_count'] = 0
            ok("No known breaches in HIBP database")
    except:
        pass

    # ── 6. ASN / BGP intel — what IP ranges does the org own ──────────────
    info("ASN / BGP — IP range intelligence...")
    main_ip = rmap.data.get('overview', {}).get('main_ip', '')
    if main_ip:
        try:
            r = requests.get(
                f"https://api.bgpview.io/ip/{main_ip}",
                timeout=8, headers=H
            )
            if r.status_code == 200:
                bgp = r.json().get('data', {})
                prefixes = bgp.get('prefixes', [])
                asns     = bgp.get('rir_allocation', {})
                if prefixes:
                    osint['ip_ranges'] = [p.get('prefix','') for p in prefixes[:5]]
                    ok(f"IP ranges: {', '.join(osint['ip_ranges'][:3])}")
                asn_list = bgp.get('asns', [])
                if asn_list:
                    osint['asn_info'] = [
                        f"AS{a.get('asn','')} — {a.get('name','')}" for a in asn_list[:3]
                    ]
        except:
            pass

    # ── Store + print summary ──────────────────────────────────────────────
    rmap.data['overview']['osint'] = osint
    rmap.save_json(out / "recon_map.json")

    print(f"\n{C.BOLD}  ◈ Organization Intelligence Summary:{C.RESET}")
    pairs = [
        ("Company",      osint.get('company_name')),
        ("Cloud/Host",   osint.get('cloud_provider')),
        ("GitHub Org",   f"{osint.get('github_name','')}  ({osint.get('github_public_repos',0)} repos)" if osint.get('github_org') else None),
        ("GitHub Loc",   osint.get('github_location')),
        ("GitHub Email", osint.get('github_email')),
        ("IP Ranges",    ', '.join(osint.get('ip_ranges', [])[:3])),
        ("Emails Found", str(len(osint.get('emails', []))) + ' contacts' if osint.get('emails') else None),
        ("Breaches",     f"{osint.get('breach_count',0)} known breaches" if 'breach_count' in osint else None),
    ]
    for label, val in pairs:
        if val:
            color = C.RED if 'breach' in label.lower() and osint.get('breach_count',0) > 0 else C.CYAN
            print(f"    {C.DIM}{label:<16}{C.RESET} {color}{val}{C.RESET}")




# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1 — TARGET OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════
def phase1(target, out, rmap):
    phase_header(1, "TARGET OVERVIEW  —  DNS | WHOIS | IP | GEO | ASN | SHODAN", C.CYAN)
    overview = {}

    # ── DNS Records (dig) ─────────────────────────────────────────────────
    info("Querying DNS records (dig)...")
    dns = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
        out_txt, _ = run(f"dig +short {rtype} {target} 2>/dev/null", timeout=15)
        if out_txt:
            dns[rtype] = [x for x in out_txt.split('\n') if x.strip()]
            ok(f"{rtype:6s} → {', '.join(dns[rtype][:3])}")
    overview['dns'] = dns

    # ── Resolve Main IP ───────────────────────────────────────────────────
    main_ip = None
    try:
        main_ip = socket.gethostbyname(target)
        ok(f"Main IP  → {C.BOLD}{main_ip}{C.RESET}")
        overview['main_ip'] = main_ip
    except:
        err("Could not resolve target IP")

    # ── WHOIS ─────────────────────────────────────────────────────────────
    info("Running WHOIS...")
    whois_raw, _ = run(f"whois {target} 2>/dev/null", timeout=30)
    if whois_raw:
        overview['whois_raw'] = whois_raw
        key_fields = {}
        for line in whois_raw.split('\n'):
            for field in ['Registrar:', 'Creation Date:', 'Registry Expiry Date:', 'Name Server:', 'Registrant Org', 'DNSSEC:']:
                if field.lower() in line.lower() and ':' in line:
                    k, _, v = line.partition(':')
                    key_fields[k.strip()] = v.strip()
                    sub(line.strip()[:80])
                    break
        overview['whois_parsed'] = key_fields

    # ── theHarvester ──────────────────────────────────────────────────────
    if has_tool('theHarvester'):
        info("theHarvester (emails, names, extra hosts from 30+ sources)...")
        out_txt, _ = run(
            f"theHarvester -d {target} -b google,bing,yahoo,baidu,duckduckgo,dnsdumpster,"
            f"hackertarget,threatcrowd,certspotter,crtsh -f /tmp/harvester_{target} 2>/dev/null",
            timeout=180
        )
        # Parse emails and hosts from output
        emails = list(set(re.findall(r'[\w.\-+]+@[\w.\-]+\.\w+', out_txt)))
        hosts  = list(set(re.findall(r'[\w.\-]+\.' + re.escape(target), out_txt)))
        if emails:
            overview['emails'] = emails
            ok(f"Emails found: {len(emails)}")
            for e in emails[:5]: sub(e)
        if hosts:
            for h in hosts:
                rmap.add_subdomain(h, 'theharvester')
            ok(f"theHarvester hosts: {len(hosts)}")
    else:
        warn("theHarvester not installed — skipping email/extra OSINT")

    # ── IP Geolocation & ASN (ipinfo.io) ─────────────────────────────────
    if main_ip:
        info(f"Geolocation + ASN via ipinfo.io...")
        try:
            r = requests.get(f"https://ipinfo.io/{main_ip}/json", timeout=10,
                             headers={'User-Agent': 'recon-script/3.0'})
            if r.status_code == 200:
                ipinfo = r.json()
                overview['ipinfo'] = ipinfo
                for k in ['org', 'city', 'region', 'country', 'timezone', 'loc', 'hostname']:
                    if k in ipinfo:
                        ok(f"{k.upper():10s} → {ipinfo[k]}")
        except Exception as e:
            warn(f"ipinfo.io failed: {e}")

    # ── Shodan InternetDB (passive open ports, CVEs — zero packets) ───────
    if main_ip:
        info(f"Shodan InternetDB (passive ports + CVEs for {main_ip})...")
        try:
            r = requests.get(f"https://internetdb.shodan.io/{main_ip}", timeout=10,
                             headers={'User-Agent': 'recon-script/3.0'})
            if r.status_code == 200:
                shodan_data = r.json()
                overview['shodan_internetdb'] = shodan_data
                if 'ports' in shodan_data and shodan_data['ports']:
                    ok(f"Shodan ports (passive) → {shodan_data['ports']}")
                    rmap.add_host(main_ip, target)
                    rmap.data['hosts'][main_ip]['ports'] = shodan_data.get('ports', [])
                    rmap.data['hosts'][main_ip]['cves']  = shodan_data.get('vulns', [])
                    if shodan_data.get('vulns'):
                        found(f"Shodan CVEs (passive) → {', '.join(shodan_data['vulns'][:5])}")
                        for cve in shodan_data.get('vulns', []):
                            rmap.add_finding('cve', 'high', main_ip, cve, 'shodan_internetdb')
                if 'tags' in shodan_data and shodan_data['tags']:
                    ok(f"Shodan tags → {shodan_data['tags']}")
        except Exception as e:
            warn(f"Shodan InternetDB failed: {e}")

    # ── Cloudflare Origin IP Bypass ───────────────────────────────────────
    # If behind Cloudflare, real server IP is hidden. Try multiple techniques
    # to find the origin before everything downstream runs blind.
    is_cloudflare = 'cloudflare' in str(overview.get('ipinfo', {}).get('org', '')).lower()
    if is_cloudflare:
        info(f"{C.YELLOW}Cloudflare detected — attempting origin IP discovery...{C.RESET}")
        origin_ips = {}

        # 1. Historical DNS — SecurityTrails public endpoint
        try:
            r = requests.get(
                f"https://securitytrails.com/domain/{target}/dns",
                timeout=10, headers={'User-Agent': 'Mozilla/5.0'}
            )
            if r.status_code == 200:
                ips_found = re.findall(r'\b(?!10\.|172\.|192\.168)(\d{1,3}\.){3}\d{1,3}\b', r.text)
                cf_ranges = ['104.','172.64.','172.65.','172.66.','172.67.','162.158.','198.41.']
                real_ips  = [ip for ip in set(ips_found) if not any(ip.startswith(p) for p in cf_ranges)]
                if real_ips:
                    origin_ips['securitytrails'] = real_ips[:3]
        except:
            pass

        # 2. Censys — certificate search for non-CF IPs
        try:
            r = requests.get(
                f"https://search.censys.io/api/v1/search/certificates?q={target}&fields=parsed.subject_dn,ip",
                timeout=10, headers={'User-Agent': 'Mozilla/5.0'}
            )
            if r.status_code == 200:
                data_c = r.json()
                for result in data_c.get('results', [])[:20]:
                    ip = result.get('ip', '')
                    if ip and not any(ip.startswith(p) for p in ['104.','172.6','162.','198.41.']):
                        origin_ips.setdefault('censys', [])
                        if ip not in origin_ips['censys']:
                            origin_ips['censys'].append(ip)
        except:
            pass

        # 3. Direct MX record IP — mail servers often NOT behind Cloudflare
        try:
            mx_records = overview.get('dns', {}).get('MX', [])
            for mx in mx_records[:2]:
                mx_host = mx.split()[-1].rstrip('.') if mx.split() else ''
                if mx_host and target in mx_host:
                    mx_ip = resolve_ip(mx_host)
                    if mx_ip:
                        cf_ranges = ['104.','172.64.','172.65.','172.66.','172.67.']
                        if not any(mx_ip.startswith(p) for p in cf_ranges):
                            origin_ips.setdefault('mx_record', [])
                            origin_ips['mx_record'].append(f"{mx_host} → {mx_ip}")
        except:
            pass

        # 4. Favicon hash — identical favicons at Cloudflare IP vs origin
        #    (note: direct probing, only if we have candidate IPs)
        try:
            r = requests.get(f"https://www.shodan.io/search?query=ssl.cert.subject.cn%3A{target}",
                             timeout=8, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                shodan_ips = re.findall(r'href="/host/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"', r.text)
                cf_ranges  = ['104.','172.6','162.','198.41.']
                real = [ip for ip in set(shodan_ips) if not any(ip.startswith(p) for p in cf_ranges)]
                if real:
                    origin_ips.setdefault('shodan_cert', real[:3])
        except:
            pass

        if origin_ips:
            overview['origin_ips'] = origin_ips
            found(f"Potential origin IPs discovered:")
            for source, ips in origin_ips.items():
                for ip in (ips if isinstance(ips, list) else [ips]):
                    print(f"    {C.YELLOW}[{source}]{C.RESET}  {C.BOLD}{ip}{C.RESET}")
            warn("Verify these IPs manually — some may still be Cloudflare infrastructure")
        else:
            info("Origin IP not found via passive methods — target is well protected")

    # ── crt.sh Certificate Count ──────────────────────────────────────────
    info("crt.sh — checking SSL certificate history...")
    try:
        r = requests.get(f"https://crt.sh/?q={target}&output=json", timeout=15,
                         headers={'User-Agent': 'recon-script/3.0'})
        if r.status_code == 200:
            certs = r.json()
            ok(f"SSL certs in CT logs → {len(certs):,}")
            overview['cert_count'] = len(certs)
    except Exception as e:
        warn(f"crt.sh failed: {e}")

    rmap.data['overview'] = overview
    rmap.save_json(out / "recon_map.json")
    ok(f"Phase 1 complete → recon_map.json updated")

    # Run OSINT intel after overview is populated
    _osint_intel(target, out, rmap)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2 — SUBDOMAIN ENUMERATION
# Active-first: Zone Transfer → NSEC → Brute-Force → Mutations → Passive APIs
# ═══════════════════════════════════════════════════════════════════════════
def phase2(target, out, rmap):
    phase_header(2, "SUBDOMAIN ENUMERATION  —  Active + Passive + Brute + Mutations", C.BLUE)

    source_counts = {}
    HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; HeyPort/3.2)'}

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │  STEP A — DNS Recon Tricks (Zero-cost active, often missed)         │
    # └─────────────────────────────────────────────────────────────────────┘
    print(f"\n{C.BOLD}{C.CYAN}  ┌── A: DNS RECON TRICKS ──────────────────────────────┐{C.RESET}")

    # ── A1: Get all nameservers for the target ────────────────────────────
    info("Resolving nameservers...")
    ns_out, _ = run(f"dig +short NS {target}", timeout=10)
    nameservers = [ns.rstrip('.') for ns in ns_out.split('\n') if ns.strip()]
    if nameservers:
        ok(f"Nameservers → {', '.join(nameservers)}")
    else:
        warn("No nameservers found — domain may not exist or is private")

    # ── A2: DNS Zone Transfer (AXFR) — misconfigured servers leak everything
    info("Attempting DNS Zone Transfer (AXFR)...")
    axfr_found = set()
    for ns in nameservers:
        axfr_out, _ = run(f"dig AXFR {target} @{ns} +time=5 2>/dev/null", timeout=15)
        if axfr_out and 'Transfer failed' not in axfr_out and len(axfr_out) > 100:
            found(f"ZONE TRANSFER SUCCESS on {ns} !")
            # Parse zone file records
            for line in axfr_out.split('\n'):
                parts = line.split()
                if len(parts) >= 5 and parts[3] in ('A', 'AAAA', 'CNAME'):
                    hostname = parts[0].rstrip('.').lower()
                    if target in hostname:
                        axfr_found.add(hostname)
            ok(f"AXFR leaked {len(axfr_found)} hosts from {ns}")
        else:
            sub(f"AXFR refused on {ns} (expected for most targets)")
    for s in axfr_found: rmap.add_subdomain(s, 'axfr')
    if axfr_found: source_counts['axfr'] = len(axfr_found)

    # ── A3: NSEC Walking (DNSSEC zone enumeration) ────────────────────────
    info("Checking DNSSEC / NSEC records (zone walking)...")
    nsec_out, _ = run(f"dig +dnssec NSEC {target} 2>/dev/null", timeout=10)
    if 'NSEC' in nsec_out:
        ok("DNSSEC/NSEC records found — zone walking possible")
        # Basic NSEC walk: follow the chain
        nsec_subs = set()
        current = target
        for _ in range(50):  # walk up to 50 NSEC records
            walk_out, _ = run(f"dig +dnssec NSEC {current} 2>/dev/null", timeout=5)
            match = re.search(r'NSEC\s+([\w.\-]+)', walk_out)
            if match:
                next_name = match.group(1).rstrip('.').lower()
                if next_name == target or next_name in nsec_subs:
                    break
                if target in next_name:
                    nsec_subs.add(next_name)
                    rmap.add_subdomain(next_name, 'nsec_walk')
                current = next_name
            else:
                break
        if nsec_subs:
            found(f"NSEC walk → {len(nsec_subs)} subdomains leaked!")
            source_counts['nsec_walk'] = len(nsec_subs)
        else:
            sub("NSEC3 hashed (walk blocked) or no DNSSEC")
    else:
        sub("No DNSSEC — NSEC walking not applicable")

    # ── A4: Common record types direct query ─────────────────────────────
    info("Querying common subdomains directly (high-value targets)...")
    common_prefixes = [
        'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'sftp', 'ssh',
        'vpn', 'remote', 'gateway', 'proxy', 'ns1', 'ns2', 'mx', 'mx1',
        'admin', 'portal', 'dashboard', 'panel', 'cp', 'cpanel', 'webmail',
        'api', 'app', 'mobile', 'dev', 'staging', 'test', 'beta', 'demo',
        'shop', 'store', 'blog', 'forum', 'wiki', 'docs', 'help', 'support',
        'cdn', 'static', 'assets', 'media', 'img', 'images', 'video',
        'auth', 'login', 'sso', 'oauth', 'id', 'accounts', 'register',
        'db', 'database', 'mysql', 'redis', 'mongo', 'elastic', 'kibana',
        'jenkins', 'gitlab', 'git', 'ci', 'jira', 'confluence', 'slack',
        'grafana', 'prometheus', 'monitor', 'status', 'health', 'metrics',
        'intranet', 'internal', 'corp', 'office', 'hr', 'finance',
        'old', 'new', 'v2', 'v3', 'legacy', 'backup', 'bak',
        'uat', 'qa', 'sandbox', 'preprod', 'prod', 'production',
        'cloud', 'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker',
        's3', 'storage', 'files', 'upload', 'download', 'data',
        'pay', 'payment', 'checkout', 'billing', 'invoice',
        'web', 'web1', 'web2', 'srv', 'server', 'host',
    ]

    def quick_resolve(prefix):
        hostname = f"{prefix}.{target}"
        ip = resolve_ip(hostname)
        return (hostname, ip) if ip else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
        results = list(ex.map(quick_resolve, common_prefixes))

    direct_found = [(h, ip) for r in results if r for h, ip in [r]]
    for hostname, ip in direct_found:
        rmap.add_subdomain(hostname, 'direct_dns')
        if hostname in rmap.data['subdomains']:
            rmap.data['subdomains'][hostname]['ips'] = [ip]
    source_counts['direct_dns'] = len(direct_found)
    if direct_found:
        ok(f"Direct DNS hits → {len(direct_found)} common subdomains found")
        for h, ip in direct_found[:10]: sub(f"{h}  [{ip}]")

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │  STEP B — Active DNS Brute-Force (3 tool options)                   │
    # └─────────────────────────────────────────────────────────────────────┘
    print(f"\n{C.BOLD}{C.YELLOW}  ┌── B: ACTIVE DNS BRUTE-FORCE ────────────────────────┐{C.RESET}")

    # Get wordlists — small, medium, large
    wordlist = ensure_wordlist(out)

    # ── B1: puredns (fastest, wildcard-aware brute force) ─────────────────
    if has_tool('puredns') and wordlist:
        info(f"puredns brute-force — wordlist: {Path(wordlist).name}")
        info("  Wildcard detection built-in — won't return false positives")
        puredns_out = out / "p2_puredns.txt"

        # puredns needs a resolvers file — use common locations or download
        resolvers_paths = [
            "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
            Path.home() / "resolvers.txt",
            out / "resolvers.txt",
        ]
        resolvers_file = next((str(p) for p in resolvers_paths if Path(p).exists()), None)
        if not resolvers_file:
            # Download a small trusted resolvers list
            res_path = out / "resolvers.txt"
            try:
                r = requests.get(
                    "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt",
                    timeout=15, headers={'User-Agent': 'heyport/3.2'}
                )
                if r.status_code == 200:
                    res_path.write_text(r.text)
                    resolvers_file = str(res_path)
                    ok(f"Resolvers downloaded → {len(r.text.splitlines())} resolvers")
            except:
                pass

        if resolvers_file:
            run(
                f"puredns bruteforce {wordlist} {target} "
                f"-r {resolvers_file} -w {puredns_out} --quiet 2>/dev/null",
                timeout=900
            )
        else:
            # Last resort — no resolvers file, use system resolver
            run(
                f"puredns bruteforce {wordlist} {target} "
                f"-w {puredns_out} --quiet 2>/dev/null",
                timeout=900
            )
        brute_subs = read_lines(puredns_out)
        for s in brute_subs: rmap.add_subdomain(s, 'puredns')
        source_counts['puredns'] = len(brute_subs)
        found(f"puredns      → {C.BOLD}{len(brute_subs):,}{C.RESET} subdomains")
    else:
        if not has_tool('puredns'):
            warn("puredns not installed: go install github.com/d3mondev/puredns/v2@latest")

    # ── B2: gobuster dns (parallel resolver, different algorithm) ─────────
    if has_tool('gobuster') and wordlist:
        info("gobuster dns — parallel DNS brute-force...")
        gobuster_out = out / "p2_gobuster.txt"
        run(
            f"gobuster dns -d {target} -w {wordlist} "
            f"-t 50 --timeout 3s --no-error "
            f"-o {gobuster_out} 2>/dev/null",
            timeout=600
        )
        gob_subs = []
        for line in read_lines(gobuster_out):
            # gobuster WITHOUT -q outputs: "Found: subdomain.domain.com"
            # gobuster WITH -q outputs:    "subdomain.domain.com"
            # Handle both formats
            m = re.search(r'Found:\s*([\w.\-]+)', line)
            if m:
                s = m.group(1).lower().strip()
            elif line.strip() and target in line and not line.startswith('['):
                s = line.strip().lower()
            else:
                continue
            if target in s and s not in gob_subs:
                gob_subs.append(s)
                rmap.add_subdomain(s, 'gobuster')
        source_counts['gobuster'] = len(gob_subs)
        found(f"gobuster     → {C.BOLD}{len(gob_subs):,}{C.RESET} subdomains")
    elif not has_tool('gobuster'):
        warn("gobuster not installed: sudo apt install gobuster")

    # ── B3: dnsx -w (brute-force mode, built into dnsx) ───────────────────
    if has_tool('dnsx') and wordlist:
        info("dnsx brute-force mode (-w)...")
        dnsx_brute_out = out / "p2_dnsx_brute.txt"
        run(
            f"dnsx -d {target} -w {wordlist} "
            f"-silent -a -threads 100 "
            f"-o {dnsx_brute_out} 2>/dev/null",
            timeout=600
        )
        dnsx_subs = [
            line.split()[0].rstrip('.').lower()
            for line in read_lines(dnsx_brute_out)
            if line.strip()
        ]
        for s in dnsx_subs: rmap.add_subdomain(s, 'dnsx_brute')
        source_counts['dnsx_brute'] = len(dnsx_subs)
        found(f"dnsx brute   → {C.BOLD}{len(dnsx_subs):,}{C.RESET} subdomains")

    # ── B4: dnsrecon (comprehensive — brute + SRV + wildcard checks) ──────
    if has_tool('dnsrecon') and wordlist:
        info("dnsrecon — comprehensive DNS enumeration...")
        dnsrecon_out = out / "p2_dnsrecon.json"
        run(
            f"dnsrecon -d {target} -t brt "
            f"-D {wordlist} --json {dnsrecon_out} -q 2>/dev/null",
            timeout=600
        )
        dr_subs = set()
        if dnsrecon_out.exists():
            try:
                dr_data = json.loads(dnsrecon_out.read_text())
                for rec in dr_data:
                    name = rec.get('name', '').lower().rstrip('.')
                    if target in name:
                        dr_subs.add(name)
            except:
                pass
        for s in dr_subs: rmap.add_subdomain(s, 'dnsrecon')
        source_counts['dnsrecon'] = len(dr_subs)
        if dr_subs:
            found(f"dnsrecon     → {C.BOLD}{len(dr_subs):,}{C.RESET} subdomains")
    elif not has_tool('dnsrecon'):
        warn("dnsrecon not installed: sudo apt install dnsrecon")

    # ── B5: Wildcard-based permutation scan (detect & enumerate wildcards) ─
    info("Wildcard subdomain check...")
    rand_sub = f"nonexistent-{re.sub(r'[^a-z0-9]', '', str(datetime.datetime.now().timestamp()))[:8]}.{target}"
    wc_ip = resolve_ip(rand_sub)
    if wc_ip:
        warn(f"Wildcard DNS detected! Random subdomain resolved to {wc_ip}")
        warn("  Brute-force results may contain false positives — filter by unique IPs")
        rmap.data['overview']['wildcard_ip'] = wc_ip
    else:
        ok("No wildcard DNS — brute-force results are clean")

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │  STEP C — Passive Sources (APIs, cert logs, threat intel)           │
    # └─────────────────────────────────────────────────────────────────────┘
    print(f"\n{C.BOLD}{C.GREEN}  ┌── C: PASSIVE API SOURCES ──────────────────────────┐{C.RESET}")

    # ── C1: subfinder ─────────────────────────────────────────────────────
    if has_tool('subfinder'):
        info("subfinder (50+ passive sources)...")
        sf_out = out / "p2_subfinder.txt"
        run(f"subfinder -d {target} -silent -all -o {sf_out} 2>/dev/null", timeout=180)
        subs = read_lines(sf_out)
        for s in subs: rmap.add_subdomain(s, 'subfinder')
        source_counts['subfinder'] = len(subs)
        ok(f"subfinder    → {len(subs):,} subdomains")
    else:
        warn("subfinder not installed: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    # ── C2: BBOT recursive ────────────────────────────────────────────────
    if has_tool('bbot'):
        info("BBOT recursive subdomain enum...")
        bbot_dir = out / "bbot_output"
        run(
            f"bbot -t {target} -f subdomain-enum "
            f"--output-dir {bbot_dir} --quiet -o txt 2>/dev/null",
            timeout=600
        )
        bbot_subs = set()
        search_dirs = list(Path(bbot_dir).rglob("*.txt")) if bbot_dir.exists() else []
        search_dirs += list(Path(bbot_dir).rglob("*.csv")) if bbot_dir.exists() else []
        for bbot_file in search_dirs:
            for line in read_lines(bbot_file):
                domain = line.split(',')[0].split()[0].strip().lower().rstrip('.')
                if domain.endswith(f'.{target}') or domain == target:
                    bbot_subs.add(domain)
        for s in bbot_subs: rmap.add_subdomain(s, 'bbot')
        source_counts['bbot'] = len(bbot_subs)
        ok(f"BBOT         → {len(bbot_subs):,} subdomains")
    else:
        warn("bbot not installed: pip install bbot")

    # ── C3: assetfinder ───────────────────────────────────────────────────
    if has_tool('assetfinder'):
        info("assetfinder...")
        af_out, _ = run(f"assetfinder --subs-only {target} 2>/dev/null", timeout=60)
        subs = [s.lower() for s in af_out.split('\n') if target in s and s.strip()]
        for s in subs: rmap.add_subdomain(s, 'assetfinder')
        source_counts['assetfinder'] = len(subs)
        ok(f"assetfinder  → {len(subs):,} subdomains")

    # ── C4: crt.sh certificate transparency ──────────────────────────────
    info("crt.sh certificate transparency...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=25, headers=HEADERS
        )
        if r.status_code == 200:
            crt_subs = set()
            for entry in r.json():
                for name in entry.get('name_value', '').split('\n'):
                    name = name.strip().lstrip('*.').lower()
                    if name.endswith(f".{target}") or name == target:
                        crt_subs.add(name)
            for s in crt_subs: rmap.add_subdomain(s, 'crt.sh')
            source_counts['crt.sh'] = len(crt_subs)
            ok(f"crt.sh       → {len(crt_subs):,} subdomains")
    except Exception as e:
        warn(f"crt.sh: {e}")

    # ── C5: HackerTarget ──────────────────────────────────────────────────
    info("HackerTarget passive DNS...")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={target}",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200 and 'error' not in r.text.lower()[:50]:
            ht_subs = set()
            for line in r.text.strip().split('\n'):
                if ',' in line:
                    d = line.split(',')[0].strip().lower()
                    if target in d: ht_subs.add(d)
            for s in ht_subs: rmap.add_subdomain(s, 'hackertarget')
            source_counts['hackertarget'] = len(ht_subs)
            ok(f"HackerTarget → {len(ht_subs):,} subdomains")
    except Exception as e:
        warn(f"HackerTarget: {e}")

    # ── C6: AlienVault OTX ───────────────────────────────────────────────
    info("AlienVault OTX passive DNS...")
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            otx_subs = set()
            for record in r.json().get('passive_dns', []):
                h = record.get('hostname', '').lower()
                if target in h: otx_subs.add(h)
            for s in otx_subs: rmap.add_subdomain(s, 'otx')
            source_counts['otx'] = len(otx_subs)
            ok(f"OTX          → {len(otx_subs):,} subdomains")
    except Exception as e:
        warn(f"OTX: {e}")

    # ── C7: RapidDNS ──────────────────────────────────────────────────────
    info("RapidDNS...")
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{target}?full=1",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            rapid_subs = set(re.findall(r'[\w\-\.]+\.' + re.escape(target), r.text))
            rapid_subs = {s.lower() for s in rapid_subs if s.endswith(target)}
            for s in rapid_subs: rmap.add_subdomain(s, 'rapiddns')
            source_counts['rapiddns'] = len(rapid_subs)
            ok(f"RapidDNS     → {len(rapid_subs):,} subdomains")
    except Exception as e:
        warn(f"RapidDNS: {e}")

    # ── C8: SecurityTrails (no key needed for basic query) ─────────────────
    info("SecurityTrails public endpoint...")
    try:
        r = requests.get(
            f"https://securitytrails.com/list/apex_domain/{target}",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            st_subs = set(re.findall(r'[\w\-\.]+\.' + re.escape(target), r.text))
            st_subs = {s.lower() for s in st_subs}
            for s in st_subs: rmap.add_subdomain(s, 'securitytrails')
            source_counts['securitytrails'] = len(st_subs)
            if st_subs: ok(f"SecurityTrails → {len(st_subs):,} subdomains")
    except Exception as e:
        warn(f"SecurityTrails: {e}")

    # ── C9: Chaos dataset ─────────────────────────────────────────────────
    info("Chaos dataset (ProjectDiscovery public bug bounty data)...")
    try:
        r = requests.get(
            "https://chaos-data.projectdiscovery.io/index.json",
            timeout=15, headers={'User-Agent': 'heyport/3.2'}
        )
        if r.status_code == 200:
            programs = r.json()
            matched  = [p for p in programs if target in p.get('domain', '')]
            if matched:
                import zipfile, io as _io
                for prog in matched[:3]:
                    dl_url = prog.get('URL', '')
                    if not dl_url: continue
                    dl = requests.get(dl_url, timeout=30, headers={'User-Agent': 'heyport/3.2'})
                    if dl.status_code == 200:
                        try:
                            z = zipfile.ZipFile(_io.BytesIO(dl.content))
                            chaos_subs = set()
                            for name in z.namelist():
                                content = z.read(name).decode('utf-8', errors='ignore')
                                for line in content.split('\n'):
                                    line = line.strip().lower()
                                    if line.endswith(f'.{target}') or line == target:
                                        chaos_subs.add(line)
                            for s in chaos_subs: rmap.add_subdomain(s, 'chaos')
                            source_counts['chaos'] = source_counts.get('chaos', 0) + len(chaos_subs)
                            ok(f"Chaos        → {len(chaos_subs):,} subdomains")
                        except: pass
            else:
                sub("Target not in Chaos public dataset")
    except Exception as e:
        warn(f"Chaos: {e}")

    # ── C10: VirusTotal public subdomains ─────────────────────────────────
    info("VirusTotal passive DNS...")
    try:
        r = requests.get(
            f"https://www.virustotal.com/vtapi/v2/domain/report?domain={target}",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            vt_subs = {e.lower() for e in r.json().get('subdomains', []) if target in e}
            for s in vt_subs: rmap.add_subdomain(s, 'virustotal')
            source_counts['virustotal'] = len(vt_subs)
            if vt_subs: ok(f"VirusTotal   → {len(vt_subs):,} subdomains")
    except Exception as e:
        warn(f"VirusTotal: {e}")

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │  STEP D — Mutation / Permutation (expand what we already found)     │
    # └─────────────────────────────────────────────────────────────────────┘
    print(f"\n{C.BOLD}{C.PURPLE}  ┌── D: MUTATION & PERMUTATION ───────────────────────┐{C.RESET}")

    all_before_mutate = rmap.all_subdomains()

    # ── D1: alterx smart mutations ────────────────────────────────────────
    if has_tool('alterx') and all_before_mutate:
        info(f"alterx — smart mutations on {len(all_before_mutate):,} found subdomains...")
        subs_for_mutate = out / "p2_subs_for_mutation.txt"
        save_lines(subs_for_mutate, all_before_mutate[:500])
        mutated_out  = out / "p2_alterx_mutations.txt"
        resolved_out = out / "p2_alterx_resolved.txt"
        run(
            f"alterx -l {subs_for_mutate} -enrich -silent "
            f"-o {mutated_out} 2>/dev/null",
            timeout=120
        )
        mutations = read_lines(mutated_out)
        info(f"  {len(mutations):,} mutation candidates → resolving...")
        if mutations and has_tool('dnsx'):
            run(
                f"dnsx -l {mutated_out} -silent -a "
                f"-o {resolved_out} -threads 100 2>/dev/null",
                timeout=300
            )
            resolved_muts = [
                line.split()[0].rstrip('.').lower()
                for line in read_lines(resolved_out)
            ]
            new_subs = [s for s in resolved_muts if s not in all_before_mutate]
            for s in new_subs: rmap.add_subdomain(s, 'alterx')
            source_counts['alterx'] = len(new_subs)
            if new_subs:
                found(f"alterx found  → {C.BOLD}{len(new_subs):,}{C.RESET} NEW subdomains via mutation!")
                for s in new_subs[:8]: sub(s)
    elif not has_tool('alterx'):
        warn("alterx not installed: go install github.com/projectdiscovery/alterx/cmd/alterx@latest")

    # ── D2: Python-based permutation fallback (if alterx missing) ─────────
    if not has_tool('alterx') and all_before_mutate:
        info("Built-in permutation engine (no alterx needed)...")
        prefixes   = ['dev', 'api', 'staging', 'test', 'beta', 'v2', 'v3', 'old',
                      'new', 'internal', 'prod', 'qa', 'uat', 'demo', 'auth',
                      'admin', 'app', 'mobile', 'web', 'static', 'cdn']
        candidates = set()
        # Only mutate base subdomains (1-2 parts) to keep it manageable
        base_subs  = [s for s in all_before_mutate if s.count('.') == len(target.split('.'))]
        for s in base_subs[:100]:
            prefix_part = s.split('.')[0]
            for px in prefixes:
                candidates.add(f"{px}-{prefix_part}.{target}")
                candidates.add(f"{prefix_part}-{px}.{target}")
                candidates.add(f"{px}.{prefix_part}.{target}")
        # Resolve candidates
        if candidates:
            cand_file = out / "p2_permutations.txt"
            save_lines(cand_file, list(candidates))
            perm_out  = out / "p2_permutations_resolved.txt"
            if has_tool('dnsx'):
                run(
                    f"dnsx -l {cand_file} -silent -a "
                    f"-o {perm_out} -threads 100 2>/dev/null",
                    timeout=300
                )
                perm_subs = [
                    line.split()[0].rstrip('.').lower()
                    for line in read_lines(perm_out)
                ]
            else:
                def resolve_candidate(c):
                    ip = resolve_ip(c)
                    return c if ip else None
                with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
                    perm_subs = [r for r in ex.map(resolve_candidate, candidates) if r]
            new_subs = [s for s in perm_subs if s not in all_before_mutate]
            for s in new_subs: rmap.add_subdomain(s, 'permutation')
            source_counts['permutation'] = len(new_subs)
            if new_subs:
                found(f"Permutation  → {C.BOLD}{len(new_subs):,}{C.RESET} NEW subdomains!")

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │  FINAL — Cross-verification, dedup, save                            │
    # └─────────────────────────────────────────────────────────────────────┘
    print(f"\n{C.BOLD}{C.CYAN}  ┌── RESULTS ──────────────────────────────────────────┐{C.RESET}")

    all_subs   = rmap.all_subdomains()
    confirmed  = rmap.confirmed_subdomains()
    single_src = [s for s in all_subs if s not in confirmed]

    print(f"\n{C.BOLD}  Source Breakdown:{C.RESET}")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        bar = '█' * min(cnt // max(1, max(source_counts.values()) // 20), 20)
        print(f"    {C.DIM}{src:<22}{C.RESET} {C.BOLD}{cnt:>5}{C.RESET}  {C.CYAN}{bar}{C.RESET}")

    print()
    found(f"Total unique subdomains   : {C.BOLD}{len(all_subs):,}{C.RESET}")
    found(f"CONFIRMED (2+ sources)    : {C.GREEN}{C.BOLD}{len(confirmed):,}{C.RESET}  ← highest priority")
    info( f"Single-source             : {len(single_src):,}")
    info( f"Active brute-force found  : {source_counts.get('puredns', 0) + source_counts.get('gobuster', 0) + source_counts.get('dnsx_brute', 0) + source_counts.get('direct_dns', 0) + source_counts.get('dnsrecon', 0):,}")
    info( f"Mutation/permutation found: {source_counts.get('alterx', 0) + source_counts.get('permutation', 0):,}")

    save_lines(out / "p2_all_subdomains.txt",       all_subs)
    save_lines(out / "p2_confirmed_subdomains.txt",  confirmed)
    save_lines(out / "p2_single_source.txt",         single_src)

    rmap.save_json(out / "recon_map.json")
    ok("Phase 2 complete → recon_map.json updated")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3 — ACTIVE FILTERING + WAF + TAKEOVER
# ═══════════════════════════════════════════════════════════════════════════
def phase3(out, rmap):
    phase_header(3, "ACTIVE FILTERING  —  DNS Alive | HTTP | WAF | Takeover", C.CYAN)

    all_subs   = rmap.all_subdomains()
    subs_file  = out / "p2_all_subdomains.txt"
    if not all_subs:
        warn("No subdomains to filter. Run Phase 2 first.")
        return

    # ── DNS Resolution (dnsx) ─────────────────────────────────────────────
    info(f"dnsx → resolving {len(all_subs):,} subdomains...")
    dns_alive_file = out / "p3_dns_alive.txt"

    if has_tool('dnsx'):
        run(
            f"dnsx -l {subs_file} -silent -a -resp "
            f"-o {dns_alive_file} -threads 100",
            timeout=600
        )
        dns_alive_raw = read_lines(dns_alive_file)
        # Parse "subdomain [IP]" format from dnsx
        dns_alive = []
        for line in dns_alive_raw:
            parts = line.split()
            sub_d = parts[0].rstrip('.')
            ip    = parts[1].strip('[]') if len(parts) > 1 else resolve_ip(sub_d)
            dns_alive.append(sub_d)
            if sub_d in rmap.data['subdomains']:
                if ip and ip not in rmap.data['subdomains'][sub_d]['ips']:
                    rmap.data['subdomains'][sub_d]['ips'].append(ip)
            rmap.add_host(ip or '', sub_d)
        # CRITICAL: overwrite dns_alive_file with CLEAN hostnames only.
        # dnsx outputs "hostname [IP]" — httpx cannot parse that format.
        # If we feed the raw file to httpx, every probe fails → HTTP Alive = 0.
        save_lines(dns_alive_file, dns_alive)
    else:
        warn("dnsx not found — using socket fallback (slower)...")
        def check_dns(s):
            ip = resolve_ip(s)
            return (s, ip) if ip else (s, None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
            results = list(ex.map(check_dns, all_subs))
        dns_alive = []
        for s, ip in results:
            if ip:
                dns_alive.append(s)
                if s in rmap.data['subdomains']:
                    rmap.data['subdomains'][s]['ips'] = [ip]
                rmap.add_host(ip, s)
        save_lines(dns_alive_file, dns_alive)

    ok(f"DNS-alive subdomains: {C.BOLD}{len(dns_alive):,}{C.RESET}")

    # ── HTTP Probing (httpx) — all relevant ports ──────────────────────────
    # Probing only 80+443 causes HTTP Alive = 0 on dev/internal infra.
    # Dev tools (Grafana, Jenkins, APIs) almost always run on non-standard ports.
    HTTP_PORTS = "80,443,8080,8443,8000,8888,8008,3000,3001,4443,9090,9443,5000,7443"
    info(f"httpx → probing {len(dns_alive):,} hosts across ports: {HTTP_PORTS}")
    http_alive_file = out / "p3_http_alive.txt"
    http_alive_json = out / "p3_http_alive.json"

    if has_tool('httpx'):
        run(
            f"httpx -l {dns_alive_file} -silent "
            f"-ports {HTTP_PORTS} "
            f"-status-code -title -tech-detect -content-length "
            f"-follow-redirects -threads 100 -timeout 10 "
            f"-json -o {http_alive_json}",
            timeout=900
        )
        # Parse httpx JSON output
        urls = []
        if http_alive_json.exists():
            for line in read_lines(http_alive_json):
                try:
                    d     = json.loads(line)
                    url   = d.get('url', '')
                    tech  = d.get('tech', [])
                    title = d.get('title', '')
                    status= d.get('status-code', 0)
                    host  = d.get('host', d.get('input', ''))
                    if not url:
                        continue
                    urls.append(url)
                    web_info = {
                        'url': url, 'status': status,
                        'title': title, 'tech': tech,
                        'content_length': d.get('content-length', 0),
                        'waf': None, 'findings': []
                    }
                    rmap.add_web(url, web_info)
                    if host in rmap.data['subdomains']:
                        rmap.data['subdomains'][host]['http'] = web_info
                    # ── Anomaly flags ────────────────────────────────────
                    if tech:
                        for t in tech:
                            if 'jquery' in t.lower() and any(c.isdigit() for c in t):
                                rmap.add_finding('old_js_lib', 'medium', url, f"Detected: {t}", 'httpx')
                    # Flag non-standard port exposure
                    for bad_port in ['8080','8443','8000','8888','3000','9090','4443','5000']:
                        if f':{bad_port}' in url:
                            rmap.add_finding('non_standard_port', 'medium', url,
                                f"Service exposed on non-standard port {bad_port}", 'httpx')
                    # Flag year-prefixed subdomains (old infra pattern)
                    year_match = re.match(r'^(20\d{2})-', host)
                    if year_match:
                        year = year_match.group(1)
                        rmap.add_finding('legacy_infra', 'high', url,
                            f"Year-prefixed subdomain '{host}' — likely abandoned {year} infrastructure. "
                            f"Check for default creds, unpatched CVEs, debug mode.", 'httpx')
                except:
                    pass
        save_if_nonempty(http_alive_file, urls)
        ok(f"HTTP-alive targets: {C.BOLD}{len(urls):,}{C.RESET}")

        # Print sample
        print()
        for line in read_lines(http_alive_json)[:10]:
            try:
                d = json.loads(line)
                status = d.get('status-code', '???')
                title  = d.get('title', '')[:40]
                url    = d.get('url', '')[:60]
                tech   = ', '.join(d.get('tech', [])[:3])
                color  = C.GREEN if str(status).startswith('2') else C.YELLOW if str(status).startswith('3') else C.RED
                print(f"    {color}[{status}]{C.RESET}  {url:<60}  {C.DIM}{title}  {tech}{C.RESET}")
            except:
                pass
        if len(urls) > 10:
            info(f"... and {len(urls) - 10} more")
    else:
        warn("httpx not installed")
        urls = []

    # ── WAF Detection (wafw00f) ────────────────────────────────────────────
    if has_tool('wafw00f') and urls:
        info(f"wafw00f → detecting WAFs on {min(len(urls), 50)} targets...")
        # Run on first 50 to keep it fast
        sample_urls = urls[:50]
        sample_file = out / "p3_wafw00f_input.txt"
        save_lines(sample_file, sample_urls)
        waf_out, _ = run(
            f"wafw00f -i {sample_file} -o {out}/p3_waf_results.txt -a 2>/dev/null",
            timeout=180
        )
        # Parse results
        waf_raw = read_lines(out / "p3_waf_results.txt") if (out / "p3_waf_results.txt").exists() else []
        waf_detected = 0
        for line in waf_raw:
            # wafw00f output: "url is behind XYZ WAF"
            if 'behind' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    url = parts[0].rstrip(':')
                    waf = line.split('behind')[-1].strip()
                    if url in rmap.data['web']:
                        rmap.data['web'][url]['waf'] = waf
                    # Find matching subdomain
                    for sub_d in rmap.data['subdomains']:
                        if sub_d in url:
                            rmap.data['subdomains'][sub_d]['waf'] = waf
                    rmap.add_finding('waf_detected', 'info', url, f"WAF: {waf}", 'wafw00f')
                    waf_detected += 1
        ok(f"WAFs detected: {waf_detected}")
    else:
        if not has_tool('wafw00f'):
            warn("wafw00f not installed — install: pip install wafw00f")

    # ── Subdomain Takeover (subjack) ──────────────────────────────────────
    if has_tool('subjack') and dns_alive:
        info(f"subjack → checking {len(dns_alive):,} subdomains for takeover opportunities...")
        run(
            f"subjack -w {dns_alive_file} -t 50 -timeout 30 "
            f"-o {out}/p3_takeover_risks.txt -v 2>/dev/null",
            timeout=180
        )
        takeover_raw = read_lines(out / "p3_takeover_risks.txt")
        # subjack -v outputs "[Not Vulnerable]" for every checked host.
        # Only lines WITHOUT "[Not Vulnerable]" are actual takeover opportunities.
        real_takeovers = [
            t for t in takeover_raw
            if t.strip() and '[not vulnerable]' not in t.lower()
        ]
        checked_count = len(takeover_raw)
        if real_takeovers:
            found(f"TAKEOVER VULNERABLE: {C.RED}{C.BOLD}{len(real_takeovers)}{C.RESET}  "
                  f"(checked {checked_count})")
            for t in real_takeovers:
                parts = t.split()
                sub_d = parts[0] if parts else t
                if sub_d in rmap.data['subdomains']:
                    rmap.data['subdomains'][sub_d]['takeover_risk'] = True
                rmap.add_finding('subdomain_takeover', 'critical', sub_d, t, 'subjack')
                print(f"    {C.RED}{C.BOLD}⚠  VULNERABLE: {t}{C.RESET}")
            # Save only real takeover risks
            save_if_nonempty(out / "p3_takeover_risks.txt", real_takeovers)
        else:
            ok(f"No takeover vulnerabilities found  (checked {checked_count} subdomains)")
            # Remove the file since it's just noise of Not Vulnerable entries
            try:
                (out / "p3_takeover_risks.txt").unlink()
            except:
                pass
    else:
        if not has_tool('subjack'):
            warn("subjack not installed — install: go install github.com/haccer/subjack@latest")

    # ── Save Tier 1 priority subdomains to dedicated file ─────────────────
    # Assign tiers first (before saving), then write the Tier 1 list
    tier_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    tier1_subs  = []
    for sub_d, data in rmap.data['subdomains'].items():
        tier = _classify_tier(sub_d, data)
        data['tier'] = tier
        tier_counts[tier] += 1
        if tier == 1:
            tier1_subs.append(sub_d)

    save_if_nonempty(out / "p3_tier1_priority.txt", sorted(tier1_subs))

    found(f"Tier 1 (High Priority): {C.RED}{C.BOLD}{tier_counts[1]}{C.RESET}  "
          f"| Tier 2 (Active): {C.YELLOW}{tier_counts[2]}{C.RESET}  "
          f"| Tier 3 (DNS only): {C.DIM}{tier_counts[3]}{C.RESET}  "
          f"| Tier 4 (Inactive): {C.DIM}{tier_counts[4]}{C.RESET}")
    if tier1_subs:
        ok(f"Tier 1 saved → p3_tier1_priority.txt  ({len(tier1_subs)} targets)")
        for s in sorted(tier1_subs)[:8]:
            sub(f"{s}")
        if len(tier1_subs) > 8:
            info(f"... and {len(tier1_subs)-8} more in p3_tier1_priority.txt")

    rmap.save_json(out / "recon_map.json")
    ok("Phase 3 complete → recon_map.json updated")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4 — SCANNING (RustScan → nmap + webanalyze + whatweb)
# ═══════════════════════════════════════════════════════════════════════════
def phase4(target, out, rmap):
    phase_header(4, "SCANNING  —  RustScan → nmap | webanalyze + whatweb", C.PURPLE)

    # Build unique IP list
    info("Resolving unique IPs from DNS-alive hosts...")
    unique_ips = set()
    try:
        main_ip = socket.gethostbyname(target)
        unique_ips.add(main_ip)
    except:
        pass

    dns_alive = [s for s, d in rmap.data['subdomains'].items() if d.get('ips')]
    for sub_d, data in rmap.data['subdomains'].items():
        for ip in data.get('ips', []):
            if ip:
                unique_ips.add(ip)

    # Also resolve any that have no IPs yet
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        resolved = list(ex.map(resolve_ip, [s for s, d in rmap.data['subdomains'].items() if not d.get('ips')]))
    unique_ips.update(ip for ip in resolved if ip)
    unique_ips.discard('')

    if not unique_ips:
        warn("No IPs to scan — run Phase 3 first")
        return

    targets_file = out / "p4_targets.txt"
    targets_file.write_text('\n'.join(unique_ips))
    ok(f"Unique IPs to scan: {C.BOLD}{len(unique_ips)}{C.RESET}")

    # ── Step 1: RustScan (fast port discovery) ────────────────────────────
    if has_tool('rustscan'):
        info("RustScan → all 65535 ports (fast discovery)...")
        rs_out, _ = run(
            f"rustscan --addresses $(cat {targets_file} | tr '\\n' ',') "
            f"--batch-size 3000 --timeout 1500 --tries 1 "
            f"-- -sV --version-intensity 5 -O --osscan-guess "
            f"-oN {out}/p4_nmap_via_rustscan.txt 2>/dev/null",
            timeout=1200
        )
        nmap_file = out / "p4_nmap_via_rustscan.txt"
        ok(f"RustScan → nmap complete → p4_nmap_via_rustscan.txt")
    else:
        warn("rustscan not found — falling back to nmap direct (slower)...")
        # nmap fallback: host discovery → port scan → services → OS
        info("nmap — host discovery...")
        run(f"nmap -sn -iL {targets_file} --open -oN {out}/p4_1_hosts.txt 2>/dev/null", timeout=120)
        info("nmap — TCP SYN scan top 1000 ports (T3)...")
        run(
            f"nmap -sS -iL {targets_file} --open -T3 --min-rate 300 --max-retries 2 "
            f"-oN {out}/p4_2_ports.txt -oG {out}/p4_2_ports_grep.txt 2>/dev/null",
            timeout=900
        )
        info("nmap — service + version detection...")
        run(
            f"nmap -sV -iL {targets_file} --open -T3 --version-intensity 5 "
            f"-oN {out}/p4_3_services.txt 2>/dev/null",
            timeout=900
        )
        info("nmap — OS fingerprinting...")
        run(
            f"nmap -O -iL {targets_file} --open -T3 --osscan-guess "
            f"-oN {out}/p4_4_os.txt 2>/dev/null",
            timeout=300
        )
        nmap_file = out / "p4_3_services.txt"

    # Parse nmap output → ReconMap
    _parse_nmap_into_map(nmap_file, rmap)
    ok("Port/service data mapped into ReconMap")

    # ── Step 2: Web Tech — webanalyze (Wappalyzer, bulk) ──────────────────
    http_file = out / "p3_http_alive.txt"
    urls       = read_lines(http_file)

    if has_tool('webanalyze') and urls:
        info(f"webanalyze (Wappalyzer engine) → {len(urls):,} targets...")
        urls_file   = out / "p4_urls.txt"
        wa_tmp_file = out / ".tmp_webanalyze.json"
        save_lines(urls_file, urls)
        run(
            f"webanalyze -hosts {urls_file} -crawl 1 "
            f"-output json 2>/dev/null > {wa_tmp_file}",
            timeout=600
        )
        if wa_tmp_file.exists() and wa_tmp_file.stat().st_size > 10:
            _parse_webanalyze_into_map(wa_tmp_file, rmap)
            wa_tmp_file.unlink(missing_ok=True)   # remove intermediate file
            ok("webanalyze complete — tech mapped into report")
        else:
            wa_tmp_file.unlink(missing_ok=True)
    else:
        if not has_tool('webanalyze'):
            warn("webanalyze not installed — install: go install github.com/rverton/webanalyze@latest")

    # ── Step 3: whatweb — deep analysis on top 20 most interesting targets ─
    if has_tool('whatweb') and urls:
        # Prioritize: Tier 1 first, then 2xx status, then others
        def url_score(u):
            host = u.replace('https://','').replace('http://','').split('/')[0]
            sub_data = rmap.data['subdomains'].get(host, {})
            tier  = sub_data.get('tier', 4)
            status= (sub_data.get('http') or {}).get('status', 0)
            return (tier, -1 if str(status).startswith('2') else 0)

        top_urls = sorted(urls, key=url_score)[:20]
        top_file = out / "p4_top_urls.txt"
        save_lines(top_file, top_urls)
        info(f"whatweb deep analysis on top {len(top_urls)} priority targets...")
        ww_tmp = out / ".tmp_whatweb.json"
        run(
            f"whatweb --input-file={top_file} "
            f"--log-json={ww_tmp} --quiet 2>/dev/null",
            timeout=300
        )
        if ww_tmp.exists() and ww_tmp.stat().st_size > 10:
            _parse_whatweb_into_map(ww_tmp, rmap)
            ww_tmp.unlink(missing_ok=True)
            ok("whatweb complete — tech + versions mapped into report")
        else:
            ww_tmp.unlink(missing_ok=True)
    else:
        if not has_tool('whatweb'):
            warn("whatweb not installed — sudo apt install whatweb")

    rmap.save_json(out / "recon_map.json")
    ok("Phase 4 complete → recon_map.json updated")


def _parse_nmap_into_map(nmap_file, rmap):
    if not Path(nmap_file).exists():
        return
    current_ip = None
    current_os = None
    for line in read_lines(nmap_file):
        # Match IP
        ip_match = re.search(r'Nmap scan report for (?:[\w.\-]+ )?(?:\()?(\d{1,3}(?:\.\d{1,3}){3})(?:\))?', line)
        if ip_match:
            current_ip = ip_match.group(1)
            rmap.add_host(current_ip)
            # Also grab hostname if present
            host_match = re.search(r'Nmap scan report for ([\w.\-]+) \(', line)
            if host_match:
                rmap.add_host(current_ip, host_match.group(1))
        # Match open port
        port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if port_match and current_ip:
            port    = int(port_match.group(1))
            proto   = port_match.group(2)
            service = port_match.group(3)
            version = port_match.group(4).strip()
            if current_ip in rmap.data['hosts']:
                if port not in rmap.data['hosts'][current_ip]['ports']:
                    rmap.data['hosts'][current_ip]['ports'].append(port)
                rmap.data['hosts'][current_ip]['services'][str(port)] = {
                    'proto': proto, 'service': service, 'version': version
                }
        # Match OS
        os_match = re.search(r'OS details?: (.+)', line)
        if os_match and current_ip:
            rmap.data['hosts'][current_ip]['os'] = os_match.group(1).strip()


def _parse_webanalyze_into_map(json_file, rmap):
    """Robust webanalyze parser — handles array, newline-JSON, and version extraction."""
    try:
        content = Path(json_file).read_text().strip()
        if not content:
            return
        # Try array first, then newline-delimited JSON
        entries = []
        if content.startswith('['):
            try:
                entries = json.loads(content)
            except:
                pass
        if not entries:
            for line in content.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass

        tech_count = 0
        for entry in entries:
            # webanalyze uses different key names across versions
            url   = (entry.get('Hostname') or entry.get('hostname') or
                     entry.get('url') or entry.get('URL') or '').strip()
            # Normalize URL — add https if missing
            if url and not url.startswith('http'):
                url = 'https://' + url

            matches = (entry.get('Matches') or entry.get('matches') or
                       entry.get('technologies') or entry.get('apps') or [])

            tech_names = []
            for m in matches:
                if isinstance(m, dict):
                    name    = (m.get('App', {}) or {}).get('name', '') or m.get('name', '') or m.get('app', '')
                    version = (m.get('Version') or m.get('version') or '')
                    if name:
                        tech_names.append(f"{name} {version}".strip() if version else name)
                elif isinstance(m, str):
                    tech_names.append(m)

            # Try to match URL to web map (exact or subdomain match)
            target_key = None
            if url in rmap.data['web']:
                target_key = url
            else:
                # Try matching by hostname
                for web_url in rmap.data['web']:
                    if url.replace('https://','').replace('http://','').split('/')[0] in web_url:
                        target_key = web_url
                        break

            if target_key and tech_names:
                existing = rmap.data['web'][target_key].get('tech', [])
                rmap.data['web'][target_key]['tech'] = list(dict.fromkeys(existing + tech_names))
                tech_count += len(tech_names)

            # Also update subdomain entry
            host = url.replace('https://','').replace('http://','').split('/')[0]
            if host in rmap.data['subdomains'] and tech_names:
                http = rmap.data['subdomains'][host].get('http') or {}
                existing = http.get('tech', [])
                http['tech'] = list(dict.fromkeys(existing + tech_names))
                rmap.data['subdomains'][host]['http'] = http

        if tech_count:
            ok(f"webanalyze → {tech_count} tech detections mapped")
    except Exception as e:
        warn(f"webanalyze parse error: {e}")


def _parse_whatweb_into_map(json_file, rmap):
    """Robust whatweb parser — extracts tech + exact version strings."""
    try:
        content = Path(json_file).read_text().strip()
        if not content:
            return
        entries = []
        if content.startswith('['):
            try:
                entries = json.loads(content)
            except:
                entries = []
        if not entries:
            for line in content.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass

        tech_count = 0
        for entry in entries:
            target_url = entry.get('target', entry.get('url', ''))
            plugins    = entry.get('plugins', {})

            tech_names = []
            for plugin_name, plugin_data in plugins.items():
                if not plugin_name or plugin_name.lower() in ('redirect','script','meta','headers'):
                    continue
                versions = plugin_data.get('version', []) or plugin_data.get('Version', [])
                if versions:
                    v = versions[0] if isinstance(versions, list) else versions
                    tech_names.append(f"{plugin_name} {v}".strip())
                else:
                    tech_names.append(plugin_name)

                # Create specific findings for interesting tech
                v_str = (versions[0] if isinstance(versions, list) and versions else '') if versions else ''
                if plugin_name == 'WordPress':
                    rmap.add_finding('cms_detected', 'info', target_url, f"WordPress {v_str}".strip(), 'whatweb')
                elif plugin_name == 'PHP' and v_str:
                    rmap.add_finding('tech_version', 'info', target_url, f"PHP {v_str}", 'whatweb')
                    # Flag old PHP
                    try:
                        major = int(v_str.split('.')[0])
                        if major < 8:
                            rmap.add_finding('outdated_tech', 'medium', target_url, f"PHP {v_str} — EOL or outdated", 'whatweb')
                    except:
                        pass
                elif plugin_name == 'Apache' and v_str:
                    rmap.add_finding('tech_version', 'info', target_url, f"Apache {v_str}", 'whatweb')

            # Match to web map
            target_key = None
            if target_url in rmap.data['web']:
                target_key = target_url
            else:
                for web_url in rmap.data['web']:
                    if target_url.replace('https://','').replace('http://','').split('/')[0] in web_url:
                        target_key = web_url
                        break

            if target_key and tech_names:
                existing = rmap.data['web'][target_key].get('tech', [])
                rmap.data['web'][target_key]['tech'] = list(dict.fromkeys(existing + tech_names))
                tech_count += len(tech_names)

            # Also update subdomain
            host = target_url.replace('https://','').replace('http://','').split('/')[0]
            if host in rmap.data['subdomains'] and tech_names:
                http = rmap.data['subdomains'][host].get('http') or {}
                existing = http.get('tech', [])
                http['tech'] = list(dict.fromkeys(existing + tech_names))
                rmap.data['subdomains'][host]['http'] = http

        if tech_count:
            ok(f"whatweb → {tech_count} tech detections mapped")
    except Exception as e:
        warn(f"whatweb parse error: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5 — VULNERABILITY MAPPING (nuclei priority + dalfox)
# ═══════════════════════════════════════════════════════════════════════════
def phase5(out, rmap):
    phase_header(5, "VULNERABILITY MAPPING  —  nuclei (Priority) + dalfox", C.RED)

    http_file = out / "p3_http_alive.txt"
    urls      = read_lines(http_file)

    # Fallback: if file is empty/missing, pull from ReconMap web entries directly
    if not urls and rmap.data.get('web'):
        urls = list(rmap.data['web'].keys())
        info(f"p3_http_alive.txt empty — using {len(urls)} URLs from ReconMap")
        save_lines(http_file, urls)

    if not urls:
        warn("No HTTP targets found — Phase 3 may have found 0 HTTP-alive hosts")
        warn("This is common when target is behind Cloudflare or ports are filtered")
        warn("Try running: httpx -u https://TARGET -silent -status-code to verify manually")
        return

    urls_file = out / "p5_targets.txt"
    save_lines(urls_file, urls)

    if has_tool('nuclei'):
        # Update templates silently
        info("Updating nuclei templates...")
        run("nuclei -update-templates -silent 2>/dev/null", timeout=60)

        # ── Priority 1: Critical + High CVEs + Takeovers ──────────────────
        info(f"nuclei PASS 1 — Critical & High CVEs + Takeovers on {len(urls):,} targets...")
        run(
            f"nuclei -l {urls_file} "
            f"-tags cve,takeover,exposure,default-login "
            f"-severity critical,high "
            f"-silent -stats "
            f"-o {out}/p5_nuclei_pass1_critical_high.txt 2>/dev/null",
            timeout=1800
        )

        # ── Priority 2: Medium (misconfigs, exposed panels) ──────────────
        info("nuclei PASS 2 — Medium severity (misconfigs, exposed panels)...")
        run(
            f"nuclei -l {urls_file} "
            f"-severity medium "
            f"-silent "
            f"-o {out}/p5_nuclei_pass2_medium.txt 2>/dev/null",
            timeout=1800
        )

        # Combine and parse findings
        all_findings = (
            read_lines(out / "p5_nuclei_pass1_critical_high.txt") +
            read_lines(out / "p5_nuclei_pass2_medium.txt")
        )

        # Parse nuclei output into ReconMap
        for line in all_findings:
            # nuclei format: [template-id] [severity] [url] some detail
            parts  = re.findall(r'\[([^\]]+)\]', line)
            if len(parts) >= 2:
                template_id = parts[0]
                severity    = parts[1].lower()
                url_match   = re.search(r'https?://\S+', line)
                target_url  = url_match.group(0) if url_match else ""
                rmap.add_finding('nuclei', severity, target_url, line, 'nuclei')

        found(f"nuclei total findings: {len(all_findings)}")
        crit  = [f for f in all_findings if 'critical' in f.lower()]
        high  = [f for f in all_findings if '[high]' in f.lower()]
        med   = [f for f in all_findings if '[medium]' in f.lower()]

        if crit:
            print(f"\n  {C.RED}{C.BOLD}  ◉ CRITICAL ({len(crit)}){C.RESET}")
            for f in crit[:5]: print(f"    {C.RED}{f}{C.RESET}")
        if high:
            print(f"\n  {C.YELLOW}{C.BOLD}  ◉ HIGH ({len(high)}){C.RESET}")
            for f in high[:5]: print(f"    {C.YELLOW}{f}{C.RESET}")
        if med:
            print(f"\n  {C.CYAN}  ◉ MEDIUM ({len(med)}){C.RESET}")
            for f in med[:5]: print(f"    {C.CYAN}{f}{C.RESET}")
    else:
        warn("nuclei not installed")

    # ── dalfox (XSS parameter hunting) ────────────────────────────────────
    if has_tool('dalfox') and urls:
        info(f"dalfox → XSS hunting on {min(len(urls), 30)} targets...")
        dalfox_targets = urls[:30]
        dalfox_file    = out / "p5_dalfox_targets.txt"
        save_lines(dalfox_file, dalfox_targets)
        run(
            f"dalfox file {dalfox_file} "
            f"--silence --only-poc r "
            f"-o {out}/p5_dalfox_xss.txt 2>/dev/null",
            timeout=600
        )
        xss_findings = read_lines(out / "p5_dalfox_xss.txt")
        if xss_findings:
            found(f"dalfox XSS findings: {len(xss_findings)}")
            for f in xss_findings[:5]:
                rmap.add_finding('xss', 'high', f, f, 'dalfox')
                print(f"    {C.YELLOW}{f}{C.RESET}")
        else:
            ok("No XSS found by dalfox")
    else:
        if not has_tool('dalfox'):
            warn("dalfox not installed — install: go install github.com/hahwul/dalfox/v2@latest")

    rmap.save_json(out / "recon_map.json")
    ok("Phase 5 complete → recon_map.json updated")


# ═══════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR — v3.2  Active-only  ·  Tiers  ·  Tech  ·  OSINT
# ═══════════════════════════════════════════════════════════════════════════
def generate_html_report(rmap, out):
    info("Generating HTML report...")

    data     = rmap.data
    target   = data['meta']['target']
    overview = data.get('overview', {})
    subs     = data.get('subdomains', {})
    hosts    = data.get('hosts', {})
    findings = data.get('findings', [])
    summary  = rmap.get_summary()
    ipinfo   = overview.get('ipinfo', {})
    shodan   = overview.get('shodan_internetdb', {})
    whois_p  = overview.get('whois_parsed', {})
    osint    = overview.get('osint', {})

    # ── Separate active from inactive ─────────────────────────────────────
    active_subs   = {s: d for s, d in subs.items() if d.get('ips') or d.get('http')}
    inactive_subs = {s: d for s, d in subs.items() if not d.get('ips') and not d.get('http')}

    # Sort active by tier then alpha
    active_sorted = sorted(active_subs.items(), key=lambda x: (x[1].get('tier', 4), x[0]))

    # Severity helpers
    sev_color = {'critical':'#dc2626','high':'#d97706','medium':'#3b82f6',
                 'low':'#059669','info':'#64748b'}
    sev_bg    = {'critical':'#fef2f2','high':'#fffbeb','medium':'#eff6ff',
                 'low':'#f0fdf4','info':'#f8fafc'}

    # ── Tier badge HTML ───────────────────────────────────────────────────
    tier_style = {
        1: ('HIGH PRIORITY', '#dc2626', '#fef2f2'),
        2: ('ACTIVE',        '#059669', '#f0fdf4'),
        3: ('DNS ONLY',      '#64748b', '#f1f5f9'),
        4: ('INACTIVE',      '#94a3b8', '#f8fafc'),
    }
    def tier_badge(t):
        label, color, bg = tier_style.get(t, ('?', '#94a3b8', '#f8fafc'))
        return f'<span style="background:{bg};color:{color};border:1px solid {color};padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:0.5px">{label}</span>'

    # ── Tech pills HTML ───────────────────────────────────────────────────
    cat_colors = {
        'Language':'#7c3aed', 'Server':'#0891b2', 'CMS':'#d97706',
        'Framework':'#059669', 'JS Library':'#2563eb', 'CDN':'#0f766e',
        'Cloud':'#0369a1', 'Database':'#b91c1c', 'Analytics':'#64748b',
        'Security':'#dc2626', 'OS':'#475569', 'Other':'#94a3b8',
    }
    def tech_pills(tech_list):
        if not tech_list:
            return '<span style="color:#475569;font-size:11px">—</span>'
        cats = _categorize_tech(tech_list)
        html_parts = []
        for cat, items in cats.items():
            color = cat_colors.get(cat, '#64748b')
            for item in items[:2]:  # max 2 per category in table
                html_parts.append(
                    f'<span title="{cat}" style="display:inline-block;background:{color}18;'
                    f'color:{color};border:1px solid {color}40;padding:1px 6px;'
                    f'border-radius:3px;font-size:10px;margin:1px;white-space:nowrap">{item}</span>'
                )
        return ' '.join(html_parts) or '—'

    def tech_full_card(tech_list):
        """Expanded tech breakdown by category for the detail view."""
        if not tech_list:
            return '<span style="color:#475569">None detected</span>'
        cats = _categorize_tech(tech_list)
        rows = ''
        for cat, items in cats.items():
            color = cat_colors.get(cat, '#64748b')
            pills = ' '.join(
                f'<span style="background:{color}18;color:{color};border:1px solid {color}40;'
                f'padding:2px 8px;border-radius:4px;font-size:11px;margin:2px;display:inline-block">'
                f'{item}</span>' for item in items
            )
            rows += f'<div style="margin:4px 0"><span style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;width:80px;display:inline-block">{cat}</span>{pills}</div>'
        return rows

    # ── Build subdomain rows (active only) ────────────────────────────────
    sub_rows_html = ''
    for s, d in active_sorted:
        tier     = d.get('tier', 4)
        ips      = ', '.join(d.get('ips', [])[:2])
        http     = d.get('http') or {}
        status   = http.get('status', '')
        title    = (http.get('title') or '')[:45]
        tech     = list(set((http.get('tech') or [])))
        waf      = d.get('waf') or ''
        takeover = d.get('takeover_risk', False)
        sources  = ', '.join(d.get('sources', [])[:3])
        sc       = str(status)
        sc_color = ('#059669' if sc.startswith('2') else '#d97706' if sc.startswith('3')
                    else '#dc2626' if sc.startswith(('4','5')) else '#94a3b8')

        takeover_cell = ('<span style="color:#dc2626;font-weight:700;font-size:11px">⚠ TAKEOVER</span>'
                         if takeover else '')
        waf_cell = (f'<span style="color:#0891b2;font-size:10px">{waf[:25]}</span>'
                    if waf else '<span style="color:#64748b;font-size:10px">None</span>')

        sub_rows_html += f'''
        <tr>
          <td style="padding:8px 12px">
            <div style="font-family:monospace;font-size:12px;color:#e2e8f0;font-weight:500">{s}</div>
            <div style="font-size:10px;color:#64748b;margin-top:2px">{sources}</div>
          </td>
          <td style="padding:8px 12px">{tier_badge(tier)}</td>
          <td style="padding:8px 12px;font-family:monospace;font-size:11px;color:#94a3b8">{ips}</td>
          <td style="padding:8px 12px"><span style="color:{sc_color};font-weight:700;font-size:13px">{status or '—'}</span></td>
          <td style="padding:8px 12px;font-size:11px;color:#cbd5e1;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{title}</td>
          <td style="padding:8px 12px;max-width:220px">{tech_pills(tech)}</td>
          <td style="padding:8px 12px">{waf_cell}</td>
          <td style="padding:8px 12px">{takeover_cell}</td>
        </tr>'''

    # ── Host rows ─────────────────────────────────────────────────────────
    host_rows_html = ''
    for ip, d in sorted(hosts.items()):
        if not ip: continue
        hostnames = ', '.join(d.get('hostnames', [])[:3])
        ports     = sorted(d.get('ports', []))
        ports_str = ' '.join(
            f'<span style="background:#1e3a5f;color:#7dd3fc;padding:1px 5px;border-radius:3px;'
            f'font-size:10px;margin:1px;font-family:monospace">{p}</span>'
            for p in ports[:12]
        )
        os_str    = d.get('os') or '—'
        cves      = d.get('cves', [])
        cve_str   = ' '.join(
            f'<span style="background:#fef2f2;color:#dc2626;padding:1px 5px;border-radius:3px;font-size:10px;margin:1px">{c}</span>'
            for c in cves[:4]
        ) if cves else ''
        services  = d.get('services', {})
        svc_str   = '<br>'.join(
            f'<span style="font-family:monospace;font-size:11px;color:#94a3b8">{p}</span>'
            f'<span style="font-size:11px;color:#e2e8f0"> {v.get("service","?")} '
            f'<span style="color:#64748b">{v.get("version","")[:30]}</span></span>'
            for p, v in list(services.items())[:5]
        )
        host_rows_html += f'''
        <tr>
          <td style="padding:8px 12px;font-family:monospace;font-weight:600;color:#7dd3fc">{ip}</td>
          <td style="padding:8px 12px;font-size:11px;color:#64748b">{hostnames}</td>
          <td style="padding:8px 12px">{ports_str}</td>
          <td style="padding:8px 12px">{svc_str}</td>
          <td style="padding:8px 12px;font-size:11px;color:#94a3b8">{os_str}</td>
          <td style="padding:8px 12px">{cve_str or '<span style="color:#64748b;font-size:11px">None</span>'}</td>
        </tr>'''

    # ── Findings rows ─────────────────────────────────────────────────────
    sev_order    = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
    findings_sorted = sorted(
        [f for f in findings if f.get('severity') in ('critical','high','medium')],
        key=lambda f: sev_order.get(f.get('severity','info'), 5)
    )
    findings_html = ''
    for f in findings_sorted[:100]:
        sev  = f.get('severity', 'info')
        fc   = sev_color.get(sev, '#64748b')
        fbg  = sev_bg.get(sev, '#f8fafc')
        findings_html += f'''
        <tr>
          <td style="padding:8px 12px">
            <span style="background:{fbg};color:{fc};border:1px solid {fc};padding:2px 8px;
              border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase">{sev}</span>
          </td>
          <td style="padding:8px 12px;font-family:monospace;font-size:11px;color:#7dd3fc">{f.get("target","")[:60]}</td>
          <td style="padding:8px 12px;font-size:11px;color:#e2e8f0">{f.get("type","")}</td>
          <td style="padding:8px 12px;font-size:11px;color:#94a3b8">{str(f.get("detail",""))[:100]}</td>
          <td style="padding:8px 12px;font-size:10px;color:#475569">{f.get("source","")}</td>
        </tr>'''

    # ── DNS records ───────────────────────────────────────────────────────
    dns_rows = ''
    for rtype, vals in overview.get('dns', {}).items():
        dns_rows += f'<tr><td style="color:#64748b;font-size:11px;padding:5px 8px;font-weight:600">{rtype}</td><td style="font-family:monospace;font-size:11px;color:#e2e8f0;padding:5px 8px">{" | ".join(vals[:4])}</td></tr>'

    # ── OSINT section ─────────────────────────────────────────────────────
    def osint_row(key, val, color='#e2e8f0'):
        if not val: return ''
        return f'<div class="irow"><span class="ikey">{key}</span><span class="ival" style="color:{color}">{str(val)[:80]}</span></div>'

    # ── Emails (collected from theHarvester + Hunter) ─────────────────────
    all_emails = list(dict.fromkeys(
        overview.get('emails', []) + osint.get('emails', [])
    ))[:20]

    # ── Cloudflare origin bypass card ─────────────────────────────────────
    origin_data = overview.get('origin_ips', {})
    if origin_data:
        rows = ''.join(
            f'<div class="irow"><span class="ikey" style="color:#d97706">{src.upper()}</span>'
            f'<span class="ival" style="color:#fbbf24">'
            f'{", ".join(ips) if isinstance(ips, list) else str(ips)}</span></div>'
            for src, ips in origin_data.items()
        )
        origin_bypass_html = (
            f'<div class="card" style="border-color:#d97706">'
            f'<h3 style="color:#d97706">⚠ Cloudflare Bypass — Potential Origin IPs</h3>'
            f'{rows}'
            f'<div style="color:#475569;font-size:11px;margin-top:8px">'
            f'Verify manually — may still be Cloudflare infrastructure</div></div>'
        )
    else:
        origin_bypass_html = ''

    # ── Stat cards ────────────────────────────────────────────────────────
    tier1_count = sum(1 for d in subs.values() if d.get('tier') == 1)
    stat_cards_html = ''.join(f'''
        <div class="scard">
          <div class="snum" style="color:{c}">{v:,}</div>
          <div class="slbl">{l}</div>
        </div>'''
        for l, v, c in [
            ("Total Found",       len(subs),                      "#0891b2"),
            ("Active",            len(active_subs),               "#059669"),
            ("High Priority T1",  tier1_count,                    "#dc2626"),
            ("HTTP Alive",        summary['http_alive'],          "#7c3aed"),
            ("Unique IPs",        summary['total_ips'],           "#0f766e"),
            ("Critical",          summary['critical'],            "#dc2626"),
            ("High",              summary['high'],                "#d97706"),
            ("Medium",            summary['medium'],              "#3b82f6"),
            ("Takeover Risks",    summary['takeover_risks'],      "#dc2626"),
            ("WAFs Detected",     summary['wafs_detected'],       "#7c3aed"),
        ]
    )

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HeyPort — {target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#0a0f1e;color:#e2e8f0;font-size:14px;line-height:1.5}}

  /* HEADER */
  .hdr{{background:linear-gradient(135deg,#0e1a2b 0%,#0c2a3a 60%,#091425 100%);
    padding:36px 40px;border-bottom:1px solid #1e3a5f}}
  .hdr-top{{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px}}
  .logo{{font-size:48px;font-weight:900;letter-spacing:-2px}}
  .logo span{{color:#38bdf8}}
  .version{{font-size:13px;color:#475569;margin-top:4px}}
  .hdr-meta{{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}}
  .pill{{background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.2);
    padding:4px 12px;border-radius:20px;font-size:12px;color:#94a3b8}}
  .pill b{{color:#e2e8f0}}

  /* STATS */
  .stats{{display:flex;flex-wrap:wrap;gap:12px;padding:20px 40px;
    background:#0e1828;border-bottom:1px solid #1e293b}}
  .scard{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
    padding:14px 18px;min-width:120px;text-align:center;flex:1}}
  .snum{{font-size:26px;font-weight:800}}
  .slbl{{font-size:10px;color:#475569;margin-top:2px;text-transform:uppercase;letter-spacing:0.5px}}

  /* CONTENT */
  .content{{padding:24px 40px;max-width:1600px}}
  .sec{{margin-bottom:32px}}
  .sec-title{{font-size:18px;font-weight:700;color:#f1f5f9;padding-bottom:8px;
    border-bottom:1px solid #1e293b;margin-bottom:16px;display:flex;align-items:center;gap:10px}}
  .cnt{{background:#0891b2;color:white;padding:1px 9px;border-radius:12px;font-size:12px}}

  /* TABLES */
  .twrap{{overflow-x:auto;border-radius:8px;border:1px solid #1e293b}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#0f172a;color:#475569;font-size:10px;text-transform:uppercase;
    letter-spacing:0.6px;padding:10px 12px;text-align:left;white-space:nowrap}}
  td{{border-bottom:1px solid #0f172a;vertical-align:middle}}
  tr:hover td{{background:rgba(56,189,248,0.03)}}

  /* OVERVIEW GRID */
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}}
  .card{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:18px}}
  .card h3{{font-size:11px;color:#38bdf8;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}}
  .irow{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #1e293b;font-size:12px}}
  .irow:last-child{{border-bottom:none}}
  .ikey{{color:#475569;min-width:100px}}
  .ival{{color:#e2e8f0;font-family:monospace;font-size:11px;text-align:right;max-width:200px;word-break:break-all}}

  /* FOOTER */
  .footer{{background:#0e1828;border-top:1px solid #1e293b;padding:20px 40px;
    color:#334155;font-size:12px;margin-top:40px}}
  .inactive-note{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
    padding:16px 20px;margin-top:16px;font-size:13px;color:#475569}}
  .inactive-note b{{color:#64748b}}

  /* ALERT */
  .alert{{background:#1a0505;border:1px solid #dc2626;border-radius:8px;padding:14px 18px;
    margin-bottom:20px;color:#fca5a5;font-weight:600;font-size:14px}}

  @media(max-width:768px){{.hdr,.content,.stats{{padding:16px}}}}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-top">
    <div>
      <div class="logo">Hey<span>Port</span></div>
      <div class="version">v3.2 — Bug Bounty &amp; Pentest Recon</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:22px;font-weight:700;color:#38bdf8">{target}</div>
      <div style="font-size:12px;color:#475569;margin-top:4px">{data['meta']['timestamp'][:19]}</div>
    </div>
  </div>
  <div class="hdr-meta">
    <span class="pill">🌐 IP: <b>{overview.get('main_ip','—')}</b></span>
    <span class="pill">🏢 <b>{ipinfo.get('org','—')}</b></span>
    <span class="pill">📍 {ipinfo.get('city','—')}, {ipinfo.get('country','—')}</span>
    {'<span class="pill">☁️ <b>' + osint.get('cloud_provider','') + '</b></span>' if osint.get('cloud_provider') else ''}
    {'<span class="pill">🏭 <b>' + osint.get('company_name','') + '</b></span>' if osint.get('company_name') else ''}
  </div>
</div>

<div class="stats">{stat_cards_html}</div>

<div class="content">

{'<div class="alert">⚠ ' + str(summary["critical"]) + ' CRITICAL finding(s) — require immediate attention</div>' if summary['critical'] > 0 else ''}

<!-- ── ORGANIZATION INTELLIGENCE ─────────────────────────────── -->
<div class="sec">
  <div class="sec-title">🏢 Organization Intelligence</div>
  <div class="grid">

    <div class="card">
      <h3>Company</h3>
      {osint_row("Name",        osint.get('company_name'))}
      {osint_row("Cloud / Host",osint.get('cloud_provider'), '#38bdf8')}
      {osint_row("ASN",         ', '.join(osint.get('asn_info', [])[:2]))}
      {osint_row("IP Ranges",   ', '.join(osint.get('ip_ranges', [])[:4]))}
      {osint_row("Location",    ipinfo.get('city','') + ', ' + ipinfo.get('country','') if ipinfo.get('city') else '')}
      {osint_row("ISP / Org",   ipinfo.get('org',''))}
    </div>

    <div class="card">
      <h3>GitHub Organization</h3>
      {osint_row("Org Name",    osint.get('github_name'))}
      {osint_row("Handle",      osint.get('github_org'))}
      {osint_row("Public Repos",str(osint.get('github_public_repos','')) if osint.get('github_public_repos') else None)}
      {osint_row("Location",    osint.get('github_location'))}
      {osint_row("Email",       osint.get('github_email'))}
      {osint_row("Website",     osint.get('github_blog'))}
      {osint_row("Description", (osint.get('github_description') or '')[:80])}
      {osint_row("Created",     osint.get('github_created'))}
      {'<div style="color:#475569;font-size:11px;margin-top:8px;padding:8px;background:#0a0f1e;border-radius:4px">No GitHub org found</div>' if not osint.get('github_org') else ''}
    </div>

    <div class="card">
      <h3>Emails &amp; Contacts</h3>
      {''.join(f'<div class="irow"><span class="ival" style="font-family:monospace;color:#7dd3fc">{e}</span></div>' for e in all_emails) or '<div style="color:#475569;font-size:12px">No emails found</div>'}
    </div>

    <div class="card">
      <h3>Breach Intelligence</h3>
      {'<div style="background:#1a0505;border:1px solid #dc2626;border-radius:6px;padding:12px;color:#fca5a5;font-weight:600">⚠ ' + str(osint.get("breach_count",0)) + ' known data breaches<br><div style="font-size:11px;font-weight:400;margin-top:6px;color:#f87171">' + ' · '.join(osint.get("breaches",[])[:6]) + '</div></div>' if osint.get('breach_count',0) > 0 else '<div style="color:#059669;font-size:13px;padding:8px">✓ No known breaches in HIBP database</div>' if 'breach_count' in osint else '<div style="color:#475569;font-size:12px">HIBP check not completed</div>'}
      <div style="margin-top:12px">
        {osint_row("Shodan CVEs", ', '.join(shodan.get('vulns',[])[:5]), '#dc2626') if shodan.get('vulns') else ''}
        {osint_row("Shodan Ports", ', '.join(str(p) for p in shodan.get('ports',[])[:8]))}
        {osint_row("Shodan Tags",  ', '.join(shodan.get('tags',[])[:5]))}
      </div>
    </div>

  </div>
</div>

<!-- ── TARGET OVERVIEW ───────────────────────────────────────── -->
<div class="sec">
  <div class="sec-title">🔍 Target Overview</div>
  <div class="grid">

    <div class="card">
      <h3>DNS Records</h3>
      <table><tbody>{dns_rows}</tbody></table>
    </div>

    <div class="card">
      <h3>WHOIS</h3>
      {''.join(f'<div class="irow"><span class="ikey">{k}</span><span class="ival">{str(v)[:50]}</span></div>' for k,v in list(whois_p.items())[:8])}
    </div>

    <div class="card">
      <h3>SSL / Certificate History</h3>
      <div class="irow"><span class="ikey">CERT COUNT</span>
        <span class="ival" style="color:#38bdf8">{overview.get('cert_count',0):,}</span></div>
      <div style="color:#475569;font-size:11px;margin-top:8px">
        High cert count = many historical subdomains in CT logs
      </div>
    </div>

    {origin_bypass_html}

  </div>
</div>

<!-- ── ACTIVE SUBDOMAINS ─────────────────────────────────────── -->
<div class="sec">
  <div class="sec-title">🌐 Active Subdomains
    <span class="cnt">{len(active_subs)}</span>
    <span style="font-size:12px;color:#475569;font-weight:400">DNS or HTTP alive — sorted by priority tier</span>
  </div>

  <!-- Tier legend -->
  <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center">
    <span style="font-size:12px;color:#475569">Priority:</span>
    {tier_badge(1)} <span style="font-size:11px;color:#475569">Juicy keywords · no WAF · takeover risk · year-prefixed old infra (2017-grafana, 2019-k8s)</span>&nbsp;&nbsp;
    {tier_badge(2)} <span style="font-size:11px;color:#475569">HTTP alive</span>&nbsp;&nbsp;
    {tier_badge(3)} <span style="font-size:11px;color:#475569">DNS resolves, no HTTP</span>
  </div>

  <div class="twrap">
  <table>
    <thead><tr>
      <th>Subdomain</th><th>Tier</th><th>IP</th>
      <th>Status</th><th>Title</th><th>Technologies</th><th>WAF</th><th>Risk</th>
    </tr></thead>
    <tbody>
      {sub_rows_html or '<tr><td colspan="8" style="text-align:center;padding:20px;color:#475569">Run Phase 3 to get active data</td></tr>'}
    </tbody>
  </table>
  </div>
</div>

<!-- ── NETWORK HOSTS ─────────────────────────────────────────── -->
<div class="sec">
  <div class="sec-title">🖥 Network Hosts <span class="cnt">{len(hosts)}</span></div>
  <div class="twrap">
  <table>
    <thead><tr>
      <th>IP Address</th><th>Hostnames</th><th>Open Ports</th>
      <th>Services &amp; Versions</th><th>OS</th><th>CVEs (Shodan)</th>
    </tr></thead>
    <tbody>
      {host_rows_html or '<tr><td colspan="6" style="text-align:center;padding:20px;color:#475569">Run Phase 4 to get scan data</td></tr>'}
    </tbody>
  </table>
  </div>
</div>

<!-- ── FINDINGS ──────────────────────────────────────────────── -->
<div class="sec">
  <div class="sec-title">🚨 Findings &amp; Vulnerabilities <span class="cnt">{len(findings_sorted)}</span>
    <span style="font-size:12px;color:#475569;font-weight:400">Critical + High + Medium only</span>
  </div>

  <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">
    <span style="background:#fef2f2;color:#dc2626;padding:4px 14px;border-radius:12px;font-size:12px;font-weight:600">🔴 Critical: {summary['critical']}</span>
    <span style="background:#fffbeb;color:#d97706;padding:4px 14px;border-radius:12px;font-size:12px;font-weight:600">🟡 High: {summary['high']}</span>
    <span style="background:#eff6ff;color:#3b82f6;padding:4px 14px;border-radius:12px;font-size:12px;font-weight:600">🔵 Medium: {summary['medium']}</span>
  </div>

  <div class="twrap">
  <table>
    <thead><tr>
      <th>Severity</th><th>Target</th><th>Type</th><th>Detail</th><th>Source</th>
    </tr></thead>
    <tbody>
      {findings_html or '<tr><td colspan="5" style="text-align:center;padding:20px;color:#475569">Run Phase 5 to find vulnerabilities</td></tr>'}
    </tbody>
  </table>
  </div>
</div>

</div><!-- /content -->

<!-- ── FOOTER: inactive stats ────────────────────────────────── -->
<div class="footer">
  <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px">
    <span>HeyPort v3.2  ·  {target}  ·  {data['meta']['timestamp'][:19]}  ·  For authorized research only</span>
    <span>Active: <b style="color:#64748b">{len(active_subs)}</b> subdomains shown above</span>
  </div>
  <div class="inactive-note">
    📊 <b>Inactive / unresolved subdomains not shown in report:</b>&nbsp;&nbsp;
    <b style="color:#94a3b8">{len(inactive_subs):,}</b> subdomains found by passive sources but did not resolve to a live IP.
    Full list: <code style="color:#64748b">p2_all_subdomains.txt</code>
    &nbsp;·&nbsp; Confirmed by 2+ sources but inactive: <b style="color:#94a3b8">{sum(1 for d in inactive_subs.values() if d.get('confirmed')):,}</b>
    &nbsp;·&nbsp; Total discovered: <b style="color:#94a3b8">{len(subs):,}</b>
  </div>
</div>

</body>
</html>'''

    report_path = out / "recon_report.html"
    report_path.write_text(html)
    ok(f"HTML Report → {report_path}")


# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
def print_summary(target, out, rmap, start_time):
    elapsed = datetime.datetime.now() - start_time
    s       = rmap.get_summary()
    rmap.data['summary'] = s
    rmap.save_json(out / "recon_map.json")

    print(f"\n{C.BOLD}{C.GREEN}{'═'*68}{C.RESET}")
    print(f"{C.BOLD}{C.GREEN}  ✔  RECON COMPLETE  —  {target}{C.RESET}")
    print(f"{C.BOLD}{'═'*68}{C.RESET}\n")

    print(f"  {'Target':<22} {C.CYAN}{target}{C.RESET}")
    print(f"  {'Time Elapsed':<22} {C.CYAN}{elapsed}{C.RESET}")
    print(f"  {'Output':<22} {C.CYAN}{out}{C.RESET}")

    print(f"\n{C.BOLD}  Recon Map Summary:{C.RESET}")
    print(f"  {'Total Subdomains':<30} {C.BOLD}{s['total_subdomains']:>6}{C.RESET}")
    print(f"  {'Confirmed (2+ sources)':<30} {C.GREEN}{C.BOLD}{s['confirmed_subdomains']:>6}{C.RESET}")
    print(f"  {'DNS Alive':<30} {C.BOLD}{s['dns_alive']:>6}{C.RESET}")
    print(f"  {'HTTP Alive':<30} {C.BOLD}{s['http_alive']:>6}{C.RESET}")
    print(f"  {'Unique IPs':<30} {C.BOLD}{s['total_ips']:>6}{C.RESET}")
    print(f"  {'Takeover Risks':<30} {C.RED}{C.BOLD}{s['takeover_risks']:>6}{C.RESET}")
    print(f"  {'Critical Findings':<30} {C.RED}{C.BOLD}{s['critical']:>6}{C.RESET}")
    print(f"  {'High Findings':<30} {C.YELLOW}{C.BOLD}{s['high']:>6}{C.RESET}")
    print(f"  {'Medium Findings':<30} {C.CYAN}{C.BOLD}{s['medium']:>6}{C.RESET}")

    print(f"\n{C.BOLD}  Output Files:{C.RESET}")
    output_files = [
        ("recon_map.json",                   "Master data map — all findings structured"),
        ("recon_report.html",                "Interactive HTML report — open in browser"),
        ("p2_all_subdomains.txt",            "All discovered subdomains"),
        ("p2_confirmed_subdomains.txt",      "Cross-verified subdomains (2+ sources)"),
        ("p3_dns_alive.txt",                 "DNS-alive subdomains (clean hostnames)"),
        ("p3_http_alive.txt",                "HTTP-alive targets"),
        ("p3_tier1_priority.txt",            "★ HIGH PRIORITY — attack these first"),
        ("p3_takeover_risks.txt",            "Subdomain takeover vulnerabilities"),
        ("p3_waf_results.txt",               "WAF detection results"),
        ("p5_nuclei_pass1_critical_high.txt","Critical/High vulnerabilities"),
        ("p5_nuclei_pass2_medium.txt",       "Medium vulnerabilities"),
        ("p5_dalfox_xss.txt",               "XSS findings"),
    ]
    for fname, desc in output_files:
        fpath = out / fname
        if fpath.exists():
            size  = fpath.stat().st_size
            lines = len(read_lines(fpath)) if fname.endswith('.txt') else '–'
            print(f"    {C.CYAN}{fname:<42}{C.RESET} {C.DIM}{str(lines):>5} entries  {size:>8,}B  {desc}{C.RESET}")

    print(f"\n  {C.BOLD}Open your report:{C.RESET}")
    print(f"  {C.CYAN}  xdg-open {out}/recon_report.html{C.RESET}")
    print(f"  {C.CYAN}  cat {out}/recon_map.json | python3 -m json.tool{C.RESET}\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="HeyPort v3.2 — Ultimate Bug Bounty Recon",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 heyport.py -t example.com                     Full recon
  python3 heyport.py -t example.com -o ./my_output      Custom dir
  python3 heyport.py -t example.com --phase 2           Phase 2 only
  python3 heyport.py -t example.com --skip-vuln         Skip Phase 5
  python3 heyport.py --check-tools                      Tool status
        """
    )
    parser.add_argument('-t', '--target',    help='Target domain (e.g. example.com)')
    parser.add_argument('-o', '--output',    default='recon_output', help='Output directory')
    parser.add_argument('--phase',           type=int, choices=[1,2,3,4,5], help='Run specific phase only')
    parser.add_argument('--skip-vuln',       action='store_true', help='Skip Phase 5 (nuclei/dalfox)')
    parser.add_argument('--check-tools',     action='store_true', help='Check tool installations')
    args = parser.parse_args()

    banner()

    if args.check_tools:
        check_tools()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Check tools at startup
    missing = check_tools()
    if missing:
        print(f"\n  {C.YELLOW}Continuing with available tools. Missing tools will be skipped.{C.RESET}\n")

    target     = args.target.lower().strip()
    start_time = datetime.datetime.now()
    out        = Path(args.output) / target / start_time.strftime('%Y%m%d_%H%M%S')
    out.mkdir(parents=True, exist_ok=True)

    ok(f"Output directory → {out}\n")

    # Initialize ReconMap
    rmap = ReconMap(target)

    run_all = args.phase is None

    # Load existing map if running single phase
    map_file = out / "recon_map.json"
    if not run_all and map_file.exists():
        try:
            rmap.data = json.loads(map_file.read_text())
            info("Loaded existing recon_map.json")
        except:
            pass

    if run_all or args.phase == 1:
        phase1(target, out, rmap)

    if run_all or args.phase == 2:
        phase2(target, out, rmap)

    if run_all or args.phase == 3:
        phase3(out, rmap)

    if run_all or args.phase == 4:
        phase4(target, out, rmap)

    if (run_all or args.phase == 5) and not args.skip_vuln:
        phase5(out, rmap)

    generate_html_report(rmap, out)
    print_summary(target, out, rmap, start_time)


if __name__ == "__main__":
    main()