# Wordlists

HeyPort does not ship wordlists — they are large files that don't belong in a Git repo.

HeyPort automatically detects wordlists from SecLists if installed. Install SecLists and you're done.

---

## Install SecLists (Recommended)

```bash
sudo apt install seclists
```

Installs to `/usr/share/seclists/` — HeyPort checks this path automatically.

---

## What HeyPort Uses

| Phase | File | Purpose |
| ----- | ---- | ------- |
| Phase 2 brute force | `Discovery/DNS/subdomains-top1million-5000.txt` | puredns, gobuster, dnsx |
| Phase 2 large scan | `Discovery/DNS/subdomains-top1million-20000.txt` | deeper brute force |

HeyPort checks for the 5000 list first. If not found, falls back to the 20000 list. If neither exists, brute force is skipped and passive sources carry the enumeration.

---

## Manual Download (if apt not available)

```bash
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

## DNS Resolvers (for puredns)

puredns needs a trusted resolvers file. HeyPort checks these locations automatically:

```text
/usr/share/seclists/Miscellaneous/dns-resolvers.txt
/opt/resolvers.txt
~/resolvers.txt
```

If none found, HeyPort downloads one automatically from:
`https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt`

You don't need to do anything manually.
