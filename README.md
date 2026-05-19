# IOC Ranger

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-informational" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
</p>

A fast, colorful, and extensible IOC checker for **hashes, IPs, domains, and URLs**.

- **VirusTotal**: file reputation, detections, and **code-signing** info  
- **AbuseIPDB**: IP abuse confidence, reports, last reported time  
- **IPQualityScore**: IP/Domain/URL risk, **VPN/Proxy/TOR** flags, fraud score
- **AlienVault OTX**: Pulse counts and threat intelligence
- **Shodan**: Open ports and vulnerabilities
- **GreyNoise**: Internet background noise and riot status
- **ThreatFox**: Threat confidence and type
- **URLScan.io**: Page screenshots and risk scores

<img width="1643" height="602" alt="image" src="https://github.com/user-attachments/assets/877ddf32-e784-4d67-863d-a33af9b0e87f" />


## Table of contents
- [Features](#features)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [Social](#social)


## Features
- Interactive CLI with cool banner (Rich) and **Progress Bar**
- **Auto-classify**: hashes • IPs • domains • URLs
- **HTML Reporting**: Generate standalone dashboards
- **Flexible Inputs**: Pipe from stdin or pass arguments
- **VirusTotal** (hash reputation & code-signing)
- **AbuseIPDB** (abuse score, last reported)
- **IPQualityScore** (risk + VPN/Proxy/TOR flags)
- **AlienVault OTX**, **Shodan**, **GreyNoise**, **ThreatFox**, **URLScan**
- CSV/JSON tables, simple on-disk caching
- Windows/macOS/Linux, no secrets committed (.env)


## Quickstart

### Windows (CMD)
```bat
git clone https://github.com/UserAaronVzla/IOC-Ranger-v2
cd IOC-Ranger-v2
python -m venv .venv && call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
copy .env.example .env  &  notepad .env   :: fill keys
python -m ioc_ranger_v2 -t mixed -i inputs\iocs_mixed.txt -f table
```


### macOS/Linux
```bash
git clone https://github.com/UserAaronVzla/IOC-Ranger-v2
cd IOC-Ranger-v2
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env && $EDITOR .env
python -m ioc_ranger_v2 -t mixed -i inputs/iocs_mixed.txt -f table
```


## Usage
```bash
python -m ioc_ranger_v2 --help

# Common Interactive:
python -m ioc_ranger_v2

# Common Noninteractive:
python -m ioc_ranger_v2 -t hashes -i inputs/hashes.txt -f table csv
python -m ioc_ranger_v2 -t mixed  -i inputs/iocs_mixed.txt -o outputs/results -f table csv json html
```


## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```dotenv
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
IPQS_API_KEY=...
ALIENVAULT_API_KEY=...
SHODAN_API_KEY=...
GREYNOISE_API_KEY=...
THREATFOX_API_KEY=...
URLSCAN_API_KEY=...
HUNTER_API_KEY=...
VIEWDNS_API_KEY=...
CACHE_TTL=86400
```

All keys are optional — sources with missing keys are skipped gracefully. `CACHE_TTL` controls how long results are cached on disk (seconds, default 86400 = 24 h).

| Key | Service | Used for |
|-----|---------|----------|
| `VT_API_KEY` | VirusTotal | Hash/domain/URL reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP abuse score |
| `IPQS_API_KEY` | IPQualityScore | IP/domain/URL risk & VPN/Proxy/TOR |
| `ALIENVAULT_API_KEY` | AlienVault OTX | Threat pulse counts |
| `SHODAN_API_KEY` | Shodan | Open ports & vulnerabilities |
| `GREYNOISE_API_KEY` | GreyNoise | Internet noise classification |
| `THREATFOX_API_KEY` | ThreatFox | Malware confidence & type |
| `URLSCAN_API_KEY` | URLScan.io | Page risk & screenshots |
| `HUNTER_API_KEY` | Hunter.io | Email deliverability & disposable check |
| `VIEWDNS_API_KEY` | ViewDNS.info | Email domain reputation & shared MX |


## Examples

**Check a mixed input file (auto-classify each IOC):**
```bash
python -m ioc_ranger_v2 -t mixed -i inputs/iocs_mixed.txt -f table csv json
```

**Check hashes only and export to HTML:**
```bash
python -m ioc_ranger_v2 -t hashes -i inputs/hashes.txt -f html -o outputs/hashes
```

**Pipe IOCs directly from the command line:**
```bash
echo "8.8.8.8" | python -m ioc_ranger_v2 -t ip -f table
```

**Increase concurrency for large batches:**
```bash
python -m ioc_ranger_v2 -t mixed -i inputs/iocs_mixed.txt -c 40 -f json
```

<img width="1901" height="285" alt="image" src="https://github.com/user-attachments/assets/69a595a2-6bac-4786-aa45-58b855d6dc01" />


## Roadmap
- [x] Progress bar + ETA
- [x] JSONL & Markdown/HTML report exports
- [x] Expanded OSINT sources (Hunter.io, ViewDNS, ThreatFox, GreyNoise, Shodan)
- [ ] WHOIS + GeoIP enrichment
- [ ] Delta mode (compare runs)
- [ ] GitHub Actions (lint/test/build)


## Social
- 📧 A.eskenazicohen@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/aaron-eskenazi-vzla)
- 🐈‍⬛ [GitHub](https://github.com/UserAaronVzla)
