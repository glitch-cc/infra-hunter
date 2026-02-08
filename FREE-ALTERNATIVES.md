# Free & Low-Cost Alternatives for Infrastructure Hunting

## DIY Scanning Tools (Free, Self-Hosted)

### 1. JARM Fingerprinting ✅ INSTALLED
**Tool:** Salesforce JARM Scanner
**Location:** `tools/jarm/jarm.py`
**Usage:**
```bash
python3 tools/jarm/jarm.py <ip> [-p port]
```
**Cost:** Free
**Rate Limit:** Only limited by your network/ethics

### 2. SSL Certificate Extraction
**Tool:** OpenSSL / Python ssl module
**Usage:**
```bash
openssl s_client -connect <ip>:443 2>/dev/null | openssl x509 -noout -text
```
**Gets:** Subject, Issuer, Serial, Fingerprint, Validity

### 3. HTTP Header Analysis
**Tool:** curl / Python requests
**Usage:**
```bash
curl -I -k https://<ip>:<port>/
```

### 4. Port Scanning
**Tool:** nmap, masscan
**Install:** `apt install nmap masscan`
**Usage:**
```bash
masscan <ip_range> -p 50050,443,8443,4443 --rate 1000
nmap -sV -p 50050 <ip>
```

---

## Free Threat Intel APIs

### 1. GreyNoise Community API
**URL:** https://api.greynoise.io/v3/community/{ip}
**Cost:** Free (limited)
**Gets:** Noise classification, known scanners
**Rate Limit:** 50/day (community)
**Sign Up:** https://viz.greynoise.io/signup

### 2. Abuse.ch Feeds (NO API KEY NEEDED)
**Feeds:**
- **Feodo Tracker:** `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
- **SSL Blacklist:** `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv`
- **URLhaus:** `https://urlhaus.abuse.ch/downloads/json_recent/`
- **ThreatFox:** `https://threatfox-api.abuse.ch/api/v1/`

**Cost:** 100% Free
**Rate Limit:** Reasonable use

### 3. AlienVault OTX
**URL:** https://otx.alienvault.com/api/
**Cost:** Free with registration
**Gets:** Pulses, IOCs, related domains/IPs
**Sign Up:** https://otx.alienvault.com/

### 4. AbuseIPDB
**URL:** https://api.abuseipdb.com/api/v2/check
**Cost:** Free tier (1,000 checks/day)
**Gets:** Abuse reports, confidence score
**Sign Up:** https://www.abuseipdb.com/register

### 5. VirusTotal
**URL:** https://www.virustotal.com/api/v3/
**Cost:** Free tier (500 lookups/day, 4/min)
**Gets:** Detection ratio, relationships
**We Have:** Already configured in keys.env

### 6. Shodan InternetDB (Free, No Auth!)
**URL:** `https://internetdb.shodan.io/{ip}`
**Cost:** 100% Free, NO API KEY
**Gets:** Open ports, hostnames, tags, vulns
**Rate Limit:** Unknown but generous

---

## Free IOC Feeds (Bulk Download)

| Feed | URL | Content |
|------|-----|---------|
| C2 JARM List | github.com/cedowens/C2-JARM | Known C2 JARM fingerprints |
| C2 Tracker | github.com/montysecurity/C2-Tracker | Active C2 IPs |
| Abuse.ch SSL | sslbl.abuse.ch | Malicious SSL certs |
| Feodo Tracker | feodotracker.abuse.ch | Banking trojan C2s |
| URLhaus | urlhaus.abuse.ch | Malware distribution URLs |
| MISP Feeds | misp-project.org | Various threat feeds |

---

## Comparison: DIY vs Paid

| Capability | DIY (Free) | Censys Pro (~$300/mo) | Shodan ($49/mo) |
|------------|-----------|----------------------|-----------------|
| JARM scan | ✅ Per-IP | ✅ Global search | ✅ Global search |
| SSL certs | ✅ Per-IP | ✅ Global search | ✅ Global search |
| HTTP headers | ✅ Per-IP | ✅ Global search | ✅ Global search |
| Port scan | ✅ Per-range | ✅ Global search | ✅ Global search |
| Historical data | ❌ | ✅ | ✅ |
| Pre-indexed | ❌ | ✅ | ✅ |
| Speed | Slow | Instant | Instant |

---

## Recommended Setup

### Minimum (Free)
1. Use DIY scanner for targeted IPs
2. Shodan InternetDB for quick port/vuln lookup
3. Abuse.ch feeds for known malware
4. GreyNoise Community for scanner detection

### Budget ($49/mo)
- Add Shodan membership for global C2 searches
- `product:"Cobalt Strike Beacon"` search unlocked

### Full Power (~$350/mo)
- Add Censys Pro for JARM + cert field searches
- Historical data access
- CensEye pivot analysis

---

## Quick Commands

```bash
# JARM fingerprint
python3 tools/jarm/jarm.py 1.2.3.4

# Shodan InternetDB (free, no auth)
curl -s "https://internetdb.shodan.io/1.2.3.4" | jq

# Abuse.ch C2 check
curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist.json" | jq '.[] | select(.ip_address=="1.2.3.4")'

# Full DIY scan
python3 tools/diy-scanner.py 1.2.3.4
```

---

## JARM Signatures Discovered (2026-02-08)

| JARM | Count | Notes |
|------|-------|-------|
| `3fd3fd00000000000043d43d00043de9480c702b80472d742fb4b3715a8cb1` | 4/5 | Port 50050 cluster, likely CS |
| `3fd3fd0003fd3fd00043d43d00043d3bef2bf79cd6719851e8198c1e8f9a14` | 1/5 | Variant |

*Last updated: 2026-02-08*
