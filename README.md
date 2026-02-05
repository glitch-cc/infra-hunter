# Infrastructure Pattern Intelligence (infra-hunter)

Track threat actor infrastructure patterns instead of chasing ephemeral IOCs.

## Philosophy

The Pyramid of Pain teaches us:
- **IPs decay in 5-14 days** — actors rotate constantly
- **Domains last slightly longer** — still ephemeral
- **TTPs persist** — how actors BUILD infrastructure doesn't change quickly

This tool tracks *patterns* in how adversaries set up infrastructure:
- SSL certificate generation habits
- Hosting provider preferences
- Port/service configurations
- Domain registration patterns
- HTTP response fingerprints

**Output:** "Actor X typically uses [pattern]. Here are 47 new hosts matching that pattern in the last 72 hours."

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Data Sources   │────▶│  Pattern Engine  │────▶│  Alert Pipeline │
│  - Censys       │     │  - Matching      │     │  - New hosts    │
│  - CT Logs      │     │  - Clustering    │     │  - Pattern hits │
│  - Passive DNS  │     │  - Attribution   │     │  - Dashboards   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         └───────────────────────┴────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      PostgreSQL         │
                    │  - Patterns             │
                    │  - Hosts                │
                    │  - Matches              │
                    │  - Historical data      │
                    └─────────────────────────┘
```

## Pattern Types

### 1. Certificate Patterns
- Subject DN / Issuer DN templates
- JARM fingerprints
- Validity periods
- Certificate authority preferences
- Self-signed detection

### 2. HTTP Patterns
- Status code + header combinations
- Response body hashes
- Missing/unusual headers
- Server software versions

### 3. Hosting Patterns
- ASN preferences
- Geographic distribution
- Provider names

### 4. Domain Patterns
- WHOIS registrar/privacy patterns
- Naming conventions (regex)
- Registration timing clusters

## Known Actor Patterns (Seeded)

| Actor | Pattern Type | Description |
|-------|-------------|-------------|
| APT29 | Cert DN | `C=Tunis, O=IT, CN=*` |
| SideWinder | JARM + HTTP | nginx 404 + specific hash |
| Lazarus | Cert Subject | Fake Wikipedia pattern |
| Cobalt Strike | Cert + HTTP | Default cert + no Server header |

## Usage

```bash
# Scan for hosts matching a pattern
infra-hunter scan --pattern sidewinder-nginx

# Add a new pattern
infra-hunter pattern add --name "my-pattern" --type cert_dn --value "C=US, O=Suspicious"

# List matches from last 72h
infra-hunter matches --hours 72

# Run continuous monitoring
infra-hunter monitor --interval 6h

# Dashboard
infra-hunter dashboard --port 5003
```

## Installation

```bash
pip install -r requirements.txt
createdb infra_hunter
python setup_db.py
```

## Data Sources

- **Censys** (configured) — Host scanning, certificates
- **crt.sh** (free) — Certificate Transparency logs
- **Future:** PassiveTotal, SecurityTrails, WHOIS

## License

MIT
