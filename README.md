# Infrastructure Hunter 🎯

Automated threat infrastructure detection using JARM fingerprints, certificate analysis, and behavioral patterns.

## Features

- **Multi-source scanning**: Shodan (JARM) + Censys (certificates)
- **32+ detection signatures**: Cobalt Strike, Sliver, Metasploit, Mythic, and more
- **Web dashboard**: Real-time matches, host tracking, pattern management
- **Scheduled scans**: Daily automated scans with alerting
- **YAML-based signatures**: Easy to create and share detection rules

## Detected C2 Frameworks

| Framework | Signatures | Detection Method |
|-----------|------------|------------------|
| Cobalt Strike | 5 | JARM, SSL cert, HTTP response |
| Sliver | 4 | JARM variants (HTTPS, mTLS, Go) |
| Metasploit | 2 | JARM (Ruby, Ruby27) |
| Mythic | 2 | JARM, certificate |
| EvilGinx2 | 2 | JARM fingerprint |
| Covenant | 1 | JARM (ASP.NET) |
| PoshC2 | 1 | JARM (Python3) |
| Merlin | 1 | JARM (Go) |
| RATs | 6+ | Default certificates |

## Quick Start

```bash
# Clone
git clone https://github.com/glitch-cc/infra-hunter.git
cd infra-hunter

# Install dependencies
pip install -r requirements.txt

# Set API keys
export SHODAN_API_KEY="your-key"
export CENSYS_API_KEY="your-key"

# Run scan
python scan_all.py
```

## Docker Deployment

```bash
docker compose up -d
```

Dashboard available at `http://localhost:5003`

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Shodan API     │────▶│  Scanner         │────▶│  SQLite DB      │
│  (JARM queries) │     │  scan_all.py     │     │  infra_hunter.db│
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │
┌─────────────────┐             │                 ┌─────────────────┐
│  Censys API     │─────────────┘                 │  Dashboard      │
│  (Cert queries) │                               │  dashboard.py   │
└─────────────────┘                               └─────────────────┘
```

## Signatures

Signatures are YAML files in `signatures/library/`:

```yaml
signature:
  id: cobalt-strike-jarm-default
  name: Cobalt Strike - JARM Default
  description: Default JARM fingerprint for Cobalt Strike
  logic:
    match: any
    conditions:
      - name: JARM Fingerprint
        type: jarm
        field: services.tls.jarm.fingerprint
        operator: equals
        value: "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
  queries:
    shodan: 'ssl.jarm:"07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"'
```

## Related

- [Threat Hunting Dataset](https://github.com/glitch-cc/threat-hunting-diy) - Signature browser and management
- [C2-JARM](https://github.com/cedowens/C2-JARM) - JARM fingerprint research

## License

MIT
