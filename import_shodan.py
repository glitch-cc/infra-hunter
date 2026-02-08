#!/usr/bin/env python3
"""
Import Shodan scan results into Infrastructure Hunter database.
Generates alerts for anomalies like geographic clusters.

Usage:
    python3 import_shodan.py --query "product:Cobalt Strike Beacon"
    python3 import_shodan.py --file scan_results.json
"""
import os
import sys
import json
import argparse
from datetime import datetime
from collections import Counter
import requests

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import get_engine, get_session, init_db
from models_v2 import ScanResult, Alert, init_v2_tables

# Shodan API
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')

# Threat type mapping based on query patterns
THREAT_MAPPING = {
    'product:"Cobalt Strike Beacon"': ('cobalt_strike', 'critical'),
    'ssl.cert.serial:146473198': ('cobalt_strike', 'critical'),
    'ssl.jarm:07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175': ('metasploit', 'high'),
    'ssl.jarm:20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6': ('evilginx2', 'critical'),
    'ssl.cert.issuer.cn:AsyncRAT': ('asyncrat', 'high'),
    'ssl.cert.subject.cn:VenomRAT': ('venomrat', 'high'),
    'ssl.cert.issuer.cn:Quasar': ('quasarrat', 'high'),
    'ssl.cert.issuer.cn:BitRAT': ('bitrat', 'high'),
    'port:50050': ('potential_c2', 'medium'),
}


def shodan_search(query: str, max_results: int = 1000) -> list:
    """Execute Shodan search and return results."""
    if not SHODAN_API_KEY:
        raise ValueError("SHODAN_API_KEY not set")
    
    results = []
    page = 1
    
    while len(results) < max_results:
        url = f"https://api.shodan.io/shodan/host/search"
        params = {
            'key': SHODAN_API_KEY,
            'query': query,
            'page': page,
        }
        
        resp = requests.get(url, params=params)
        data = resp.json()
        
        if 'error' in data:
            print(f"Shodan error: {data['error']}")
            break
        
        matches = data.get('matches', [])
        if not matches:
            break
        
        results.extend(matches)
        page += 1
        
        print(f"  Fetched page {page-1}: {len(matches)} results (total: {len(results)})")
        
        if len(matches) < 100:  # Last page
            break
    
    return results[:max_results]


def import_results(results: list, query: str, session) -> tuple:
    """Import results into database. Returns (imported_count, alert_list)."""
    
    # Determine threat type from query
    threat_type, severity = 'unknown', 'medium'
    for pattern, (t_type, sev) in THREAT_MAPPING.items():
        if pattern in query:
            threat_type, severity = t_type, sev
            break
    
    imported = 0
    country_counts = Counter()
    org_counts = Counter()
    sample_ips = []
    
    for match in results:
        ip = match.get('ip_str')
        if not ip:
            continue
        
        # Extract data
        location = match.get('location', {})
        country = location.get('country_name', 'Unknown')
        country_code = location.get('country_code', '')
        
        # Count for alerts
        country_counts[country] += 1
        org_counts[match.get('org', 'Unknown')] += 1
        
        if len(sample_ips) < 10:
            sample_ips.append(ip)
        
        # Create scan result
        result = ScanResult(
            data_source='shodan',
            scan_date=datetime.utcnow(),
            query_used=query,
            signature_id=threat_type,
            ip=ip,
            port=match.get('port'),
            country=country,
            country_code=country_code,
            city=location.get('city'),
            asn=match.get('asn'),
            asn_name=match.get('isp'),
            org=match.get('org'),
            jarm=match.get('ssl', {}).get('jarm'),
            ssl_cert_sha256=match.get('ssl', {}).get('cert', {}).get('fingerprint', {}).get('sha256'),
            ssl_cert_issuer=str(match.get('ssl', {}).get('cert', {}).get('issuer', '')),
            ssl_cert_subject=str(match.get('ssl', {}).get('cert', {}).get('subject', '')),
            http_title=match.get('http', {}).get('title'),
            http_server=match.get('http', {}).get('server'),
            http_status=match.get('http', {}).get('status'),
            threat_type=threat_type,
            confidence='high' if threat_type != 'unknown' else 'medium',
            severity=severity,
            tags=match.get('tags', []),
            raw_data=match,
        )
        
        session.add(result)
        imported += 1
    
    session.commit()
    
    # Generate alerts
    alerts = []
    
    # Check for geographic concentration (>50% in one country)
    total = sum(country_counts.values())
    for country, count in country_counts.most_common(3):
        pct = (count / total) * 100 if total > 0 else 0
        if pct > 50 and count > 10:
            alert = Alert(
                title=f"Geographic Concentration: {threat_type.upper()} in {country}",
                description=f"{count} of {total} hosts ({pct:.1f}%) are located in {country}. "
                           f"This may indicate a targeted campaign or regional threat actor.",
                severity='high' if pct > 70 else 'medium',
                alert_type='cluster',
                query=query,
                affected_count=count,
                affected_countries=[country],
                sample_ips=sample_ips[:5],
                threat_type=threat_type,
                evidence={
                    'country_distribution': dict(country_counts.most_common(10)),
                    'percentage': pct,
                    'total_hosts': total,
                },
            )
            session.add(alert)
            alerts.append(alert)
    
    # Check for new high-severity threat types
    if severity == 'critical' and total > 50:
        alert = Alert(
            title=f"Large {threat_type.upper()} Infrastructure Detected",
            description=f"Found {total} hosts matching {threat_type} signatures. "
                       f"Top countries: {', '.join([f'{c} ({n})' for c, n in country_counts.most_common(3)])}",
            severity='critical',
            alert_type='threshold',
            query=query,
            affected_count=total,
            affected_countries=list(dict(country_counts.most_common(5)).keys()),
            sample_ips=sample_ips,
            threat_type=threat_type,
            evidence={
                'country_distribution': dict(country_counts.most_common(10)),
                'org_distribution': dict(org_counts.most_common(10)),
            },
        )
        session.add(alert)
        alerts.append(alert)
    
    session.commit()
    
    return imported, alerts


def main():
    parser = argparse.ArgumentParser(description='Import Shodan results into Infrastructure Hunter')
    parser.add_argument('--query', '-q', help='Shodan query to execute')
    parser.add_argument('--file', '-f', help='JSON file with Shodan results')
    parser.add_argument('--max', '-m', type=int, default=1000, help='Max results to import')
    parser.add_argument('--db', help='Database URL', default=os.environ.get('INFRA_HUNTER_DB'))
    args = parser.parse_args()
    
    if not args.query and not args.file:
        parser.error("Either --query or --file is required")
    
    # Initialize database
    engine = get_engine(args.db)
    init_db(engine)
    init_v2_tables(engine)
    session = get_session(engine)
    
    if args.query:
        print(f"Executing Shodan query: {args.query}")
        results = shodan_search(args.query, args.max)
    else:
        print(f"Loading from file: {args.file}")
        with open(args.file) as f:
            data = json.load(f)
            results = data.get('matches', data) if isinstance(data, dict) else data
    
    print(f"Importing {len(results)} results...")
    imported, alerts = import_results(results, args.query or 'file_import', session)
    
    print(f"\n✓ Imported {imported} results")
    
    if alerts:
        print(f"\n⚠️  Generated {len(alerts)} alerts:")
        for alert in alerts:
            print(f"  [{alert.severity.upper()}] {alert.title}")
    
    session.close()


if __name__ == '__main__':
    main()
