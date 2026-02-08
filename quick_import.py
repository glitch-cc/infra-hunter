#!/usr/bin/env python3
"""
Quick import of today's Shodan scan results.
Run this to populate the database with current findings.
"""
import os
import sys
import requests
from datetime import datetime
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load API key
keys_file = '/root/.openclaw/.secure/keys.env'
if os.path.exists(keys_file):
    with open(keys_file) as f:
        for line in f:
            if line.strip() and not line.startswith('#') and '=' in line:
                key, val = line.strip().split('=', 1)
                os.environ[key] = val.strip('"')

from models import get_engine, init_db
from models_v2 import ScanResult, Alert, init_v2_tables, get_session

# Queries to run with threat mapping
QUERIES = [
    ('product:"Cobalt Strike Beacon"', 'cobalt_strike', 'critical'),
    ('ssl.cert.serial:146473198', 'cobalt_strike_default_cert', 'critical'),
    ('ssl.jarm:07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175', 'metasploit', 'high'),
    ('ssl.jarm:20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6', 'evilginx2', 'critical'),
    ('ssl.cert.issuer.cn:AsyncRAT', 'asyncrat', 'high'),
    ('ssl.cert.subject.cn:VenomRAT', 'venomrat', 'high'),
    ('ssl.cert.issuer.cn:Quasar', 'quasarrat', 'high'),
]

def shodan_search(query: str, api_key: str, limit: int = 100) -> dict:
    """Execute Shodan search."""
    url = "https://api.shodan.io/shodan/host/search"
    params = {
        'key': api_key,
        'query': query,
    }
    resp = requests.get(url, params=params)
    return resp.json()


def main():
    api_key = os.environ.get('SHODAN_API_KEY')
    if not api_key:
        print("Error: SHODAN_API_KEY not found")
        sys.exit(1)
    
    # Initialize database
    db_url = os.environ.get('INFRA_HUNTER_DB', 'sqlite:///infra_hunter.db')
    print(f"Using database: {db_url}")
    
    engine = get_engine(db_url)
    init_db(engine)
    init_v2_tables(engine)
    
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    session = Session()
    
    total_imported = 0
    all_alerts = []
    
    for query, threat_type, severity in QUERIES:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        print(f"Threat: {threat_type} | Severity: {severity}")
        print('='*60)
        
        try:
            data = shodan_search(query, api_key)
            
            if 'error' in data:
                print(f"  Error: {data['error']}")
                continue
            
            total = data.get('total', 0)
            matches = data.get('matches', [])
            
            print(f"  Total results: {total}")
            print(f"  Fetched: {len(matches)}")
            
            if not matches:
                continue
            
            # Import results
            country_counts = Counter()
            for match in matches:
                ip = match.get('ip_str')
                if not ip:
                    continue
                
                location = match.get('location', {})
                country = location.get('country_name', 'Unknown')
                country_code = location.get('country_code', '')
                
                country_counts[country] += 1
                
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
                    threat_type=threat_type,
                    severity=severity,
                    tags=match.get('tags', []),
                    raw_data=match,
                )
                session.add(result)
                total_imported += 1
            
            session.commit()
            
            # Generate alerts for geographic concentration
            for country, count in country_counts.most_common(3):
                pct = (count / len(matches)) * 100
                if pct > 50 and count > 5:
                    alert = Alert(
                        title=f"Geographic Cluster: {threat_type.upper()} in {country}",
                        description=f"{count} of {len(matches)} hosts ({pct:.1f}%) in {country}. "
                                   f"May indicate targeted campaign.",
                        severity='high' if pct > 70 else 'medium',
                        alert_type='cluster',
                        query=query,
                        affected_count=count,
                        affected_countries=[country],
                        sample_ips=[m.get('ip_str') for m in matches[:5]],
                        threat_type=threat_type,
                        evidence={'countries': dict(country_counts), 'total': total},
                    )
                    session.add(alert)
                    all_alerts.append(alert)
                    print(f"  ⚠️  Alert: {country} has {pct:.1f}% of hosts")
            
            # Alert for large threat detection
            if total > 100 and severity == 'critical':
                alert = Alert(
                    title=f"Large {threat_type.upper()} Infrastructure: {total} hosts",
                    description=f"Detected {total} hosts with {threat_type} signatures.",
                    severity='critical',
                    alert_type='threshold',
                    query=query,
                    affected_count=total,
                    threat_type=threat_type,
                    evidence={'total': total, 'fetched': len(matches)},
                )
                session.add(alert)
                all_alerts.append(alert)
            
            session.commit()
            
            print(f"  ✓ Imported {len(matches)} results")
            print(f"  Top countries: {', '.join([f'{c}({n})' for c,n in country_counts.most_common(5)])}")
            
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
    
    session.close()
    
    print(f"\n{'='*60}")
    print(f"IMPORT COMPLETE")
    print(f"{'='*60}")
    print(f"Total results imported: {total_imported}")
    print(f"Alerts generated: {len(all_alerts)}")
    
    if all_alerts:
        print("\nAlerts:")
        for a in all_alerts:
            print(f"  [{a.severity.upper()}] {a.title}")


if __name__ == '__main__':
    main()
