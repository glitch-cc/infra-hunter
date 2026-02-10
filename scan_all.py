#!/usr/bin/env python3
"""
Unified scanner - uses Censys for certs, Shodan for JARM.
"""
import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shodan_scanner import ShodanScanner
from signatures.manager import SignatureManager

# Load API keys
keys_path = os.path.expanduser('~/.openclaw/.secure/keys.env')
if os.path.exists(keys_path):
    with open(keys_path) as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                k, v = line.strip().split('=', 1)
                os.environ[k] = v.strip('"\'')

def scan_with_shodan(query: str, max_results: int = 100):
    """Run a Shodan query."""
    scanner = ShodanScanner()
    return scanner.search(query, max_results)

def scan_with_censys(query: str, max_results: int = 100):
    """Run a Censys query."""
    import requests
    token = os.environ.get('CENSYS_API_KEY')
    org = os.environ.get('CENSYS_ORG_ID')
    
    resp = requests.post(
        f"https://api.platform.censys.io/v3/global/search/query?org={org}",
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        json={'query': query, 'page_size': min(max_results, 100)}
    )
    
    if resp.status_code != 200:
        return []
    
    data = resp.json()
    results = []
    for hit in data.get('result', {}).get('hits', []):
        host = hit.get('host_v1', {}).get('resource', {})
        results.append({
            'ip': host.get('ip', ''),
            'country': host.get('location', {}).get('country_code', ''),
            'asn': host.get('autonomous_system', {}).get('asn'),
            'org': host.get('autonomous_system', {}).get('name', ''),
        })
    return results


def main():
    mgr = SignatureManager()
    mgr.load_all()
    
    all_results = {}
    
    # Get all enabled signatures
    sigs = mgr.list(enabled_only=True)
    print(f"📋 Loaded {len(sigs)} signatures\n")
    
    for sig in sigs:
        # Determine which source to use
        shodan_query = sig.queries_shodan
        censys_query = sig.queries_censys
        
        # Use Shodan for JARM queries
        if shodan_query and 'ssl.jarm' in shodan_query:
            print(f"🔍 [{sig.id}] Scanning with Shodan (JARM)...")
            try:
                results = scan_with_shodan(shodan_query, max_results=50)
                if results:
                    all_results[sig.id] = {
                        'name': sig.name,
                        'source': 'shodan',
                        'query': shodan_query,
                        'count': len(results),
                        'hosts': [{'ip': r.ip, 'country': r.country, 'org': r.org} for r in results[:10]]
                    }
                    print(f"   ✓ Found {len(results)} hosts")
                else:
                    print(f"   · No matches")
            except Exception as e:
                print(f"   ✗ Error: {e}")
        
        # Use Censys for cert queries  
        elif censys_query and ('cert.' in censys_query or 'fingerprint' in censys_query.lower()):
            # Convert to Platform API field names
            platform_query = censys_query.replace(
                'services.tls.certificates.leaf_data.fingerprint',
                'host.services.cert.fingerprint_sha256'
            ).replace(
                'services.tls.certificates.leaf_data.',
                'host.services.cert.parsed.'
            )
            
            print(f"🔍 [{sig.id}] Scanning with Censys (cert)...")
            try:
                results = scan_with_censys(platform_query, max_results=50)
                if results:
                    all_results[sig.id] = {
                        'name': sig.name,
                        'source': 'censys',
                        'query': platform_query,
                        'count': len(results),
                        'hosts': results[:10]
                    }
                    print(f"   ✓ Found {len(results)} hosts")
                else:
                    print(f"   · No matches")
            except Exception as e:
                print(f"   ✗ Error: {e}")
        else:
            print(f"⏭️  [{sig.id}] Skipping (no supported query)")
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 SCAN SUMMARY")
    print(f"{'='*60}")
    
    total_hosts = 0
    for sig_id, data in sorted(all_results.items(), key=lambda x: -x[1]['count']):
        print(f"\n🎯 {data['name']}")
        print(f"   Source: {data['source']} | Matches: {data['count']}")
        for h in data['hosts'][:5]:
            print(f"   - {h['ip']} ({h.get('country', '??')}) {h.get('org', '')[:30]}")
        total_hosts += data['count']
    
    print(f"\n{'='*60}")
    print(f"Total: {len(all_results)} patterns matched, {total_hosts} hosts found")
    
    # Save results
    outfile = f"scan-results/scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    os.makedirs('scan-results', exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"Results saved to: {outfile}")


if __name__ == '__main__':
    main()
