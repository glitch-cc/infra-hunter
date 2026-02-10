#!/usr/bin/env python3
"""
Unified scanner with temporal tracking.
Uses Censys for certs, Shodan for JARM.
Tracks deltas: NEW/CHANGED/GONE hosts over time.
"""
import os
import sys
import json
import sqlite3
from datetime import datetime, timezone
from collections import defaultdict

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
    scanner = ShodanScanner()
    return scanner.search(query, max_results)


def scan_with_censys(query: str, max_results: int = 100):
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


def init_temporal_tables(db_path: str):
    """Initialize temporal tracking tables if they don't exist."""
    db = sqlite3.connect(db_path)
    cur = db.cursor()
    
    # Add status column to hosts if not exists
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN status TEXT DEFAULT 'active'")
    except: pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN gone_since DATETIME")
    except: pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN change_count INTEGER DEFAULT 0")
    except: pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN last_change_at DATETIME")
    except: pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN favicon_hash TEXT")
    except: pass
    try:
        cur.execute("ALTER TABLE hosts ADD COLUMN html_title TEXT")
    except: pass
    
    # Host history table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS host_history (
            id INTEGER PRIMARY KEY,
            host_id INTEGER NOT NULL,
            scan_id INTEGER,
            snapshot_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            jarm TEXT,
            cert_fingerprint TEXT,
            ports TEXT,
            services TEXT,
            asn INTEGER,
            asn_name TEXT,
            pattern_ids TEXT,
            raw_data TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
    """)
    
    # Host changes table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS host_changes (
            id INTEGER PRIMARY KEY,
            host_id INTEGER NOT NULL,
            scan_id INTEGER,
            change_type TEXT NOT NULL,
            changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            field_name TEXT,
            old_value TEXT,
            new_value TEXT,
            pattern_id INTEGER,
            severity TEXT DEFAULT 'info',
            details TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
    """)
    
    # Scan summaries table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_summaries (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_hosts INTEGER DEFAULT 0,
            new_hosts INTEGER DEFAULT 0,
            changed_hosts INTEGER DEFAULT 0,
            gone_hosts INTEGER DEFAULT 0,
            returned_hosts INTEGER DEFAULT 0,
            total_matches INTEGER DEFAULT 0,
            new_matches INTEGER DEFAULT 0,
            hosts_by_pattern TEXT,
            new_by_pattern TEXT,
            hosts_by_actor TEXT,
            hosts_by_country TEXT,
            duration_seconds INTEGER,
            patterns_scanned INTEGER
        )
    """)
    
    # Alerts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            title TEXT NOT NULL,
            description TEXT,
            host_id INTEGER,
            pattern_id INTEGER,
            scan_id INTEGER,
            data TEXT,
            status TEXT DEFAULT 'new',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            acknowledged_at DATETIME,
            delivered_to TEXT
        )
    """)
    
    # Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_host_status ON hosts(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_host_gone ON hosts(gone_since)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_history_host ON host_history(host_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_changes_host ON host_changes(host_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_changes_type ON host_changes(change_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    
    db.commit()
    db.close()


def save_to_database_with_temporal(all_results: dict, db_path: str = 'infra_hunter.db'):
    """
    Save scan results to SQLite database with temporal tracking.
    Returns detailed delta report.
    """
    init_temporal_tables(db_path)
    
    now = datetime.now(timezone.utc).isoformat()
    db = sqlite3.connect(db_path)
    cur = db.cursor()
    
    stats = {
        'new_hosts': 0,
        'changed_hosts': 0,
        'returned_hosts': 0,
        'new_matches': 0,
        'total_hosts': 0,
    }
    
    new_hosts_list = []
    changed_hosts_list = []
    seen_ips = set()
    pattern_matches = defaultdict(list)  # pattern_name -> [ips]
    new_by_pattern = defaultdict(list)
    hosts_by_country = defaultdict(int)
    
    # Record scan job
    cur.execute("""
        INSERT INTO scan_jobs (job_type, status, started_at, created_at)
        VALUES ('pattern_scan', 'running', ?, ?)
    """, (now, now))
    scan_id = cur.lastrowid
    
    for sig_id, data in all_results.items():
        # Get or create pattern
        cur.execute("SELECT id FROM patterns WHERE name = ?", (data['name'],))
        row = cur.fetchone()
        if not row:
            cur.execute("""
                INSERT INTO patterns (name, pattern_type, definition, description, confidence, censys_query, enabled, created_at)
                VALUES (?, 'composite', '{}', ?, 'medium', ?, 1, ?)
            """, (data['name'], f"Source: {data['source']}", data['query'], now))
            pattern_id = cur.lastrowid
        else:
            pattern_id = row[0]
        
        for host in data['hosts']:
            ip = host['ip'] if isinstance(host, dict) else host.ip
            country = host.get('country', '') if isinstance(host, dict) else getattr(host, 'country', '')
            org = host.get('org', '') if isinstance(host, dict) else getattr(host, 'org', '')
            jarm = host.get('jarm') if isinstance(host, dict) else getattr(host, 'jarm', None)
            
            seen_ips.add(ip)
            pattern_matches[data['name']].append(ip)
            hosts_by_country[country] += 1
            
            # Check if host exists
            cur.execute("SELECT id, status, gone_since, jarm FROM hosts WHERE ip = ?", (ip,))
            row = cur.fetchone()
            
            if not row:
                # NEW host
                cur.execute("""
                    INSERT INTO hosts (ip, country, asn_name, first_seen, last_seen, last_scanned, 
                                      scan_count, status, jarm, censys_data)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 'new', ?, ?)
                """, (ip, country, org, now, now, now, jarm, json.dumps({'country': country, 'org': org})))
                host_id = cur.lastrowid
                stats['new_hosts'] += 1
                new_hosts_list.append({'ip': ip, 'country': country, 'org': org, 'pattern': data['name']})
                new_by_pattern[data['name']].append(ip)
                
                # Record change
                cur.execute("""
                    INSERT INTO host_changes (host_id, scan_id, change_type, changed_at, severity, details)
                    VALUES (?, ?, 'first_seen', ?, 'medium', ?)
                """, (host_id, scan_id, now, json.dumps({'pattern': data['name']})))
                
            else:
                host_id, status, gone_since, old_jarm = row
                
                if gone_since:
                    # RETURNED host
                    cur.execute("""
                        UPDATE hosts SET status = 'active', gone_since = NULL, 
                                        last_seen = ?, last_scanned = ?, scan_count = scan_count + 1
                        WHERE id = ?
                    """, (now, now, host_id))
                    stats['returned_hosts'] += 1
                    
                    cur.execute("""
                        INSERT INTO host_changes (host_id, scan_id, change_type, changed_at, severity, details)
                        VALUES (?, ?, 'host_returned', ?, 'medium', ?)
                    """, (host_id, scan_id, now, json.dumps({'gone_since': gone_since})))
                    
                else:
                    # Check for CHANGES
                    changes = []
                    if jarm and old_jarm and jarm != old_jarm:
                        changes.append(('jarm_changed', 'jarm', old_jarm, jarm))
                    
                    if changes:
                        stats['changed_hosts'] += 1
                        changed_hosts_list.append({'ip': ip, 'changes': [c[0] for c in changes]})
                        
                        for change_type, field, old_val, new_val in changes:
                            cur.execute("""
                                INSERT INTO host_changes (host_id, scan_id, change_type, changed_at, 
                                                         field_name, old_value, new_value, severity)
                                VALUES (?, ?, ?, ?, ?, ?, ?, 'medium')
                            """, (host_id, scan_id, change_type, now, field, old_val, new_val))
                        
                        cur.execute("""
                            UPDATE hosts SET change_count = change_count + ?, last_change_at = ?
                            WHERE id = ?
                        """, (len(changes), now, host_id))
                    
                    # Update host
                    cur.execute("""
                        UPDATE hosts SET last_seen = ?, last_scanned = ?, scan_count = scan_count + 1,
                                        status = 'active', jarm = COALESCE(?, jarm)
                        WHERE id = ?
                    """, (now, now, jarm, host_id))
            
            # Record match
            cur.execute("SELECT id FROM matches WHERE host_id = ? AND pattern_id = ?", (host_id, pattern_id))
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO matches (host_id, pattern_id, match_score, status, matched_at, match_details)
                    VALUES (?, ?, 0.8, 'new', ?, '{}')
                """, (host_id, pattern_id, now))
                stats['new_matches'] += 1
            
            # Record history snapshot
            cur.execute("""
                INSERT INTO host_history (host_id, scan_id, snapshot_at, jarm, asn_name, pattern_ids)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (host_id, scan_id, now, jarm, org, json.dumps([pattern_id])))
    
    stats['total_hosts'] = len(seen_ips)
    
    # Find hosts that went GONE (not seen in 48 hours)
    cur.execute("""
        SELECT id, ip FROM hosts 
        WHERE last_seen < datetime('now', '-48 hours')
        AND (gone_since IS NULL OR gone_since = '')
        AND status != 'gone'
    """)
    gone_hosts = cur.fetchall()
    for host_id, ip in gone_hosts:
        if ip not in seen_ips:
            cur.execute("UPDATE hosts SET status = 'gone', gone_since = ? WHERE id = ?", (now, host_id))
            cur.execute("""
                INSERT INTO host_changes (host_id, scan_id, change_type, changed_at, severity)
                VALUES (?, ?, 'host_gone', ?, 'info')
            """, (host_id, scan_id, now))
    
    # Record scan summary
    cur.execute("""
        INSERT INTO scan_summaries (scan_id, scanned_at, total_hosts, new_hosts, changed_hosts, 
                                   gone_hosts, returned_hosts, new_matches, hosts_by_pattern, 
                                   new_by_pattern, hosts_by_country, patterns_scanned)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, now, stats['total_hosts'], stats['new_hosts'], stats['changed_hosts'],
        len(gone_hosts), stats['returned_hosts'], stats['new_matches'],
        json.dumps({k: len(v) for k, v in pattern_matches.items()}),
        json.dumps({k: len(v) for k, v in new_by_pattern.items()}),
        json.dumps(dict(hosts_by_country)),
        len(all_results)
    ))
    
    # Generate alerts for significant findings
    if stats['new_hosts'] >= 5:
        cur.execute("""
            INSERT INTO alerts (alert_type, severity, title, description, scan_id, data, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'new', ?)
        """, (
            'new_host_surge',
            'high' if stats['new_hosts'] >= 20 else 'medium',
            f"🚨 {stats['new_hosts']} new C2 hosts detected",
            f"Scan found {stats['new_hosts']} new hosts matching threat patterns.",
            scan_id,
            json.dumps({'new_hosts': new_hosts_list[:20], 'by_pattern': {k: len(v) for k, v in new_by_pattern.items()}}),
            now
        ))
    
    for pattern_name, ips in new_by_pattern.items():
        if len(ips) >= 3:
            cur.execute("""
                INSERT INTO alerts (alert_type, severity, title, description, scan_id, data, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'new', ?)
            """, (
                'pattern_spike',
                'high',
                f"📈 {len(ips)} new hosts for {pattern_name}",
                f"Pattern '{pattern_name}' matched {len(ips)} new hosts.",
                scan_id,
                json.dumps({'pattern': pattern_name, 'ips': ips[:20]}),
                now
            ))
    
    # Update scan job
    cur.execute("""
        UPDATE scan_jobs SET status = 'completed', completed_at = ?,
                            hosts_found = ?, new_matches = ?
        WHERE id = ?
    """, (now, stats['total_hosts'], stats['new_matches'], scan_id))
    
    db.commit()
    db.close()
    
    return {
        'scan_id': scan_id,
        'stats': stats,
        'new_hosts': new_hosts_list,
        'changed_hosts': changed_hosts_list,
        'gone_hosts': len(gone_hosts),
        'new_by_pattern': {k: len(v) for k, v in new_by_pattern.items()},
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='infra_hunter.db')
    parser.add_argument('--max-results', type=int, default=50)
    args = parser.parse_args()
    
    mgr = SignatureManager()
    mgr.load_all()
    
    all_results = {}
    sigs = mgr.list(enabled_only=True)
    print(f"📋 Loaded {len(sigs)} signatures\n")
    
    for sig in sigs:
        shodan_query = sig.queries_shodan
        censys_query = sig.queries_censys
        
        if shodan_query and 'ssl.jarm' in shodan_query:
            print(f"🔍 [{sig.id}] Scanning with Shodan (JARM)...")
            try:
                results = scan_with_shodan(shodan_query, max_results=args.max_results)
                if results:
                    all_results[sig.id] = {
                        'name': sig.name,
                        'source': 'shodan',
                        'query': shodan_query,
                        'count': len(results),
                        'hosts': [{'ip': r.ip, 'country': r.country, 'org': r.org, 'jarm': getattr(r, 'jarm', None)} for r in results[:20]]
                    }
                    print(f"   ✓ Found {len(results)} hosts")
                else:
                    print(f"   · No matches")
            except Exception as e:
                print(f"   ✗ Error: {e}")
        
        elif censys_query and ('cert.' in censys_query or 'fingerprint' in censys_query.lower()):
            platform_query = censys_query.replace(
                'services.tls.certificates.leaf_data.fingerprint',
                'host.services.cert.fingerprint_sha256'
            ).replace(
                'services.tls.certificates.leaf_data.',
                'host.services.cert.parsed.'
            )
            
            print(f"🔍 [{sig.id}] Scanning with Censys (cert)...")
            try:
                results = scan_with_censys(platform_query, max_results=args.max_results)
                if results:
                    all_results[sig.id] = {
                        'name': sig.name,
                        'source': 'censys',
                        'query': platform_query,
                        'count': len(results),
                        'hosts': results[:20]
                    }
                    print(f"   ✓ Found {len(results)} hosts")
                else:
                    print(f"   · No matches")
            except Exception as e:
                print(f"   ✗ Error: {e}")
        else:
            print(f"⏭️  [{sig.id}] Skipping (no supported query)")
    
    # Save with temporal tracking
    print(f"\n💾 Saving to database with temporal tracking...")
    report = save_to_database_with_temporal(all_results, args.db)
    
    # Print delta report
    print(f"\n{'='*60}")
    print("📊 DELTA REPORT")
    print(f"{'='*60}")
    print(f"🆕 New hosts:      {report['stats']['new_hosts']}")
    print(f"🔄 Changed hosts:  {report['stats']['changed_hosts']}")
    print(f"👋 Gone hosts:     {report['gone_hosts']}")
    print(f"↩️  Returned hosts: {report['stats']['returned_hosts']}")
    print(f"🎯 New matches:    {report['stats']['new_matches']}")
    print(f"📊 Total tracked:  {report['stats']['total_hosts']}")
    
    if report['new_by_pattern']:
        print(f"\n📈 New by pattern:")
        for pattern, count in sorted(report['new_by_pattern'].items(), key=lambda x: -x[1]):
            print(f"   {pattern}: +{count}")
    
    if report['new_hosts']:
        print(f"\n🆕 New hosts (first 10):")
        for h in report['new_hosts'][:10]:
            print(f"   {h['ip']:15} {h['country']:3} {h.get('org', '')[:30]} [{h['pattern']}]")
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 PATTERN SUMMARY")
    print(f"{'='*60}")
    
    total_hosts = 0
    for sig_id, data in sorted(all_results.items(), key=lambda x: -x[1]['count']):
        print(f"\n🎯 {data['name']}")
        print(f"   Source: {data['source']} | Matches: {data['count']}")
        total_hosts += data['count']
    
    print(f"\n{'='*60}")
    print(f"Total: {len(all_results)} patterns matched, {total_hosts} hosts found")
    
    # Save JSON
    outfile = f"scan-results/scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    os.makedirs('scan-results', exist_ok=True)
    with open(outfile, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'delta_report': report,
            'results': all_results
        }, f, indent=2)
    print(f"Results saved to: {outfile}")


if __name__ == '__main__':
    main()
