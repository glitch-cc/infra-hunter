#!/usr/bin/env python3
"""
ZoomEye Integration for Infrastructure Hunter.
Chinese Shodan equivalent - 3000 free searches/month.

API Docs: https://www.zoomeye.ai/doc

Usage:
    from sources.zoomeye import ZoomEyeScanner
    
    scanner = ZoomEyeScanner(api_key="your-key")
    
    # Search by JARM
    results = scanner.search('ssl.jarm:"07d14d16d21d21d..."')
    
    # Search by cert
    results = scanner.search('ssl.cert.subject.cn:"*.evil.com"')
"""
import os
import requests
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ZoomEyeHost:
    """Host result from ZoomEye."""
    ip: str
    port: int
    country: str = ""
    city: str = ""
    org: str = ""
    isp: str = ""
    
    # Service info
    service: str = ""
    banner: str = ""
    
    # SSL/TLS info
    jarm: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_fingerprint: str = ""
    
    # Timestamps
    timestamp: str = ""
    
    # Raw data
    raw: Dict = None


class ZoomEyeScanner:
    """
    Scanner for ZoomEye search engine.
    
    Free tier: 3000 searches/month
    """
    
    BASE_URL = "https://api.zoomeye.ai"
    
    def __init__(self, api_key: Optional[str] = None, delay: float = 1.0):
        """
        Initialize scanner.
        
        Args:
            api_key: ZoomEye API key (or set ZOOMEYE_API_KEY env var)
            delay: Delay between requests
        """
        self.api_key = api_key or os.environ.get('ZOOMEYE_API_KEY')
        if not self.api_key:
            raise ValueError("ZoomEye API key required")
        
        self.delay = delay
        self.session = requests.Session()
        self.session.headers['API-KEY'] = self.api_key
        self._last_request = 0
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()
    
    def get_quota(self) -> Dict:
        """Get remaining quota info."""
        resp = self.session.get(f"{self.BASE_URL}/resources-info")
        resp.raise_for_status()
        return resp.json()
    
    def search(
        self,
        query: str,
        max_results: int = 100,
        facets: Optional[List[str]] = None
    ) -> List[ZoomEyeHost]:
        """
        Search ZoomEye for hosts.
        
        Args:
            query: ZoomEye query string (similar to Shodan)
            max_results: Maximum results to return
            facets: Optional facets for aggregation
            
        Returns:
            List of ZoomEyeHost objects
        """
        self._rate_limit()
        
        results = []
        page = 1
        per_page = 20  # ZoomEye default
        
        while len(results) < max_results:
            params = {
                'query': query,
                'page': page,
            }
            if facets:
                params['facets'] = ','.join(facets)
            
            try:
                resp = self.session.get(
                    f"{self.BASE_URL}/host/search",
                    params=params,
                    timeout=30
                )
                
                if resp.status_code == 402:
                    print("[ZoomEye] Quota exceeded")
                    break
                    
                resp.raise_for_status()
                data = resp.json()
                
                matches = data.get('matches', [])
                if not matches:
                    break
                
                for m in matches:
                    host = self._parse_host(m)
                    if host:
                        results.append(host)
                        if len(results) >= max_results:
                            break
                
                # Check if more pages
                total = data.get('total', 0)
                if page * per_page >= total:
                    break
                    
                page += 1
                self._rate_limit()
                
            except requests.exceptions.RequestException as e:
                print(f"[ZoomEye] Error: {e}")
                break
        
        return results
    
    def _parse_host(self, match: Dict) -> Optional[ZoomEyeHost]:
        """Parse a match result into ZoomEyeHost."""
        try:
            portinfo = match.get('portinfo', {})
            geoinfo = match.get('geoinfo', {})
            
            # Extract SSL info if available
            ssl_info = portinfo.get('ssl', {}) or {}
            cert = ssl_info.get('cert', {}) or {}
            
            return ZoomEyeHost(
                ip=match.get('ip', ''),
                port=portinfo.get('port', 0),
                country=geoinfo.get('country', {}).get('code', ''),
                city=geoinfo.get('city', {}).get('names', {}).get('en', ''),
                org=geoinfo.get('organization', ''),
                isp=geoinfo.get('isp', ''),
                service=portinfo.get('service', ''),
                banner=portinfo.get('banner', '')[:500] if portinfo.get('banner') else '',
                jarm=ssl_info.get('jarm', ''),
                cert_subject=cert.get('subject', {}).get('CN', ''),
                cert_issuer=cert.get('issuer', {}).get('CN', ''),
                cert_fingerprint=cert.get('fingerprint', {}).get('sha256', ''),
                timestamp=match.get('timestamp', ''),
                raw=match
            )
        except Exception as e:
            print(f"[ZoomEye] Error parsing host: {e}")
            return None
    
    def search_jarm(self, jarm_hash: str, max_results: int = 100) -> List[ZoomEyeHost]:
        """
        Search by JARM fingerprint.
        
        Args:
            jarm_hash: JARM fingerprint to search
            max_results: Maximum results
        """
        return self.search(f'ssl.jarm:"{jarm_hash}"', max_results)
    
    def search_cert_cn(self, common_name: str, max_results: int = 100) -> List[ZoomEyeHost]:
        """
        Search by certificate Common Name.
        
        Args:
            common_name: CN to search (can use wildcards)
            max_results: Maximum results
        """
        return self.search(f'ssl.cert.subject.cn:"{common_name}"', max_results)
    
    def search_cert_fingerprint(self, fingerprint: str, max_results: int = 100) -> List[ZoomEyeHost]:
        """
        Search by certificate SHA256 fingerprint.
        
        Args:
            fingerprint: SHA256 fingerprint
            max_results: Maximum results
        """
        return self.search(f'ssl.cert.fingerprint:"{fingerprint}"', max_results)
    
    def to_infrahunter_hosts(self, results: List[ZoomEyeHost]) -> List[Dict]:
        """
        Convert ZoomEye results to InfraHunter host format.
        
        Args:
            results: List of ZoomEyeHost objects
            
        Returns:
            List of dicts compatible with InfraHunter Host model
        """
        hosts = []
        seen_ips = set()
        
        for r in results:
            if r.ip in seen_ips:
                continue
            seen_ips.add(r.ip)
            
            hosts.append({
                'ip': r.ip,
                'country': r.country,
                'org': r.org or r.isp,
                'jarm': r.jarm,
                'cert_subject': r.cert_subject,
                'cert_issuer': r.cert_issuer,
                'cert_fingerprint': r.cert_fingerprint,
                'ports': [r.port] if r.port else [],
                'source': 'zoomeye',
            })
        
        return hosts


def translate_shodan_query(shodan_query: str) -> str:
    """
    Translate a Shodan query to ZoomEye syntax.
    
    Basic translations - not comprehensive.
    """
    # Direct mappings
    translations = {
        'ssl.jarm:': 'ssl.jarm:',
        'ssl.cert.subject.cn:': 'ssl.cert.subject.cn:',
        'ssl.cert.issuer.cn:': 'ssl.cert.issuer.cn:',
        'ssl.cert.fingerprint:': 'ssl.cert.fingerprint:',
        'http.title:': 'title:',
        'http.html:': 'body:',
        'port:': 'port:',
        'country:': 'country:',
        'org:': 'org:',
        'asn:': 'asn:',
    }
    
    result = shodan_query
    for shodan_key, zoomeye_key in translations.items():
        result = result.replace(shodan_key, zoomeye_key)
    
    return result


# ============== CLI ==============

def main():
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description='ZoomEye Scanner')
    parser.add_argument('command', choices=['search', 'quota', 'test'])
    parser.add_argument('query', nargs='?', help='Search query')
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--api-key', help='ZoomEye API key')
    
    args = parser.parse_args()
    
    api_key = args.api_key or os.environ.get('ZOOMEYE_API_KEY')
    
    if args.command == 'quota':
        scanner = ZoomEyeScanner(api_key)
        quota = scanner.get_quota()
        print(json.dumps(quota, indent=2))
        return
    
    if args.command == 'test':
        print("Testing ZoomEye integration...")
        scanner = ZoomEyeScanner(api_key)
        
        # Check quota
        quota = scanner.get_quota()
        remaining = quota.get('quota_info', {}).get('remain_total_quota', 0)
        print(f"Quota remaining: {remaining}")
        
        # Test JARM search (Cobalt Strike default)
        jarm = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
        print(f"\nSearching for Cobalt Strike JARM...")
        results = scanner.search_jarm(jarm, max_results=5)
        print(f"Found {len(results)} hosts")
        for r in results[:3]:
            print(f"  - {r.ip}:{r.port} ({r.country}) {r.org[:30]}")
        
        print("\n✓ ZoomEye integration working!")
        return
    
    if args.command == 'search':
        if not args.query:
            print("Error: query required")
            return
        
        scanner = ZoomEyeScanner(api_key)
        results = scanner.search(args.query, max_results=args.limit)
        
        print(f"Found {len(results)} hosts for '{args.query}':\n")
        for host in results:
            print(f"{host.ip}:{host.port}")
            print(f"  Country: {host.country}, Org: {host.org}")
            if host.jarm:
                print(f"  JARM: {host.jarm[:30]}...")
            if host.cert_subject:
                print(f"  Cert CN: {host.cert_subject}")
            print()


if __name__ == '__main__':
    main()
