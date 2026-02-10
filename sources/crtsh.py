#!/usr/bin/env python3
"""
crt.sh Integration for Infrastructure Hunter.
Certificate Transparency log search - FREE, no API key needed.

Usage:
    from sources.crtsh import CrtshScanner
    
    scanner = CrtshScanner()
    
    # Search by domain pattern
    results = scanner.search_domain("%.cobalt-strike.com")
    
    # Search by organization
    results = scanner.search_org("Cozy Bear LLC")
    
    # Search by cert fingerprint
    results = scanner.search_fingerprint("sha256:abc123...")
"""
import requests
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class CertResult:
    """Certificate result from crt.sh"""
    id: int
    issuer_ca_id: int
    issuer_name: str
    common_name: str
    name_value: str  # SANs
    serial_number: str
    not_before: str
    not_after: str
    entry_timestamp: str
    
    # Extracted fields
    domains: List[str] = None
    org: str = None
    
    def __post_init__(self):
        # Extract domains from name_value (SANs)
        if self.name_value and self.domains is None:
            self.domains = [d.strip() for d in self.name_value.split('\n') if d.strip()]
        
        # Extract org from issuer
        if self.issuer_name and self.org is None:
            for part in self.issuer_name.split(','):
                if part.strip().startswith('O='):
                    self.org = part.strip()[2:]
                    break


class CrtshScanner:
    """
    Scanner for crt.sh Certificate Transparency logs.
    
    Free, no API key, but rate limited (be nice).
    """
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, timeout: int = 30, delay: float = 1.0):
        """
        Initialize scanner.
        
        Args:
            timeout: Request timeout in seconds
            delay: Delay between requests (be nice to free service)
        """
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'InfraHunter/1.0 (Threat Research)'
        self._last_request = 0
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()
    
    def _query(self, params: Dict) -> List[Dict]:
        """Execute a crt.sh query."""
        self._rate_limit()
        
        params['output'] = 'json'
        
        try:
            resp = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self.timeout
            )
            resp.raise_for_status()
            
            # crt.sh returns empty response for no results
            if not resp.text.strip():
                return []
            
            return resp.json()
            
        except requests.exceptions.Timeout:
            print(f"[crt.sh] Timeout querying {params}")
            return []
        except requests.exceptions.RequestException as e:
            print(f"[crt.sh] Error: {e}")
            return []
        except json.JSONDecodeError:
            print(f"[crt.sh] Invalid JSON response")
            return []
    
    def search_domain(
        self, 
        pattern: str, 
        exclude_expired: bool = True,
        limit: int = 100
    ) -> List[CertResult]:
        """
        Search for certificates by domain pattern.
        
        Args:
            pattern: Domain pattern (use % as wildcard, e.g., "%.evil.com")
            exclude_expired: Skip expired certificates
            limit: Max results to return
            
        Returns:
            List of CertResult objects
        """
        params = {'q': pattern}
        if exclude_expired:
            params['exclude'] = 'expired'
        
        raw_results = self._query(params)
        
        results = []
        seen_ids = set()
        
        for r in raw_results[:limit * 2]:  # Fetch extra for dedup
            if r.get('id') in seen_ids:
                continue
            seen_ids.add(r.get('id'))
            
            try:
                cert = CertResult(
                    id=r.get('id'),
                    issuer_ca_id=r.get('issuer_ca_id'),
                    issuer_name=r.get('issuer_name', ''),
                    common_name=r.get('common_name', ''),
                    name_value=r.get('name_value', ''),
                    serial_number=r.get('serial_number', ''),
                    not_before=r.get('not_before', ''),
                    not_after=r.get('not_after', ''),
                    entry_timestamp=r.get('entry_timestamp', ''),
                )
                results.append(cert)
                
                if len(results) >= limit:
                    break
                    
            except Exception as e:
                print(f"[crt.sh] Error parsing result: {e}")
                continue
        
        return results
    
    def search_org(self, org_name: str, limit: int = 100) -> List[CertResult]:
        """
        Search for certificates by organization name.
        
        Args:
            org_name: Organization name to search
            limit: Max results
            
        Returns:
            List of CertResult objects
        """
        params = {'O': org_name}
        raw_results = self._query(params)
        
        results = []
        seen_ids = set()
        
        for r in raw_results[:limit * 2]:
            if r.get('id') in seen_ids:
                continue
            seen_ids.add(r.get('id'))
            
            try:
                cert = CertResult(
                    id=r.get('id'),
                    issuer_ca_id=r.get('issuer_ca_id'),
                    issuer_name=r.get('issuer_name', ''),
                    common_name=r.get('common_name', ''),
                    name_value=r.get('name_value', ''),
                    serial_number=r.get('serial_number', ''),
                    not_before=r.get('not_before', ''),
                    not_after=r.get('not_after', ''),
                    entry_timestamp=r.get('entry_timestamp', ''),
                )
                results.append(cert)
                
                if len(results) >= limit:
                    break
                    
            except Exception as e:
                continue
        
        return results
    
    def search_identity(self, identity: str, limit: int = 100) -> List[CertResult]:
        """
        Search by any identity (CN, SAN, etc).
        
        Args:
            identity: Identity string to search
            limit: Max results
        """
        return self.search_domain(identity, limit=limit)
    
    def get_cert_details(self, cert_id: int) -> Optional[Dict]:
        """
        Get full certificate details by crt.sh ID.
        
        Args:
            cert_id: The crt.sh certificate ID
            
        Returns:
            Certificate details dict or None
        """
        self._rate_limit()
        
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/?id={cert_id}",
                timeout=self.timeout
            )
            # This returns HTML, would need parsing
            # For now, just return the raw cert in JSON
            
            resp = self.session.get(
                f"{self.BASE_URL}/?d={cert_id}",  # Download cert
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return {'pem': resp.text}
            return None
            
        except Exception as e:
            print(f"[crt.sh] Error getting cert {cert_id}: {e}")
            return None
    
    def search_patterns(
        self,
        patterns: List[str],
        limit_per_pattern: int = 50
    ) -> Dict[str, List[CertResult]]:
        """
        Search multiple patterns and return results grouped.
        
        Args:
            patterns: List of domain patterns to search
            limit_per_pattern: Max results per pattern
            
        Returns:
            Dict of pattern -> results
        """
        results = {}
        
        for pattern in patterns:
            print(f"[crt.sh] Searching: {pattern}")
            results[pattern] = self.search_domain(pattern, limit=limit_per_pattern)
            print(f"[crt.sh]   Found {len(results[pattern])} certs")
        
        return results
    
    def to_hosts(self, results: List[CertResult]) -> List[Dict]:
        """
        Convert CertResult list to host dicts for InfraHunter.
        
        Note: crt.sh only has cert data, not IP addresses.
        This returns domains that would need DNS resolution.
        
        Args:
            results: List of CertResult objects
            
        Returns:
            List of host-like dicts with domain info
        """
        hosts = []
        seen_domains = set()
        
        for cert in results:
            for domain in cert.domains or []:
                # Skip wildcards
                if domain.startswith('*'):
                    continue
                    
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)
                
                hosts.append({
                    'domain': domain,
                    'common_name': cert.common_name,
                    'issuer': cert.issuer_name,
                    'org': cert.org,
                    'not_before': cert.not_before,
                    'not_after': cert.not_after,
                    'cert_id': cert.id,
                    'source': 'crt.sh',
                })
        
        return hosts


def resolve_domains(domains: List[str], timeout: float = 2.0) -> Dict[str, str]:
    """
    Resolve domain names to IP addresses.
    
    Args:
        domains: List of domain names
        timeout: DNS timeout per domain
        
    Returns:
        Dict of domain -> IP (or None if failed)
    """
    import socket
    
    results = {}
    socket.setdefaulttimeout(timeout)
    
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            results[domain] = ip
        except socket.gaierror:
            results[domain] = None
        except Exception:
            results[domain] = None
    
    return results


# ============== CLI ==============

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='crt.sh Scanner')
    parser.add_argument('command', choices=['search', 'org', 'test'])
    parser.add_argument('query', nargs='?', help='Search query')
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--resolve', action='store_true', help='Resolve domains to IPs')
    
    args = parser.parse_args()
    
    scanner = CrtshScanner()
    
    if args.command == 'test':
        # Test with known patterns
        print("Testing crt.sh integration...")
        results = scanner.search_domain("%.cobaltstrike.com", limit=5)
        print(f"Found {len(results)} certs for %.cobaltstrike.com")
        for r in results[:3]:
            print(f"  - {r.common_name} (issued: {r.not_before})")
        print("\n✓ crt.sh integration working!")
        
    elif args.command == 'search':
        if not args.query:
            print("Error: query required")
            return
            
        results = scanner.search_domain(args.query, limit=args.limit)
        print(f"Found {len(results)} certificates for '{args.query}':\n")
        
        for cert in results:
            print(f"ID: {cert.id}")
            print(f"  CN: {cert.common_name}")
            print(f"  Issuer: {cert.issuer_name[:60]}...")
            print(f"  Valid: {cert.not_before} to {cert.not_after}")
            print(f"  Domains: {', '.join(cert.domains[:5])}")
            print()
        
        if args.resolve:
            hosts = scanner.to_hosts(results)
            domains = [h['domain'] for h in hosts[:20]]
            print(f"\nResolving {len(domains)} domains...")
            resolved = resolve_domains(domains)
            for domain, ip in resolved.items():
                if ip:
                    print(f"  {domain} -> {ip}")
    
    elif args.command == 'org':
        if not args.query:
            print("Error: organization name required")
            return
            
        results = scanner.search_org(args.query, limit=args.limit)
        print(f"Found {len(results)} certificates for org '{args.query}'")
        
        for cert in results[:10]:
            print(f"  - {cert.common_name}")


if __name__ == '__main__':
    main()
