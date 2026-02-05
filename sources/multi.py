"""
Multi-source scanner for Infrastructure Hunter.
Combines Censys, Shodan, and crt.sh.
"""
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import source modules
from .crtsh import CrtshScanner, CertResult, build_crtsh_query
from .shodan_source import ShodanScanner, ShodanResult, build_shodan_query


@dataclass 
class UnifiedResult:
    """Unified result across all data sources."""
    source: str  # censys, shodan, crtsh
    ip: Optional[str]
    domain: Optional[str]
    country: Optional[str]
    asn: Optional[int]
    asn_name: Optional[str]
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    cert_fingerprint: Optional[str]
    cert_not_before: Optional[datetime]
    cert_not_after: Optional[datetime]
    ports: List[int]
    hostnames: List[str]
    http_status: Optional[int]
    http_server: Optional[str]
    raw_data: Dict


class MultiScanner:
    """
    Scanner that combines multiple data sources.
    
    Sources:
    - Censys: Full host data (requires API token)
    - Shodan: Full host data (requires API key with credits)
    - crt.sh: Certificate data only (FREE, no auth)
    """
    
    def __init__(self, 
                 enable_censys: bool = True,
                 enable_shodan: bool = True,
                 enable_crtsh: bool = True):
        """
        Initialize multi-scanner.
        
        Args:
            enable_censys: Enable Censys (requires CENSYS_API_TOKEN)
            enable_shodan: Enable Shodan (requires SHODAN_API_KEY)
            enable_crtsh: Enable crt.sh (free, always works)
        """
        self.sources = {}
        self.errors = {}
        
        if enable_crtsh:
            try:
                self.sources['crtsh'] = CrtshScanner()
            except Exception as e:
                self.errors['crtsh'] = str(e)
        
        if enable_shodan:
            try:
                self.sources['shodan'] = ShodanScanner()
                # Check if we have query credits
                info = self.sources['shodan'].api_info()
                if info.get('query_credits', 0) == 0:
                    self.errors['shodan'] = 'No query credits (free tier - can only lookup IPs)'
            except Exception as e:
                self.errors['shodan'] = str(e)
        
        if enable_censys:
            try:
                # Import here to avoid circular deps
                import sys
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from scanner import CensysScanner
                self.sources['censys'] = CensysScanner()
            except Exception as e:
                self.errors['censys'] = str(e)
    
    def get_status(self) -> Dict:
        """Get status of all sources."""
        return {
            'enabled': list(self.sources.keys()),
            'errors': self.errors,
        }
    
    def search_crtsh(self, pattern: str, limit: int = 100) -> List[UnifiedResult]:
        """Search crt.sh for certificates."""
        if 'crtsh' not in self.sources:
            return []
        
        results = []
        certs = self.sources['crtsh'].search_by_pattern(pattern, limit=limit)
        
        for cert in certs:
            results.append(UnifiedResult(
                source='crtsh',
                ip=None,  # crt.sh doesn't give IPs
                domain=cert.common_name,
                country=None,
                asn=None,
                asn_name=None,
                cert_subject=f"CN={cert.common_name}",
                cert_issuer=cert.issuer_name,
                cert_fingerprint=None,
                cert_not_before=cert.not_before,
                cert_not_after=cert.not_after,
                ports=[],
                hostnames=[cert.common_name] + cert.name_value.split('\n') if cert.name_value else [cert.common_name],
                http_status=None,
                http_server=None,
                raw_data={'id': cert.id, 'serial': cert.serial_number},
            ))
        
        return results
    
    def search_shodan(self, query: str, limit: int = 100) -> List[UnifiedResult]:
        """Search Shodan for hosts."""
        if 'shodan' not in self.sources:
            return []
        
        # Check if we have credits
        if 'shodan' in self.errors and 'No query credits' in self.errors['shodan']:
            raise Exception("Shodan free tier doesn't support search. Use lookup_ip() instead.")
        
        results = []
        hosts = self.sources['shodan'].search(query, max_results=limit)
        
        for host in hosts:
            results.append(self._shodan_to_unified(host))
        
        return results
    
    def search_censys(self, query: str, limit: int = 100) -> List[UnifiedResult]:
        """Search Censys for hosts."""
        if 'censys' not in self.sources:
            return []
        
        results = []
        hosts = self.sources['censys'].search(query, max_results=limit)
        
        for host in hosts:
            results.append(UnifiedResult(
                source='censys',
                ip=host.ip,
                domain=host.hostnames[0] if host.hostnames else None,
                country=host.country,
                asn=host.asn,
                asn_name=host.asn_name,
                cert_subject=host.cert_subject,
                cert_issuer=host.cert_issuer,
                cert_fingerprint=host.cert_fingerprint,
                cert_not_before=host.cert_not_before,
                cert_not_after=host.cert_not_after,
                ports=host.ports,
                hostnames=host.hostnames,
                http_status=host.http_status,
                http_server=host.http_server,
                raw_data=host.raw_data,
            ))
        
        return results
    
    def lookup_ip_shodan(self, ip: str) -> Optional[UnifiedResult]:
        """Look up a specific IP in Shodan (works on free tier)."""
        if 'shodan' not in self.sources:
            return None
        
        host = self.sources['shodan'].get_host(ip)
        if host:
            return self._shodan_to_unified(host)
        return None
    
    def _shodan_to_unified(self, host: ShodanResult) -> UnifiedResult:
        """Convert Shodan result to unified format."""
        return UnifiedResult(
            source='shodan',
            ip=host.ip,
            domain=host.hostnames[0] if host.hostnames else None,
            country=host.country,
            asn=int(host.asn.replace('AS', '')) if host.asn else None,
            asn_name=host.org,
            cert_subject=host.cert_subject,
            cert_issuer=host.cert_issuer,
            cert_fingerprint=host.cert_fingerprint,
            cert_not_before=None,
            cert_not_after=host.cert_expires,
            ports=host.ports,
            hostnames=host.hostnames,
            http_status=host.http_status,
            http_server=host.http_server,
            raw_data=host.raw_data,
        )
    
    def search_pattern(self, pattern_type: str, definition: Dict, 
                       sources: List[str] = None, limit: int = 100) -> Dict[str, List[UnifiedResult]]:
        """
        Search all enabled sources for a pattern.
        
        Args:
            pattern_type: Type of pattern
            definition: Pattern definition
            sources: List of sources to use (default: all enabled)
            limit: Max results per source
            
        Returns:
            Dict mapping source name to list of results
        """
        if sources is None:
            sources = list(self.sources.keys())
        
        results = {}
        
        # crt.sh - for cert patterns
        if 'crtsh' in sources and pattern_type in ['cert_subject_dn', 'cert_issuer_dn', 'domain_regex']:
            query = build_crtsh_query(pattern_type, definition)
            if query:
                try:
                    results['crtsh'] = self.search_crtsh(query, limit=limit)
                except Exception as e:
                    results['crtsh_error'] = str(e)
        
        # Shodan - if we have credits
        if 'shodan' in sources and 'shodan' not in self.errors:
            query = build_shodan_query(pattern_type, definition)
            if query:
                try:
                    results['shodan'] = self.search_shodan(query, limit=limit)
                except Exception as e:
                    results['shodan_error'] = str(e)
        
        # Censys
        if 'censys' in sources and 'censys' in self.sources:
            # Import query builder
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from scanner import build_censys_query
            query = build_censys_query(pattern_type, definition)
            if query:
                try:
                    results['censys'] = self.search_censys(query, limit=limit)
                except Exception as e:
                    results['censys_error'] = str(e)
        
        return results


if __name__ == '__main__':
    # Test multi-scanner
    print("Initializing multi-scanner...")
    scanner = MultiScanner()
    
    status = scanner.get_status()
    print(f"Enabled sources: {status['enabled']}")
    if status['errors']:
        print(f"Source errors: {status['errors']}")
    
    # Test crt.sh (always free)
    print("\nSearching crt.sh for 'O=IT'...")
    results = scanner.search_crtsh('O=IT', limit=5)
    print(f"Found {len(results)} certificates")
    for r in results[:3]:
        print(f"  {r.cert_subject} - {r.domain}")
