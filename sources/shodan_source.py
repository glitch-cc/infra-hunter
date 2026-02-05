"""
Shodan integration for Infrastructure Hunter.
Requires API key.
"""
import os
import shodan
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import hashlib


@dataclass
class ShodanResult:
    """Host result from Shodan."""
    ip: str
    asn: Optional[str]
    org: Optional[str]
    isp: Optional[str]
    country: Optional[str]
    city: Optional[str]
    ports: List[int]
    hostnames: List[str]
    # Certificate data
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    cert_fingerprint: Optional[str]
    cert_expires: Optional[datetime]
    # HTTP data
    http_status: Optional[int]
    http_server: Optional[str]
    http_title: Optional[str]
    # Raw
    raw_data: Dict


class ShodanScanner:
    """Scanner using Shodan API."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan scanner.
        
        Args:
            api_key: Shodan API key. If not provided, reads from env.
        """
        self.api_key = api_key or os.environ.get('SHODAN_API_KEY')
        
        if not self.api_key:
            # Try loading from keys.env
            keys_path = os.path.expanduser('~/.openclaw/.secure/keys.env')
            if os.path.exists(keys_path):
                with open(keys_path) as f:
                    for line in f:
                        if line.startswith('SHODAN_API_KEY='):
                            self.api_key = line.split('=', 1)[1].strip().strip('"\'')
                            break
        
        if not self.api_key:
            raise ValueError("Shodan API key not found. Set SHODAN_API_KEY env var.")
        
        self.api = shodan.Shodan(self.api_key)
    
    def search(self, query: str, max_results: int = 100) -> List[ShodanResult]:
        """
        Search Shodan for hosts matching a query.
        
        Args:
            query: Shodan query string
            max_results: Maximum results to return
            
        Returns:
            List of ShodanResult objects
        """
        results = []
        
        try:
            # Shodan paginates at 100 results per page
            for banner in self.api.search_cursor(query):
                results.append(self._parse_banner(banner))
                if len(results) >= max_results:
                    break
                    
        except shodan.APIError as e:
            raise Exception(f"Shodan API error: {e}")
        
        return results
    
    def get_host(self, ip: str) -> Optional[ShodanResult]:
        """Get information about a specific host."""
        try:
            data = self.api.host(ip)
            return self._parse_host(data)
        except shodan.APIError:
            return None
    
    def count(self, query: str) -> int:
        """Get count of results for a query (doesn't use query credits)."""
        try:
            result = self.api.count(query)
            return result.get('total', 0)
        except shodan.APIError:
            return 0
    
    def _parse_banner(self, banner: Dict) -> ShodanResult:
        """Parse a Shodan banner into ShodanResult."""
        # Extract SSL/cert data
        ssl = banner.get('ssl', {})
        cert = ssl.get('cert', {})
        
        cert_subject = None
        cert_issuer = None
        cert_fingerprint = None
        cert_expires = None
        
        if cert:
            # Format subject
            subject = cert.get('subject', {})
            if subject:
                parts = [f"{k}={v}" for k, v in subject.items()]
                cert_subject = ', '.join(parts)
            
            # Format issuer
            issuer = cert.get('issuer', {})
            if issuer:
                parts = [f"{k}={v}" for k, v in issuer.items()]
                cert_issuer = ', '.join(parts)
            
            cert_fingerprint = cert.get('fingerprint', {}).get('sha256')
            
            # Parse expiry
            expires = cert.get('expires')
            if expires:
                try:
                    cert_expires = datetime.strptime(expires, '%Y%m%d%H%M%SZ')
                except:
                    pass
        
        # HTTP data
        http = banner.get('http', {})
        
        return ShodanResult(
            ip=banner.get('ip_str', ''),
            asn=banner.get('asn'),
            org=banner.get('org'),
            isp=banner.get('isp'),
            country=banner.get('location', {}).get('country_code'),
            city=banner.get('location', {}).get('city'),
            ports=[banner.get('port')] if banner.get('port') else [],
            hostnames=banner.get('hostnames', []),
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
            cert_fingerprint=cert_fingerprint,
            cert_expires=cert_expires,
            http_status=http.get('status'),
            http_server=http.get('server'),
            http_title=http.get('title'),
            raw_data=banner,
        )
    
    def _parse_host(self, data: Dict) -> ShodanResult:
        """Parse full Shodan host data."""
        # Aggregate data from all banners/services
        ports = data.get('ports', [])
        hostnames = data.get('hostnames', [])
        
        # Get cert from first SSL service
        cert_subject = None
        cert_issuer = None
        cert_fingerprint = None
        cert_expires = None
        http_status = None
        http_server = None
        http_title = None
        
        for service in data.get('data', []):
            ssl = service.get('ssl', {})
            cert = ssl.get('cert', {})
            
            if cert and not cert_subject:
                subject = cert.get('subject', {})
                if subject:
                    parts = [f"{k}={v}" for k, v in subject.items()]
                    cert_subject = ', '.join(parts)
                
                issuer = cert.get('issuer', {})
                if issuer:
                    parts = [f"{k}={v}" for k, v in issuer.items()]
                    cert_issuer = ', '.join(parts)
                
                cert_fingerprint = cert.get('fingerprint', {}).get('sha256')
                
                expires = cert.get('expires')
                if expires:
                    try:
                        cert_expires = datetime.strptime(expires, '%Y%m%d%H%M%SZ')
                    except:
                        pass
            
            http = service.get('http', {})
            if http and not http_status:
                http_status = http.get('status')
                http_server = http.get('server')
                http_title = http.get('title')
        
        return ShodanResult(
            ip=data.get('ip_str', ''),
            asn=data.get('asn'),
            org=data.get('org'),
            isp=data.get('isp'),
            country=data.get('country_code'),
            city=data.get('city'),
            ports=ports,
            hostnames=hostnames,
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
            cert_fingerprint=cert_fingerprint,
            cert_expires=cert_expires,
            http_status=http_status,
            http_server=http_server,
            http_title=http_title,
            raw_data=data,
        )
    
    def api_info(self) -> Dict:
        """Get API plan info and remaining credits."""
        try:
            return self.api.info()
        except shodan.APIError as e:
            return {'error': str(e)}


def build_shodan_query(pattern_type: str, definition: Dict) -> str:
    """
    Build a Shodan query from pattern definition.
    
    Args:
        pattern_type: Type of pattern
        definition: Pattern definition
        
    Returns:
        Shodan query string
    """
    if pattern_type == 'cert_subject_dn':
        pattern = definition.get('pattern', '')
        # Shodan uses ssl.cert.subject.X format
        # e.g., "C=Tunis, O=IT" -> ssl.cert.subject.O:"IT"
        import re
        parts = []
        for match in re.finditer(r'([A-Z]+)=([^,*]+)', pattern):
            key = match.group(1)
            val = match.group(2)
            parts.append(f'ssl.cert.subject.{key}:"{val}"')
        return ' '.join(parts)
    
    elif pattern_type == 'cert_issuer_dn':
        pattern = definition.get('pattern', '')
        import re
        parts = []
        for match in re.finditer(r'([A-Z]+)=([^,*]+)', pattern):
            key = match.group(1)
            val = match.group(2)
            parts.append(f'ssl.cert.issuer.{key}:"{val}"')
        return ' '.join(parts)
    
    elif pattern_type == 'cert_fingerprint':
        fp = definition.get('fingerprint', '')
        return f'ssl.cert.fingerprint:"{fp}"'
    
    elif pattern_type == 'jarm':
        jarm = definition.get('fingerprint', '')
        return f'ssl.jarm:"{jarm}"'
    
    elif pattern_type == 'http_headers':
        parts = []
        required = definition.get('required', {})
        status = definition.get('status')
        
        if status:
            parts.append(f'http.status:{status}')
        
        for header, value in required.items():
            if header.lower() == 'server':
                parts.append(f'http.server:"{value}"' if value != '*' else 'http.server:*')
            elif header.lower() == 'content-type':
                parts.append(f'http.html:"{value}"' if value != '*' else '')
        
        return ' '.join(filter(None, parts))
    
    elif pattern_type == 'asn':
        asns = definition.get('asns', [])
        if isinstance(asns, int):
            asns = [asns]
        if len(asns) == 1:
            return f'asn:AS{asns[0]}'
        return ' OR '.join(f'asn:AS{a}' for a in asns)
    
    elif pattern_type == 'port_combo':
        ports = definition.get('required', [])
        return ' '.join(f'port:{p}' for p in ports)
    
    elif pattern_type == 'hosting_provider':
        providers = definition.get('providers', [])
        if providers:
            return ' OR '.join(f'org:"{p}"' for p in providers)
        return ''
    
    return ''


if __name__ == '__main__':
    # Test
    try:
        scanner = ShodanScanner()
        info = scanner.api_info()
        print(f"Shodan API Info:")
        print(f"  Plan: {info.get('plan', 'unknown')}")
        print(f"  Query Credits: {info.get('query_credits', 0)}")
        print(f"  Scan Credits: {info.get('scan_credits', 0)}")
        
        # Test search
        print("\nTesting search for 'apache'...")
        count = scanner.count('apache')
        print(f"  Total results: {count:,}")
        
    except Exception as e:
        print(f"Error: {e}")
