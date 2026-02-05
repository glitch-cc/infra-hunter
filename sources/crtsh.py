"""
crt.sh Certificate Transparency integration.
FREE - No API key required.
"""
import requests
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class CertResult:
    """Certificate from crt.sh"""
    id: int
    issuer_name: str
    common_name: str
    name_value: str  # All names in cert (CN + SANs)
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    serial_number: str
    issuer_ca_id: int


class CrtshScanner:
    """Scanner using crt.sh Certificate Transparency logs."""
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'InfraHunter/1.0'
        })
    
    def search_by_pattern(self, pattern: str, limit: int = 100) -> List[CertResult]:
        """
        Search for certificates matching a pattern.
        
        Args:
            pattern: Search pattern (supports % wildcards)
                     e.g., "%.gov.pk" or "Tunis"
            limit: Max results to return
            
        Returns:
            List of CertResult objects
        """
        # crt.sh uses SQL LIKE syntax with %
        params = {
            'q': pattern,
            'output': 'json',
        }
        
        try:
            resp = self.session.get(f"{self.BASE_URL}/", params=params, timeout=30)
            
            if resp.status_code != 200:
                raise Exception(f"crt.sh error: {resp.status_code}")
            
            # Handle empty results
            if not resp.text or resp.text.strip() == '':
                return []
            
            data = resp.json()
            
            results = []
            seen_ids = set()
            
            for entry in data[:limit]:
                cert_id = entry.get('id')
                if cert_id in seen_ids:
                    continue
                seen_ids.add(cert_id)
                
                # Parse dates
                not_before = None
                not_after = None
                
                if entry.get('not_before'):
                    try:
                        not_before = datetime.fromisoformat(entry['not_before'].replace('T', ' ').split('.')[0])
                    except:
                        pass
                
                if entry.get('not_after'):
                    try:
                        not_after = datetime.fromisoformat(entry['not_after'].replace('T', ' ').split('.')[0])
                    except:
                        pass
                
                results.append(CertResult(
                    id=cert_id,
                    issuer_name=entry.get('issuer_name', ''),
                    common_name=entry.get('common_name', ''),
                    name_value=entry.get('name_value', ''),
                    not_before=not_before,
                    not_after=not_after,
                    serial_number=entry.get('serial_number', ''),
                    issuer_ca_id=entry.get('issuer_ca_id', 0),
                ))
            
            return results
            
        except requests.exceptions.JSONDecodeError:
            return []
        except Exception as e:
            raise Exception(f"crt.sh search failed: {e}")
    
    def search_by_org(self, org: str, limit: int = 100) -> List[CertResult]:
        """Search for certs by organization name in issuer/subject."""
        return self.search_by_pattern(f"O={org}", limit=limit)
    
    def search_by_domain(self, domain: str, include_subdomains: bool = True, limit: int = 100) -> List[CertResult]:
        """Search for certs by domain name."""
        if include_subdomains:
            pattern = f"%.{domain}"
        else:
            pattern = domain
        return self.search_by_pattern(pattern, limit=limit)
    
    def get_cert_details(self, cert_id: int) -> Optional[Dict]:
        """Get full certificate details by ID."""
        try:
            resp = self.session.get(f"{self.BASE_URL}/?id={cert_id}&output=json", timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return None
    
    def search_recent(self, pattern: str, days: int = 7, limit: int = 100) -> List[CertResult]:
        """
        Search for recently issued certificates matching pattern.
        Note: crt.sh doesn't have a direct date filter, so we filter client-side.
        """
        results = self.search_by_pattern(pattern, limit=limit * 3)  # Fetch more to filter
        
        cutoff = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=days)
        
        recent = []
        for r in results:
            if r.not_before and r.not_before >= cutoff:
                recent.append(r)
                if len(recent) >= limit:
                    break
        
        return recent


def build_crtsh_query(pattern_type: str, definition: Dict) -> str:
    """
    Build a crt.sh query from pattern definition.
    
    Args:
        pattern_type: Type of pattern
        definition: Pattern definition
        
    Returns:
        crt.sh query string
    """
    if pattern_type == 'cert_subject_dn':
        pattern = definition.get('pattern', '')
        # Convert to crt.sh format - extract key parts
        # e.g., "C=Tunis, O=IT*" -> "O=IT"
        if 'O=' in pattern:
            # Extract organization
            import re
            match = re.search(r'O=([^,*]+)', pattern)
            if match:
                return f"O={match.group(1)}"
        if 'CN=' in pattern:
            match = re.search(r'CN=([^,*]+)', pattern)
            if match:
                return match.group(1)
        return pattern.replace('*', '%')
    
    elif pattern_type == 'cert_issuer_dn':
        pattern = definition.get('pattern', '')
        if 'O=' in pattern:
            import re
            match = re.search(r'O=([^,*]+)', pattern)
            if match:
                return f"O={match.group(1)}"
        return pattern.replace('*', '%')
    
    elif pattern_type == 'domain_regex':
        # Convert regex to SQL LIKE pattern (basic conversion)
        pattern = definition.get('regex', '')
        pattern = pattern.replace('.*', '%').replace('.+', '%')
        pattern = pattern.replace('\\', '')
        return pattern
    
    return ''


if __name__ == '__main__':
    # Test
    scanner = CrtshScanner()
    
    print("Testing crt.sh search for 'github.com'...")
    results = scanner.search_by_domain('github.com', limit=5)
    
    for r in results:
        print(f"  CN: {r.common_name}")
        print(f"  Issuer: {r.issuer_name[:50]}...")
        print(f"  Valid: {r.not_before} - {r.not_after}")
        print()
