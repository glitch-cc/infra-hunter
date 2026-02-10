"""
Shodan Scanner for JARM-based signatures.
"""
import os
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class ShodanResult:
    ip: str
    port: int
    country: str
    org: str
    asn: str
    jarm: Optional[str]
    hostnames: List[str]
    raw_data: Dict


class ShodanScanner:
    """Scanner using Shodan API for JARM queries."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('SHODAN_API_KEY')
        if not self.api_key:
            keys_path = os.path.expanduser('~/.openclaw/.secure/keys.env')
            if os.path.exists(keys_path):
                with open(keys_path) as f:
                    for line in f:
                        if line.startswith('SHODAN_API_KEY='):
                            self.api_key = line.split('=', 1)[1].strip().strip('"\'')
                            break
        
        if not self.api_key:
            raise ValueError("Shodan API key not found")
        
        self.base_url = "https://api.shodan.io"
    
    def search(self, query: str, max_results: int = 100) -> List[ShodanResult]:
        """Search Shodan."""
        results = []
        
        resp = requests.get(
            f"{self.base_url}/shodan/host/search",
            params={'key': self.api_key, 'query': query}
        )
        
        if resp.status_code != 200:
            raise Exception(f"Shodan API error: {resp.status_code} - {resp.text}")
        
        data = resp.json()
        
        for match in data.get('matches', [])[:max_results]:
            results.append(ShodanResult(
                ip=match.get('ip_str', ''),
                port=match.get('port', 0),
                country=match.get('location', {}).get('country_code', ''),
                org=match.get('org', ''),
                asn=match.get('asn', ''),
                jarm=match.get('ssl', {}).get('jarm') if 'ssl' in match else None,
                hostnames=match.get('hostnames', []),
                raw_data=match,
            ))
        
        return results
    
    def get_credits(self) -> dict:
        """Check remaining credits."""
        resp = requests.get(f"{self.base_url}/api-info", params={'key': self.api_key})
        return resp.json()


if __name__ == '__main__':
    scanner = ShodanScanner()
    print(f"Credits: {scanner.get_credits()}")
