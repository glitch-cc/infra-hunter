"""
Scanner module for Infrastructure Pattern Intelligence.
Uses Censys Platform API v3 to discover hosts matching patterns.
"""
import os
import re
import json
import hashlib
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

# Censys Platform API v3 configuration
CENSYS_API_BASE = "https://api.platform.censys.io/v3"
CENSYS_ORG_ID = "a33e6dee-618d-4694-bdd2-dc9fa59d98c5"


@dataclass
class ScanResult:
    """Result from a scan operation."""
    ip: str
    asn: Optional[int]
    asn_name: Optional[str]
    country: Optional[str]
    city: Optional[str]
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    cert_fingerprint: Optional[str]
    cert_not_before: Optional[datetime]
    cert_not_after: Optional[datetime]
    cert_self_signed: Optional[bool]
    jarm: Optional[str]
    http_status: Optional[int]
    http_headers: Optional[Dict]
    http_body_hash: Optional[str]
    http_server: Optional[str]
    ports: List[int]
    services: List[Dict]
    hostnames: List[str]
    raw_data: Dict


class CensysScanner:
    """Scanner using Censys Platform API v3."""

    def __init__(self, api_token: Optional[str] = None):
        """
        Initialize Censys scanner.
        
        Args:
            api_token: Censys PAT token. If not provided, reads from env.
        """
        self.api_token = api_token or os.environ.get('CENSYS_API_TOKEN')
        if not self.api_token:
            # Try loading from keys.env
            keys_path = os.path.expanduser('~/.openclaw/.secure/keys.env')
            if os.path.exists(keys_path):
                with open(keys_path) as f:
                    for line in f:
                        if line.startswith('CENSYS_API_TOKEN='):
                            self.api_token = line.split('=', 1)[1].strip().strip('"\'')
                            break
        
        if not self.api_token:
            raise ValueError("Censys API token not found. Set CENSYS_API_TOKEN env var.")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })

    def search(self, query: str, max_results: int = 100) -> List[ScanResult]:
        """
        Search Censys for hosts matching a query.
        
        Args:
            query: CenQL query string
            max_results: Maximum number of results to return
            
        Returns:
            List of ScanResult objects
        """
        results = []
        cursor = None
        
        while len(results) < max_results:
            payload = {
                'query': query,
                'page_size': min(100, max_results - len(results)),
            }
            if cursor:
                payload['cursor'] = cursor
            
            resp = self.session.post(
                f"{CENSYS_API_BASE}/global/search/query",
                params={'organization_id': CENSYS_ORG_ID},
                json=payload
            )
            
            if resp.status_code != 200:
                raise Exception(f"Censys API error: {resp.status_code} - {resp.text}")
            
            data = resp.json()
            
            # Platform API returns results in result.hits
            hits = data.get('result', {}).get('hits', [])
            for hit in hits:
                # Platform API wraps host data in host_v1.resource
                host_data = hit.get('host_v1', {}).get('resource', hit)
                results.append(self._parse_host_v1(host_data))
            
            # Check for more pages
            cursor = data.get('result', {}).get('next_page_token')
            if not cursor or len(hits) == 0:
                break
        
        return results

    def get_host(self, ip: str) -> Optional[ScanResult]:
        """Get detailed information about a specific host."""
        resp = self.session.get(
            f"{CENSYS_API_BASE}/global/asset/host/{ip}",
            params={'organization_id': CENSYS_ORG_ID}
        )
        
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise Exception(f"Censys API error: {resp.status_code} - {resp.text}")
        
        data = resp.json()
        host_data = data.get('resource', data)
        return self._parse_host_v1(host_data)

    def _parse_host_v1(self, data: Dict) -> ScanResult:
        """Parse Censys Platform API v1 host data into ScanResult."""
        # Extract location info
        location = data.get('location', {})
        
        # Extract autonomous system info
        autonomous_system = data.get('autonomous_system', {})
        
        # Extract services/ports
        services = data.get('services', [])
        ports = list(set(s.get('port') for s in services if s.get('port')))
        
        # Extract certificate data from first service with cert
        cert_subject = None
        cert_issuer = None
        cert_fingerprint = None
        cert_not_before = None
        cert_not_after = None
        cert_self_signed = None
        jarm = None
        http_status = None
        http_headers = None
        http_body_hash = None
        http_server = None
        
        for svc in services:
            # Certificate data
            if 'cert' in svc and not cert_fingerprint:
                cert = svc['cert']
                cert_fingerprint = cert.get('fingerprint_sha256')
                
                parsed = cert.get('parsed', {})
                cert_subject = parsed.get('subject_dn')
                cert_issuer = parsed.get('issuer_dn')
                
                # Validity
                validity = parsed.get('validity', {})
                if validity.get('start'):
                    try:
                        cert_not_before = datetime.fromisoformat(validity['start'].replace('Z', '+00:00'))
                    except:
                        pass
                if validity.get('end'):
                    try:
                        cert_not_after = datetime.fromisoformat(validity['end'].replace('Z', '+00:00'))
                    except:
                        pass
                
                # Self-signed check
                if cert_subject and cert_issuer:
                    cert_self_signed = cert_subject == cert_issuer
            
            # JARM from TLS
            if 'tls' in svc and not jarm:
                tls = svc.get('tls', {})
                jarm = tls.get('jarm', {}).get('fingerprint')
            
            # HTTP data
            if svc.get('protocol') == 'HTTP' and not http_status:
                http_response = svc.get('http', {}).get('response', {})
                http_status = http_response.get('status_code')
                http_headers = http_response.get('headers', {})
                http_server = http_headers.get('server') if http_headers else None
                
                body = http_response.get('body')
                if body:
                    http_body_hash = hashlib.sha256(body.encode()).hexdigest()
        
        # Extract hostnames from DNS/web
        hostnames = []
        for svc in services:
            if 'web' in svc:
                web = svc.get('web', {})
                if web.get('hostname'):
                    hostnames.append(web['hostname'])
        hostnames = list(set(hostnames))
        
        return ScanResult(
            ip=data.get('ip', ''),
            asn=autonomous_system.get('asn'),
            asn_name=autonomous_system.get('name') or autonomous_system.get('description'),
            country=location.get('country_code'),
            city=location.get('city'),
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
            cert_fingerprint=cert_fingerprint,
            cert_not_before=cert_not_before,
            cert_not_after=cert_not_after,
            cert_self_signed=cert_self_signed,
            jarm=jarm,
            http_status=http_status,
            http_headers=http_headers,
            http_body_hash=http_body_hash,
            http_server=http_server,
            ports=ports,
            services=[{'port': s.get('port'), 'service_name': s.get('protocol')} for s in services],
            hostnames=hostnames,
            raw_data=data,
        )

    def _parse_host(self, data: Dict) -> ScanResult:
        """Parse Censys host data into ScanResult."""
        # Extract location info
        location = data.get('location', {})
        
        # Extract autonomous system info
        autonomous_system = data.get('autonomous_system', {})
        
        # Extract services/ports
        services = data.get('services', [])
        ports = list(set(s.get('port') for s in services if s.get('port')))
        
        # Extract certificate data (from first TLS service)
        cert_subject = None
        cert_issuer = None
        cert_fingerprint = None
        cert_not_before = None
        cert_not_after = None
        cert_self_signed = None
        jarm = None
        
        for svc in services:
            if 'tls' in svc:
                tls = svc['tls']
                certs = tls.get('certificates', {})
                
                # JARM
                if not jarm and 'jarm' in tls:
                    jarm = tls['jarm'].get('fingerprint')
                
                # Leaf certificate
                leaf = certs.get('leaf_data', {})
                if leaf:
                    subject = leaf.get('subject', {})
                    issuer = leaf.get('issuer', {})
                    
                    cert_subject = cert_subject or self._format_dn(subject)
                    cert_issuer = cert_issuer or self._format_dn(issuer)
                    cert_fingerprint = cert_fingerprint or leaf.get('fingerprint')
                    
                    # Validity
                    validity = leaf.get('validity', {})
                    if validity.get('start'):
                        cert_not_before = datetime.fromisoformat(validity['start'].replace('Z', '+00:00'))
                    if validity.get('end'):
                        cert_not_after = datetime.fromisoformat(validity['end'].replace('Z', '+00:00'))
                    
                    # Self-signed check
                    if cert_subject and cert_issuer:
                        cert_self_signed = cert_subject == cert_issuer
                
                break  # Only process first TLS service
        
        # Extract HTTP data (from first HTTP service)
        http_status = None
        http_headers = None
        http_body_hash = None
        http_server = None
        
        for svc in services:
            if 'http' in svc:
                http = svc['http']
                resp = http.get('response', {})
                
                http_status = resp.get('status_code')
                http_headers = resp.get('headers', {})
                http_server = http_headers.get('server') if http_headers else None
                
                # Body hash
                body = resp.get('body')
                if body:
                    http_body_hash = hashlib.sha256(body.encode()).hexdigest()
                
                break
        
        # Extract hostnames from DNS
        dns = data.get('dns', {})
        hostnames = list(set(
            dns.get('names', []) + 
            dns.get('reverse_dns', {}).get('names', [])
        ))
        
        return ScanResult(
            ip=data.get('ip', ''),
            asn=autonomous_system.get('asn'),
            asn_name=autonomous_system.get('name'),
            country=location.get('country_code'),
            city=location.get('city'),
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
            cert_fingerprint=cert_fingerprint,
            cert_not_before=cert_not_before,
            cert_not_after=cert_not_after,
            cert_self_signed=cert_self_signed,
            jarm=jarm,
            http_status=http_status,
            http_headers=http_headers,
            http_body_hash=http_body_hash,
            http_server=http_server,
            ports=ports,
            services=[{'port': s.get('port'), 'service_name': s.get('service_name')} for s in services],
            hostnames=hostnames,
            raw_data=data,
        )

    def _format_dn(self, dn_dict: Dict) -> str:
        """Format Distinguished Name from dict to string."""
        parts = []
        # Standard order
        for key in ['country', 'state', 'locality', 'organization', 'organizational_unit', 'common_name', 'email_address']:
            if key in dn_dict:
                val = dn_dict[key]
                if isinstance(val, list):
                    val = val[0] if val else ''
                short_key = {
                    'country': 'C',
                    'state': 'ST',
                    'locality': 'L',
                    'organization': 'O',
                    'organizational_unit': 'OU',
                    'common_name': 'CN',
                    'email_address': 'emailAddress',
                }.get(key, key)
                parts.append(f"{short_key}={val}")
        return ', '.join(parts)


class PatternMatcher:
    """Match hosts against defined patterns."""

    def __init__(self):
        self.matchers = {
            'cert_subject_dn': self._match_cert_subject,
            'cert_issuer_dn': self._match_cert_issuer,
            'cert_fingerprint': self._match_cert_fingerprint,
            'jarm': self._match_jarm,
            'http_headers': self._match_http_headers,
            'http_body_hash': self._match_http_body,
            'asn': self._match_asn,
            'hosting_provider': self._match_hosting,
            'port_combo': self._match_ports,
            'domain_regex': self._match_domain,
            'composite': self._match_composite,
        }

    def matches(self, host: ScanResult, pattern_type: str, definition: Dict) -> tuple[bool, Dict]:
        """
        Check if a host matches a pattern.
        
        Args:
            host: ScanResult to check
            pattern_type: Type of pattern
            definition: Pattern definition dict
            
        Returns:
            Tuple of (matched: bool, details: dict)
        """
        matcher = self.matchers.get(pattern_type)
        if not matcher:
            return False, {'error': f'Unknown pattern type: {pattern_type}'}
        
        return matcher(host, definition)

    def _match_cert_subject(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match certificate subject DN."""
        if not host.cert_subject:
            return False, {}
        
        pattern = definition.get('pattern', '')
        if definition.get('exact'):
            matched = host.cert_subject == pattern
        else:
            # Wildcard matching with * 
            regex = pattern.replace('*', '.*')
            matched = bool(re.match(regex, host.cert_subject, re.IGNORECASE))
        
        return matched, {'cert_subject': host.cert_subject, 'pattern': pattern}

    def _match_cert_issuer(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match certificate issuer DN."""
        if not host.cert_issuer:
            return False, {}
        
        pattern = definition.get('pattern', '')
        if definition.get('exact'):
            matched = host.cert_issuer == pattern
        else:
            regex = pattern.replace('*', '.*')
            matched = bool(re.match(regex, host.cert_issuer, re.IGNORECASE))
        
        return matched, {'cert_issuer': host.cert_issuer, 'pattern': pattern}

    def _match_cert_fingerprint(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match certificate fingerprint."""
        if not host.cert_fingerprint:
            return False, {}
        
        fingerprint = definition.get('fingerprint', '').lower()
        matched = host.cert_fingerprint.lower() == fingerprint
        
        return matched, {'cert_fingerprint': host.cert_fingerprint}

    def _match_jarm(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match JARM fingerprint."""
        if not host.jarm:
            return False, {}
        
        jarm = definition.get('fingerprint', '')
        
        if definition.get('prefix'):
            # Match just prefix (useful for partial matching)
            matched = host.jarm.startswith(jarm)
        else:
            matched = host.jarm == jarm
        
        return matched, {'jarm': host.jarm, 'pattern': jarm}

    def _match_http_headers(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match HTTP header patterns."""
        if not host.http_headers:
            return False, {}
        
        headers = host.http_headers
        required = definition.get('required', {})
        forbidden = definition.get('forbidden', [])
        status = definition.get('status')
        
        details = {'matched_headers': {}}
        
        # Check status code
        if status and host.http_status != status:
            return False, details
        
        # Check required headers
        for header, expected in required.items():
            actual = headers.get(header.lower()) or headers.get(header)
            if actual is None:
                return False, details
            if expected != '*' and str(actual) != str(expected):
                return False, details
            details['matched_headers'][header] = actual
        
        # Check forbidden headers
        for header in forbidden:
            if header.lower() in [h.lower() for h in headers.keys()]:
                return False, details
        
        return True, details

    def _match_http_body(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match HTTP body hash."""
        if not host.http_body_hash:
            return False, {}
        
        expected_hash = definition.get('hash', '').lower()
        matched = host.http_body_hash.lower() == expected_hash
        
        return matched, {'body_hash': host.http_body_hash}

    def _match_asn(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match Autonomous System Number."""
        if not host.asn:
            return False, {}
        
        asns = definition.get('asns', [])
        if isinstance(asns, int):
            asns = [asns]
        
        matched = host.asn in asns
        
        return matched, {'asn': host.asn, 'asn_name': host.asn_name}

    def _match_hosting(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match hosting provider name."""
        if not host.asn_name:
            return False, {}
        
        providers = definition.get('providers', [])
        name_lower = host.asn_name.lower()
        
        matched = any(p.lower() in name_lower for p in providers)
        
        return matched, {'asn_name': host.asn_name}

    def _match_ports(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match port combination."""
        if not host.ports:
            return False, {}
        
        required = set(definition.get('required', []))
        forbidden = set(definition.get('forbidden', []))
        
        host_ports = set(host.ports)
        
        # Check required ports
        if not required.issubset(host_ports):
            return False, {'ports': host.ports}
        
        # Check forbidden ports
        if host_ports.intersection(forbidden):
            return False, {'ports': host.ports}
        
        return True, {'ports': host.ports}

    def _match_domain(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match domain name regex pattern."""
        if not host.hostnames:
            return False, {}
        
        pattern = definition.get('regex', '')
        
        for hostname in host.hostnames:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True, {'matched_hostname': hostname, 'pattern': pattern}
        
        return False, {}

    def _match_composite(self, host: ScanResult, definition: Dict) -> tuple[bool, Dict]:
        """Match multiple sub-patterns (AND logic)."""
        sub_patterns = definition.get('patterns', [])
        operator = definition.get('operator', 'AND')  # AND or OR
        
        results = []
        all_details = {}
        
        for sub in sub_patterns:
            sub_type = sub.get('type')
            sub_def = sub.get('definition', {})
            matched, details = self.matches(host, sub_type, sub_def)
            results.append(matched)
            all_details[sub_type] = details
        
        if operator == 'AND':
            return all(results), all_details
        else:  # OR
            return any(results), all_details


def build_censys_query(pattern_type: str, definition: Dict) -> str:
    """
    Build a CenQL query from a pattern definition.
    Uses Censys Platform API v1 field names.
    
    Args:
        pattern_type: Type of pattern
        definition: Pattern definition
        
    Returns:
        CenQL query string
    """
    if pattern_type == 'cert_subject_dn':
        pattern = definition.get('pattern', '')
        # Platform API uses host.services.cert.parsed.subject_dn
        return f'host.services.cert.parsed.subject_dn:"{pattern}"'
    
    elif pattern_type == 'cert_issuer_dn':
        pattern = definition.get('pattern', '')
        return f'host.services.cert.parsed.issuer_dn:"{pattern}"'
    
    elif pattern_type == 'cert_fingerprint':
        fp = definition.get('fingerprint', '')
        return f'host.services.cert.fingerprint_sha256:"{fp}"'
    
    elif pattern_type == 'jarm':
        jarm = definition.get('fingerprint', '')
        return f'host.services.tls.jarm.fingerprint:"{jarm}"'
    
    elif pattern_type == 'http_headers':
        parts = []
        required = definition.get('required', {})
        forbidden = definition.get('forbidden', [])
        status = definition.get('status')
        
        if status:
            parts.append(f'host.services.http.response.status_code:{status}')
        
        for header, value in required.items():
            # Platform API header field names
            header_field = f'host.services.http.response.headers.{header.lower()}'
            if value != '*':
                parts.append(f'{header_field}:"{value}"')
            else:
                parts.append(f'{header_field}:*')
        
        for header in forbidden:
            parts.append(f'NOT host.services.http.response.headers.{header.lower()}:*')
        
        return ' AND '.join(parts)
    
    elif pattern_type == 'http_body_hash':
        h = definition.get('hash', '')
        return f'host.services.http.response.body_hash:"{h}"'
    
    elif pattern_type == 'asn':
        asns = definition.get('asns', [])
        if isinstance(asns, int):
            asns = [asns]
        if len(asns) == 1:
            return f'host.autonomous_system.asn:{asns[0]}'
        return '(' + ' OR '.join(f'host.autonomous_system.asn:{a}' for a in asns) + ')'
    
    elif pattern_type == 'port_combo':
        parts = []
        for port in definition.get('required', []):
            parts.append(f'host.services.port:{port}')
        return ' AND '.join(parts)
    
    elif pattern_type == 'composite':
        sub_queries = []
        for sub in definition.get('patterns', []):
            q = build_censys_query(sub['type'], sub.get('definition', {}))
            if q:
                sub_queries.append(f'({q})')
        
        operator = definition.get('operator', 'AND')
        return f' {operator} '.join(sub_queries)
    
    return ''


# Pre-defined known threat actor patterns
KNOWN_PATTERNS = {
    'apt29-wellmess': {
        'name': 'APT29 WellMess',
        'pattern_type': 'composite',
        'definition': {
            'operator': 'AND',
            'patterns': [
                {
                    'type': 'cert_subject_dn',
                    'definition': {'pattern': 'C=Tunis, O=IT*'}
                },
                {
                    'type': 'cert_issuer_dn',
                    'definition': {'pattern': 'C=Tunis, O=IT, CN=*'}
                }
            ]
        },
        'description': 'APT29 WellMess C2 certificate pattern from NCSC-UK advisory',
        'actor': 'APT29',
        'confidence': 'high',
        'references': ['https://www.ncsc.gov.uk/files/Advisory-APT29-targets-COVID-19-vaccine-development.pdf']
    },
    'cobalt-strike-default': {
        'name': 'Cobalt Strike Default',
        'pattern_type': 'http_headers',
        'definition': {
            'status': 404,
            'required': {
                'content-type': 'text/plain',
                'content-length': '0'
            },
            'forbidden': ['server']
        },
        'description': 'Default Cobalt Strike HTTP response pattern',
        'confidence': 'medium',
        'references': ['https://censys.com/blog/advanced-persistent-infrastructure-tracking']
    },
    'cobalt-strike-cert': {
        'name': 'Cobalt Strike Default Cert',
        'pattern_type': 'cert_fingerprint',
        'definition': {
            'fingerprint': '87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c'
        },
        'description': 'Default Cobalt Strike SSL certificate fingerprint',
        'confidence': 'high',
        'references': ['https://censys.com/blog/advanced-persistent-infrastructure-tracking']
    },
    'sidewinder-nginx': {
        'name': 'SideWinder nginx Pattern',
        'pattern_type': 'composite',
        'definition': {
            'operator': 'AND',
            'patterns': [
                {
                    'type': 'http_headers',
                    'definition': {
                        'status': 404,
                        'required': {
                            'server': 'nginx',
                            'content-type': 'text/html',
                            'content-length': '535'
                        }
                    }
                }
            ]
        },
        'description': 'SideWinder APT nginx 404 response pattern',
        'actor': 'SideWinder',
        'confidence': 'medium',
        'references': ['https://www.bridewell.com/insights/blogs/detail/the-distinctive-rattle-of-apt-sidewinder']
    },
    'sidewinder-jarm-1': {
        'name': 'SideWinder JARM Pattern 1',
        'pattern_type': 'jarm',
        'definition': {
            'fingerprint': '3fd3fd0003fd3fd21c3fd3fd3fd3fd703dc1bf20eb9604decefea997eabff7'
        },
        'description': 'SideWinder APT JARM fingerprint',
        'actor': 'SideWinder',
        'confidence': 'high',
        'references': ['https://www.bridewell.com/insights/blogs/detail/the-distinctive-rattle-of-apt-sidewinder']
    },
    'sidewinder-jarm-2': {
        'name': 'SideWinder JARM Pattern 2',
        'pattern_type': 'jarm',
        'definition': {
            'fingerprint': '40d40d40d00040d1dc40d40d40d40de9ab649921aa9add8c37a8978aa3ea88'
        },
        'description': 'SideWinder APT JARM fingerprint (variant)',
        'actor': 'SideWinder',
        'confidence': 'high',
        'references': ['https://www.bridewell.com/insights/blogs/detail/the-distinctive-rattle-of-apt-sidewinder']
    },
    'lazarus-fake-wikipedia': {
        'name': 'Lazarus Fake Wikipedia Cert',
        'pattern_type': 'cert_subject_dn',
        'definition': {
            'pattern': '*wikipedia.org*info@wikipedia.org*',
        },
        'description': 'Lazarus Group fake Wikipedia SSL certificate pattern',
        'actor': 'Lazarus',
        'confidence': 'high',
        'references': ['https://pastebin.com/QQYidKTt']
    },
}


if __name__ == '__main__':
    # Quick test
    import sys
    
    try:
        scanner = CensysScanner()
        print("Censys scanner initialized successfully!")
        
        # Test a simple query
        results = scanner.search('services.port:443', max_results=5)
        print(f"Test query returned {len(results)} results")
        
        if results:
            r = results[0]
            print(f"  First result: {r.ip}")
            print(f"    Country: {r.country}")
            print(f"    ASN: {r.asn} ({r.asn_name})")
            print(f"    JARM: {r.jarm}")
            print(f"    Ports: {r.ports}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
