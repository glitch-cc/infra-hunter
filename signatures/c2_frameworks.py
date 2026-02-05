#!/usr/bin/env python3
"""
C2 Framework Infrastructure Signatures

High-quality signatures for detecting Command & Control frameworks.
Sources:
- https://github.com/cedowens/C2-JARM
- https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm
- https://t3l3m3try.medium.com/hunting-cobalt-strike-servers-385c5bedda7b
- DFIR Report, Unit42, Microsoft Security Blog
"""

# =============================================================================
# COBALT STRIKE - Most prevalent commercial C2, used by APTs and ransomware
# =============================================================================
COBALT_STRIKE = {
    'name': 'Cobalt Strike',
    'description': 'Commercial adversary simulation tool, widely abused by APTs and ransomware operators',
    'users': ['APT29', 'APT41', 'FIN7', 'Conti', 'Ryuk', 'LockBit', 'REvil'],
    
    'signatures': {
        # Default SSL Certificate (HIGH confidence)
        'default_ssl_cert': {
            'type': 'cert_fingerprint',
            'sha256': '87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c',
            'sha1': '6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c',
            'md5': '950098276a495286eb2a2556fbab6d83',
            'serial': '146473198',
            'confidence': 'high',
            'shodan_query': 'ssl:"6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"',
            'censys_query': 'services.tls.certificates.leaf_data.fingerprint:"6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"',
        },
        
        # JARM Fingerprints (MEDIUM confidence - can have false positives)
        'jarm_default': {
            'type': 'jarm',
            'fingerprint': '07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2',
            'confidence': 'medium',
            'note': 'Default JARM, can match other Java applications',
            'shodan_query': 'ssl.jarm:"07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"',
        },
        'jarm_java11': {
            'type': 'jarm',
            'fingerprint': '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1',
            'confidence': 'medium',
            'note': 'Java 11 implementation',
            'shodan_query': 'ssl.jarm:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"',
        },
        
        # HTTP Response Pattern (MEDIUM-HIGH confidence when combined)
        'http_404_response': {
            'type': 'http_pattern',
            'status': 404,
            'headers': {
                'Content-Type': 'text/plain',
                'Content-Length': '0',
            },
            'forbidden_headers': ['Server'],
            'confidence': 'medium',
            'shodan_query': '"HTTP/1.1 404 Not Found" "Content-Type: text/plain" "Content-Length: 0" -Server',
        },
        
        # Management Port (MEDIUM confidence)
        'mgmt_port_50050': {
            'type': 'port_banner',
            'port': 50050,
            'banner_hash': -2007783223,
            'confidence': 'medium',
            'shodan_query': 'port:50050 hash:-2007783223',
        },
    },
}

# =============================================================================
# SLIVER - Open source C2, increasingly popular replacement for Cobalt Strike
# =============================================================================
SLIVER = {
    'name': 'Sliver',
    'description': 'Open-source cross-platform C2 framework by BishopFox',
    'users': ['Various APTs', 'Ransomware operators migrating from CS'],
    
    'signatures': {
        'jarm_https': {
            'type': 'jarm',
            'fingerprint': '3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910',
            'confidence': 'medium',
            'note': 'HTTPS listener, can be randomized in newer versions',
            'shodan_query': 'ssl.jarm:"3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910"',
        },
        'jarm_mtls': {
            'type': 'jarm',
            'fingerprint': '00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01',
            'confidence': 'medium',
            'note': 'mTLS listener',
            'shodan_query': 'ssl.jarm:"00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01"',
        },
        'jarm_go': {
            'type': 'jarm',
            'fingerprint': '2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883',
            'confidence': 'medium',
            'note': 'Go 1.15.2 implementation',
            'shodan_query': 'ssl.jarm:"2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883"',
        },
        'http_404_nocache': {
            'type': 'http_pattern',
            'status': 404,
            'headers': {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Content-Length': '0',
            },
            'confidence': 'medium',
            'shodan_query': '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0"',
        },
    },
}

# =============================================================================
# METASPLOIT - Most common pentesting framework
# =============================================================================
METASPLOIT = {
    'name': 'Metasploit',
    'description': 'Most widely used penetration testing framework',
    'users': ['Pentesters', 'Script kiddies', 'Some APTs for initial access'],
    
    'signatures': {
        'jarm_ruby27': {
            'type': 'jarm',
            'fingerprint': '07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d',
            'confidence': 'medium',
            'note': 'Ruby 2.7.0p0 SSL listener',
            'shodan_query': 'ssl.jarm:"07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d"',
        },
        'jarm_ruby': {
            'type': 'jarm',
            'fingerprint': '07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823',
            'confidence': 'medium',
            'note': 'Ruby SSL listener variant',
            'shodan_query': 'ssl.jarm:"07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823"',
        },
    },
}

# =============================================================================
# MYTHIC - Modern C2 with web UI
# =============================================================================
MYTHIC = {
    'name': 'Mythic',
    'description': 'Cross-platform post-exploitation framework with web-based UI',
    'users': ['Red teams', 'Some APT operations'],
    
    'signatures': {
        'jarm_aiohttp': {
            'type': 'jarm',
            'fingerprint': '2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb',
            'confidence': 'medium',
            'note': 'Python 3 with aiohttp 3',
            'shodan_query': 'ssl.jarm:"2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb"',
        },
    },
}

# =============================================================================
# COVENANT - .NET C2
# =============================================================================
COVENANT = {
    'name': 'Covenant',
    'description': '.NET C2 framework with collaborative red team features',
    'users': ['Red teams', 'Some threat actors'],
    
    'signatures': {
        'jarm_aspnet': {
            'type': 'jarm',
            'fingerprint': '21d14d00000000021c21d14d21d21d1ee8ae98bf3ef941e91529a93ac62b8b',
            'confidence': 'medium',
            'note': 'ASP.NET Core',
            'shodan_query': 'ssl.jarm:"21d14d00000000021c21d14d21d21d1ee8ae98bf3ef941e91529a93ac62b8b"',
        },
    },
}

# =============================================================================
# MERLIN - Go-based C2
# =============================================================================
MERLIN = {
    'name': 'Merlin',
    'description': 'Go-based cross-platform post-exploitation HTTP/2 C2',
    'users': ['Red teams'],
    
    'signatures': {
        'jarm_go': {
            'type': 'jarm',
            'fingerprint': '29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38',
            'confidence': 'medium',
            'note': 'Go 1.15.2 linux/amd64',
            'shodan_query': 'ssl.jarm:"29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38"',
        },
    },
}

# =============================================================================
# DEIMOS C2 - Open source Go C2
# =============================================================================
DEIMOS = {
    'name': 'DeimosC2',
    'description': 'Open-source Go-based C2 framework',
    'users': ['Red teams', 'Used by Lazarus Group'],
    
    'signatures': {
        'jarm_go_websocket': {
            'type': 'jarm',
            'fingerprint': '00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64',
            'confidence': 'medium',
            'note': 'Go with gorilla/websocket package',
            'shodan_query': 'ssl.jarm:"00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64"',
        },
    },
}

# =============================================================================
# EVILGINX2 - Phishing framework
# =============================================================================
EVILGINX2 = {
    'name': 'EvilGinx2',
    'description': 'Man-in-the-middle attack framework for phishing credentials and session cookies',
    'users': ['Phishing campaigns', 'APTs for credential theft'],
    
    'signatures': {
        'jarm_go': {
            'type': 'jarm',
            'fingerprint': '20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6',
            'confidence': 'high',
            'note': 'Go 1.10.4 - fairly unique',
            'shodan_query': 'ssl.jarm:"20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6"',
        },
    },
}

# =============================================================================
# POSHC2 - PowerShell C2
# =============================================================================
POSHC2 = {
    'name': 'PoshC2',
    'description': 'PowerShell-based C2 framework',
    'users': ['Red teams'],
    
    'signatures': {
        'jarm_python3': {
            'type': 'jarm',
            'fingerprint': '2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261',
            'confidence': 'medium',
            'note': 'Python3 http.server',
            'shodan_query': 'ssl.jarm:"2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261"',
        },
    },
}

# =============================================================================
# ALL C2 FRAMEWORKS
# =============================================================================
ALL_C2_FRAMEWORKS = {
    'cobalt_strike': COBALT_STRIKE,
    'sliver': SLIVER,
    'metasploit': METASPLOIT,
    'mythic': MYTHIC,
    'covenant': COVENANT,
    'merlin': MERLIN,
    'deimos': DEIMOS,
    'evilginx2': EVILGINX2,
    'poshc2': POSHC2,
}


def get_all_jarm_fingerprints():
    """Return all JARM fingerprints with metadata."""
    jarms = []
    for framework_id, framework in ALL_C2_FRAMEWORKS.items():
        for sig_name, sig in framework['signatures'].items():
            if sig['type'] == 'jarm':
                jarms.append({
                    'framework': framework['name'],
                    'framework_id': framework_id,
                    'signature': sig_name,
                    'fingerprint': sig['fingerprint'],
                    'confidence': sig['confidence'],
                    'shodan_query': sig.get('shodan_query', ''),
                    'note': sig.get('note', ''),
                })
    return jarms


def get_infra_hunter_patterns():
    """Return patterns in infra-hunter format for database seeding."""
    patterns = []
    
    for framework_id, framework in ALL_C2_FRAMEWORKS.items():
        for sig_name, sig in framework['signatures'].items():
            pattern_name = f"{framework['name']} - {sig_name.replace('_', ' ').title()}"
            
            if sig['type'] == 'jarm':
                patterns.append({
                    'name': pattern_name,
                    'pattern_type': 'jarm',
                    'definition': {
                        'fingerprint': sig['fingerprint'],
                    },
                    'description': f"{framework['description']}. {sig.get('note', '')}",
                    'actor': None,  # C2 tools are used by multiple actors
                    'confidence': sig['confidence'],
                    'references': [sig.get('shodan_query', '')],
                    'shodan_query': sig.get('shodan_query', ''),
                })
            
            elif sig['type'] == 'cert_fingerprint':
                patterns.append({
                    'name': pattern_name,
                    'pattern_type': 'cert_fingerprint',
                    'definition': {
                        'fingerprint': sig['sha256'],
                        'serial': sig.get('serial'),
                    },
                    'description': f"{framework['description']}. Default SSL certificate.",
                    'actor': None,
                    'confidence': sig['confidence'],
                    'references': [sig.get('shodan_query', '')],
                    'shodan_query': sig.get('shodan_query', ''),
                })
    
    return patterns


def print_summary():
    """Print a summary of all signatures."""
    print("=" * 70)
    print("C2 FRAMEWORK SIGNATURES SUMMARY")
    print("=" * 70)
    
    for framework_id, framework in ALL_C2_FRAMEWORKS.items():
        print(f"\n### {framework['name']} ###")
        print(f"Description: {framework['description']}")
        print(f"Known users: {', '.join(framework['users'])}")
        print("Signatures:")
        for sig_name, sig in framework['signatures'].items():
            print(f"  - {sig_name}: {sig['type']} (confidence: {sig['confidence']})")
            if sig['type'] == 'jarm':
                print(f"    JARM: {sig['fingerprint']}")
    
    print("\n" + "=" * 70)
    jarms = get_all_jarm_fingerprints()
    print(f"Total JARM fingerprints: {len(jarms)}")
    print("=" * 70)


if __name__ == '__main__':
    print_summary()
