#!/usr/bin/env python3
"""
ShadowSyndicate Infrastructure Signatures
Based on Group-IB research: https://www.group-ib.com/blog/shadowsyndicate-raas/

ShadowSyndicate is a threat actor/RaaS affiliate linked to:
- Ransomware: Quantum, Nokoyawa, BlackCat/ALPHV, Royal, Cl0p, Cactus, Play, LockBit, RansomHub
- Tools: Cobalt Strike, Sliver, IcedID, Matanbuchus
- Connected to: TrickBot, Ryuk/Conti, FIN7, TrueBot, Evil Corp

Key tracking indicator: Reused SSH fingerprints across infrastructure
"""

# SSH Fingerprints - the KEY tracking indicator
SSH_FINGERPRINTS = {
    'shadowsyndicate-primary': {
        'fingerprint': '1ca4cbac895fc3bd12417b77fc6ed31d',
        'format': 'md5',
        'description': 'Primary ShadowSyndicate SSH fingerprint (85+ servers as of Sept 2023)',
        'first_seen': '2022-07-16',
        'confidence': 'high',
    },
    'shadowsyndicate-secondary': {
        'fingerprint': 'b5:4c:ce:68:9e:91:39:e8:24:b6:e5:1a:84:a7:a1:03',
        'format': 'md5-colonated',
        'description': 'Secondary SSH fingerprint (138 servers as of May 2025)',
        'first_seen': '2023-10-01',
        'confidence': 'high',
    },
}

# Known IPs (from various reports)
KNOWN_IPS = [
    # Initial scanning IPs
    '91.238.181.225',
    '5.188.86.169',
    # Servers with SSH fingerprint (May 2025)
    '88.214.25.246',
    '147.78.46.104',
    '147.78.47.226',
    '147.78.47.231',
    '193.142.30.96',
    '200.107.207.13',
]

# ASNs used by ShadowSyndicate bulletproof hosting
ASNS = {
    47890: 'UNMANAGED LTD',
    215540: 'GLOBAL CONNECTIVITY SOLUTIONS LLP',
    209272: 'Alviva Holding Limited',
    209132: 'Alviva Holding Limited',
    59580: 'Batterflyai Media ltd.',
    273045: 'DataHome S.A.',
    57043: 'HOSTKEY B.V.',
    50867: 'HOSTKEY B.V.',
    49453: 'Global layer B.V.',
    43350: 'NForce Entertainment B.V.',
    209588: 'Flyservers S.A.',
}

# Geographic distribution (server counts from Group-IB)
GEO_DISTRIBUTION = {
    'PA': 23,  # Panama
    'CY': 11,  # Cyprus
    'RU': 9,   # Russia
    'SC': 8,   # Seychelles
    'CR': 7,   # Costa Rica
    'CZ': 7,   # Czechia
    'BZ': 6,   # Belize
    'BG': 3,   # Bulgaria
    'HN': 3,   # Honduras
    'NL': 3,   # Netherlands
}

# Shodan queries for hunting
SHODAN_QUERIES = {
    'ssh-fingerprint-primary': 'ssh.fingerprint:1ca4cbac895fc3bd12417b77fc6ed31d',
    'ssh-fingerprint-secondary': 'ssh.fingerprint:b54cce689e9139e824b6e51a84a7a103',
    'asn-hunting': ' OR '.join(f'asn:AS{asn}' for asn in ASNS.keys()),
    'cobalt-strike-asn': f'product:"Cobalt Strike" ({" OR ".join(f"asn:AS{asn}" for asn in list(ASNS.keys())[:5])})',
}

# Censys queries for hunting
CENSYS_QUERIES = {
    'asn-hunting': ' OR '.join(f'host.autonomous_system.asn:{asn}' for asn in ASNS.keys()),
}


def get_infra_hunter_patterns():
    """
    Return patterns in infra-hunter format for database seeding.
    """
    patterns = []
    
    # SSH fingerprint patterns (these are the gold - very high confidence)
    patterns.append({
        'name': 'ShadowSyndicate SSH Primary',
        'pattern_type': 'ssh_fingerprint',
        'definition': {
            'fingerprint': '1ca4cbac895fc3bd12417b77fc6ed31d',
            'format': 'md5',
        },
        'description': 'ShadowSyndicate primary SSH fingerprint - 85+ servers, links to Cl0p, LockBit, BlackCat, RansomHub',
        'actor': 'ShadowSyndicate',
        'confidence': 'high',
        'references': [
            'https://www.group-ib.com/blog/shadowsyndicate-raas/',
            'https://thehackernews.com/2023/09/shadowsyndicate-new-cybercrime-group.html',
        ],
        'shodan_query': 'ssh.fingerprint:1ca4cbac895fc3bd12417b77fc6ed31d',
    })
    
    patterns.append({
        'name': 'ShadowSyndicate SSH Secondary',
        'pattern_type': 'ssh_fingerprint',
        'definition': {
            'fingerprint': 'b5:4c:ce:68:9e:91:39:e8:24:b6:e5:1a:84:a7:a1:03',
            'format': 'md5-colonated',
        },
        'description': 'ShadowSyndicate secondary SSH fingerprint - 138 servers (May 2025)',
        'actor': 'ShadowSyndicate',
        'confidence': 'high',
        'references': [
            'https://gbhackers.com/shadowsyndicate-infrastructure-used-by-multiple-ransomware-group/',
        ],
        'shodan_query': 'ssh.fingerprint:b54cce689e9139e824b6e51a84a7a103',
    })
    
    # ASN patterns (medium confidence - shared hosting but associated with group)
    patterns.append({
        'name': 'ShadowSyndicate ASN Cluster',
        'pattern_type': 'asn',
        'definition': {
            'asns': list(ASNS.keys()),
        },
        'description': 'ASNs associated with ShadowSyndicate bulletproof hosting network',
        'actor': 'ShadowSyndicate',
        'confidence': 'low',  # ASNs have legitimate users too
        'references': [
            'https://www.intrinsec.com/shadowsyndicate-infrastructure/',
        ],
        'shodan_query': ' OR '.join(f'asn:AS{asn}' for asn in ASNS.keys()),
    })
    
    # Cobalt Strike on associated ASNs (higher confidence combo)
    patterns.append({
        'name': 'ShadowSyndicate Cobalt Strike',
        'pattern_type': 'composite',
        'definition': {
            'operator': 'AND',
            'patterns': [
                {'type': 'product', 'definition': {'name': 'Cobalt Strike'}},
                {'type': 'asn', 'definition': {'asns': [209132, 209272, 57043, 50867, 43350]}},
            ],
        },
        'description': 'Cobalt Strike C2 on ShadowSyndicate-associated ASNs',
        'actor': 'ShadowSyndicate',
        'confidence': 'medium',
        'shodan_query': 'product:"Cobalt Strike" (asn:AS209132 OR asn:AS209272 OR asn:AS57043)',
    })
    
    return patterns


def print_iocs():
    """Print IOCs in various formats."""
    print("=" * 60)
    print("SHADOWSYNDICATE INDICATORS OF COMPROMISE")
    print("=" * 60)
    
    print("\n### SSH FINGERPRINTS (HIGH VALUE) ###")
    for name, data in SSH_FINGERPRINTS.items():
        print(f"\n{name}:")
        print(f"  Fingerprint: {data['fingerprint']}")
        print(f"  Format: {data['format']}")
        print(f"  Confidence: {data['confidence']}")
    
    print("\n\n### KNOWN IPs ###")
    for ip in KNOWN_IPS:
        print(f"  {ip}")
    
    print("\n\n### ASSOCIATED ASNs ###")
    for asn, name in ASNS.items():
        print(f"  AS{asn} - {name}")
    
    print("\n\n### SHODAN QUERIES ###")
    for name, query in SHODAN_QUERIES.items():
        print(f"\n{name}:")
        print(f"  {query}")
    
    print("\n\n### GEOGRAPHIC FOCUS ###")
    for country, count in sorted(GEO_DISTRIBUTION.items(), key=lambda x: -x[1]):
        print(f"  {country}: {count} servers")


if __name__ == '__main__':
    print_iocs()
