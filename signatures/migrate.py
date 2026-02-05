#!/usr/bin/env python3
"""
Migrate existing Python-based signatures to YAML format.
"""
import sys
import os
from pathlib import Path
from datetime import date

sys.path.insert(0, str(Path(__file__).parent.parent))

from signatures.manager import SignatureManager, Signature, Condition, LIBRARY_PATH
from signatures.c2_frameworks import ALL_C2_FRAMEWORKS


def migrate_c2_frameworks(mgr: SignatureManager) -> int:
    """Migrate C2 framework signatures to YAML."""
    count = 0
    
    for framework_id, framework in ALL_C2_FRAMEWORKS.items():
        for sig_name, sig_data in framework['signatures'].items():
            # Build signature ID
            sig_id = f"{framework_id}-{sig_name}".replace('_', '-')
            
            # Skip if already exists
            if mgr.get(sig_id):
                print(f"  Skip (exists): {sig_id}")
                continue
            
            # Determine condition type and field
            sig_type = sig_data['type']
            if sig_type == 'jarm':
                cond_type = 'jarm'
                cond_field = 'services.jarm.fingerprint'
                cond_value = sig_data['fingerprint']
            elif sig_type == 'cert_fingerprint':
                cond_type = 'cert_fingerprint'
                cond_field = 'services.tls.certificates.leaf_data.fingerprint'
                cond_value = sig_data['sha256']
            elif sig_type == 'http_pattern':
                cond_type = 'http_header'
                cond_field = 'services.http.response.status_code'
                cond_value = str(sig_data.get('status', 200))
            elif sig_type == 'port_banner':
                cond_type = 'port'
                cond_field = 'services.port'
                cond_value = str(sig_data.get('port', 0))
            else:
                print(f"  Skip (unknown type {sig_type}): {sig_id}")
                continue
            
            # Map confidence
            conf = sig_data.get('confidence', 'medium')
            
            # Build condition
            conditions = [Condition(
                name=sig_name.replace('_', ' ').title(),
                type=cond_type,
                field=cond_field,
                operator='equals',
                value=cond_value,
                weight=80 if conf == 'high' else 60 if conf == 'medium' else 40,
                note=sig_data.get('note'),
            )]
            
            # Build signature
            sig = Signature(
                id=sig_id,
                name=f"{framework['name']} - {sig_name.replace('_', ' ').title()}",
                version="1.0.0",
                category="c2-frameworks",
                description=f"{framework['description']}. {sig_data.get('note', '')}".strip(),
                logic_match="any",
                conditions=conditions,
                author="C2-JARM Research",
                attribution_actors=framework.get('users', [])[:5],  # First 5
                attribution_confidence="low",
                attribution_note="C2 tool used by multiple actors",
                confidence=conf,
                severity="critical" if conf == "high" else "high",
                false_positive_rate="low" if conf == "high" else "medium",
                last_verified=date.today().isoformat(),
                queries_shodan=sig_data.get('shodan_query'),
                references=[
                    {"url": "https://github.com/cedowens/C2-JARM", "title": "C2-JARM"},
                ],
                enabled=True,
            )
            
            # Auto-generate Censys query
            sig.queries_censys = sig.generate_censys_query()
            
            # Validate
            errors = sig.validate()
            if errors:
                print(f"  Validation errors for {sig_id}: {errors}")
                continue
            
            # Save
            path = mgr.save(sig)
            print(f"  Migrated: {sig_id} -> {path.name}")
            count += 1
    
    return count


def migrate_shadowsyndicate(mgr: SignatureManager) -> int:
    """Migrate ShadowSyndicate signatures to YAML."""
    from signatures.shadowsyndicate import SIGNATURES, SSH_FINGERPRINTS, COBALT_STRIKE_WATERMARKS
    
    count = 0
    
    # SSH fingerprints
    for i, fp in enumerate(SSH_FINGERPRINTS[:5]):  # First 5 as examples
        sig_id = f"shadowsyndicate-ssh-{i+1}"
        
        if mgr.get(sig_id):
            print(f"  Skip (exists): {sig_id}")
            continue
        
        sig = Signature(
            id=sig_id,
            name=f"ShadowSyndicate SSH Fingerprint #{i+1}",
            version="1.0.0",
            category="ransomware",
            description="SSH key fingerprint associated with ShadowSyndicate RaaS affiliate infrastructure.",
            logic_match="any",
            conditions=[Condition(
                name="SSH Fingerprint",
                type="banner",
                field="services.ssh.server_host_key.fingerprint_sha256",
                operator="equals",
                value=fp,
                weight=90,
            )],
            author="Group-IB Research",
            attribution_actors=["ShadowSyndicate"],
            attribution_confidence="high",
            confidence="high",
            severity="critical",
            last_verified=date.today().isoformat(),
            references=[
                {"url": "https://www.group-ib.com/blog/shadowsyndicate-raas/", "title": "Group-IB ShadowSyndicate"},
            ],
        )
        sig.queries_censys = sig.generate_censys_query()
        
        path = mgr.save(sig)
        print(f"  Migrated: {sig_id}")
        count += 1
    
    # Cobalt Strike watermarks  
    for wm in COBALT_STRIKE_WATERMARKS:
        sig_id = f"shadowsyndicate-cs-{wm}"
        
        if mgr.get(sig_id):
            continue
        
        sig = Signature(
            id=sig_id,
            name=f"ShadowSyndicate Cobalt Strike Watermark {wm}",
            version="1.0.0",
            category="ransomware",
            description=f"Cobalt Strike watermark {wm} associated with ShadowSyndicate operations.",
            logic_match="any",
            conditions=[Condition(
                name="CS Watermark",
                type="banner",
                field="services.cobalt_strike.watermark",
                operator="equals",
                value=str(wm),
                weight=85,
            )],
            author="Group-IB Research",
            attribution_actors=["ShadowSyndicate"],
            attribution_confidence="high",
            confidence="high",
            severity="critical",
            last_verified=date.today().isoformat(),
        )
        
        path = mgr.save(sig)
        print(f"  Migrated: {sig_id}")
        count += 1
    
    return count


def main():
    print("=" * 60)
    print("Migrating Python signatures to YAML format")
    print("=" * 60)
    
    mgr = SignatureManager()
    total = 0
    
    print("\n[1/2] Migrating C2 Frameworks...")
    total += migrate_c2_frameworks(mgr)
    
    print("\n[2/2] Migrating ShadowSyndicate...")
    try:
        total += migrate_shadowsyndicate(mgr)
    except Exception as e:
        print(f"  Error: {e}")
    
    print("\n" + "=" * 60)
    print(f"Migration complete: {total} signatures created")
    
    stats = mgr.stats()
    print(f"\nLibrary stats:")
    print(f"  Total: {stats['total']}")
    print(f"  By category: {stats['by_category']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
