#!/usr/bin/env python3
"""
Load threat actor signatures into the infra-hunter database.
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import get_engine, get_session, Actor, Pattern, Host
from signatures.shadowsyndicate import get_infra_hunter_patterns, KNOWN_IPS, ASNS


def load_shadowsyndicate(session, verbose=True):
    """Load ShadowSyndicate patterns into the database."""
    
    # Create/get actor
    actor = session.query(Actor).filter_by(name='ShadowSyndicate').first()
    if not actor:
        actor = Actor(
            name='ShadowSyndicate',
            aliases=['Infra Storm'],
            description='RaaS affiliate linked to Quantum, Nokoyawa, BlackCat, Royal, Cl0p, Cactus, Play, LockBit, RansomHub. Tracked by unique SSH fingerprints.',
            country='RU',  # Likely Russian-linked
            confidence='high',
            references=[
                'https://www.group-ib.com/blog/shadowsyndicate-raas/',
                'https://thehackernews.com/2023/09/shadowsyndicate-new-cybercrime-group.html',
            ],
        )
        session.add(actor)
        session.flush()
        if verbose:
            print(f"Created actor: ShadowSyndicate (ID: {actor.id})")
    else:
        if verbose:
            print(f"Actor exists: ShadowSyndicate (ID: {actor.id})")
    
    # Load patterns
    patterns = get_infra_hunter_patterns()
    loaded = 0
    
    for p_data in patterns:
        existing = session.query(Pattern).filter_by(name=p_data['name']).first()
        if existing:
            if verbose:
                print(f"  Pattern exists: {p_data['name']}")
            continue
        
        pattern = Pattern(
            name=p_data['name'],
            pattern_type=p_data['pattern_type'],
            definition=p_data['definition'],
            description=p_data['description'],
            actor_id=actor.id,
            confidence=p_data['confidence'],
            source='Group-IB Research',
            references=p_data.get('references', []),
            censys_query=p_data.get('shodan_query', ''),  # Using shodan query format
        )
        session.add(pattern)
        loaded += 1
        if verbose:
            print(f"  Added pattern: {p_data['name']}")
    
    # Add known IPs as hosts
    for ip in KNOWN_IPS:
        existing = session.query(Host).filter_by(ip=ip).first()
        if not existing:
            host = Host(
                ip=ip,
                censys_data={'source': 'shadowsyndicate-iocs', 'actor': 'ShadowSyndicate'},
            )
            session.add(host)
            if verbose:
                print(f"  Added known IP: {ip}")
    
    session.commit()
    
    if verbose:
        print(f"\nLoaded {loaded} new patterns for ShadowSyndicate")
    
    return loaded


def load_all_signatures(db_url=None, verbose=True):
    """Load all available signatures."""
    if db_url is None:
        db_url = os.environ.get('INFRA_HUNTER_DB', 'postgresql://postgres:postgres@localhost/infra_hunter')
    
    engine = get_engine(db_url)
    session = get_session(engine)
    
    try:
        total = 0
        
        if verbose:
            print("Loading ShadowSyndicate signatures...")
        total += load_shadowsyndicate(session, verbose=verbose)
        
        # Add more signature loaders here as we create them
        # total += load_apt29(session, verbose=verbose)
        # total += load_lazarus(session, verbose=verbose)
        
        if verbose:
            print(f"\nTotal: {total} new patterns loaded")
        
        return total
        
    finally:
        session.close()


if __name__ == '__main__':
    load_all_signatures(verbose=True)
