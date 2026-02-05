#!/usr/bin/env python3
"""
Automated certificate monitoring for Infrastructure Hunter.
Watches crt.sh for new certs matching threat actor patterns.
"""
import os
import sys
import time
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import get_engine, get_session, Pattern, Host, Match, Actor
from sources.crtsh import CrtshScanner, build_crtsh_query

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# Cert patterns to monitor (domain patterns associated with threat actors)
CERT_MONITOR_PATTERNS = {
    'apt29-wellmess': {
        'query': 'O=IT',
        'description': 'APT29 WellMess - Certs with O=IT (Tunis pattern)',
        'actor': 'APT29',
        'confidence': 'medium',
    },
    'sidewinder-gov': {
        'query': '%.gov.pk',
        'description': 'SideWinder - Pakistan government impersonation',
        'actor': 'SideWinder', 
        'confidence': 'medium',
    },
    'sidewinder-mil': {
        'query': '%.mil.pk',
        'description': 'SideWinder - Pakistan military impersonation',
        'actor': 'SideWinder',
        'confidence': 'medium',
    },
    'lazarus-wiki': {
        'query': '%wikipedia%',
        'description': 'Lazarus - Fake Wikipedia patterns',
        'actor': 'Lazarus',
        'confidence': 'low',  # High false positive rate
    },
    'dprk-gov-impersonation': {
        'query': '%.gov.%',
        'description': 'DPRK - Government domain impersonation',
        'actor': 'DPRK',
        'confidence': 'low',
    },
    'cobalt-strike-keywords': {
        'query': '%cobaltstrike%',
        'description': 'Cobalt Strike - Obvious naming',
        'actor': None,
        'confidence': 'high',
    },
    'c2-keywords': {
        'query': '%c2server%',
        'description': 'C2 Server - Obvious naming',
        'actor': None,
        'confidence': 'high',
    },
}


class CertMonitor:
    """Monitor crt.sh for new certificates matching threat patterns."""
    
    def __init__(self, db_url: Optional[str] = None):
        """Initialize the monitor."""
        self.db_url = db_url or os.environ.get('INFRA_HUNTER_DB', 'postgresql://localhost/infra_hunter')
        self.scanner = CrtshScanner()
        self.state_file = os.path.join(os.path.dirname(__file__), 'monitor_state.json')
        self.state = self._load_state()
    
    def _load_state(self) -> Dict:
        """Load monitoring state from file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except:
                pass
        return {
            'last_check': {},
            'seen_cert_ids': {},
        }
    
    def _save_state(self):
        """Save monitoring state to file."""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2, default=str)
    
    def check_pattern(self, pattern_name: str, pattern_config: Dict, 
                      days_back: int = 7) -> List[Dict]:
        """
        Check crt.sh for new certs matching a pattern.
        
        Args:
            pattern_name: Name of the pattern
            pattern_config: Pattern configuration
            days_back: How many days back to search
            
        Returns:
            List of new certificate matches
        """
        query = pattern_config['query']
        logger.info(f"Checking pattern '{pattern_name}': {query}")
        
        try:
            # Search crt.sh
            results = self.scanner.search_by_pattern(query, limit=200)
            
            # Filter to recent certs
            cutoff = datetime.utcnow() - timedelta(days=days_back)
            recent = [r for r in results if r.not_before and r.not_before >= cutoff]
            
            # Filter out already-seen certs
            seen = set(self.state.get('seen_cert_ids', {}).get(pattern_name, []))
            new_certs = [r for r in recent if r.id not in seen]
            
            # Update seen list
            if pattern_name not in self.state['seen_cert_ids']:
                self.state['seen_cert_ids'][pattern_name] = []
            self.state['seen_cert_ids'][pattern_name].extend([r.id for r in new_certs])
            
            # Keep only last 1000 IDs per pattern
            self.state['seen_cert_ids'][pattern_name] = self.state['seen_cert_ids'][pattern_name][-1000:]
            
            logger.info(f"  Found {len(results)} total, {len(recent)} recent, {len(new_certs)} new")
            
            return [{
                'cert_id': r.id,
                'common_name': r.common_name,
                'issuer': r.issuer_name,
                'not_before': r.not_before,
                'not_after': r.not_after,
                'names': r.name_value,
                'pattern': pattern_name,
                'actor': pattern_config.get('actor'),
                'confidence': pattern_config.get('confidence', 'medium'),
            } for r in new_certs]
            
        except Exception as e:
            logger.error(f"  Error checking pattern: {e}")
            return []
    
    def run_check(self, patterns: Dict = None, days_back: int = 7) -> Dict[str, List[Dict]]:
        """
        Run a full check across all patterns.
        
        Args:
            patterns: Patterns to check (default: CERT_MONITOR_PATTERNS)
            days_back: How many days back to search
            
        Returns:
            Dict mapping pattern name to list of new matches
        """
        if patterns is None:
            patterns = CERT_MONITOR_PATTERNS
        
        all_matches = {}
        
        for name, config in patterns.items():
            matches = self.check_pattern(name, config, days_back=days_back)
            if matches:
                all_matches[name] = matches
            
            # Rate limit - crt.sh is free, be nice
            time.sleep(2)
        
        # Update state
        self.state['last_check'] = datetime.utcnow().isoformat()
        self._save_state()
        
        return all_matches
    
    def save_matches_to_db(self, matches: Dict[str, List[Dict]]):
        """Save matches to the database."""
        if not matches:
            return
        
        engine = get_engine(self.db_url)
        session = get_session(engine)
        
        try:
            for pattern_name, certs in matches.items():
                for cert in certs:
                    # Create a host record for the domain
                    domain = cert['common_name']
                    
                    # Check if host exists
                    host = session.query(Host).filter_by(ip=domain).first()
                    if not host:
                        host = Host(
                            ip=domain,  # Using domain as identifier for cert-only data
                            cert_subject=f"CN={cert['common_name']}",
                            cert_issuer=cert['issuer'],
                            cert_not_before=cert['not_before'],
                            cert_not_after=cert['not_after'],
                            hostnames=cert['names'].split('\n') if cert['names'] else [domain],
                            censys_data={'source': 'crtsh', 'cert_id': cert['cert_id']},
                        )
                        session.add(host)
                        session.flush()
                    
                    # Find or create pattern
                    pattern = session.query(Pattern).filter_by(name=f"crtsh-{pattern_name}").first()
                    if not pattern:
                        # Find actor
                        actor_id = None
                        if cert['actor']:
                            actor = session.query(Actor).filter_by(name=cert['actor']).first()
                            if not actor:
                                actor = Actor(name=cert['actor'])
                                session.add(actor)
                                session.flush()
                            actor_id = actor.id
                        
                        pattern = Pattern(
                            name=f"crtsh-{pattern_name}",
                            pattern_type='cert_subject_dn',
                            definition={'crtsh_query': CERT_MONITOR_PATTERNS.get(pattern_name, {}).get('query', '')},
                            description=CERT_MONITOR_PATTERNS.get(pattern_name, {}).get('description', ''),
                            actor_id=actor_id,
                            confidence=cert['confidence'],
                            source='crtsh-monitor',
                        )
                        session.add(pattern)
                        session.flush()
                    
                    # Create match
                    existing = session.query(Match).filter_by(
                        pattern_id=pattern.id,
                        host_id=host.id
                    ).first()
                    
                    if not existing:
                        match = Match(
                            pattern_id=pattern.id,
                            host_id=host.id,
                            match_details={
                                'cert_id': cert['cert_id'],
                                'source': 'crtsh',
                            },
                        )
                        session.add(match)
                        pattern.total_matches += 1
                        pattern.last_match_at = datetime.utcnow()
            
            session.commit()
            logger.info(f"Saved {sum(len(v) for v in matches.values())} matches to database")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error saving to database: {e}")
        finally:
            session.close()
    
    def format_alert(self, matches: Dict[str, List[Dict]]) -> str:
        """Format matches as an alert message."""
        if not matches:
            return "No new certificates found matching threat actor patterns."
        
        lines = ["🚨 *New Certificates Detected*\n"]
        
        for pattern_name, certs in matches.items():
            config = CERT_MONITOR_PATTERNS.get(pattern_name, {})
            actor = config.get('actor', 'Unknown')
            
            lines.append(f"*{pattern_name}* ({actor}) - {len(certs)} new")
            
            for cert in certs[:5]:  # Limit to 5 per pattern
                lines.append(f"  • `{cert['common_name']}`")
                lines.append(f"    Issued: {cert['not_before'].strftime('%Y-%m-%d') if cert['not_before'] else 'Unknown'}")
            
            if len(certs) > 5:
                lines.append(f"  ... and {len(certs) - 5} more")
            
            lines.append("")
        
        return "\n".join(lines)


def run_monitor(db_url: str = None, days_back: int = 7, save_to_db: bool = True) -> Dict:
    """
    Run the certificate monitor.
    
    Args:
        db_url: Database URL
        days_back: Days to look back
        save_to_db: Whether to save matches to database
        
    Returns:
        Dict with results
    """
    monitor = CertMonitor(db_url=db_url)
    
    logger.info("Starting certificate monitor...")
    matches = monitor.run_check(days_back=days_back)
    
    if save_to_db and matches:
        monitor.save_matches_to_db(matches)
    
    # Generate alert
    alert = monitor.format_alert(matches)
    
    return {
        'matches': matches,
        'total_new': sum(len(v) for v in matches.values()),
        'alert': alert,
    }


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Certificate Monitor for Threat Hunting')
    parser.add_argument('--days', type=int, default=7, help='Days to look back')
    parser.add_argument('--no-save', action='store_true', help='Do not save to database')
    parser.add_argument('--db', default=None, help='Database URL')
    args = parser.parse_args()
    
    result = run_monitor(
        db_url=args.db or os.environ.get('INFRA_HUNTER_DB'),
        days_back=args.days,
        save_to_db=not args.no_save,
    )
    
    print(result['alert'])
    print(f"\nTotal new certificates: {result['total_new']}")
