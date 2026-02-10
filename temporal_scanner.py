#!/usr/bin/env python3
"""
Temporal Scanner for Infrastructure Hunter.
Handles delta detection, history tracking, and trend analysis.
"""
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import sessionmaker

from models import Host, Pattern, Match, ScanJob, get_engine
from models_temporal import (
    HostHistory, HostChange, ScanSummary, Alert,
    HostStatus, ChangeType, init_temporal_tables
)


class TemporalScanner:
    """
    Manages temporal tracking for infrastructure scanning.
    Detects changes, maintains history, generates alerts.
    """
    
    # How long before a host is considered "gone"
    GONE_THRESHOLD_HOURS = 48
    
    # Severity mappings for different change types
    CHANGE_SEVERITY = {
        ChangeType.FIRST_SEEN.value: 'medium',
        ChangeType.CERT_CHANGED.value: 'low',
        ChangeType.JARM_CHANGED.value: 'medium',
        ChangeType.PORTS_CHANGED.value: 'low',
        ChangeType.NEW_PATTERN_MATCH.value: 'high',
        ChangeType.PATTERN_UNMATCHED.value: 'low',
        ChangeType.HOST_GONE.value: 'info',
        ChangeType.HOST_RETURNED.value: 'medium',
        ChangeType.FAVICON_CHANGED.value: 'low',
        ChangeType.HTTP_CHANGED.value: 'info',
    }

    def __init__(self, db_url: Optional[str] = None):
        """Initialize with database connection."""
        self.engine = get_engine(db_url)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        
        # Ensure temporal tables exist
        init_temporal_tables(self.engine)
    
    def process_scan_results(
        self,
        hosts_data: List[Dict[str, Any]],
        pattern_matches: Dict[str, List[str]],  # pattern_name -> list of IPs
        scan_job: Optional[ScanJob] = None
    ) -> ScanSummary:
        """
        Process scan results and track temporal changes.
        
        Args:
            hosts_data: List of host dicts from scanner
            pattern_matches: Mapping of pattern names to matched IPs
            scan_job: Optional ScanJob record
            
        Returns:
            ScanSummary with delta statistics
        """
        scan_time = datetime.utcnow()
        scan_id = scan_job.id if scan_job else None
        
        # Track stats
        stats = {
            'new': 0,
            'changed': 0,
            'active': 0,
            'returned': 0,
            'new_matches': 0,
        }
        
        seen_ips = set()
        hosts_by_pattern = defaultdict(int)
        new_by_pattern = defaultdict(int)
        hosts_by_country = defaultdict(int)
        hosts_by_actor = defaultdict(int)
        new_by_actor = defaultdict(int)
        
        # Load pattern lookup
        patterns = {p.name: p for p in self.session.query(Pattern).filter_by(enabled=True).all()}
        
        # Process each host
        for host_data in hosts_data:
            ip = host_data.get('ip')
            if not ip:
                continue
                
            seen_ips.add(ip)
            
            # Get or create host
            host = self.session.query(Host).filter_by(ip=ip).first()
            is_new = host is None
            was_gone = host and host.gone_since is not None if hasattr(host, 'gone_since') else False
            
            if is_new:
                # New host
                host = self._create_host(host_data, scan_time)
                self.session.add(host)
                self.session.flush()  # Get ID
                
                self._record_change(
                    host, ChangeType.FIRST_SEEN, scan_id,
                    details={'source': host_data.get('source', 'unknown')}
                )
                stats['new'] += 1
                
            else:
                # Existing host - check for changes
                changes = self._detect_changes(host, host_data)
                
                if was_gone:
                    # Host returned
                    self._record_change(
                        host, ChangeType.HOST_RETURNED, scan_id,
                        details={'gone_since': str(host.gone_since)}
                    )
                    host.gone_since = None
                    stats['returned'] += 1
                    
                elif changes:
                    # Host changed
                    for change_type, old_val, new_val, field in changes:
                        self._record_change(
                            host, change_type, scan_id,
                            field_name=field,
                            old_value=str(old_val) if old_val else None,
                            new_value=str(new_val) if new_val else None
                        )
                    stats['changed'] += 1
                    host.change_count = (host.change_count or 0) + len(changes)
                    host.last_change_at = scan_time
                    
                else:
                    stats['active'] += 1
                
                # Update host fields
                self._update_host(host, host_data, scan_time)
            
            # Record history snapshot
            self._record_snapshot(host, scan_id, host_data)
            
            # Track pattern matches
            host_patterns = []
            for pattern_name, matched_ips in pattern_matches.items():
                if ip in matched_ips and pattern_name in patterns:
                    pattern = patterns[pattern_name]
                    host_patterns.append(pattern.id)
                    hosts_by_pattern[pattern_name] += 1
                    
                    if is_new:
                        new_by_pattern[pattern_name] += 1
                    
                    if pattern.actor:
                        hosts_by_actor[pattern.actor.name] += 1
                        if is_new:
                            new_by_actor[pattern.actor.name] += 1
                    
                    # Check if this is a new match for existing host
                    if not is_new:
                        existing_match = self.session.query(Match).filter_by(
                            host_id=host.id, pattern_id=pattern.id
                        ).first()
                        
                        if not existing_match:
                            # New pattern match for existing host
                            match = Match(
                                host_id=host.id,
                                pattern_id=pattern.id,
                                matched_at=scan_time,
                                status='new'
                            )
                            self.session.add(match)
                            
                            self._record_change(
                                host, ChangeType.NEW_PATTERN_MATCH, scan_id,
                                pattern_id=pattern.id,
                                details={'pattern_name': pattern_name}
                            )
                            stats['new_matches'] += 1
            
            # Track by country
            country = host_data.get('country') or host.country
            if country:
                hosts_by_country[country] += 1
        
        # Find hosts that went GONE
        gone_threshold = scan_time - timedelta(hours=self.GONE_THRESHOLD_HOURS)
        gone_hosts = self.session.query(Host).filter(
            Host.last_seen < gone_threshold,
            Host.gone_since.is_(None) if hasattr(Host, 'gone_since') else True
        ).all()
        
        for host in gone_hosts:
            if host.ip not in seen_ips:
                host.gone_since = scan_time
                host.status = 'gone'
                self._record_change(
                    host, ChangeType.HOST_GONE, scan_id,
                    details={'last_seen': str(host.last_seen)}
                )
        
        # Create scan summary
        summary = ScanSummary(
            scan_id=scan_id,
            scanned_at=scan_time,
            total_hosts=len(seen_ips),
            new_hosts=stats['new'],
            changed_hosts=stats['changed'],
            gone_hosts=len(gone_hosts),
            returned_hosts=stats['returned'],
            total_matches=sum(hosts_by_pattern.values()),
            new_matches=stats['new_matches'],
            hosts_by_pattern=dict(hosts_by_pattern),
            new_by_pattern=dict(new_by_pattern),
            hosts_by_actor=dict(hosts_by_actor),
            new_by_actor=dict(new_by_actor),
            hosts_by_country=dict(hosts_by_country),
        )
        self.session.add(summary)
        
        # Generate alerts for significant changes
        self._generate_alerts(summary, stats, new_by_pattern, new_by_actor)
        
        self.session.commit()
        return summary
    
    def _create_host(self, data: Dict, scan_time: datetime) -> Host:
        """Create a new Host record from scan data."""
        return Host(
            ip=data['ip'],
            asn=data.get('asn'),
            asn_name=data.get('asn_name'),
            country=data.get('country'),
            city=data.get('city'),
            jarm=data.get('jarm'),
            cert_fingerprint=data.get('cert_fingerprint'),
            cert_subject=data.get('cert_subject'),
            cert_issuer=data.get('cert_issuer'),
            http_status=data.get('http_status'),
            http_server=data.get('http_server'),
            http_headers=data.get('http_headers'),
            ports=data.get('ports', []),
            services=data.get('services', []),
            hostnames=data.get('hostnames', []),
            first_seen=scan_time,
            last_seen=scan_time,
            scan_count=1,
            status='new',
            favicon_hash=data.get('favicon_hash'),
            html_title=data.get('html_title'),
        )
    
    def _update_host(self, host: Host, data: Dict, scan_time: datetime):
        """Update existing host with new scan data."""
        host.last_seen = scan_time
        host.scan_count = (host.scan_count or 0) + 1
        
        # Update fields that may have changed
        for field in ['asn', 'asn_name', 'country', 'city', 'jarm', 
                      'cert_fingerprint', 'cert_subject', 'cert_issuer',
                      'http_status', 'http_server', 'http_headers',
                      'ports', 'services', 'hostnames']:
            if field in data and data[field] is not None:
                setattr(host, field, data[field])
        
        # Update extended fields if they exist
        if hasattr(host, 'favicon_hash') and 'favicon_hash' in data:
            host.favicon_hash = data['favicon_hash']
        if hasattr(host, 'html_title') and 'html_title' in data:
            host.html_title = data['html_title']
        
        # Clear gone status
        if hasattr(host, 'gone_since'):
            host.gone_since = None
        if hasattr(host, 'status'):
            host.status = 'active'
    
    def _detect_changes(self, host: Host, data: Dict) -> List[Tuple]:
        """
        Detect changes between existing host and new data.
        Returns list of (ChangeType, old_value, new_value, field_name).
        """
        changes = []
        
        # Critical fields to track
        tracked_fields = [
            ('jarm', ChangeType.JARM_CHANGED),
            ('cert_fingerprint', ChangeType.CERT_CHANGED),
        ]
        
        for field, change_type in tracked_fields:
            old_val = getattr(host, field, None)
            new_val = data.get(field)
            
            if new_val and old_val and new_val != old_val:
                changes.append((change_type, old_val, new_val, field))
        
        # Port changes
        old_ports = set(host.ports or [])
        new_ports = set(data.get('ports', []))
        if new_ports and old_ports != new_ports:
            changes.append((
                ChangeType.PORTS_CHANGED,
                sorted(old_ports),
                sorted(new_ports),
                'ports'
            ))
        
        # Favicon changes
        if hasattr(host, 'favicon_hash'):
            old_favicon = host.favicon_hash
            new_favicon = data.get('favicon_hash')
            if new_favicon and old_favicon and new_favicon != old_favicon:
                changes.append((
                    ChangeType.FAVICON_CHANGED,
                    old_favicon,
                    new_favicon,
                    'favicon_hash'
                ))
        
        return changes
    
    def _record_change(
        self,
        host: Host,
        change_type: ChangeType,
        scan_id: Optional[int],
        field_name: Optional[str] = None,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        pattern_id: Optional[int] = None,
        details: Optional[Dict] = None
    ):
        """Record a host change event."""
        change = HostChange(
            host_id=host.id,
            scan_id=scan_id,
            change_type=change_type.value if isinstance(change_type, ChangeType) else change_type,
            changed_at=datetime.utcnow(),
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            pattern_id=pattern_id,
            details=details,
            severity=self.CHANGE_SEVERITY.get(
                change_type.value if isinstance(change_type, ChangeType) else change_type,
                'info'
            )
        )
        self.session.add(change)
    
    def _record_snapshot(self, host: Host, scan_id: Optional[int], data: Dict):
        """Record a historical snapshot of host state."""
        # Get current pattern matches
        pattern_ids = [m.pattern_id for m in host.matches] if host.matches else []
        
        snapshot = HostHistory(
            host_id=host.id,
            scan_id=scan_id,
            snapshot_at=datetime.utcnow(),
            jarm=host.jarm,
            cert_fingerprint=host.cert_fingerprint,
            cert_subject=host.cert_subject,
            cert_issuer=host.cert_issuer,
            http_status=host.http_status,
            http_server=host.http_server,
            favicon_hash=getattr(host, 'favicon_hash', None),
            html_title=getattr(host, 'html_title', None),
            ports=host.ports,
            services=host.services,
            asn=host.asn,
            asn_name=host.asn_name,
            pattern_ids=pattern_ids,
            raw_data=data.get('raw_data'),
        )
        self.session.add(snapshot)
    
    def _generate_alerts(
        self,
        summary: ScanSummary,
        stats: Dict,
        new_by_pattern: Dict[str, int],
        new_by_actor: Dict[str, int]
    ):
        """Generate alerts for significant findings."""
        alerts = []
        
        # Alert: Many new hosts
        if stats['new'] >= 10:
            alerts.append(Alert(
                alert_type='new_host_surge',
                severity='high' if stats['new'] >= 50 else 'medium',
                title=f"🚨 {stats['new']} new hosts detected",
                description=f"Scan detected {stats['new']} new hosts matching tracked patterns.",
                scan_id=summary.scan_id,
                data={'new_count': stats['new'], 'by_pattern': dict(new_by_pattern)},
            ))
        
        # Alert: New hosts for specific high-value patterns
        for pattern_name, count in new_by_pattern.items():
            if count >= 5:
                alerts.append(Alert(
                    alert_type='pattern_spike',
                    severity='high',
                    title=f"📈 {count} new hosts for {pattern_name}",
                    description=f"Pattern '{pattern_name}' matched {count} new hosts.",
                    scan_id=summary.scan_id,
                    data={'pattern': pattern_name, 'new_count': count},
                ))
        
        # Alert: Actor infrastructure growth
        for actor_name, count in new_by_actor.items():
            if count >= 3:
                alerts.append(Alert(
                    alert_type='actor_growth',
                    severity='high',
                    title=f"🎭 {actor_name} infrastructure grew by {count}",
                    description=f"Threat actor '{actor_name}' has {count} new hosts.",
                    scan_id=summary.scan_id,
                    data={'actor': actor_name, 'new_count': count},
                ))
        
        for alert in alerts:
            self.session.add(alert)
    
    def get_trends(self, days: int = 30) -> Dict:
        """Get trend data for the dashboard."""
        since = datetime.utcnow() - timedelta(days=days)
        
        summaries = self.session.query(ScanSummary).filter(
            ScanSummary.scanned_at >= since
        ).order_by(ScanSummary.scanned_at).all()
        
        return {
            'dates': [s.scanned_at.isoformat() for s in summaries],
            'total_hosts': [s.total_hosts for s in summaries],
            'new_hosts': [s.new_hosts for s in summaries],
            'changed_hosts': [s.changed_hosts for s in summaries],
            'gone_hosts': [s.gone_hosts for s in summaries],
        }
    
    def get_recent_alerts(self, limit: int = 20) -> List[Alert]:
        """Get recent unacknowledged alerts."""
        return self.session.query(Alert).filter(
            Alert.status == 'new'
        ).order_by(Alert.created_at.desc()).limit(limit).all()
    
    def get_host_timeline(self, host_id: int, limit: int = 50) -> List[HostChange]:
        """Get change timeline for a specific host."""
        return self.session.query(HostChange).filter(
            HostChange.host_id == host_id
        ).order_by(HostChange.changed_at.desc()).limit(limit).all()
    
    def get_delta_report(self, since_hours: int = 24) -> Dict:
        """
        Get a delta report showing what changed recently.
        Perfect for daily briefings.
        """
        since = datetime.utcnow() - timedelta(hours=since_hours)
        
        # New hosts
        new_hosts = self.session.query(Host).filter(
            Host.first_seen >= since
        ).all()
        
        # Recent changes (excluding first_seen)
        changes = self.session.query(HostChange).filter(
            HostChange.changed_at >= since,
            HostChange.change_type != ChangeType.FIRST_SEEN.value
        ).order_by(HostChange.changed_at.desc()).all()
        
        # Hosts that went dark
        gone_hosts = self.session.query(Host).filter(
            Host.gone_since >= since if hasattr(Host, 'gone_since') else False
        ).all()
        
        # Pattern breakdown for new hosts
        new_by_pattern = defaultdict(list)
        for host in new_hosts:
            for match in host.matches:
                new_by_pattern[match.pattern.name].append(host.ip)
        
        return {
            'period_hours': since_hours,
            'since': since.isoformat(),
            'summary': {
                'new_hosts': len(new_hosts),
                'changes': len(changes),
                'gone_hosts': len(gone_hosts),
            },
            'new_hosts': [
                {
                    'ip': h.ip,
                    'country': h.country,
                    'asn_name': h.asn_name,
                    'patterns': [m.pattern.name for m in h.matches],
                    'first_seen': h.first_seen.isoformat(),
                }
                for h in new_hosts[:50]
            ],
            'new_by_pattern': {k: v for k, v in new_by_pattern.items()},
            'significant_changes': [
                {
                    'host_ip': self.session.query(Host).get(c.host_id).ip,
                    'change_type': c.change_type,
                    'field': c.field_name,
                    'old': c.old_value[:100] if c.old_value else None,
                    'new': c.new_value[:100] if c.new_value else None,
                    'when': c.changed_at.isoformat(),
                }
                for c in changes[:30]
            ],
            'gone_hosts': [
                {'ip': h.ip, 'last_seen': h.last_seen.isoformat()}
                for h in gone_hosts[:20]
            ],
        }


def main():
    """CLI for temporal scanner testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Temporal Scanner CLI')
    parser.add_argument('command', choices=['init', 'trends', 'delta', 'alerts'])
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--hours', type=int, default=24)
    parser.add_argument('--db', default='sqlite:///infra_hunter.db')
    
    args = parser.parse_args()
    
    scanner = TemporalScanner(args.db)
    
    if args.command == 'init':
        print("Temporal tables initialized.")
        
    elif args.command == 'trends':
        trends = scanner.get_trends(args.days)
        print(json.dumps(trends, indent=2))
        
    elif args.command == 'delta':
        report = scanner.get_delta_report(args.hours)
        print(json.dumps(report, indent=2))
        
    elif args.command == 'alerts':
        alerts = scanner.get_recent_alerts()
        for a in alerts:
            print(f"[{a.severity}] {a.title}")
            print(f"  {a.description}")
            print()


if __name__ == '__main__':
    main()
