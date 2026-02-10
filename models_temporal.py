"""
Temporal tracking models for Infrastructure Hunter.
Adds historical tracking, delta detection, and trend analysis.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    Boolean, ForeignKey, JSON, Float, Index, Enum, func
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import enum

# Import base from existing models
from models import Base, Host, Pattern, Match, ScanJob


class HostStatus(enum.Enum):
    """Host lifecycle status."""
    NEW = "new"           # First seen this scan
    ACTIVE = "active"     # Seen again, no significant changes
    CHANGED = "changed"   # Seen again, with changes
    GONE = "gone"         # Not seen in recent scans
    RETURNED = "returned" # Was gone, now back


class ChangeType(enum.Enum):
    """Types of changes we track."""
    FIRST_SEEN = "first_seen"
    CERT_CHANGED = "cert_changed"
    JARM_CHANGED = "jarm_changed"
    PORTS_CHANGED = "ports_changed"
    NEW_PATTERN_MATCH = "new_pattern_match"
    PATTERN_UNMATCHED = "pattern_unmatched"
    HOST_GONE = "host_gone"
    HOST_RETURNED = "host_returned"
    FAVICON_CHANGED = "favicon_changed"
    HTTP_CHANGED = "http_changed"


class HostHistory(Base):
    """
    Historical snapshots of host state.
    Captures point-in-time data for trend analysis.
    """
    __tablename__ = 'host_history'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    scan_id = Column(Integer, ForeignKey('scan_jobs.id'), nullable=True)
    
    # Snapshot of key fields at this point in time
    snapshot_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # TLS/Cert state
    jarm = Column(String(62))
    cert_fingerprint = Column(String(64))
    cert_subject = Column(Text)
    cert_issuer = Column(Text)
    cert_not_after = Column(DateTime)
    
    # HTTP state
    http_status = Column(Integer)
    http_server = Column(String(255))
    favicon_hash = Column(String(32))  # mmh3 hash
    html_title = Column(String(500))
    body_hash = Column(String(64))
    
    # Network state
    ports = Column(JSON)
    services = Column(JSON)
    asn = Column(Integer)
    asn_name = Column(String(255))
    
    # Pattern matches at this snapshot
    pattern_ids = Column(JSON, default=list)  # List of matched pattern IDs
    
    # Raw source data
    raw_data = Column(JSON)

    __table_args__ = (
        Index('idx_history_host', 'host_id'),
        Index('idx_history_date', 'snapshot_at'),
        Index('idx_history_scan', 'scan_id'),
    )


class HostChange(Base):
    """
    Individual change events for a host.
    Enables timeline view and change alerting.
    """
    __tablename__ = 'host_changes'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    scan_id = Column(Integer, ForeignKey('scan_jobs.id'), nullable=True)
    
    change_type = Column(String(50), nullable=False)  # From ChangeType enum
    changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # What changed
    field_name = Column(String(100))  # e.g., 'jarm', 'cert_fingerprint'
    old_value = Column(Text)
    new_value = Column(Text)
    
    # Context
    pattern_id = Column(Integer, ForeignKey('patterns.id'), nullable=True)
    details = Column(JSON)  # Additional context
    
    # For alerting
    severity = Column(String(20), default='info')  # info, low, medium, high, critical
    alerted = Column(Boolean, default=False)
    alerted_at = Column(DateTime)

    __table_args__ = (
        Index('idx_change_host', 'host_id'),
        Index('idx_change_date', 'changed_at'),
        Index('idx_change_type', 'change_type'),
        Index('idx_change_severity', 'severity'),
        Index('idx_change_alerted', 'alerted'),
    )


class ScanSummary(Base):
    """
    Summary statistics for each scan run.
    Enables trend dashboards and alerting.
    """
    __tablename__ = 'scan_summaries'

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_jobs.id'), nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Counts
    total_hosts = Column(Integer, default=0)
    new_hosts = Column(Integer, default=0)
    changed_hosts = Column(Integer, default=0)
    gone_hosts = Column(Integer, default=0)
    returned_hosts = Column(Integer, default=0)
    
    # Pattern stats
    total_matches = Column(Integer, default=0)
    new_matches = Column(Integer, default=0)
    
    # By pattern breakdown (pattern_id -> count)
    hosts_by_pattern = Column(JSON, default=dict)
    new_by_pattern = Column(JSON, default=dict)
    
    # By actor breakdown
    hosts_by_actor = Column(JSON, default=dict)
    new_by_actor = Column(JSON, default=dict)
    
    # By country
    hosts_by_country = Column(JSON, default=dict)
    
    # By ASN (top 20)
    top_asns = Column(JSON, default=list)
    
    # Scan metadata
    duration_seconds = Column(Integer)
    patterns_scanned = Column(Integer)
    api_calls = Column(Integer)
    errors = Column(JSON, default=list)

    __table_args__ = (
        Index('idx_summary_date', 'scanned_at'),
    )


class Alert(Base):
    """
    Alerts generated from significant changes.
    """
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    
    alert_type = Column(String(50), nullable=False)  # new_hosts, pattern_spike, etc.
    severity = Column(String(20), default='info')
    
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Related entities
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=True)
    pattern_id = Column(Integer, ForeignKey('patterns.id'), nullable=True)
    scan_id = Column(Integer, ForeignKey('scan_jobs.id'), nullable=True)
    
    # Alert data
    data = Column(JSON)  # Flexible payload
    
    # Status
    status = Column(String(20), default='new')  # new, acknowledged, resolved
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Delivery
    delivered_to = Column(JSON, default=list)  # channels notified

    __table_args__ = (
        Index('idx_alert_status', 'status'),
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_date', 'created_at'),
    )


# Extend Host model with new fields
def upgrade_host_model():
    """
    Additional columns to add to hosts table.
    Run via ALTER TABLE or migration.
    """
    return """
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS favicon_hash VARCHAR(32);
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS html_title VARCHAR(500);
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS gone_since TIMESTAMP;
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS change_count INTEGER DEFAULT 0;
    ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_change_at TIMESTAMP;
    
    CREATE INDEX IF NOT EXISTS idx_host_status ON hosts(status);
    CREATE INDEX IF NOT EXISTS idx_host_favicon ON hosts(favicon_hash);
    CREATE INDEX IF NOT EXISTS idx_host_gone_since ON hosts(gone_since);
    """


def init_temporal_tables(engine):
    """Create the new temporal tracking tables."""
    # Create new tables
    HostHistory.__table__.create(engine, checkfirst=True)
    HostChange.__table__.create(engine, checkfirst=True)
    ScanSummary.__table__.create(engine, checkfirst=True)
    Alert.__table__.create(engine, checkfirst=True)
    
    # Upgrade hosts table with new columns
    with engine.connect() as conn:
        for stmt in upgrade_host_model().split(';'):
            stmt = stmt.strip()
            if stmt:
                try:
                    conn.execute(stmt)
                except Exception as e:
                    print(f"Migration warning: {e}")
        conn.commit()
