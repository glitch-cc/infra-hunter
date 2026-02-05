"""
Database models for Infrastructure Pattern Intelligence.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    Boolean, ForeignKey, JSON, Float, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import os

Base = declarative_base()

# Pattern Types
PATTERN_TYPES = [
    'cert_subject_dn',    # Certificate Subject DN pattern
    'cert_issuer_dn',     # Certificate Issuer DN pattern
    'cert_fingerprint',   # Certificate SHA256 fingerprint
    'jarm',               # JARM TLS fingerprint
    'http_headers',       # HTTP header combination pattern
    'http_body_hash',     # HTTP response body hash
    'asn',                # Autonomous System Number
    'hosting_provider',   # Hosting provider name
    'port_combo',         # Port combination pattern
    'whois_pattern',      # WHOIS field pattern
    'domain_regex',       # Domain naming pattern (regex)
    'composite',          # Multiple patterns combined
]


class Actor(Base):
    """Threat actor or campaign for attribution."""
    __tablename__ = 'actors'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    aliases = Column(JSON, default=list)  # Alternative names
    description = Column(Text)
    country = Column(String(10))  # ISO country code if known
    active = Column(Boolean, default=True)
    confidence = Column(String(20), default='unknown')  # high, medium, low, unknown
    references = Column(JSON, default=list)  # Source URLs
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    patterns = relationship('Pattern', back_populates='actor')


class Pattern(Base):
    """Infrastructure pattern definition."""
    __tablename__ = 'patterns'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    pattern_type = Column(String(50), nullable=False)  # From PATTERN_TYPES
    
    # Pattern definition (structure depends on type)
    definition = Column(JSON, nullable=False)
    
    # Censys query (auto-generated or manual)
    censys_query = Column(Text)
    
    # Attribution
    actor_id = Column(Integer, ForeignKey('actors.id'), nullable=True)
    actor = relationship('Actor', back_populates='patterns')
    
    # Metadata
    description = Column(Text)
    confidence = Column(String(20), default='medium')  # high, medium, low
    enabled = Column(Boolean, default=True)
    source = Column(String(255))  # Where we learned this pattern
    references = Column(JSON, default=list)
    
    # Stats
    total_matches = Column(Integer, default=0)
    last_match_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    matches = relationship('Match', back_populates='pattern')

    __table_args__ = (
        Index('idx_pattern_type', 'pattern_type'),
        Index('idx_pattern_actor', 'actor_id'),
        Index('idx_pattern_enabled', 'enabled'),
    )


class Host(Base):
    """Discovered host/infrastructure."""
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False)  # IPv4 or IPv6
    
    # Host details
    asn = Column(Integer)
    asn_name = Column(String(255))
    country = Column(String(10))
    city = Column(String(255))
    
    # Certificate data (if applicable)
    cert_subject = Column(Text)
    cert_issuer = Column(Text)
    cert_fingerprint = Column(String(64))  # SHA256
    cert_not_before = Column(DateTime)
    cert_not_after = Column(DateTime)
    cert_self_signed = Column(Boolean)
    
    # JARM fingerprint
    jarm = Column(String(62))
    
    # HTTP response data
    http_status = Column(Integer)
    http_headers = Column(JSON)
    http_body_hash = Column(String(64))  # SHA256 of body
    http_server = Column(String(255))
    
    # Services/ports
    ports = Column(JSON, default=list)
    services = Column(JSON, default=list)
    
    # Hostnames
    hostnames = Column(JSON, default=list)
    
    # Raw data from sources
    censys_data = Column(JSON)
    
    # Tracking
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime)
    scan_count = Column(Integer, default=1)
    
    matches = relationship('Match', back_populates='host')

    __table_args__ = (
        Index('idx_host_ip', 'ip'),
        Index('idx_host_jarm', 'jarm'),
        Index('idx_host_asn', 'asn'),
        Index('idx_host_cert_fingerprint', 'cert_fingerprint'),
        Index('idx_host_first_seen', 'first_seen'),
    )


class Match(Base):
    """Pattern match record."""
    __tablename__ = 'matches'

    id = Column(Integer, primary_key=True)
    pattern_id = Column(Integer, ForeignKey('patterns.id'), nullable=False)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    
    # Match details
    match_score = Column(Float, default=1.0)  # For fuzzy matching
    match_details = Column(JSON)  # What specifically matched
    
    # Status
    status = Column(String(20), default='new')  # new, reviewed, confirmed, false_positive
    notes = Column(Text)
    
    # Tracking
    matched_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)
    reviewed_by = Column(String(255))

    pattern = relationship('Pattern', back_populates='matches')
    host = relationship('Host', back_populates='matches')

    __table_args__ = (
        UniqueConstraint('pattern_id', 'host_id', name='uq_pattern_host'),
        Index('idx_match_pattern', 'pattern_id'),
        Index('idx_match_status', 'status'),
        Index('idx_match_date', 'matched_at'),
    )


class ScanJob(Base):
    """Track scanning jobs."""
    __tablename__ = 'scan_jobs'

    id = Column(Integer, primary_key=True)
    pattern_id = Column(Integer, ForeignKey('patterns.id'), nullable=True)
    
    # Job info
    job_type = Column(String(50), nullable=False)  # full_scan, pattern_scan, update
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    
    # Results
    hosts_found = Column(Integer, default=0)
    new_matches = Column(Integer, default=0)
    error_message = Column(Text)
    
    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Query used
    query = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)


def get_engine(db_url: Optional[str] = None):
    """Get SQLAlchemy engine."""
    if db_url is None:
        db_url = os.environ.get('INFRA_HUNTER_DB', 'postgresql://localhost/infra_hunter')
    return create_engine(db_url)


def get_session(engine=None):
    """Get a new database session."""
    if engine is None:
        engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()


def init_db(engine=None):
    """Initialize database tables."""
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(engine)
    return engine
