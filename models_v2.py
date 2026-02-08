"""
Extended database models for Infrastructure Hunter v2.
Adds scan results, alerts, and data source tracking.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    Boolean, ForeignKey, JSON, Float, Index, UniqueConstraint, Enum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import os
import enum

# Import existing models
from models import Base, Actor, Pattern, Host, Match, ScanJob, get_engine, get_session

# Alert Severity Levels
class AlertSeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# Data Sources
class DataSource(enum.Enum):
    SHODAN = "shodan"
    CENSYS = "censys"
    GREYNOISE = "greynoise"
    DIY_SCAN = "diy_scan"
    ABUSE_CH = "abuse_ch"
    MANUAL = "manual"


class ScanResult(Base):
    """Individual scan result from any data source."""
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True)
    
    # Source info
    data_source = Column(String(50), nullable=False)  # shodan, censys, diy_scan, etc.
    scan_date = Column(DateTime, default=datetime.utcnow)
    query_used = Column(Text)
    signature_id = Column(String(100))  # Reference to our signature ID
    
    # Target info
    ip = Column(String(45), nullable=False)
    port = Column(Integer)
    
    # Location
    country = Column(String(100))
    country_code = Column(String(10))
    city = Column(String(255))
    asn = Column(Integer)
    asn_name = Column(String(255))
    org = Column(String(255))
    
    # Fingerprints
    jarm = Column(String(62))
    ssl_cert_sha256 = Column(String(64))
    ssl_cert_issuer = Column(Text)
    ssl_cert_subject = Column(Text)
    ssl_cert_serial = Column(String(100))
    http_title = Column(String(500))
    http_server = Column(String(255))
    http_status = Column(Integer)
    
    # Classification
    threat_type = Column(String(100))  # cobalt_strike, asyncrat, phishing, etc.
    confidence = Column(String(20), default='medium')
    severity = Column(String(20), default='high')
    
    # Tags
    tags = Column(JSON, default=list)  # e.g., ["self-signed", "cloud", "eol-product"]
    
    # Raw data
    raw_data = Column(JSON)
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_scan_result_ip', 'ip'),
        Index('idx_scan_result_source', 'data_source'),
        Index('idx_scan_result_threat', 'threat_type'),
        Index('idx_scan_result_country', 'country_code'),
        Index('idx_scan_result_date', 'scan_date'),
        Index('idx_scan_result_jarm', 'jarm'),
    )


class Alert(Base):
    """Alerts for anomalies, clusters, and notable findings."""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    
    # Alert info
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default='medium')  # critical, high, medium, low, info
    alert_type = Column(String(50), nullable=False)  # cluster, anomaly, threshold, new_actor
    
    # Related data
    query = Column(Text)  # Query that generated this
    affected_count = Column(Integer, default=0)
    affected_countries = Column(JSON, default=list)
    sample_ips = Column(JSON, default=list)
    
    # Threat context
    threat_type = Column(String(100))
    related_signature = Column(String(100))
    
    # Evidence
    evidence = Column(JSON)  # Supporting data
    
    # Status
    status = Column(String(20), default='new')  # new, acknowledged, investigating, resolved, false_positive
    assigned_to = Column(String(255))
    notes = Column(Text)
    
    # Tracking
    triggered_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    __table_args__ = (
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_status', 'status'),
        Index('idx_alert_type', 'alert_type'),
        Index('idx_alert_date', 'triggered_at'),
    )


class DataSourceConfig(Base):
    """Configuration for data sources (API keys, limits, etc.)."""
    __tablename__ = 'data_source_configs'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    enabled = Column(Boolean, default=True)
    
    # API config (encrypted in production)
    api_key = Column(String(500))
    api_endpoint = Column(String(500))
    
    # Rate limiting
    rate_limit_per_day = Column(Integer)
    rate_limit_per_minute = Column(Integer)
    current_daily_usage = Column(Integer, default=0)
    usage_reset_at = Column(DateTime)
    
    # Last sync
    last_sync_at = Column(DateTime)
    last_sync_status = Column(String(50))
    last_sync_results = Column(Integer)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SearchQuery(Base):
    """Saved search queries for quick access."""
    __tablename__ = 'search_queries'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Query definition
    query_type = Column(String(50))  # shodan, censys, local
    query_string = Column(Text, nullable=False)
    
    # Schedule (for automated runs)
    schedule_enabled = Column(Boolean, default=False)
    schedule_cron = Column(String(100))  # e.g., "0 6 * * *"
    
    # Results
    last_run_at = Column(DateTime)
    last_result_count = Column(Integer)
    
    # Alert thresholds
    alert_on_new = Column(Boolean, default=True)
    alert_threshold = Column(Integer)  # Alert if count exceeds this
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def init_v2_tables(engine=None):
    """Initialize new v2 tables."""
    if engine is None:
        engine = get_engine()
    
    # Create only the new tables
    ScanResult.__table__.create(engine, checkfirst=True)
    Alert.__table__.create(engine, checkfirst=True)
    DataSourceConfig.__table__.create(engine, checkfirst=True)
    SearchQuery.__table__.create(engine, checkfirst=True)
    
    return engine
