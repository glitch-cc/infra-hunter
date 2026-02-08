#!/usr/bin/env python3
"""
Infrastructure Hunter API - Search and query endpoints.
"""
import os
import sys
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import get_session, Pattern, Host, Match
from models_v2 import ScanResult, Alert

api = Blueprint('api', __name__, url_prefix='/api')


@api.route('/search')
def search():
    """
    Search scan results.
    
    Query params:
        q: Free text search (IP, country, org, threat_type)
        threat_type: Filter by threat type
        country: Filter by country code
        severity: Filter by severity
        source: Filter by data source
        days: Results from last N days
        limit: Max results (default 100)
    """
    session = get_session()
    
    q = request.args.get('q', '')
    threat_type = request.args.get('threat_type')
    country = request.args.get('country')
    severity = request.args.get('severity')
    source = request.args.get('source')
    days = request.args.get('days', type=int)
    limit = request.args.get('limit', 100, type=int)
    
    query = session.query(ScanResult)
    
    # Apply filters
    if q:
        query = query.filter(
            (ScanResult.ip.ilike(f'%{q}%')) |
            (ScanResult.country.ilike(f'%{q}%')) |
            (ScanResult.org.ilike(f'%{q}%')) |
            (ScanResult.threat_type.ilike(f'%{q}%')) |
            (ScanResult.jarm.ilike(f'%{q}%'))
        )
    
    if threat_type:
        query = query.filter(ScanResult.threat_type == threat_type)
    
    if country:
        query = query.filter(ScanResult.country_code == country.upper())
    
    if severity:
        query = query.filter(ScanResult.severity == severity)
    
    if source:
        query = query.filter(ScanResult.data_source == source)
    
    if days:
        since = datetime.utcnow() - timedelta(days=days)
        query = query.filter(ScanResult.scan_date >= since)
    
    # Execute
    results = query.order_by(ScanResult.scan_date.desc()).limit(limit).all()
    
    session.close()
    
    return jsonify({
        'count': len(results),
        'results': [{
            'id': r.id,
            'ip': r.ip,
            'port': r.port,
            'country': r.country,
            'country_code': r.country_code,
            'org': r.org,
            'asn': r.asn,
            'threat_type': r.threat_type,
            'severity': r.severity,
            'confidence': r.confidence,
            'jarm': r.jarm,
            'tags': r.tags,
            'data_source': r.data_source,
            'scan_date': r.scan_date.isoformat() if r.scan_date else None,
        } for r in results]
    })


@api.route('/alerts')
def get_alerts():
    """Get alerts with optional filters."""
    session = get_session()
    
    status = request.args.get('status')
    severity = request.args.get('severity')
    alert_type = request.args.get('type')
    days = request.args.get('days', type=int, default=30)
    
    query = session.query(Alert)
    
    if status:
        query = query.filter(Alert.status == status)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    
    since = datetime.utcnow() - timedelta(days=days)
    query = query.filter(Alert.triggered_at >= since)
    
    alerts = query.order_by(Alert.triggered_at.desc()).all()
    
    session.close()
    
    return jsonify({
        'count': len(alerts),
        'alerts': [{
            'id': a.id,
            'title': a.title,
            'description': a.description,
            'severity': a.severity,
            'alert_type': a.alert_type,
            'status': a.status,
            'affected_count': a.affected_count,
            'affected_countries': a.affected_countries,
            'sample_ips': a.sample_ips,
            'threat_type': a.threat_type,
            'triggered_at': a.triggered_at.isoformat() if a.triggered_at else None,
        } for a in alerts]
    })


@api.route('/alerts/<int:alert_id>', methods=['PATCH'])
def update_alert(alert_id):
    """Update alert status."""
    session = get_session()
    
    alert = session.query(Alert).get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    data = request.json or {}
    
    if 'status' in data:
        alert.status = data['status']
        if data['status'] == 'acknowledged':
            alert.acknowledged_at = datetime.utcnow()
        elif data['status'] == 'resolved':
            alert.resolved_at = datetime.utcnow()
    
    if 'notes' in data:
        alert.notes = data['notes']
    
    if 'assigned_to' in data:
        alert.assigned_to = data['assigned_to']
    
    session.commit()
    session.close()
    
    return jsonify({'success': True, 'alert_id': alert_id})


@api.route('/stats')
def get_stats():
    """Get dashboard statistics."""
    session = get_session()
    
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    
    # Scan results stats
    total_results = session.query(ScanResult).count()
    results_24h = session.query(ScanResult).filter(ScanResult.scan_date >= day_ago).count()
    results_7d = session.query(ScanResult).filter(ScanResult.scan_date >= week_ago).count()
    
    # Threat type breakdown
    from sqlalchemy import func
    threat_counts = session.query(
        ScanResult.threat_type,
        func.count(ScanResult.id)
    ).group_by(ScanResult.threat_type).all()
    
    # Country breakdown
    country_counts = session.query(
        ScanResult.country_code,
        func.count(ScanResult.id)
    ).group_by(ScanResult.country_code).order_by(func.count(ScanResult.id).desc()).limit(10).all()
    
    # Alert stats
    total_alerts = session.query(Alert).count()
    new_alerts = session.query(Alert).filter(Alert.status == 'new').count()
    critical_alerts = session.query(Alert).filter(Alert.severity == 'critical', Alert.status == 'new').count()
    
    session.close()
    
    return jsonify({
        'scan_results': {
            'total': total_results,
            'last_24h': results_24h,
            'last_7d': results_7d,
        },
        'threats': dict(threat_counts),
        'countries': dict(country_counts),
        'alerts': {
            'total': total_alerts,
            'new': new_alerts,
            'critical': critical_alerts,
        },
    })


@api.route('/export')
def export_results():
    """Export results as JSON or CSV."""
    session = get_session()
    
    format = request.args.get('format', 'json')
    threat_type = request.args.get('threat_type')
    days = request.args.get('days', type=int, default=7)
    
    query = session.query(ScanResult)
    
    if threat_type:
        query = query.filter(ScanResult.threat_type == threat_type)
    
    since = datetime.utcnow() - timedelta(days=days)
    query = query.filter(ScanResult.scan_date >= since)
    
    results = query.all()
    
    session.close()
    
    if format == 'csv':
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ip', 'port', 'country', 'org', 'threat_type', 'severity', 'jarm', 'scan_date'])
        for r in results:
            writer.writerow([r.ip, r.port, r.country, r.org, r.threat_type, r.severity, r.jarm, r.scan_date])
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=infrastructure_hunter_export.csv'}
        )
    
    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'count': len(results),
        'results': [{
            'ip': r.ip,
            'port': r.port,
            'country': r.country,
            'country_code': r.country_code,
            'org': r.org,
            'threat_type': r.threat_type,
            'severity': r.severity,
            'jarm': r.jarm,
            'scan_date': r.scan_date.isoformat() if r.scan_date else None,
        } for r in results]
    })


@api.route('/signatures')
def get_signatures():
    """Get available signatures from YAML files."""
    import yaml
    from pathlib import Path
    
    sig_dir = Path(__file__).parent / 'signatures' / 'library'
    signatures = []
    
    for category_dir in sig_dir.iterdir():
        if category_dir.is_dir():
            for sig_file in category_dir.glob('*.yaml'):
                try:
                    with open(sig_file) as f:
                        sig = yaml.safe_load(f)
                        if sig and 'signature' in sig:
                            s = sig['signature']
                            signatures.append({
                                'id': s.get('id'),
                                'name': s.get('name'),
                                'category': s.get('category'),
                                'description': s.get('description'),
                                'enabled': s.get('enabled', True),
                                'severity': s.get('metadata', {}).get('severity'),
                                'queries': s.get('queries', {}),
                            })
                except Exception as e:
                    print(f"Error loading {sig_file}: {e}")
    
    return jsonify({
        'count': len(signatures),
        'signatures': signatures
    })
