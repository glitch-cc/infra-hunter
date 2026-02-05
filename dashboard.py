#!/usr/bin/env python3
"""
Infrastructure Hunter Dashboard.
Web interface for viewing patterns, hosts, and matches.
"""
import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import get_engine, get_session, Actor, Pattern, Host, Match, ScanJob

app = Flask(__name__)

# HTML Template
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Infrastructure Hunter</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117; 
            color: #c9d1d9;
            line-height: 1.5;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 1.1em; text-transform: uppercase; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
        }
        .stat-value { font-size: 2em; font-weight: bold; color: #58a6ff; }
        .stat-label { color: #8b949e; font-size: 0.9em; }
        
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .card-header {
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
        }
        .card-body { padding: 16px; }
        
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #21262d; color: #8b949e; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }
        tr:hover { background: #21262d; }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .badge-new { background: #238636; color: white; }
        .badge-reviewed { background: #1f6feb; color: white; }
        .badge-confirmed { background: #8957e5; color: white; }
        .badge-false_positive { background: #da3633; color: white; }
        .badge-high { background: #238636; color: white; }
        .badge-medium { background: #d29922; color: black; }
        .badge-low { background: #8b949e; color: black; }
        
        .ip { font-family: monospace; color: #79c0ff; }
        .jarm { font-family: monospace; font-size: 0.8em; color: #8b949e; }
        
        .filters {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        .filters select, .filters input {
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 8px 12px;
            border-radius: 6px;
        }
        .filters button {
            background: #238636;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
        }
        .filters button:hover { background: #2ea043; }
        
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }
        .tab {
            padding: 8px 16px;
            background: transparent;
            border: none;
            color: #8b949e;
            cursor: pointer;
            border-radius: 6px;
        }
        .tab.active { background: #21262d; color: #58a6ff; }
        .tab:hover { color: #c9d1d9; }
        
        .hidden { display: none; }
        
        .actor-tag {
            background: #30363d;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }
        
        .empty { text-align: center; padding: 40px; color: #8b949e; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Infrastructure Hunter</h1>
        
        <nav style="display:flex;gap:20px;margin-bottom:20px;padding-bottom:10px;border-bottom:1px solid #30363d;">
            <a href="/" style="color:#58a6ff;font-weight:600;">Dashboard</a>
            <a href="/signatures" style="color:#8b949e;">Signatures</a>
            <a href="/signatures/create" style="color:#8b949e;">+ Create Signature</a>
        </nav>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.patterns }}</div>
                <div class="stat-label">Patterns ({{ stats.enabled_patterns }} enabled)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.hosts }}</div>
                <div class="stat-label">Hosts Tracked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.matches }}</div>
                <div class="stat-label">Total Matches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.new_matches }}</div>
                <div class="stat-label">New Matches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.recent_matches }}</div>
                <div class="stat-label">Last 24 Hours</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.actors }}</div>
                <div class="stat-label">Threat Actors</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('matches')">Recent Matches</button>
            <button class="tab" onclick="showTab('patterns')">Patterns</button>
            <button class="tab" onclick="showTab('hosts')">Hosts</button>
            <button class="tab" onclick="showTab('actors')">Actors</button>
        </div>
        
        <!-- Matches Tab -->
        <div id="matches-tab" class="tab-content">
            <div class="card">
                <div class="card-header">Recent Pattern Matches</div>
                <div class="card-body">
                    {% if matches %}
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Pattern</th>
                                <th>Actor</th>
                                <th>Country</th>
                                <th>Status</th>
                                <th>Matched</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for m in matches %}
                            <tr>
                                <td><span class="ip">{{ m.host.ip }}</span></td>
                                <td>{{ m.pattern.name }}</td>
                                <td>
                                    {% if m.pattern.actor %}
                                    <span class="actor-tag">{{ m.pattern.actor.name }}</span>
                                    {% else %}
                                    <span style="color: #8b949e">-</span>
                                    {% endif %}
                                </td>
                                <td>{{ m.host.country or '-' }}</td>
                                <td><span class="badge badge-{{ m.status }}">{{ m.status }}</span></td>
                                <td>{{ m.matched_at.strftime('%Y-%m-%d %H:%M') }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty">No matches found. Run a scan to detect infrastructure.</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Patterns Tab -->
        <div id="patterns-tab" class="tab-content hidden">
            <div class="card">
                <div class="card-header">Infrastructure Patterns</div>
                <div class="card-body">
                    {% if patterns %}
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Actor</th>
                                <th>Confidence</th>
                                <th>Matches</th>
                                <th>Last Match</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for p in patterns %}
                            <tr>
                                <td>{{ p.name }}</td>
                                <td>{{ p.pattern_type }}</td>
                                <td>
                                    {% if p.actor %}
                                    <span class="actor-tag">{{ p.actor.name }}</span>
                                    {% else %}
                                    <span style="color: #8b949e">-</span>
                                    {% endif %}
                                </td>
                                <td><span class="badge badge-{{ p.confidence }}">{{ p.confidence }}</span></td>
                                <td>{{ p.total_matches }}</td>
                                <td>{{ p.last_match_at.strftime('%Y-%m-%d') if p.last_match_at else 'Never' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty">No patterns defined. Initialize with --seed to add known patterns.</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Hosts Tab -->
        <div id="hosts-tab" class="tab-content hidden">
            <div class="card">
                <div class="card-header">Tracked Hosts (Recent)</div>
                <div class="card-body">
                    {% if hosts %}
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Country</th>
                                <th>ASN</th>
                                <th>JARM</th>
                                <th>Ports</th>
                                <th>First Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for h in hosts %}
                            <tr>
                                <td><span class="ip">{{ h.ip }}</span></td>
                                <td>{{ h.country or '-' }}</td>
                                <td>{{ h.asn_name[:25] + '...' if h.asn_name and h.asn_name|length > 25 else h.asn_name or '-' }}</td>
                                <td><span class="jarm">{{ h.jarm[:20] + '...' if h.jarm else '-' }}</span></td>
                                <td>{{ h.ports[:5]|join(', ') if h.ports else '-' }}</td>
                                <td>{{ h.first_seen.strftime('%Y-%m-%d') }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty">No hosts tracked yet. Run a scan to discover infrastructure.</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Actors Tab -->
        <div id="actors-tab" class="tab-content hidden">
            <div class="card">
                <div class="card-header">Threat Actors</div>
                <div class="card-body">
                    {% if actors %}
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Country</th>
                                <th>Aliases</th>
                                <th>Patterns</th>
                                <th>Confidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for a in actors %}
                            <tr>
                                <td><strong>{{ a.name }}</strong></td>
                                <td>{{ a.country or '-' }}</td>
                                <td>{{ a.aliases|join(', ') if a.aliases else '-' }}</td>
                                <td>{{ a.patterns|length }}</td>
                                <td><span class="badge badge-{{ a.confidence }}">{{ a.confidence }}</span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty">No threat actors defined.</div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(name) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(name + '-tab').classList.remove('hidden');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    """Main dashboard view."""
    db_url = os.environ.get('INFRA_HUNTER_DB', 'postgresql://localhost/infra_hunter')
    session = get_session(get_engine(db_url))
    
    try:
        # Stats
        last_24h = datetime.utcnow() - timedelta(hours=24)
        stats = {
            'actors': session.query(Actor).count(),
            'patterns': session.query(Pattern).count(),
            'enabled_patterns': session.query(Pattern).filter_by(enabled=True).count(),
            'hosts': session.query(Host).count(),
            'matches': session.query(Match).count(),
            'new_matches': session.query(Match).filter_by(status='new').count(),
            'recent_matches': session.query(Match).filter(Match.matched_at >= last_24h).count(),
        }
        
        # Recent matches
        matches = session.query(Match).order_by(Match.matched_at.desc()).limit(50).all()
        
        # Patterns
        patterns = session.query(Pattern).order_by(Pattern.total_matches.desc()).all()
        
        # Recent hosts
        hosts = session.query(Host).order_by(Host.first_seen.desc()).limit(50).all()
        
        # Actors
        actors = session.query(Actor).all()
        
        return render_template_string(
            TEMPLATE,
            stats=stats,
            matches=matches,
            patterns=patterns,
            hosts=hosts,
            actors=actors,
        )
    finally:
        session.close()


@app.route('/api/stats')
def api_stats():
    """API endpoint for stats."""
    db_url = os.environ.get('INFRA_HUNTER_DB', 'postgresql://localhost/infra_hunter')
    session = get_session(get_engine(db_url))
    
    try:
        last_24h = datetime.utcnow() - timedelta(hours=24)
        return jsonify({
            'actors': session.query(Actor).count(),
            'patterns': session.query(Pattern).count(),
            'hosts': session.query(Host).count(),
            'matches': session.query(Match).count(),
            'new_matches': session.query(Match).filter_by(status='new').count(),
            'recent_matches': session.query(Match).filter(Match.matched_at >= last_24h).count(),
        })
    finally:
        session.close()


@app.route('/api/matches')
def api_matches():
    """API endpoint for matches."""
    db_url = os.environ.get('INFRA_HUNTER_DB', 'postgresql://localhost/infra_hunter')
    session = get_session(get_engine(db_url))
    
    try:
        hours = int(request.args.get('hours', 72))
        since = datetime.utcnow() - timedelta(hours=hours)
        
        matches = session.query(Match).filter(Match.matched_at >= since).order_by(Match.matched_at.desc()).all()
        
        return jsonify([{
            'id': m.id,
            'ip': m.host.ip,
            'pattern': m.pattern.name,
            'actor': m.pattern.actor.name if m.pattern.actor else None,
            'country': m.host.country,
            'status': m.status,
            'matched_at': m.matched_at.isoformat(),
        } for m in matches])
    finally:
        session.close()


# =============================================================================
# SIGNATURE MANAGEMENT ROUTES
# =============================================================================

from signatures.manager import SignatureManager, Signature, Condition, CATEGORIES, CONFIDENCE_LEVELS, SEVERITY_LEVELS, CONDITION_TYPES

SIGNATURE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Signature Manager - Infrastructure Hunter</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117; 
            color: #c9d1d9;
            line-height: 1.5;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 1.1em; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        
        .nav { 
            display: flex; 
            gap: 20px; 
            margin-bottom: 20px; 
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }
        .nav a { color: #8b949e; }
        .nav a.active { color: #58a6ff; font-weight: 600; }
        
        .stats-row {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat { 
            background: #161b22; 
            padding: 15px 20px; 
            border-radius: 8px;
            border: 1px solid #30363d;
        }
        .stat-value { font-size: 1.5em; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 0.9em; color: #8b949e; }
        
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .card-header {
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-body { padding: 16px; }
        
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #21262d; color: #8b949e; font-weight: 600; font-size: 0.85em; }
        tr:hover { background: #21262d; }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .badge-high { background: #238636; }
        .badge-medium { background: #d29922; color: black; }
        .badge-low { background: #8b949e; color: black; }
        .badge-enabled { background: #238636; }
        .badge-disabled { background: #da3633; }
        .badge-critical { background: #da3633; }
        
        .btn {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 0.9em;
            text-decoration: none;
        }
        .btn-primary { background: #238636; color: white; }
        .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
        .btn-danger { background: #da3633; color: white; }
        .btn:hover { opacity: 0.9; }
        
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #8b949e; }
        .form-control {
            width: 100%;
            padding: 8px 12px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
        }
        .form-control:focus { border-color: #58a6ff; outline: none; }
        select.form-control { cursor: pointer; }
        textarea.form-control { min-height: 80px; resize: vertical; }
        
        .condition-card {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 10px;
        }
        .condition-header { 
            display: flex; 
            justify-content: space-between; 
            margin-bottom: 10px;
        }
        .condition-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }
        
        .mono { font-family: monospace; }
        .text-muted { color: #8b949e; }
        .text-small { font-size: 0.85em; }
        
        .filters {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        .filters select { 
            padding: 6px 10px; 
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Signature Manager</h1>
        <nav class="nav">
            <a href="/">← Dashboard</a>
            <a href="/signatures" class="active">Signatures</a>
            <a href="/signatures/create">+ Create New</a>
        </nav>
        
        {{ content | safe }}
    </div>
</body>
</html>
'''


@app.route('/signatures')
def signatures_list():
    """List all signatures."""
    mgr = SignatureManager()
    
    # Get filters
    category = request.args.get('category')
    confidence = request.args.get('confidence')
    
    sigs = mgr.list(category=category)
    if confidence:
        sigs = [s for s in sigs if s.confidence == confidence]
    
    stats = mgr.stats()
    
    rows = ""
    for sig in sigs:
        conf_class = f"badge-{sig.confidence}"
        status_class = "badge-enabled" if sig.enabled else "badge-disabled"
        rows += f'''
        <tr>
            <td><a href="/signatures/{sig.id}" class="mono">{sig.id}</a></td>
            <td>{sig.name[:50]}{"..." if len(sig.name) > 50 else ""}</td>
            <td>{sig.category}</td>
            <td><span class="badge {conf_class}">{sig.confidence}</span></td>
            <td><span class="badge {status_class}">{"enabled" if sig.enabled else "disabled"}</span></td>
            <td>{len(sig.conditions)}</td>
            <td class="text-muted">{sig.version}</td>
        </tr>
        '''
    
    content = f'''
    <div class="stats-row">
        <div class="stat"><div class="stat-value">{stats["total"]}</div><div class="stat-label">Total</div></div>
        <div class="stat"><div class="stat-value">{stats["enabled"]}</div><div class="stat-label">Enabled</div></div>
        <div class="stat"><div class="stat-value">{stats["by_confidence"].get("high", 0)}</div><div class="stat-label">High Confidence</div></div>
        <div class="stat"><div class="stat-value">{len(stats["by_category"])}</div><div class="stat-label">Categories</div></div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <span>Signatures</span>
            <a href="/signatures/create" class="btn btn-primary">+ Create</a>
        </div>
        <div class="card-body">
            <div class="filters">
                <select onchange="location.href='?category='+this.value">
                    <option value="">All Categories</option>
                    {"".join(f'<option value="{c}" {"selected" if c == category else ""}>{c}</option>' for c in CATEGORIES)}
                </select>
                <select onchange="location.href='?confidence='+this.value">
                    <option value="">All Confidence</option>
                    {"".join(f'<option value="{c}" {"selected" if c == confidence else ""}>{c}</option>' for c in CONFIDENCE_LEVELS)}
                </select>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Category</th>
                        <th>Confidence</th>
                        <th>Status</th>
                        <th>Conditions</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else '<tr><td colspan="7" class="text-muted" style="text-align:center;padding:40px;">No signatures found</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
    '''
    
    return render_template_string(SIGNATURE_TEMPLATE, content=content)


@app.route('/signatures/<sig_id>')
def signature_detail(sig_id):
    """View signature details."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        return render_template_string(SIGNATURE_TEMPLATE, content='<div class="card"><div class="card-body text-muted">Signature not found</div></div>')
    
    conditions_html = ""
    for i, cond in enumerate(sig.conditions, 1):
        conditions_html += f'''
        <div class="condition-card">
            <div class="condition-header">
                <strong>{i}. {cond.name}</strong>
                <span class="text-muted">weight: {cond.weight}</span>
            </div>
            <div class="condition-grid">
                <div><span class="text-muted">Type:</span> {cond.type}</div>
                <div><span class="text-muted">Operator:</span> {cond.operator}</div>
                <div><span class="text-muted">Field:</span> <code>{cond.field}</code></div>
                <div><span class="text-muted">Value:</span> <code>{cond.value[:60]}{"..." if len(str(cond.value)) > 60 else ""}</code></div>
            </div>
            {f'<div class="text-small text-muted" style="margin-top:8px;">Note: {cond.note}</div>' if cond.note else ''}
        </div>
        '''
    
    refs_html = ""
    for ref in sig.references:
        url = ref.get("url", "")
        title = ref.get("title", url)
        refs_html += f'<li><a href="{url}" target="_blank">{title}</a></li>'
    
    conf_class = f"badge-{sig.confidence}"
    sev_class = f"badge-{sig.severity}"
    
    content = f'''
    <div class="card">
        <div class="card-header">
            <span>{sig.name}</span>
            <div>
                <a href="/signatures/{sig.id}/edit" class="btn btn-secondary">Edit</a>
                <a href="/signatures/{sig.id}/toggle" class="btn btn-secondary">{"Disable" if sig.enabled else "Enable"}</a>
            </div>
        </div>
        <div class="card-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
                <div>
                    <p><span class="text-muted">ID:</span> <code>{sig.id}</code></p>
                    <p><span class="text-muted">Version:</span> {sig.version}</p>
                    <p><span class="text-muted">Category:</span> {sig.category}</p>
                    <p><span class="text-muted">Author:</span> {sig.author or "—"}</p>
                </div>
                <div>
                    <p><span class="text-muted">Confidence:</span> <span class="badge {conf_class}">{sig.confidence}</span></p>
                    <p><span class="text-muted">Severity:</span> <span class="badge {sev_class}">{sig.severity}</span></p>
                    <p><span class="text-muted">FP Rate:</span> {sig.false_positive_rate}</p>
                    <p><span class="text-muted">Status:</span> {"✓ Enabled" if sig.enabled else "○ Disabled"}</p>
                </div>
            </div>
            
            <h2>Description</h2>
            <p style="margin-bottom:20px;">{sig.description}</p>
            
            {f'''<h2>Attribution</h2>
            <p>Actors: {", ".join(sig.attribution_actors)}</p>
            <p>Confidence: {sig.attribution_confidence}</p>
            {f"<p class='text-muted text-small'>{sig.attribution_note}</p>" if sig.attribution_note else ""}
            ''' if sig.attribution_actors else ""}
            
            <h2>Detection Logic (match: {sig.logic_match})</h2>
            {conditions_html}
            
            <h2>Queries</h2>
            <div class="condition-card">
                <p><strong>Censys:</strong></p>
                <code style="word-break:break-all;">{sig.queries_censys or sig.generate_censys_query() or "—"}</code>
            </div>
            {f'<div class="condition-card"><p><strong>Shodan:</strong></p><code style="word-break:break-all;">{sig.queries_shodan}</code></div>' if sig.queries_shodan else ""}
            
            {f'<h2>References</h2><ul style="margin-left:20px;">{refs_html}</ul>' if refs_html else ""}
        </div>
    </div>
    
    <a href="/signatures" class="btn btn-secondary">← Back to List</a>
    '''
    
    return render_template_string(SIGNATURE_TEMPLATE, content=content)


@app.route('/signatures/<sig_id>/toggle')
def signature_toggle(sig_id):
    """Toggle signature enabled/disabled."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if sig:
        sig.enabled = not sig.enabled
        mgr.save(sig)
    
    return f'<script>location.href="/signatures/{sig_id}";</script>'


@app.route('/signatures/create', methods=['GET', 'POST'])
def signature_create():
    """Create a new signature."""
    from datetime import date
    
    if request.method == 'POST':
        mgr = SignatureManager()
        
        # Parse conditions from form
        conditions = []
        i = 1
        while f'cond_{i}_name' in request.form:
            if request.form.get(f'cond_{i}_name'):
                conditions.append(Condition(
                    name=request.form[f'cond_{i}_name'],
                    type=request.form.get(f'cond_{i}_type', 'jarm'),
                    field=request.form.get(f'cond_{i}_field', ''),
                    operator=request.form.get(f'cond_{i}_operator', 'equals'),
                    value=request.form.get(f'cond_{i}_value', ''),
                    weight=int(request.form.get(f'cond_{i}_weight', 50)),
                    note=request.form.get(f'cond_{i}_note') or None,
                ))
            i += 1
        
        # Parse actors
        actors_str = request.form.get('attribution_actors', '')
        actors = [a.strip() for a in actors_str.split(',') if a.strip()]
        
        sig = Signature(
            id=request.form['id'],
            name=request.form['name'],
            version="1.0.0",
            category=request.form['category'],
            description=request.form.get('description', ''),
            logic_match=request.form.get('logic_match', 'any'),
            conditions=conditions,
            author=request.form.get('author') or None,
            attribution_actors=actors,
            attribution_confidence=request.form.get('attribution_confidence', 'low'),
            confidence=request.form.get('confidence', 'medium'),
            severity=request.form.get('severity', 'medium'),
            last_verified=date.today().isoformat(),
        )
        sig.queries_censys = sig.generate_censys_query()
        
        errors = sig.validate()
        if not errors:
            mgr.save(sig)
            return f'<script>location.href="/signatures/{sig.id}";</script>'
    
    # Form
    cat_options = ''.join(f'<option value="{c}">{c}</option>' for c in CATEGORIES)
    conf_options = ''.join(f'<option value="{c}" {"selected" if c == "medium" else ""}>{c}</option>' for c in CONFIDENCE_LEVELS)
    sev_options = ''.join(f'<option value="{c}" {"selected" if c == "medium" else ""}>{c}</option>' for c in SEVERITY_LEVELS)
    type_options = ''.join(f'<option value="{c}">{c}</option>' for c in CONDITION_TYPES)
    
    content = f'''
    <div class="card">
        <div class="card-header">Create New Signature</div>
        <div class="card-body">
            <form method="POST">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>ID (lowercase-with-hyphens)</label>
                        <input type="text" name="id" class="form-control mono" required pattern="[a-z0-9-]+">
                    </div>
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" name="name" class="form-control" required>
                    </div>
                </div>
                
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>Category</label>
                        <select name="category" class="form-control">{cat_options}</select>
                    </div>
                    <div class="form-group">
                        <label>Confidence</label>
                        <select name="confidence" class="form-control">{conf_options}</select>
                    </div>
                    <div class="form-group">
                        <label>Severity</label>
                        <select name="severity" class="form-control">{sev_options}</select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" class="form-control"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Author</label>
                    <input type="text" name="author" class="form-control">
                </div>
                
                <div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>Attribution Actors (comma-separated)</label>
                        <input type="text" name="attribution_actors" class="form-control" placeholder="APT29, FIN7, etc.">
                    </div>
                    <div class="form-group">
                        <label>Match Logic</label>
                        <select name="logic_match" class="form-control">
                            <option value="any">Any (OR)</option>
                            <option value="all">All (AND)</option>
                        </select>
                    </div>
                </div>
                
                <h2>Detection Conditions</h2>
                <div id="conditions">
                    <div class="condition-card">
                        <div class="condition-grid">
                            <div class="form-group">
                                <label>Condition Name</label>
                                <input type="text" name="cond_1_name" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label>Type</label>
                                <select name="cond_1_type" class="form-control">{type_options}</select>
                            </div>
                            <div class="form-group">
                                <label>Field</label>
                                <input type="text" name="cond_1_field" class="form-control mono" placeholder="services.tls.certificates.leaf_data.fingerprint">
                            </div>
                            <div class="form-group">
                                <label>Value</label>
                                <input type="text" name="cond_1_value" class="form-control mono">
                            </div>
                            <div class="form-group">
                                <label>Weight (0-100)</label>
                                <input type="number" name="cond_1_weight" class="form-control" value="50" min="0" max="100">
                            </div>
                            <div class="form-group">
                                <label>Note (optional)</label>
                                <input type="text" name="cond_1_note" class="form-control">
                            </div>
                        </div>
                    </div>
                </div>
                
                <div style="margin-top:20px;">
                    <button type="submit" class="btn btn-primary">Create Signature</button>
                    <a href="/signatures" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
    '''
    
    return render_template_string(SIGNATURE_TEMPLATE, content=content)


@app.route('/signatures/<sig_id>/edit', methods=['GET', 'POST'])
def signature_edit(sig_id):
    """Edit a signature."""
    from datetime import date
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        return render_template_string(SIGNATURE_TEMPLATE, content='<div class="card"><div class="card-body">Signature not found</div></div>')
    
    if request.method == 'POST':
        # Update fields
        sig.name = request.form['name']
        sig.category = request.form['category']
        sig.description = request.form.get('description', '')
        sig.author = request.form.get('author') or None
        sig.confidence = request.form.get('confidence', 'medium')
        sig.severity = request.form.get('severity', 'medium')
        sig.logic_match = request.form.get('logic_match', 'any')
        
        # Parse actors
        actors_str = request.form.get('attribution_actors', '')
        sig.attribution_actors = [a.strip() for a in actors_str.split(',') if a.strip()]
        
        # Bump version
        parts = sig.version.split('.')
        parts[-1] = str(int(parts[-1]) + 1)
        sig.version = '.'.join(parts)
        
        sig.last_verified = date.today().isoformat()
        sig.queries_censys = sig.generate_censys_query()
        
        mgr.save(sig)
        return f'<script>location.href="/signatures/{sig.id}";</script>'
    
    # Form with current values
    cat_options = ''.join(f'<option value="{c}" {"selected" if c == sig.category else ""}>{c}</option>' for c in CATEGORIES)
    conf_options = ''.join(f'<option value="{c}" {"selected" if c == sig.confidence else ""}>{c}</option>' for c in CONFIDENCE_LEVELS)
    sev_options = ''.join(f'<option value="{c}" {"selected" if c == sig.severity else ""}>{c}</option>' for c in SEVERITY_LEVELS)
    
    conditions_html = ""
    for i, cond in enumerate(sig.conditions, 1):
        conditions_html += f'''
        <div class="condition-card">
            <p><strong>{cond.name}</strong> ({cond.type})</p>
            <p class="mono text-small">{cond.field} = {cond.value}</p>
        </div>
        '''
    
    content = f'''
    <div class="card">
        <div class="card-header">Edit Signature: {sig.id}</div>
        <div class="card-body">
            <form method="POST">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>ID (read-only)</label>
                        <input type="text" class="form-control mono" value="{sig.id}" disabled>
                    </div>
                    <div class="form-group">
                        <label>Name</label>
                        <input type="text" name="name" class="form-control" value="{sig.name}" required>
                    </div>
                </div>
                
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>Category</label>
                        <select name="category" class="form-control">{cat_options}</select>
                    </div>
                    <div class="form-group">
                        <label>Confidence</label>
                        <select name="confidence" class="form-control">{conf_options}</select>
                    </div>
                    <div class="form-group">
                        <label>Severity</label>
                        <select name="severity" class="form-control">{sev_options}</select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" class="form-control">{sig.description}</textarea>
                </div>
                
                <div class="form-group">
                    <label>Author</label>
                    <input type="text" name="author" class="form-control" value="{sig.author or ''}">
                </div>
                
                <div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;">
                    <div class="form-group">
                        <label>Attribution Actors</label>
                        <input type="text" name="attribution_actors" class="form-control" value="{', '.join(sig.attribution_actors)}">
                    </div>
                    <div class="form-group">
                        <label>Match Logic</label>
                        <select name="logic_match" class="form-control">
                            <option value="any" {"selected" if sig.logic_match == "any" else ""}>Any (OR)</option>
                            <option value="all" {"selected" if sig.logic_match == "all" else ""}>All (AND)</option>
                        </select>
                    </div>
                </div>
                
                <h2>Detection Conditions</h2>
                <p class="text-muted text-small">Edit conditions via CLI: <code>python sig_cli.py edit {sig.id}</code></p>
                {conditions_html}
                
                <div style="margin-top:20px;">
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                    <a href="/signatures/{sig.id}" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
    '''
    
    return render_template_string(SIGNATURE_TEMPLATE, content=content)


@app.route('/api/signatures')
def api_signatures():
    """API endpoint for signatures."""
    mgr = SignatureManager()
    sigs = mgr.list()
    
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'version': s.version,
        'category': s.category,
        'confidence': s.confidence,
        'severity': s.severity,
        'enabled': s.enabled,
        'conditions': len(s.conditions),
    } for s in sigs])


@app.route('/api/signatures/<sig_id>')
def api_signature_detail(sig_id):
    """API endpoint for signature detail."""
    import yaml
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        return jsonify({'error': 'Not found'}), 404
    
    return jsonify(sig.to_dict())


def run_dashboard(host='0.0.0.0', port=5003):
    """Run the dashboard server."""
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Infrastructure Hunter Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5003, help='Port to listen on')
    args = parser.parse_args()
    
    print(f"Starting dashboard on http://{args.host}:{args.port}")
    run_dashboard(args.host, args.port)
