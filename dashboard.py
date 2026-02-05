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
