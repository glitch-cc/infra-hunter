#!/usr/bin/env python3
"""
Delta Dashboard for Infrastructure Hunter.
Shows what's NEW, CHANGED, GONE - the intel that matters.
"""
import os
import json
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
DB_PATH = os.environ.get('INFRA_HUNTER_DB', 'infra_hunter.db')

# ============== STYLES ==============

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
}
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }

/* Header */
.header { 
    display: flex; 
    justify-content: space-between; 
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 1px solid #30363d;
}
h1 {
    font-size: 2em;
    background: linear-gradient(90deg, #58a6ff, #a855f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.time-filters { display: flex; gap: 10px; }
.time-btn {
    padding: 8px 16px;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    cursor: pointer;
    transition: all 0.2s;
}
.time-btn:hover, .time-btn.active { background: #30363d; border-color: #58a6ff; }

/* Delta Cards */
.delta-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin-bottom: 30px;
}
.delta-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
}
.delta-card.new { border-color: #238636; }
.delta-card.changed { border-color: #d29922; }
.delta-card.gone { border-color: #f85149; }
.delta-card.returned { border-color: #58a6ff; }
.delta-value {
    font-size: 3em;
    font-weight: bold;
    margin-bottom: 5px;
}
.delta-card.new .delta-value { color: #3fb950; }
.delta-card.changed .delta-value { color: #d29922; }
.delta-card.gone .delta-value { color: #f85149; }
.delta-card.returned .delta-value { color: #58a6ff; }
.delta-label { color: #8b949e; font-size: 0.9em; }

/* Alerts */
.alerts-section { margin-bottom: 30px; }
.alert {
    background: #161b22;
    border-left: 4px solid #d29922;
    padding: 15px 20px;
    margin-bottom: 10px;
    border-radius: 0 8px 8px 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.alert.high { border-left-color: #f85149; }
.alert.medium { border-left-color: #d29922; }
.alert.low { border-left-color: #8b949e; }
.alert-content h4 { margin-bottom: 5px; color: #f0f6fc; }
.alert-content p { color: #8b949e; font-size: 0.9em; }
.alert-time { color: #8b949e; font-size: 0.85em; }

/* Tables */
.section { margin-bottom: 30px; }
.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}
.section-header h2 { font-size: 1.3em; color: #f0f6fc; }
.badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.85em;
}
.badge-new { background: #23863626; color: #3fb950; }
.badge-changed { background: #d2992226; color: #d29922; }
.badge-gone { background: #f8514926; color: #f85149; }

table { width: 100%; border-collapse: collapse; }
th, td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #21262d;
}
th { background: #161b22; color: #8b949e; font-weight: 500; }
tr:hover { background: #161b2288; }
.ip { font-family: monospace; color: #58a6ff; }
.pattern-tag {
    background: #30363d;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    margin-right: 5px;
}

/* Charts placeholder */
.chart-container {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px;
    height: 300px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #8b949e;
}

/* Pattern breakdown */
.pattern-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 15px;
}
.pattern-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 15px;
}
.pattern-card h4 { 
    color: #f0f6fc; 
    margin-bottom: 10px;
    font-size: 0.95em;
}
.pattern-stats { display: flex; gap: 15px; }
.pattern-stat { text-align: center; }
.pattern-stat .value { font-size: 1.5em; font-weight: bold; color: #58a6ff; }
.pattern-stat .label { font-size: 0.75em; color: #8b949e; }
.pattern-stat.new .value { color: #3fb950; }

/* Timeline */
.timeline { position: relative; }
.timeline-item {
    display: flex;
    gap: 15px;
    padding: 15px 0;
    border-left: 2px solid #30363d;
    margin-left: 10px;
    padding-left: 25px;
    position: relative;
}
.timeline-item::before {
    content: '';
    position: absolute;
    left: -6px;
    top: 20px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #30363d;
}
.timeline-item.new::before { background: #3fb950; }
.timeline-item.changed::before { background: #d29922; }
.timeline-item.gone::before { background: #f85149; }
.timeline-time { color: #8b949e; font-size: 0.85em; min-width: 100px; }
.timeline-content { flex: 1; }
.timeline-content strong { color: #f0f6fc; }
"""

# ============== TEMPLATES ==============

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Infra Hunter - Delta Dashboard</title>
    <style>""" + CSS + """</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Infrastructure Delta</h1>
            <div class="time-filters">
                <button class="time-btn" onclick="loadData(6)">6h</button>
                <button class="time-btn active" onclick="loadData(24)">24h</button>
                <button class="time-btn" onclick="loadData(72)">3d</button>
                <button class="time-btn" onclick="loadData(168)">7d</button>
            </div>
        </div>
        
        <!-- Delta Summary Cards -->
        <div class="delta-grid">
            <div class="delta-card new">
                <div class="delta-value" id="new-count">-</div>
                <div class="delta-label">🆕 New Hosts</div>
            </div>
            <div class="delta-card changed">
                <div class="delta-value" id="changed-count">-</div>
                <div class="delta-label">🔄 Changed</div>
            </div>
            <div class="delta-card gone">
                <div class="delta-value" id="gone-count">-</div>
                <div class="delta-label">👋 Gone</div>
            </div>
            <div class="delta-card returned">
                <div class="delta-value" id="returned-count">-</div>
                <div class="delta-label">↩️ Returned</div>
            </div>
        </div>
        
        <!-- Alerts -->
        <div class="alerts-section" id="alerts-container">
            <h2 style="margin-bottom: 15px;">🚨 Active Alerts</h2>
            <div id="alerts-list"></div>
        </div>
        
        <!-- New by Pattern -->
        <div class="section">
            <div class="section-header">
                <h2>📈 New Hosts by Pattern</h2>
            </div>
            <div class="pattern-grid" id="pattern-grid"></div>
        </div>
        
        <!-- New Hosts Table -->
        <div class="section">
            <div class="section-header">
                <h2>🆕 New Hosts</h2>
                <span class="badge badge-new" id="new-badge">0 new</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Country</th>
                        <th>ASN/Org</th>
                        <th>Patterns</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody id="new-hosts-table"></tbody>
            </table>
        </div>
        
        <!-- Recent Changes Timeline -->
        <div class="section">
            <div class="section-header">
                <h2>📜 Change Timeline</h2>
            </div>
            <div class="timeline" id="timeline"></div>
        </div>
    </div>
    
    <script>
    let currentHours = 24;
    
    async function loadData(hours) {
        currentHours = hours;
        document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        
        const resp = await fetch('/api/delta?hours=' + hours);
        const data = await resp.json();
        
        // Update counts
        document.getElementById('new-count').textContent = data.summary.new_hosts;
        document.getElementById('changed-count').textContent = data.summary.changes;
        document.getElementById('gone-count').textContent = data.summary.gone_hosts;
        document.getElementById('returned-count').textContent = data.summary.returned_hosts || 0;
        document.getElementById('new-badge').textContent = data.summary.new_hosts + ' new';
        
        // Update alerts
        const alertsHtml = data.alerts.map(a => `
            <div class="alert ${a.severity}">
                <div class="alert-content">
                    <h4>${a.title}</h4>
                    <p>${a.description || ''}</p>
                </div>
                <div class="alert-time">${formatTime(a.created_at)}</div>
            </div>
        `).join('');
        document.getElementById('alerts-list').innerHTML = alertsHtml || '<p style="color:#8b949e">No active alerts</p>';
        
        // Update pattern grid
        const patternHtml = Object.entries(data.new_by_pattern || {}).map(([name, count]) => `
            <div class="pattern-card">
                <h4>${name}</h4>
                <div class="pattern-stats">
                    <div class="pattern-stat new">
                        <div class="value">+${count}</div>
                        <div class="label">NEW</div>
                    </div>
                    <div class="pattern-stat">
                        <div class="value">${data.total_by_pattern?.[name] || count}</div>
                        <div class="label">TOTAL</div>
                    </div>
                </div>
            </div>
        `).join('');
        document.getElementById('pattern-grid').innerHTML = patternHtml || '<p style="color:#8b949e">No new pattern matches</p>';
        
        // Update new hosts table
        const hostsHtml = data.new_hosts.slice(0, 50).map(h => `
            <tr>
                <td class="ip">${h.ip}</td>
                <td>${h.country || '??'}</td>
                <td>${(h.org || h.asn_name || '').substring(0, 40)}</td>
                <td>${(h.patterns || []).map(p => `<span class="pattern-tag">${p}</span>`).join('')}</td>
                <td>${formatTime(h.first_seen)}</td>
            </tr>
        `).join('');
        document.getElementById('new-hosts-table').innerHTML = hostsHtml || '<tr><td colspan="5" style="color:#8b949e">No new hosts</td></tr>';
        
        // Update timeline
        const timelineHtml = data.changes.slice(0, 30).map(c => `
            <div class="timeline-item ${c.change_type.includes('first') ? 'new' : c.change_type.includes('gone') ? 'gone' : 'changed'}">
                <div class="timeline-time">${formatTime(c.changed_at)}</div>
                <div class="timeline-content">
                    <strong>${c.ip}</strong> - ${formatChangeType(c.change_type)}
                    ${c.field_name ? `<br><small>${c.field_name}: ${(c.old_value || '').substring(0,30)} → ${(c.new_value || '').substring(0,30)}</small>` : ''}
                </div>
            </div>
        `).join('');
        document.getElementById('timeline').innerHTML = timelineHtml || '<p style="color:#8b949e">No recent changes</p>';
    }
    
    function formatTime(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        const now = new Date();
        const diff = (now - d) / 1000;
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return d.toLocaleDateString();
    }
    
    function formatChangeType(type) {
        const map = {
            'first_seen': '🆕 First seen',
            'jarm_changed': '🔄 JARM changed',
            'cert_changed': '🔐 Certificate changed',
            'ports_changed': '🔌 Ports changed',
            'host_gone': '👋 Went dark',
            'host_returned': '↩️ Returned',
            'new_pattern_match': '🎯 New pattern match',
        };
        return map[type] || type;
    }
    
    // Initial load
    loadData(24);
    </script>
</body>
</html>
"""


# ============== API ROUTES ==============

def get_db():
    return sqlite3.connect(DB_PATH)


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/delta')
def api_delta():
    hours = int(request.args.get('hours', 24))
    since = datetime.utcnow() - timedelta(hours=hours)
    since_str = since.strftime('%Y-%m-%d %H:%M:%S')
    
    db = get_db()
    cur = db.cursor()
    
    # New hosts
    cur.execute("""
        SELECT h.ip, h.country, h.asn_name, h.first_seen,
               GROUP_CONCAT(p.name) as patterns
        FROM hosts h
        LEFT JOIN matches m ON h.id = m.host_id
        LEFT JOIN patterns p ON m.pattern_id = p.id
        WHERE h.first_seen >= ?
        GROUP BY h.id
        ORDER BY h.first_seen DESC
        LIMIT 100
    """, (since_str,))
    new_hosts = [
        {
            'ip': r[0], 'country': r[1], 'asn_name': r[2], 
            'first_seen': r[3], 'patterns': r[4].split(',') if r[4] else []
        }
        for r in cur.fetchall()
    ]
    
    # Changes
    cur.execute("""
        SELECT c.change_type, c.changed_at, c.field_name, c.old_value, c.new_value, h.ip
        FROM host_changes c
        JOIN hosts h ON c.host_id = h.id
        WHERE c.changed_at >= ?
        ORDER BY c.changed_at DESC
        LIMIT 100
    """, (since_str,))
    changes = [
        {
            'change_type': r[0], 'changed_at': r[1], 'field_name': r[2],
            'old_value': r[3], 'new_value': r[4], 'ip': r[5]
        }
        for r in cur.fetchall()
    ]
    
    # Gone hosts
    cur.execute("SELECT COUNT(*) FROM hosts WHERE gone_since >= ?", (since_str,))
    gone_count = cur.fetchone()[0]
    
    # Returned hosts (changes with type host_returned)
    cur.execute("""
        SELECT COUNT(*) FROM host_changes 
        WHERE change_type = 'host_returned' AND changed_at >= ?
    """, (since_str,))
    returned_count = cur.fetchone()[0]
    
    # Alerts
    cur.execute("""
        SELECT alert_type, severity, title, description, created_at, data
        FROM alerts
        WHERE status = 'new' AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 20
    """, (since_str,))
    alerts = [
        {
            'alert_type': r[0], 'severity': r[1], 'title': r[2],
            'description': r[3], 'created_at': r[4], 'data': json.loads(r[5]) if r[5] else {}
        }
        for r in cur.fetchall()
    ]
    
    # New by pattern
    cur.execute("""
        SELECT p.name, COUNT(DISTINCT h.id) as cnt
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        JOIN patterns p ON m.pattern_id = p.id
        WHERE h.first_seen >= ?
        GROUP BY p.id
        ORDER BY cnt DESC
    """, (since_str,))
    new_by_pattern = {r[0]: r[1] for r in cur.fetchall()}
    
    # Total by pattern
    cur.execute("""
        SELECT p.name, COUNT(DISTINCT h.id) as cnt
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        JOIN patterns p ON m.pattern_id = p.id
        WHERE h.status != 'gone'
        GROUP BY p.id
    """)
    total_by_pattern = {r[0]: r[1] for r in cur.fetchall()}
    
    db.close()
    
    return jsonify({
        'period_hours': hours,
        'summary': {
            'new_hosts': len(new_hosts),
            'changes': len([c for c in changes if c['change_type'] != 'first_seen']),
            'gone_hosts': gone_count,
            'returned_hosts': returned_count,
        },
        'new_hosts': new_hosts,
        'changes': changes,
        'alerts': alerts,
        'new_by_pattern': new_by_pattern,
        'total_by_pattern': total_by_pattern,
    })


@app.route('/api/trends')
def api_trends():
    days = int(request.args.get('days', 30))
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        SELECT scanned_at, total_hosts, new_hosts, changed_hosts, gone_hosts
        FROM scan_summaries
        WHERE scanned_at >= datetime('now', ?)
        ORDER BY scanned_at
    """, (f'-{days} days',))
    
    results = cur.fetchall()
    db.close()
    
    return jsonify({
        'dates': [r[0] for r in results],
        'total_hosts': [r[1] for r in results],
        'new_hosts': [r[2] for r in results],
        'changed_hosts': [r[3] for r in results],
        'gone_hosts': [r[4] for r in results],
    })


@app.route('/api/host/<ip>/timeline')
def api_host_timeline(ip):
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'Host not found'}), 404
    
    host_id = row[0]
    
    cur.execute("""
        SELECT change_type, changed_at, field_name, old_value, new_value, severity
        FROM host_changes
        WHERE host_id = ?
        ORDER BY changed_at DESC
        LIMIT 50
    """, (host_id,))
    
    changes = [
        {
            'change_type': r[0], 'changed_at': r[1], 'field_name': r[2],
            'old_value': r[3], 'new_value': r[4], 'severity': r[5]
        }
        for r in cur.fetchall()
    ]
    
    db.close()
    return jsonify({'ip': ip, 'changes': changes})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)
