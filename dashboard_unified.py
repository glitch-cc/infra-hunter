#!/usr/bin/env python3
"""
Infrastructure Hunter - Unified Dashboard
Combines pattern tracking, delta detection, and temporal analysis.
"""
import os
import sys
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request, Response

app = Flask(__name__)

# Handle SQLAlchemy-style URI or plain path
_db_env = os.environ.get('INFRA_HUNTER_DB', 'infra_hunter.db')
if _db_env.startswith('sqlite:///'):
    DB_PATH = _db_env.replace('sqlite:///', '')
else:
    DB_PATH = _db_env
if not DB_PATH.startswith('/'):
    DB_PATH = os.path.join(os.path.dirname(__file__), DB_PATH)


def get_db():
    return sqlite3.connect(DB_PATH)


# ============== UNIFIED TEMPLATE ==============

TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Infrastructure Hunter</title>
    <style>
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
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #30363d;
        }
        h1 {
            font-size: 1.8em;
            background: linear-gradient(90deg, #58a6ff, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header-stats {
            display: flex;
            gap: 20px;
            font-size: 0.9em;
            color: #8b949e;
        }
        .header-stats strong { color: #c9d1d9; }
        
        /* Navigation */
        .nav {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            background: #161b22;
            padding: 5px;
            border-radius: 8px;
            border: 1px solid #30363d;
        }
        .nav-btn {
            padding: 10px 20px;
            background: transparent;
            border: none;
            color: #8b949e;
            cursor: pointer;
            border-radius: 6px;
            font-size: 0.95em;
            transition: all 0.2s;
        }
        .nav-btn:hover { color: #c9d1d9; background: #21262d; }
        .nav-btn.active { background: #238636; color: white; }
        
        /* Time filters */
        .time-filters {
            display: flex;
            gap: 8px;
            margin-left: auto;
        }
        .time-btn {
            padding: 6px 12px;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 4px;
            color: #8b949e;
            cursor: pointer;
            font-size: 0.85em;
        }
        .time-btn:hover, .time-btn.active { background: #30363d; color: #c9d1d9; border-color: #58a6ff; }
        
        /* Delta Cards */
        .delta-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }
        .delta-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: all 0.2s;
        }
        .delta-card:hover { border-color: #58a6ff; }
        .delta-card.new { border-left: 4px solid #3fb950; }
        .delta-card.changed { border-left: 4px solid #d29922; }
        .delta-card.gone { border-left: 4px solid #f85149; }
        .delta-card.total { border-left: 4px solid #58a6ff; }
        .delta-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .delta-card.new .delta-value { color: #3fb950; }
        .delta-card.changed .delta-value { color: #d29922; }
        .delta-card.gone .delta-value { color: #f85149; }
        .delta-card.total .delta-value { color: #58a6ff; }
        .delta-label { color: #8b949e; font-size: 0.9em; }
        
        /* Cards */
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .card-header {
            background: #21262d;
            padding: 12px 16px;
            border-bottom: 1px solid #30363d;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-body { padding: 0; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #21262d; }
        th { background: #161b22; color: #8b949e; font-weight: 500; font-size: 0.85em; text-transform: uppercase; }
        tr:hover { background: #1c2128; }
        
        .ip { font-family: 'Monaco', 'Menlo', monospace; color: #58a6ff; }
        .country { color: #8b949e; }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 500;
        }
        .badge-new { background: #23863626; color: #3fb950; }
        .badge-high { background: #f8514926; color: #f85149; }
        .badge-medium { background: #d2992226; color: #d29922; }
        .badge-low { background: #8b949e26; color: #8b949e; }
        
        .pattern-tag {
            display: inline-block;
            background: #30363d;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            margin: 2px;
        }
        
        /* Alerts */
        .alert {
            padding: 12px 16px;
            border-left: 4px solid #d29922;
            background: #161b22;
            margin-bottom: 8px;
            border-radius: 0 6px 6px 0;
        }
        .alert.high { border-left-color: #f85149; }
        .alert.medium { border-left-color: #d29922; }
        .alert h4 { color: #f0f6fc; margin-bottom: 4px; }
        .alert p { color: #8b949e; font-size: 0.9em; }
        
        /* Pattern Grid */
        .pattern-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            padding: 16px;
        }
        .pattern-card {
            background: #21262d;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
        }
        .pattern-card:hover { border-color: #58a6ff; transform: translateY(-2px); }
        .pattern-card h4 { color: #f0f6fc; margin-bottom: 8px; font-size: 0.95em; }
        .pattern-stats { display: flex; gap: 20px; margin-top: 10px; }
        .pattern-stat { text-align: center; }
        .pattern-stat .value { font-size: 1.4em; font-weight: bold; color: #58a6ff; }
        .pattern-stat .label { font-size: 0.75em; color: #8b949e; }
        .pattern-stat.new .value { color: #3fb950; }
        
        /* Modal */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            width: 90%;
            max-width: 900px;
            max-height: 80vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        .modal-header {
            padding: 16px 20px;
            background: #21262d;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 { color: #f0f6fc; font-size: 1.2em; }
        .modal-close {
            background: none;
            border: none;
            color: #8b949e;
            font-size: 1.5em;
            cursor: pointer;
            padding: 0 8px;
        }
        .modal-close:hover { color: #f0f6fc; }
        .modal-body {
            padding: 20px;
            overflow-y: auto;
            flex: 1;
        }
        .modal-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #30363d;
        }
        .modal-meta-item { }
        .modal-meta-item .label { color: #8b949e; font-size: 0.85em; }
        .modal-meta-item .value { color: #f0f6fc; font-weight: 600; }
        .modal-link {
            display: inline-block;
            margin-top: 15px;
            padding: 8px 16px;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #58a6ff;
            text-decoration: none;
        }
        .modal-link:hover { background: #30363d; }
        
        /* Timeline */
        .timeline { padding: 16px; }
        .timeline-item {
            display: flex;
            gap: 15px;
            padding: 12px 0;
            border-bottom: 1px solid #21262d;
        }
        .timeline-item:last-child { border-bottom: none; }
        .timeline-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #30363d;
            margin-top: 5px;
            flex-shrink: 0;
        }
        .timeline-item.new .timeline-dot { background: #3fb950; }
        .timeline-item.changed .timeline-dot { background: #d29922; }
        .timeline-item.gone .timeline-dot { background: #f85149; }
        .timeline-time { color: #8b949e; font-size: 0.85em; min-width: 80px; }
        .timeline-content { flex: 1; }
        .timeline-content strong { color: #f0f6fc; }
        .timeline-content small { color: #8b949e; display: block; margin-top: 4px; }
        
        /* Tab content */
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        /* Empty state */
        .empty { text-align: center; padding: 40px; color: #8b949e; }
        
        /* Responsive */
        @media (max-width: 768px) {
            .delta-grid { grid-template-columns: repeat(2, 1fr); }
            .header { flex-direction: column; gap: 15px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Infrastructure Hunter</h1>
            <div class="header-stats">
                <span><strong id="total-hosts">-</strong> hosts</span>
                <span><strong id="total-patterns">-</strong> patterns</span>
                <span>Last scan: <strong id="last-scan">-</strong></span>
            </div>
        </div>
        
        <div class="nav">
            <button class="nav-btn active" onclick="showTab('delta')">📊 Delta</button>
            <button class="nav-btn" onclick="showTab('hosts')">💻 Hosts</button>
            <button class="nav-btn" onclick="showTab('patterns')">🎯 Patterns</button>
            <button class="nav-btn" onclick="showTab('alerts')">🚨 Alerts</button>
            <button class="nav-btn" onclick="showTab('timeline')">📜 Timeline</button>
            <div class="time-filters">
                <button class="time-btn" onclick="setHours(6)">6h</button>
                <button class="time-btn active" onclick="setHours(24)">24h</button>
                <button class="time-btn" onclick="setHours(72)">3d</button>
                <button class="time-btn" onclick="setHours(168)">7d</button>
            </div>
        </div>
        
        <!-- DELTA TAB -->
        <div id="delta-tab" class="tab-content active">
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
                <div class="delta-card total">
                    <div class="delta-value" id="total-count">-</div>
                    <div class="delta-label">📊 Total Tracked</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span>📈 New by Pattern</span>
                </div>
                <div class="card-body">
                    <div class="pattern-grid" id="pattern-grid"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span>🆕 New Hosts</span>
                    <span class="badge badge-new" id="new-badge">0</span>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Country</th>
                                <th>Organization</th>
                                <th>Patterns</th>
                                <th>First Seen</th>
                            </tr>
                        </thead>
                        <tbody id="new-hosts-table"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- HOSTS TAB -->
        <div id="hosts-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>All Tracked Hosts</span>
                    <span class="badge" id="hosts-badge">0</span>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Country</th>
                                <th>Organization</th>
                                <th>Patterns</th>
                                <th>Status</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody id="hosts-table"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- PATTERNS TAB -->
        <div id="patterns-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>Detection Patterns</span>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Confidence</th>
                                <th>Total Hosts</th>
                                <th>New (24h)</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="patterns-table"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- ALERTS TAB -->
        <div id="alerts-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>Active Alerts</span>
                </div>
                <div class="card-body" style="padding: 16px;">
                    <div id="alerts-list"></div>
                </div>
            </div>
        </div>
        
        <!-- TIMELINE TAB -->
        <div id="timeline-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>Change Timeline</span>
                </div>
                <div class="card-body">
                    <div class="timeline" id="timeline"></div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- PATTERN MODAL -->
    <div class="modal-overlay" id="pattern-modal" onclick="if(event.target===this)closeModal()">
        <div class="modal">
            <div class="modal-header">
                <h3 id="modal-title">Pattern Details</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-meta">
                    <div class="modal-meta-item">
                        <div class="label">New Hosts</div>
                        <div class="value" id="modal-new-count" style="color: #3fb950">-</div>
                    </div>
                    <div class="modal-meta-item">
                        <div class="label">Total Hosts</div>
                        <div class="value" id="modal-total-count">-</div>
                    </div>
                    <div class="modal-meta-item">
                        <div class="label">Confidence</div>
                        <div class="value" id="modal-confidence">-</div>
                    </div>
                </div>
                <div style="display: flex; gap: 20px; align-items: center;">
                    <a href="#" class="modal-link" id="modal-sig-link" target="_blank">🎯 View Signature Definition</a>
                    <a href="#" class="modal-link" id="modal-stix-link" download>📥 Download IOCs (STIX)</a>
                </div>
                <h4 style="margin: 20px 0 15px; color: #f0f6fc;">New Hosts Matching This Pattern</h4>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Country</th>
                            <th>Organization</th>
                            <th>First Seen</th>
                        </tr>
                    </thead>
                    <tbody id="modal-hosts-table"></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
    let currentHours = 24;
    let currentTab = 'delta';
    
    function showTab(tab) {
        currentTab = tab;
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(tab + '-tab').classList.add('active');
        event.target.classList.add('active');
        loadData();
    }
    
    function setHours(hours) {
        currentHours = hours;
        document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        loadData();
    }
    
    async function loadData() {
        const [delta, hosts, patterns, alerts] = await Promise.all([
            fetch('api/delta?hours=' + currentHours).then(r => r.json()),
            fetch('api/hosts?limit=100').then(r => r.json()),
            fetch('api/patterns').then(r => r.json()),
            fetch('api/alerts?hours=' + currentHours).then(r => r.json()),
        ]);
        
        // Header stats
        document.getElementById('total-hosts').textContent = hosts.total || 0;
        document.getElementById('total-patterns').textContent = patterns.length || 0;
        document.getElementById('last-scan').textContent = delta.last_scan || 'Never';
        
        // Delta cards
        document.getElementById('new-count').textContent = delta.summary?.new_hosts || 0;
        document.getElementById('changed-count').textContent = delta.summary?.changes || 0;
        document.getElementById('gone-count').textContent = delta.summary?.gone_hosts || 0;
        document.getElementById('total-count').textContent = hosts.total || 0;
        document.getElementById('new-badge').textContent = delta.summary?.new_hosts || 0;
        
        // Pattern grid - clickable cards
        window.deltaData = delta;  // Store for modal use
        const patternHtml = Object.entries(delta.new_by_pattern || {})
            .sort((a, b) => b[1] - a[1])
            .map(([name, count]) => `
                <div class="pattern-card" onclick="openPatternModal('${name.replace(/'/g, "\\'")}', ${count}, ${delta.total_by_pattern?.[name] || count})">
                    <h4>${name}</h4>
                    <div class="pattern-stats">
                        <div class="pattern-stat new">
                            <div class="value">+${count}</div>
                            <div class="label">NEW</div>
                        </div>
                        <div class="pattern-stat">
                            <div class="value">${delta.total_by_pattern?.[name] || count}</div>
                            <div class="label">TOTAL</div>
                        </div>
                    </div>
                </div>
            `).join('') || '<div class="empty">No new patterns in this period</div>';
        document.getElementById('pattern-grid').innerHTML = patternHtml;
        
        // New hosts table
        const newHostsHtml = (delta.new_hosts || []).slice(0, 50).map(h => `
            <tr>
                <td class="ip">${h.ip}</td>
                <td class="country">${h.country || '??'}</td>
                <td>${(h.asn_name || h.org || '').substring(0, 35)}</td>
                <td>${(h.patterns || []).map(p => '<span class="pattern-tag">' + p + '</span>').join('')}</td>
                <td>${formatTime(h.first_seen)}</td>
            </tr>
        `).join('') || '<tr><td colspan="5" class="empty">No new hosts</td></tr>';
        document.getElementById('new-hosts-table').innerHTML = newHostsHtml;
        
        // All hosts table
        document.getElementById('hosts-badge').textContent = hosts.total || 0;
        const hostsHtml = (hosts.hosts || []).map(h => `
            <tr>
                <td class="ip">${h.ip}</td>
                <td class="country">${h.country || '??'}</td>
                <td>${(h.asn_name || '').substring(0, 35)}</td>
                <td>${(h.patterns || []).map(p => '<span class="pattern-tag">' + p + '</span>').join('')}</td>
                <td><span class="badge badge-${h.status || 'low'}">${h.status || 'active'}</span></td>
                <td>${formatTime(h.first_seen)}</td>
                <td>${formatTime(h.last_seen)}</td>
            </tr>
        `).join('') || '<tr><td colspan="7" class="empty">No hosts tracked</td></tr>';
        document.getElementById('hosts-table').innerHTML = hostsHtml;
        
        // Patterns table
        const patternsHtml = patterns.map(p => `
            <tr>
                <td><strong>${p.name}</strong></td>
                <td>${p.pattern_type || 'composite'}</td>
                <td><span class="badge badge-${p.confidence || 'medium'}">${p.confidence || 'medium'}</span></td>
                <td>${p.total_hosts || 0}</td>
                <td style="color: #3fb950">${p.new_hosts || 0}</td>
                <td>${p.enabled ? '✅ Active' : '⏸️ Disabled'}</td>
            </tr>
        `).join('') || '<tr><td colspan="6" class="empty">No patterns configured</td></tr>';
        document.getElementById('patterns-table').innerHTML = patternsHtml;
        
        // Alerts
        const alertsHtml = (alerts.alerts || []).map(a => `
            <div class="alert ${a.severity}">
                <h4>${a.title}</h4>
                <p>${a.description || ''}</p>
            </div>
        `).join('') || '<div class="empty">No alerts in this period</div>';
        document.getElementById('alerts-list').innerHTML = alertsHtml;
        
        // Timeline
        const timelineHtml = (delta.changes || []).slice(0, 30).map(c => `
            <div class="timeline-item ${getChangeClass(c.change_type)}">
                <div class="timeline-dot"></div>
                <div class="timeline-time">${formatTime(c.changed_at)}</div>
                <div class="timeline-content">
                    <strong>${c.ip}</strong> — ${formatChangeType(c.change_type)}
                    ${c.field_name ? '<small>' + c.field_name + ': ' + (c.old_value || '').substring(0, 30) + ' → ' + (c.new_value || '').substring(0, 30) + '</small>' : ''}
                </div>
            </div>
        `).join('') || '<div class="empty">No changes in this period</div>';
        document.getElementById('timeline').innerHTML = timelineHtml;
    }
    
    function formatTime(iso) {
        if (!iso) return '-';
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
    
    function getChangeClass(type) {
        if (type.includes('first') || type.includes('new')) return 'new';
        if (type.includes('gone')) return 'gone';
        return 'changed';
    }
    
    // Modal functions
    async function openPatternModal(patternName, newCount, totalCount) {
        document.getElementById('modal-title').textContent = patternName;
        document.getElementById('modal-new-count').textContent = '+' + newCount;
        document.getElementById('modal-total-count').textContent = totalCount;
        
        // Fetch hosts for this pattern
        const resp = await fetch('api/pattern-hosts?name=' + encodeURIComponent(patternName) + '&hours=' + currentHours);
        const data = await resp.json();
        
        // Set signature link
        const sigId = patternName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '');
        document.getElementById('modal-sig-link').href = '/dataset/view/' + sigId;
        
        // Set STIX download link
        if (data.pattern_id && data.count > 0) {
            document.getElementById('modal-stix-link').href = '/api/pattern/' + data.pattern_id + '/stix';
            document.getElementById('modal-stix-link').style.display = 'inline';
        } else {
            document.getElementById('modal-stix-link').style.display = 'none';
        }
        
        document.getElementById('modal-confidence').textContent = data.confidence || 'medium';
        
        const hostsHtml = (data.hosts || []).map(h => `
            <tr>
                <td class="ip">${h.ip}</td>
                <td class="country">${h.country || '??'}</td>
                <td>${(h.asn_name || '').substring(0, 40)}</td>
                <td>${formatTime(h.first_seen)}</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty">No hosts found</td></tr>';
        document.getElementById('modal-hosts-table').innerHTML = hostsHtml;
        
        document.getElementById('pattern-modal').classList.add('active');
    }
    
    function closeModal() {
        document.getElementById('pattern-modal').classList.remove('active');
    }
    
    // Close modal on Escape key
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
    
    // Initial load
    loadData();
    </script>
</body>
</html>
'''


# ============== API ROUTES ==============

@app.route('/')
def index():
    return render_template_string(TEMPLATE)


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
        {'ip': r[0], 'country': r[1], 'asn_name': r[2], 'first_seen': r[3], 
         'patterns': r[4].split(',') if r[4] else []}
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
        {'change_type': r[0], 'changed_at': r[1], 'field_name': r[2],
         'old_value': r[3], 'new_value': r[4], 'ip': r[5]}
        for r in cur.fetchall()
    ]
    
    # Gone hosts
    cur.execute("SELECT COUNT(*) FROM hosts WHERE gone_since >= ?", (since_str,))
    gone_count = cur.fetchone()[0]
    
    # New by pattern
    cur.execute("""
        SELECT p.name, COUNT(DISTINCT h.id) as cnt
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        JOIN patterns p ON m.pattern_id = p.id
        WHERE h.first_seen >= ?
        GROUP BY p.id ORDER BY cnt DESC
    """, (since_str,))
    new_by_pattern = {r[0]: r[1] for r in cur.fetchall()}
    
    # Total by pattern
    cur.execute("""
        SELECT p.name, COUNT(DISTINCT h.id) as cnt
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        JOIN patterns p ON m.pattern_id = p.id
        GROUP BY p.id
    """)
    total_by_pattern = {r[0]: r[1] for r in cur.fetchall()}
    
    # Last scan
    cur.execute("SELECT MAX(scanned_at) FROM scan_summaries")
    row = cur.fetchone()
    last_scan = row[0] if row and row[0] else None
    
    db.close()
    
    return jsonify({
        'period_hours': hours,
        'summary': {
            'new_hosts': len(new_hosts),
            'changes': len([c for c in changes if c['change_type'] != 'first_seen']),
            'gone_hosts': gone_count,
        },
        'new_hosts': new_hosts,
        'changes': changes,
        'new_by_pattern': new_by_pattern,
        'total_by_pattern': total_by_pattern,
        'last_scan': last_scan,
    })


@app.route('/api/hosts')
def api_hosts():
    limit = int(request.args.get('limit', 100))
    
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT COUNT(*) FROM hosts")
    total = cur.fetchone()[0]
    
    cur.execute("""
        SELECT h.ip, h.country, h.asn_name, h.first_seen, h.last_seen, h.status,
               GROUP_CONCAT(p.name) as patterns
        FROM hosts h
        LEFT JOIN matches m ON h.id = m.host_id
        LEFT JOIN patterns p ON m.pattern_id = p.id
        GROUP BY h.id
        ORDER BY h.last_seen DESC
        LIMIT ?
    """, (limit,))
    
    hosts = [
        {'ip': r[0], 'country': r[1], 'asn_name': r[2], 'first_seen': r[3],
         'last_seen': r[4], 'status': r[5] or 'active',
         'patterns': r[6].split(',') if r[6] else []}
        for r in cur.fetchall()
    ]
    
    db.close()
    return jsonify({'total': total, 'hosts': hosts})


@app.route('/api/patterns')
def api_patterns():
    db = get_db()
    cur = db.cursor()
    
    since_24h = (datetime.utcnow() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    
    cur.execute("""
        SELECT p.id, p.name, p.pattern_type, p.confidence, p.enabled,
               COUNT(DISTINCT m.host_id) as total_hosts,
               SUM(CASE WHEN h.first_seen >= ? THEN 1 ELSE 0 END) as new_hosts
        FROM patterns p
        LEFT JOIN matches m ON p.id = m.pattern_id
        LEFT JOIN hosts h ON m.host_id = h.id
        GROUP BY p.id
        ORDER BY total_hosts DESC
    """, (since_24h,))
    
    patterns = [
        {'id': r[0], 'name': r[1], 'pattern_type': r[2], 'confidence': r[3],
         'enabled': bool(r[4]), 'total_hosts': r[5], 'new_hosts': r[6] or 0}
        for r in cur.fetchall()
    ]
    
    db.close()
    return jsonify(patterns)


@app.route('/api/alerts')
def api_alerts():
    hours = int(request.args.get('hours', 24))
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        SELECT alert_type, severity, title, description, created_at
        FROM alerts
        WHERE created_at >= ?
        ORDER BY created_at DESC
        LIMIT 50
    """, (since,))
    
    alerts = [
        {'alert_type': r[0], 'severity': r[1], 'title': r[2], 
         'description': r[3], 'created_at': r[4]}
        for r in cur.fetchall()
    ]
    
    db.close()
    return jsonify({'alerts': alerts})


@app.route('/api/pattern-hosts')
def api_pattern_hosts():
    """Get hosts matching a specific pattern, filtered by time."""
    pattern_name = request.args.get('name', '')
    hours = int(request.args.get('hours', 24))
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    
    db = get_db()
    cur = db.cursor()
    
    # Get pattern info
    cur.execute("SELECT id, confidence FROM patterns WHERE name = ?", (pattern_name,))
    row = cur.fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Pattern not found', 'hosts': [], 'confidence': 'unknown'})
    
    pattern_id, confidence = row
    
    # Get new hosts matching this pattern
    cur.execute("""
        SELECT h.ip, h.country, h.asn_name, h.first_seen, h.jarm
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        WHERE m.pattern_id = ? AND h.first_seen >= ?
        ORDER BY h.first_seen DESC
        LIMIT 100
    """, (pattern_id, since))
    
    hosts = [
        {'ip': r[0], 'country': r[1], 'asn_name': r[2], 'first_seen': r[3], 'jarm': r[4]}
        for r in cur.fetchall()
    ]
    
    db.close()
    return jsonify({
        'pattern': pattern_name,
        'pattern_id': pattern_id,
        'confidence': confidence or 'medium',
        'hosts': hosts,
        'count': len(hosts)
    })


@app.route('/api/pattern/<int:pattern_id>/stix')
def api_pattern_stix(pattern_id):
    """Download STIX 2.1 bundle for a pattern's matched hosts."""
    import uuid
    
    db = get_db()
    cur = db.cursor()
    
    # Get pattern info
    cur.execute("SELECT id, name, pattern_type, description FROM patterns WHERE id = ?", (pattern_id,))
    row = cur.fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Pattern not found'}), 404
    
    _, pattern_name, pattern_type, description = row
    
    # Get all hosts matching this pattern
    cur.execute("""
        SELECT h.ip, h.country, h.asn_name, h.first_seen, h.jarm
        FROM hosts h
        JOIN matches m ON h.id = m.host_id
        WHERE m.pattern_id = ?
    """, (pattern_id,))
    
    hosts = cur.fetchall()
    db.close()
    
    if not hosts:
        return jsonify({'error': 'No hosts found for this pattern'}), 404
    
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
    objects = []
    
    # Create Infrastructure object
    infra_id = f"infrastructure--{uuid.uuid5(uuid.NAMESPACE_DNS, f'infra-hunter-{pattern_id}')}"
    infra = {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": infra_id,
        "created": now,
        "modified": now,
        "name": pattern_name,
        "description": description or f"C2 infrastructure detected by pattern: {pattern_type}",
        "infrastructure_types": ["command-and-control"],
    }
    objects.append(infra)
    
    # Create Indicator for each host
    for host in hosts:
        ip, country, asn_name, first_seen, jarm = host
        indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{pattern_id}-{ip}')}"
        
        created_time = first_seen if first_seen else now
        if isinstance(created_time, str) and 'T' not in created_time:
            created_time = created_time.replace(' ', 'T') + '.000Z'
        elif not isinstance(created_time, str):
            created_time = now
        
        labels = ["c2", pattern_type or "unknown"]
        if country:
            labels.append(f"country:{country}")
        if asn_name:
            labels.append(f"asn:{asn_name[:50]}")
        if jarm:
            labels.append(f"jarm:{jarm[:16]}")
        
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": created_time,
            "modified": now,
            "name": f"{pattern_name} - {ip}",
            "description": f"C2 infrastructure IP detected via {pattern_type}",
            "indicator_types": ["malicious-activity", "attribution"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": created_time,
            "labels": labels,
        }
        objects.append(indicator)
        
        # Relationship: indicator -> infrastructure
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": infra_id,
        }
        objects.append(rel)
    
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    
    filename = f"infra-hunter-{pattern_name.lower().replace(' ', '-')}-stix.json"
    
    return Response(
        json.dumps(bundle, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


if __name__ == '__main__':
    print(f"Using database: {DB_PATH}")
    app.run(host='0.0.0.0', port=5003, debug=False)
