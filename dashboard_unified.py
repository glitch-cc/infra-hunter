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
        
        /* Deep Dive Side Panel */
        .side-panel {
            position: fixed;
            top: 0;
            right: -500px;
            width: 500px;
            height: 100vh;
            background: #161b22;
            border-left: 1px solid #30363d;
            z-index: 1001;
            transition: right 0.3s ease;
            display: flex;
            flex-direction: column;
            box-shadow: -5px 0 20px rgba(0,0,0,0.5);
        }
        .side-panel.active { right: 0; }
        .side-panel-header {
            padding: 16px 20px;
            background: #21262d;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .side-panel-header h3 { color: #f0f6fc; font-size: 1.1em; }
        .side-panel-close {
            background: none;
            border: none;
            color: #8b949e;
            font-size: 1.5em;
            cursor: pointer;
        }
        .side-panel-close:hover { color: #f0f6fc; }
        .side-panel-body {
            padding: 20px;
            overflow-y: auto;
            flex: 1;
        }
        .side-panel-actions {
            padding: 16px 20px;
            background: #21262d;
            border-top: 1px solid #30363d;
            display: flex;
            gap: 10px;
        }
        .side-panel-actions button {
            padding: 8px 16px;
            border-radius: 6px;
            border: 1px solid #30363d;
            background: #21262d;
            color: #c9d1d9;
            cursor: pointer;
            font-size: 0.9em;
        }
        .side-panel-actions button:hover { background: #30363d; }
        .side-panel-actions button.primary {
            background: #238636;
            border-color: #238636;
            color: white;
        }
        .side-panel-actions button.primary:hover { background: #2ea043; }
        
        .deep-dive-section {
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #30363d;
        }
        .deep-dive-section:last-child { border-bottom: none; }
        .deep-dive-section h4 {
            color: #58a6ff;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 12px;
        }
        .deep-dive-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            font-size: 0.9em;
        }
        .deep-dive-row .label { color: #8b949e; }
        .deep-dive-row .value { color: #f0f6fc; font-family: monospace; }
        .deep-dive-row .value.warn { color: #d29922; }
        .deep-dive-row .value.danger { color: #f85149; }
        .deep-dive-row .value.safe { color: #3fb950; }
        
        .service-card {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 10px;
        }
        .service-card-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .service-port { color: #79c0ff; font-weight: bold; }
        .service-proto { color: #8b949e; font-size: 0.85em; }
        .service-details { font-size: 0.85em; color: #8b949e; }
        .service-details code {
            background: #21262d;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
            color: #c9d1d9;
        }
        
        .ip-link {
            color: #79c0ff;
            cursor: pointer;
            text-decoration: none;
        }
        .ip-link:hover { text-decoration: underline; }
        
        .jarm-display {
            font-family: monospace;
            font-size: 0.75em;
            word-break: break-all;
            background: #0d1117;
            padding: 8px;
            border-radius: 4px;
            margin-top: 8px;
        }
        
        .loading-spinner {
            text-align: center;
            padding: 40px;
            color: #8b949e;
        }
        
        .side-panel-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        .side-panel-overlay.active { display: block; }
        
        /* Contact Cards */
        .contact-card {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
        }
        .contact-card.security { border-left: 3px solid #3fb950; }
        .contact-card .contact-name {
            font-weight: 600;
            color: #f0f6fc;
        }
        .contact-card .contact-title {
            font-size: 0.85em;
            color: #8b949e;
            margin: 4px 0;
        }
        .contact-card .contact-email {
            font-family: monospace;
            color: #79c0ff;
            font-size: 0.9em;
        }
        .contact-card .contact-source {
            font-size: 0.75em;
            color: #8b949e;
            float: right;
        }
        .contact-card .contact-actions {
            margin-top: 8px;
        }
        .contact-card .contact-actions a {
            font-size: 0.8em;
            color: #58a6ff;
            margin-right: 12px;
            text-decoration: none;
        }
        .contact-card .contact-actions a:hover { text-decoration: underline; }
        
        .standard-emails {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }
        .standard-email {
            background: #21262d;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85em;
            color: #79c0ff;
            cursor: pointer;
        }
        .standard-email:hover { background: #30363d; }
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
                <td class="ip"><span class="ip-link" onclick="openDeepDive('${h.ip}')">${h.ip}</span></td>
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
                <td class="ip"><span class="ip-link" onclick="openDeepDive('${h.ip}')">${h.ip}</span></td>
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
            document.getElementById('modal-stix-link').href = 'api/pattern/' + data.pattern_id + '/stix';
            document.getElementById('modal-stix-link').style.display = 'inline';
        } else {
            document.getElementById('modal-stix-link').style.display = 'none';
        }
        
        document.getElementById('modal-confidence').textContent = data.confidence || 'medium';
        
        const hostsHtml = (data.hosts || []).map(h => `
            <tr>
                <td class="ip"><span class="ip-link" onclick="openDeepDive('${h.ip}')">${h.ip}</span></td>
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
    document.addEventListener('keydown', e => { 
        if (e.key === 'Escape') {
            closeModal();
            closeSidePanel();
        }
    });
    
    // ========== DEEP DIVE SIDE PANEL ==========
    
    let currentDeepDiveData = null;
    
    async function openDeepDive(ip) {
        const panel = document.getElementById('deep-dive-panel');
        const overlay = document.getElementById('side-panel-overlay');
        const body = document.getElementById('deep-dive-body');
        
        // Show panel with loading state
        panel.classList.add('active');
        overlay.classList.add('active');
        document.getElementById('deep-dive-ip').textContent = ip;
        body.innerHTML = '<div class="loading-spinner">🔍 Fetching intel for ' + ip + '...</div>';
        
        try {
            const resp = await fetch('api/host/' + ip + '/deepdive');
            const data = await resp.json();
            
            if (data.error) {
                body.innerHTML = '<div class="empty">❌ ' + data.error + '</div>';
                return;
            }
            
            currentDeepDiveData = data;
            renderDeepDive(data);
        } catch (err) {
            body.innerHTML = '<div class="empty">❌ Failed to fetch data: ' + err.message + '</div>';
        }
    }
    
    function renderDeepDive(data) {
        const body = document.getElementById('deep-dive-body');
        
        let html = '';
        
        // Basic Info Section
        html += '<div class="deep-dive-section">';
        html += '<h4>📍 Basic Info</h4>';
        html += '<div class="deep-dive-row"><span class="label">IP Address</span><span class="value">' + data.ip + '</span></div>';
        html += '<div class="deep-dive-row"><span class="label">ASN</span><span class="value">' + (data.asn?.name || 'Unknown') + '</span></div>';
        html += '<div class="deep-dive-row"><span class="label">ASN Number</span><span class="value">AS' + (data.asn?.asn || '?') + '</span></div>';
        html += '<div class="deep-dive-row"><span class="label">Location</span><span class="value">' + (data.location?.city || '?') + ', ' + (data.location?.country || '?') + '</span></div>';
        if (data.jarm) {
            html += '<div class="deep-dive-row"><span class="label">JARM</span></div>';
            html += '<div class="jarm-display">' + data.jarm + '</div>';
        }
        html += '</div>';
        
        // Pattern Matches Section
        if (data.patterns && data.patterns.length > 0) {
            html += '<div class="deep-dive-section">';
            html += '<h4>🎯 Pattern Matches</h4>';
            data.patterns.forEach(p => {
                html += '<div class="deep-dive-row"><span class="label">' + p.name + '</span><span class="value danger">' + p.matched_at + '</span></div>';
            });
            html += '</div>';
        }
        
        // Services Section
        if (data.services && data.services.length > 0) {
            html += '<div class="deep-dive-section">';
            html += '<h4>🔌 Services (' + data.services.length + ')</h4>';
            data.services.forEach(svc => {
                html += '<div class="service-card">';
                html += '<div class="service-card-header">';
                html += '<span class="service-port">:' + svc.port + '</span>';
                html += '<span class="service-proto">' + (svc.protocol || 'TCP') + '</span>';
                html += '</div>';
                html += '<div class="service-details">';
                if (svc.service_name) html += '<div>Service: <code>' + svc.service_name + '</code></div>';
                if (svc.product) html += '<div>Product: <code>' + svc.product + '</code></div>';
                if (svc.banner) html += '<div>Banner: <code>' + svc.banner.substring(0, 80) + (svc.banner.length > 80 ? '...' : '') + '</code></div>';
                if (svc.tls_subject) html += '<div>TLS: <code>' + svc.tls_subject + '</code></div>';
                if (svc.http_title) html += '<div>Title: <code>' + svc.http_title + '</code></div>';
                html += '</div>';
                html += '</div>';
            });
            html += '</div>';
        }
        
        // Timeline Section
        if (data.timeline && data.timeline.length > 0) {
            html += '<div class="deep-dive-section">';
            html += '<h4>📅 Timeline</h4>';
            html += '<div class="deep-dive-row"><span class="label">First Seen</span><span class="value">' + (data.first_seen || 'Unknown') + '</span></div>';
            html += '<div class="deep-dive-row"><span class="label">Last Seen</span><span class="value">' + (data.last_seen || 'Unknown') + '</span></div>';
            html += '</div>';
        }
        
        // Risk Assessment
        html += '<div class="deep-dive-section">';
        html += '<h4>⚠️ Risk Assessment</h4>';
        const riskClass = data.risk_level === 'high' ? 'danger' : (data.risk_level === 'medium' ? 'warn' : 'safe');
        html += '<div class="deep-dive-row"><span class="label">Risk Level</span><span class="value ' + riskClass + '">' + (data.risk_level || 'Unknown').toUpperCase() + '</span></div>';
        if (data.risk_factors && data.risk_factors.length > 0) {
            data.risk_factors.forEach(rf => {
                html += '<div class="deep-dive-row"><span class="label">• ' + rf + '</span></div>';
            });
        }
        html += '</div>';
        
        body.innerHTML = html;
    }
    
    function closeSidePanel() {
        document.getElementById('deep-dive-panel').classList.remove('active');
        document.getElementById('side-panel-overlay').classList.remove('active');
        currentDeepDiveData = null;
    }
    
    function downloadDeepDive() {
        if (!currentDeepDiveData) return;
        
        const blob = new Blob([JSON.stringify(currentDeepDiveData, null, 2)], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'deepdive-' + currentDeepDiveData.ip + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    
    async function findContacts() {
        if (!currentDeepDiveData || !currentDeepDiveData.asn) return;
        
        const orgName = currentDeepDiveData.asn.name || currentDeepDiveData.asn;
        if (!orgName) {
            alert('No organization name available');
            return;
        }
        
        const btn = document.getElementById('find-contacts-btn');
        btn.textContent = '🔄 Searching...';
        btn.disabled = true;
        
        try {
            const resp = await fetch('api/org/' + encodeURIComponent(orgName) + '/contacts');
            const data = await resp.json();
            
            // Add contacts to deep dive data
            currentDeepDiveData.contacts = data;
            
            // Render contacts section
            let html = '<div class="deep-dive-section"><h4>📇 Security Contacts</h4>';
            
            if (data.error) {
                html += '<p style="color:#f85149;">' + data.error + '</p>';
            } else {
                // Domain and email pattern
                if (data.domain) {
                    html += '<div class="deep-dive-row"><span class="label">Domain</span><span class="value">' + data.domain + '</span></div>';
                }
                if (data.email_pattern) {
                    html += '<div class="deep-dive-row"><span class="label">Email Pattern</span><span class="value">' + data.email_pattern + '</span></div>';
                }
                
                // Standard security emails
                if (data.standard_emails && data.standard_emails.length > 0) {
                    html += '<div style="margin:12px 0;"><span class="label">Standard Security Emails:</span>';
                    html += '<div class="standard-emails">';
                    data.standard_emails.forEach(e => {
                        html += '<span class="standard-email" onclick="copyToClipboard(\'' + e.email + '\')" title="Click to copy">' + e.email + '</span>';
                    });
                    html += '</div></div>';
                }
                
                // Security contacts
                const securityContacts = (data.contacts || []).filter(c => c.is_security_role);
                if (securityContacts.length > 0) {
                    html += '<div style="margin-top:15px;"><span class="label">Security/IR Contacts (' + securityContacts.length + '):</span></div>';
                    securityContacts.forEach(c => {
                        html += '<div class="contact-card security">';
                        html += '<span class="contact-source">' + (c.source || '') + '</span>';
                        html += '<div class="contact-name">' + (c.first_name || '') + ' ' + (c.last_name || '') + '</div>';
                        html += '<div class="contact-title">' + (c.position || 'Unknown Role') + '</div>';
                        html += '<div class="contact-email">' + (c.email || 'No email') + '</div>';
                        if (c.linkedin || c.email) {
                            html += '<div class="contact-actions">';
                            if (c.email) html += '<a href="mailto:' + c.email + '">✉️ Email</a>';
                            if (c.linkedin) html += '<a href="' + c.linkedin + '" target="_blank">🔗 LinkedIn</a>';
                            html += '</div>';
                        }
                        html += '</div>';
                    });
                }
                
                // Other contacts (IT, etc)
                const otherContacts = (data.contacts || []).filter(c => !c.is_security_role);
                if (otherContacts.length > 0) {
                    html += '<div style="margin-top:15px;"><span class="label">Other IT Contacts (' + otherContacts.length + '):</span></div>';
                    otherContacts.slice(0, 5).forEach(c => {
                        html += '<div class="contact-card">';
                        html += '<span class="contact-source">' + (c.source || '') + '</span>';
                        html += '<div class="contact-name">' + (c.first_name || '') + ' ' + (c.last_name || '') + '</div>';
                        html += '<div class="contact-title">' + (c.position || 'Unknown Role') + '</div>';
                        html += '<div class="contact-email">' + (c.email || 'No email') + '</div>';
                        html += '</div>';
                    });
                }
                
                if (data.total_contacts === 0 && (!data.standard_emails || data.standard_emails.length === 0)) {
                    html += '<p style="color:#8b949e;">No contacts found</p>';
                }
            }
            
            html += '</div>';
            
            // Append to body
            document.getElementById('deep-dive-body').innerHTML += html;
            
            btn.textContent = '✅ Contacts Found';
            setTimeout(() => { btn.textContent = '🔍 Find Contacts'; btn.disabled = false; }, 2000);
            
        } catch (err) {
            btn.textContent = '❌ Error';
            setTimeout(() => { btn.textContent = '🔍 Find Contacts'; btn.disabled = false; }, 2000);
            console.error('Contact search error:', err);
        }
    }
    
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            // Brief visual feedback could be added here
        });
    }
    
    // Initial load
    loadData();
    </script>
    
    <!-- Deep Dive Side Panel -->
    <div class="side-panel-overlay" id="side-panel-overlay" onclick="closeSidePanel()"></div>
    <div class="side-panel" id="deep-dive-panel">
        <div class="side-panel-header">
            <h3>🔍 Deep Dive: <span id="deep-dive-ip"></span></h3>
            <button class="side-panel-close" onclick="closeSidePanel()">&times;</button>
        </div>
        <div class="side-panel-body" id="deep-dive-body">
            <!-- Content loaded dynamically -->
        </div>
        <div class="side-panel-actions">
            <button onclick="findContacts()" id="find-contacts-btn">🔍 Find Contacts</button>
            <button onclick="downloadDeepDive()" class="primary">📥 Download JSON</button>
            <button onclick="closeSidePanel()">Close</button>
        </div>
    </div>
</body>
</html>
'''


# ============== API ROUTES ==============

@app.route('/')
def index():
    resp = Response(render_template_string(TEMPLATE), content_type='text/html; charset=utf-8')
    return resp


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


@app.route('/api/host/<ip>/deepdive')
def api_host_deepdive(ip):
    """Get deep dive intel for a specific host IP."""
    import subprocess
    import re
    
    db = get_db()
    cur = db.cursor()
    
    # Get host from our database
    cur.execute("""
        SELECT h.id, h.ip, h.country, h.asn_name, h.jarm, h.ports, h.first_seen, h.last_seen
        FROM hosts h WHERE h.ip = ?
    """, (ip,))
    row = cur.fetchone()
    
    if not row:
        db.close()
        return jsonify({'error': 'Host not found in database', 'ip': ip})
    
    host_id, ip, country, asn_name, jarm, ports, first_seen, last_seen = row
    
    # Get pattern matches
    cur.execute("""
        SELECT p.name, p.pattern_type, m.matched_at
        FROM matches m
        JOIN patterns p ON m.pattern_id = p.id
        WHERE m.host_id = ?
        ORDER BY m.matched_at DESC
    """, (host_id,))
    patterns = [{'name': r[0], 'type': r[1], 'matched_at': r[2]} for r in cur.fetchall()]
    db.close()
    
    # Build response
    result = {
        'ip': ip,
        'country': country,
        'asn': {'name': asn_name},
        'jarm': jarm,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'patterns': patterns,
        'services': [],
        'location': {'country': country},
        'risk_level': 'unknown',
        'risk_factors': []
    }
    
    # Try to get Censys data using cencli (handles auth properly)
    try:
        import subprocess
        
        # Find cencli - check local path first, then system path
        cencli_paths = ['/app/cencli', '/usr/local/bin/cencli', 'cencli']
        cencli_cmd = None
        for path in cencli_paths:
            if os.path.exists(path):
                cencli_cmd = path
                break
        
        if not cencli_cmd:
            result['censys_error'] = 'cencli not found'
        else:
            # Run cencli to get host data
            proc = subprocess.run(
                [cencli_cmd, 'view', ip, '-O', 'json'],
                capture_output=True,
                text=True,
                timeout=15
            )
        
            if proc.returncode == 0 and proc.stdout:
                censys_data = json.loads(proc.stdout)
                if isinstance(censys_data, list) and len(censys_data) > 0:
                    host_data = censys_data[0]
                    
                    # Extract ASN info
                    if 'autonomous_system' in host_data:
                        asn_info = host_data['autonomous_system']
                        result['asn'] = {
                            'asn': asn_info.get('asn'),
                            'name': asn_info.get('name') or asn_info.get('description'),
                            'bgp_prefix': asn_info.get('bgp_prefix')
                        }
                    
                    # Extract location
                    if 'location' in host_data:
                        loc = host_data['location']
                        result['location'] = {
                            'city': loc.get('city'),
                            'province': loc.get('province'),
                            'country': loc.get('country'),
                            'timezone': loc.get('timezone'),
                            'coordinates': loc.get('coordinates')
                        }
                    
                    # Extract services
                    services = []
                    for svc in host_data.get('services', []):
                        service_info = {
                            'port': svc.get('port'),
                            'protocol': svc.get('transport_protocol', 'tcp').upper(),
                            'service_name': svc.get('service_name') or svc.get('protocol'),
                        }
                        
                        # Get banner
                        if svc.get('banner'):
                            service_info['banner'] = svc['banner'][:200]
                        
                        # Get software/product info
                        if svc.get('software'):
                            sw = svc['software'][0] if isinstance(svc['software'], list) else svc['software']
                            if isinstance(sw, dict):
                                service_info['product'] = sw.get('product') or sw.get('vendor')
                        
                        # SSH specific
                        if svc.get('ssh', {}).get('endpoint_id', {}).get('software_version'):
                            service_info['product'] = svc['ssh']['endpoint_id']['software_version']
                        
                        # HTTP specific
                        if svc.get('http', {}).get('response', {}).get('html_title'):
                            service_info['http_title'] = svc['http']['response']['html_title']
                        
                        # TLS specific
                        if svc.get('tls', {}).get('certificates', {}).get('leaf_data', {}).get('subject_dn'):
                            service_info['tls_subject'] = svc['tls']['certificates']['leaf_data']['subject_dn']
                        
                        services.append(service_info)
                    
                    result['services'] = services
            else:
                result['censys_error'] = proc.stderr or 'cencli failed'
    except subprocess.TimeoutExpired:
        result['censys_error'] = 'Censys lookup timed out'
    except FileNotFoundError:
        result['censys_error'] = 'cencli not installed'
    except Exception as e:
        result['censys_error'] = str(e)
    
    # Calculate risk level
    risk_factors = []
    risk_score = 0
    
    if patterns:
        risk_score += 30
        for p in patterns:
            if 'cobalt' in p['name'].lower():
                risk_factors.append('Cobalt Strike JARM signature match')
                risk_score += 40
            elif 'sliver' in p['name'].lower() or 'mythic' in p['name'].lower():
                risk_factors.append(f'{p["name"]} C2 framework signature')
                risk_score += 35
            else:
                risk_factors.append(f'Pattern match: {p["name"]}')
                risk_score += 20
    
    # Check for concerning services
    for svc in result.get('services', []):
        product = (svc.get('product') or '').lower()
        if 'goanywhere' in product:
            risk_factors.append('GoAnywhere MFT detected (CVE-2023-0669 target)')
            risk_score += 25
        if svc.get('port') in [4444, 5555, 8443, 50050]:
            risk_factors.append(f'Suspicious port {svc["port"]} open')
            risk_score += 15
    
    if risk_score >= 60:
        result['risk_level'] = 'high'
    elif risk_score >= 30:
        result['risk_level'] = 'medium'
    else:
        result['risk_level'] = 'low'
    
    result['risk_factors'] = risk_factors
    result['risk_score'] = risk_score
    
    return jsonify(result)


@app.route('/api/org/<path:org_name>/contacts')
def api_org_contacts(org_name):
    """Find security/IT contacts for an organization."""
    import requests as req
    import re
    
    result = {
        'organization': org_name,
        'domain': None,
        'contacts': [],
        'standard_emails': [],
        'email_pattern': None,
        'linkedin_company': None,
    }
    
    # Get API keys from environment
    hunter_key = os.environ.get('HUNTER_API_KEY')
    apollo_key = os.environ.get('APOLLO_API_KEY')
    rapidapi_key = os.environ.get('RAPIDAPI_KEY')
    
    # Try to extract/guess domain from org name
    # Common patterns: "Company Name" -> company.com, company.org, company.edu
    org_lower = org_name.lower()
    domain = None
    
    # Check for known patterns
    if 'college' in org_lower or 'university' in org_lower or 'institute' in org_lower:
        # Educational - try .edu
        words = re.sub(r'[^a-z\s]', '', org_lower).split()
        # Try abbreviation or key word
        if 'baylor' in words:
            domain = 'bcm.edu'  # Baylor College of Medicine
    
    # If no domain found, try Hunter domain search by company name
    if not domain and hunter_key:
        try:
            resp = req.get(
                'https://api.hunter.io/v2/domain-search',
                params={'company': org_name, 'api_key': hunter_key},
                timeout=15
            )
            if resp.ok:
                data = resp.json().get('data', {})
                domain = data.get('domain')
                result['email_pattern'] = data.get('pattern')
        except Exception as e:
            result['hunter_error'] = str(e)
    
    if domain:
        result['domain'] = domain
        
        # Generate standard security emails
        result['standard_emails'] = [
            {'email': f'abuse@{domain}', 'type': 'Standard', 'role': 'Abuse Contact'},
            {'email': f'security@{domain}', 'type': 'Standard', 'role': 'Security Team'},
            {'email': f'soc@{domain}', 'type': 'Standard', 'role': 'Security Operations'},
            {'email': f'csirt@{domain}', 'type': 'Standard', 'role': 'Incident Response'},
            {'email': f'infosec@{domain}', 'type': 'Standard', 'role': 'Information Security'},
            {'email': f'it-security@{domain}', 'type': 'Standard', 'role': 'IT Security'},
        ]
        
        # Search Hunter.io for actual contacts
        if hunter_key:
            try:
                resp = req.get(
                    'https://api.hunter.io/v2/domain-search',
                    params={'domain': domain, 'api_key': hunter_key, 'limit': 20},
                    timeout=15
                )
                if resp.ok:
                    data = resp.json().get('data', {})
                    result['email_pattern'] = data.get('pattern')
                    result['organization'] = data.get('organization') or org_name
                    
                    # Filter for security/IT roles
                    security_keywords = ['security', 'ciso', 'cso', 'infosec', 'cyber', 
                                        'incident', 'soc', 'threat', 'vulnerability',
                                        'it director', 'it manager', 'cto', 'cio',
                                        'information security', 'network security']
                    
                    for email in data.get('emails', []):
                        position = (email.get('position') or '').lower()
                        # Check if security/IT related
                        is_security = any(kw in position for kw in security_keywords)
                        
                        contact = {
                            'email': email.get('value'),
                            'first_name': email.get('first_name'),
                            'last_name': email.get('last_name'),
                            'position': email.get('position'),
                            'confidence': email.get('confidence'),
                            'linkedin': email.get('linkedin'),
                            'is_security_role': is_security,
                            'source': 'Hunter.io'
                        }
                        result['contacts'].append(contact)
                    
                    # Sort: security roles first, then by confidence
                    result['contacts'].sort(
                        key=lambda x: (not x.get('is_security_role', False), -(x.get('confidence') or 0))
                    )
            except Exception as e:
                result['hunter_error'] = str(e)
        
        # Search Apollo for security titles
        if apollo_key:
            try:
                # Search for people with security titles at this company
                resp = req.post(
                    'https://api.apollo.io/api/v1/mixed_people/search',
                    headers={'X-Api-Key': apollo_key, 'Content-Type': 'application/json'},
                    json={
                        'organization_domains': [domain],
                        'person_titles': ['CISO', 'CSO', 'Chief Security Officer', 
                                         'Chief Information Security Officer',
                                         'VP Security', 'Director of Security',
                                         'Security Director', 'IT Director',
                                         'Information Security Manager',
                                         'Security Operations Manager'],
                        'per_page': 10
                    },
                    timeout=15
                )
                if resp.ok:
                    people = resp.json().get('people', [])
                    for person in people:
                        # Check if we already have this email
                        email = person.get('email')
                        if email and not any(c.get('email') == email for c in result['contacts']):
                            contact = {
                                'email': email,
                                'first_name': person.get('first_name'),
                                'last_name': person.get('last_name'),
                                'position': person.get('title'),
                                'linkedin': person.get('linkedin_url'),
                                'is_security_role': True,
                                'source': 'Apollo'
                            }
                            result['contacts'].insert(0, contact)  # Add at top
            except Exception as e:
                result['apollo_error'] = str(e)
        
        # LinkedIn employee search via RapidAPI
        if rapidapi_key:
            try:
                # First get company LinkedIn URL
                company_resp = req.get(
                    f'https://fresh-linkedin-profile-data.p.rapidapi.com/get-company-by-domain?domain={domain}',
                    headers={
                        'x-rapidapi-key': rapidapi_key,
                        'x-rapidapi-host': 'fresh-linkedin-profile-data.p.rapidapi.com'
                    },
                    timeout=15
                )
                
                if company_resp.ok:
                    company_data = company_resp.json().get('data', {})
                    result['linkedin_company'] = {
                        'name': company_data.get('company_name'),
                        'url': company_data.get('linkedin_url'),
                        'employees': company_data.get('employee_count'),
                        'industry': company_data.get('industry')
                    }
                    
                    # Search for security and IT employees
                    linkedin_url = company_data.get('linkedin_url')
                    if linkedin_url:
                        # Security roles first, then IT roles
                        security_roles = ['CISO', 'Chief Information Security', 'Security Director', 
                                         'Information Security', 'Incident Response', 'Security Operations',
                                         'Cybersecurity', 'Threat Intelligence', 'SOC Manager']
                        it_roles = ['CIO', 'Chief Information Officer', 'IT Director', 'VP IT',
                                   'Director of IT', 'IT Manager', 'Infrastructure Manager',
                                   'Network Director', 'Systems Director', 'CTO', 'Chief Technology']
                        
                        for role in security_roles + it_roles:
                            try:
                                emp_resp = req.post(
                                    'https://fresh-linkedin-profile-data.p.rapidapi.com/search-employees',
                                    headers={
                                        'x-rapidapi-key': rapidapi_key,
                                        'x-rapidapi-host': 'fresh-linkedin-profile-data.p.rapidapi.com',
                                        'Content-Type': 'application/json'
                                    },
                                    json={
                                        'company_linkedin_url': linkedin_url,
                                        'keyword': role,
                                        'page': 1
                                    },
                                    timeout=20
                                )
                                
                                if emp_resp.ok:
                                    employees = emp_resp.json().get('data', [])
                                    for emp in employees[:3]:  # Top 3 per role
                                        # Check if already have this person
                                        emp_linkedin = emp.get('linkedin_url')
                                        if emp_linkedin and not any(c.get('linkedin') == emp_linkedin for c in result['contacts']):
                                            is_security = role in security_roles
                                            contact = {
                                                'first_name': emp.get('first_name'),
                                                'last_name': emp.get('last_name'),
                                                'position': emp.get('title'),
                                                'linkedin': emp_linkedin,
                                                'is_security_role': is_security,
                                                'is_it_role': not is_security,
                                                'source': 'LinkedIn',
                                                'profile_picture': emp.get('profile_picture')
                                            }
                                            # Security at top, IT after
                                            if is_security:
                                                result['contacts'].insert(0, contact)
                                            else:
                                                result['contacts'].append(contact)
                            except:
                                pass  # Continue with next role
            except Exception as e:
                result['linkedin_error'] = str(e)
    else:
        result['error'] = 'Could not determine domain for organization'
    
    # Count security vs other contacts
    result['security_contacts'] = len([c for c in result['contacts'] if c.get('is_security_role')])
    result['total_contacts'] = len(result['contacts'])
    
    return jsonify(result)


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
