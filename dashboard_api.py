#!/usr/bin/env python3
"""
Dashboard API for SDN Firewall - FIXED VERSION
Real-time statistics from controller logs
"""

from flask import Flask, jsonify, send_file
from flask_cors import CORS
import json
import os
import re
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
CORS(app)  # Allow frontend to access

# File paths
LOG_FILE = "ryu.log"
STATS_CACHE = {}
LAST_UPDATE = None
UPDATE_INTERVAL = 2  # Update cache every 2 seconds

def parse_controller_log():
    """Parse ryu.log and extract stats - FIXED VERSION"""
    global STATS_CACHE, LAST_UPDATE
    
    # Check if need to update (cache mechanism)
    now = datetime.now()
    if LAST_UPDATE and (now - LAST_UPDATE).seconds < UPDATE_INTERVAL:
        return STATS_CACHE
    
    # Initialize stats
    stats = {
        'allowed': 0,
        'blocked': 0,
        'encrypted': 0,
        'plaintext': 0,
        'unverified': 0,
        'switches': 0,
        'flows': [],
        'top_sources': defaultdict(int),
        'top_destinations': defaultdict(int),
        'recent_events': []
    }
    
    if not os.path.exists(LOG_FILE):
        STATS_CACHE = stats
        LAST_UPDATE = now
        return stats
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            # Process last 300 lines for better accuracy
            for line in lines[-300:]:
                # Extract timestamp from line if available
                time_match = re.search(r'(\d{2}:\d{2}:\d{2})', line)
                timestamp = time_match.group(1) if time_match else datetime.now().strftime('%H:%M:%S')
                
                # Count switches
                if 'Switch' in line and 'connected' in line:
                    stats['switches'] += 1
                
                # Count allowed flows - Multiple patterns
                if '✅ ALLOWED' in line or 'ALLOWED by policy' in line or 'ALLOWED by default' in line:
                    stats['allowed'] += 1
                    
                    # Extract IPs using improved regex
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(?:→|->)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        src, dst = ip_match.groups()
                        stats['top_sources'][src] += 1
                        stats['top_destinations'][dst] += 1
                        
                        # Add to flows list
                        stats['flows'].append({
                            'src': src,
                            'dst': dst,
                            'status': 'allowed',
                            'time': timestamp
                        })
                
                # Count blocked flows
                if '🚫 BLOCKED' in line or 'BLOCKED by policy' in line:
                    stats['blocked'] += 1
                    
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(?:→|->)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        src, dst = ip_match.groups()
                        stats['top_sources'][src] += 1
                        stats['top_destinations'][dst] += 1
                        
                        stats['flows'].append({
                            'src': src,
                            'dst': dst,
                            'status': 'blocked',
                            'time': timestamp
                        })
                        
                        stats['recent_events'].append({
                            'type': 'blocked',
                            'severity': 'high',
                            'message': f'Traffic blocked: {src} → {dst}',
                            'time': timestamp
                        })
                
                # Count encrypted traffic
                if '🔒 ENCRYPTED' in line or 'ENCRYPTED:' in line:
                    stats['encrypted'] += 1
                    
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(?:→|->)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        src, dst = ip_match.groups()
                        stats['flows'].append({
                            'src': src,
                            'dst': dst,
                            'status': 'encrypted',
                            'time': timestamp
                        })
                
                # Count plaintext traffic
                if '📡 PLAINTEXT' in line or 'PLAINTEXT:' in line:
                    stats['plaintext'] += 1
                
                # Count unverified attempts
                if '🔐 UNVERIFIED' in line or 'UNVERIFIED HOST' in line:
                    stats['unverified'] += 1
                    
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(?:→|->)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        src, dst = ip_match.groups()
                        stats['recent_events'].append({
                            'type': 'unverified',
                            'severity': 'medium',
                            'message': f'Unverified host attempt: {src} → {dst}',
                            'time': timestamp
                        })
        
        # Keep only last 15 flows and events
        stats['flows'] = stats['flows'][-15:]
        stats['recent_events'] = stats['recent_events'][-15:]
        
        # Convert defaultdict to regular dict for JSON serialization
        stats['top_sources'] = dict(stats['top_sources'])
        stats['top_destinations'] = dict(stats['top_destinations'])
        
        STATS_CACHE = stats
        LAST_UPDATE = now
        
    except Exception as e:
        print(f"Error parsing log: {e}")
        STATS_CACHE = stats
        LAST_UPDATE = now
    
    return stats

@app.route('/api/stats')
def get_stats():
    """Get overall statistics - FIXED VERSION"""
    stats = parse_controller_log()
    
    # Calculate rates safely
    total_traffic = stats['encrypted'] + stats['plaintext']
    encryption_rate = round((stats['encrypted'] / max(total_traffic, 1)) * 100, 1)
    
    total_flows = stats['allowed'] + stats['blocked']
    block_rate = round((stats['blocked'] / max(total_flows, 1)) * 100, 1)
    
    return jsonify({
        'allowed': stats['allowed'],
        'blocked': stats['blocked'],
        'encrypted': stats['encrypted'],
        'plaintext': stats['plaintext'],
        'unverified': stats['unverified'],
        'switches': stats['switches'],
        'encryption_rate': encryption_rate,
        'block_rate': block_rate,
        'total_flows': total_flows,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/flows')
def get_flows():
    """Get recent flows"""
    stats = parse_controller_log()
    return jsonify({
        'flows': stats['flows'],
        'count': len(stats['flows'])
    })


@app.route('/api/top-hosts')
def get_top_hosts():
    """Get top communicating hosts"""
    stats = parse_controller_log()
    
    # Convert to sorted lists
    top_sources = sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:5]
    top_destinations = sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:5]
    
    return jsonify({
        'sources': [{'ip': ip, 'count': count} for ip, count in top_sources],
        'destinations': [{'ip': ip, 'count': count} for ip, count in top_destinations]
    })


@app.route('/api/events')
def get_events():
    """Get recent security events"""
    stats = parse_controller_log()
    return jsonify({
        'events': stats['recent_events'],
        'count': len(stats['recent_events'])
    })


@app.route('/api/policy')
def get_policy():
    """Get current firewall policy"""
    try:
        with open('policy.json', 'r') as f:
            policy = json.load(f)
        return jsonify(policy)
    except:
        return jsonify({'allow': [], 'block': []})


@app.route('/api/health')
def health_check():
    """Check if API is running"""
    return jsonify({
        'status': 'ok',
        'message': 'Dashboard API is running',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 SDN Firewall Dashboard API")
    print("=" * 60)
    print("📍 API Endpoints:")
    print("   http://localhost:5000/api/stats       - Statistics")
    print("   http://localhost:5000/api/flows       - Recent flows")
    print("   http://localhost:5000/api/top-hosts   - Top hosts")
    print("   http://localhost:5000/api/events      - Security events")
    print("   http://localhost:5000/api/policy      - Firewall policy")
    print("   http://localhost:5000/api/health      - Health check")
    print("=" * 60)
    print("✅ API ready! Open dashboard at:")
    print("   file:///path/to/dashboard.html")
    print("   or http://localhost:5000 (if serving HTML)")
    print("🔄 Updates every 2 seconds")
    print()
    @app.route('/')
    def serve_dashboard():
        return send_file('dashboard.html')
    app.run(debug=True, host='0.0.0.0', port=5000)