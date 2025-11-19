#!/usr/bin/env python3
"""
Dashboard API for SDN Firewall
Real-time statistics from controller logs
"""

from flask import Flask, jsonify
from flask_cors import CORS
import json
import os
import re
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow frontend to access

# File paths
LOG_FILE = "ryu.log"
STATS_CACHE = {}
LAST_UPDATE = None

def parse_controller_log():
    """Parse ryu.log and extract stats"""
    global STATS_CACHE, LAST_UPDATE
    
    # Check if need to update (every 3 seconds)
    now = datetime.now()
    if LAST_UPDATE and (now - LAST_UPDATE).seconds < 3:
        return STATS_CACHE
    
    stats = {
        'allowed': 0,
        'blocked': 0,
        'encrypted': 0,
        'plaintext': 0,
        'unverified': 0,
        'switches': 0,
        'flows': [],
        'top_sources': {},
        'top_destinations': {},
        'recent_events': []
    }
    
    if not os.path.exists(LOG_FILE):
        return stats
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            for line in lines[-200:]:  # Last 200 lines only
                # Count switches
                if 'Switch' in line and 'connected' in line:
                    stats['switches'] += 1
                
                # Count allowed flows
                if '✅ ALLOWED' in line:
                    stats['allowed'] += 1
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*→\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        src, dst = match.groups()
                        stats['top_sources'][src] = stats['top_sources'].get(src, 0) + 1
                        stats['top_destinations'][dst] = stats['top_destinations'].get(dst, 0) + 1
                        stats['flows'].append({
                            'src': src,
                            'dst': dst,
                            'status': 'allowed',
                            'time': datetime.now().strftime('%H:%M:%S')
                        })
                
                # Count blocked flows
                if '🚫 BLOCKED' in line:
                    stats['blocked'] += 1
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*→\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        src, dst = match.groups()
                        stats['flows'].append({
                            'src': src,
                            'dst': dst,
                            'status': 'blocked',
                            'time': datetime.now().strftime('%H:%M:%S')
                        })
                        stats['recent_events'].append({
                            'type': 'blocked',
                            'message': f'Blocked: {src} → {dst}',
                            'time': datetime.now().strftime('%H:%M:%S')
                        })
                
                # Count encrypted
                if '🔒 ENCRYPTED' in line:
                    stats['encrypted'] += 1
                
                # Count plaintext
                if '📡 PLAINTEXT' in line:
                    stats['plaintext'] += 1
                
                # Count unverified
                if '🔍 UNVERIFIED' in line:
                    stats['unverified'] += 1
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*→\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        src, dst = match.groups()
                        stats['recent_events'].append({
                            'type': 'unverified',
                            'message': f'Unverified: {src} → {dst}',
                            'time': datetime.now().strftime('%H:%M:%S')
                        })
        
        # Keep only last 10 flows
        stats['flows'] = stats['flows'][-10:]
        stats['recent_events'] = stats['recent_events'][-10:]
        
        STATS_CACHE = stats
        LAST_UPDATE = now
        
    except Exception as e:
        print(f"Error parsing log: {e}")
    
    return stats


@app.route('/api/stats')
def get_stats():
    """Get overall statistics"""
    stats = parse_controller_log()
    
    return jsonify({
        'total_flows': stats['allowed'] + stats['blocked'],
        'allowed': stats['allowed'],
        'blocked': stats['blocked'],
        'encrypted': stats['encrypted'],
        'plaintext': stats['plaintext'],
        'unverified': stats['unverified'],
        'switches': stats['switches'],
        'encryption_rate': round((stats['encrypted'] / max(stats['encrypted'] + stats['plaintext'], 1)) * 100, 1),
        'block_rate': round((stats['blocked'] / max(stats['allowed'] + stats['blocked'], 1)) * 100, 1),
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
        'events': stats['recent_events']
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
    print("🚀 Dashboard API Starting...")
    print("=" * 60)
    print("📍 API Endpoints:")
    print("   http://localhost:5000/api/stats       - Overall statistics")
    print("   http://localhost:5000/api/flows       - Recent flows")
    print("   http://localhost:5000/api/top-hosts   - Top hosts")
    print("   http://localhost:5000/api/events      - Security events")
    print("   http://localhost:5000/api/policy      - Firewall policy")
    print("   http://localhost:5000/api/health      - Health check")
    print("=" * 60)
    print("✅ API ready! Access dashboard at http://localhost:5000")
    print("🔄 Auto-refreshes every 3 seconds")
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
