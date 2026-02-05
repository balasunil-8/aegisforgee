"""
AegisForge Analytics Dashboard
Security analytics and insights for attack monitoring
Version: 2.0
"""

from flask import Flask, jsonify, request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json


class SecurityAnalytics:
    """Analytics engine for tracking and analyzing security events"""
    
    def __init__(self):
        self.attack_logs: List[Dict] = []
        self.endpoint_stats: Dict[str, Dict] = defaultdict(lambda: {
            'total_requests': 0,
            'attack_requests': 0,
            'benign_requests': 0,
            'attack_types': Counter()
        })
        self.user_stats: Dict[str, Dict] = defaultdict(lambda: {
            'total_requests': 0,
            'attacks_detected': 0,
            'attacks_blocked': 0,
            'last_activity': None
        })
    
    def log_attack(self, endpoint: str, payload: str, attack_type: str, 
                   user: Optional[str] = None, blocked: bool = True,
                   timestamp: Optional[datetime] = None):
        """Log an attack attempt"""
        log_entry = {
            'endpoint': endpoint,
            'payload': payload[:500],  # Limit payload size
            'attack_type': attack_type,
            'user': user or 'anonymous',
            'blocked': blocked,
            'timestamp': timestamp or datetime.utcnow(),
            'severity': self._calculate_severity(attack_type)
        }
        
        self.attack_logs.append(log_entry)
        
        # Update endpoint stats
        self.endpoint_stats[endpoint]['total_requests'] += 1
        if attack_type:
            self.endpoint_stats[endpoint]['attack_requests'] += 1
            self.endpoint_stats[endpoint]['attack_types'][attack_type] += 1
        else:
            self.endpoint_stats[endpoint]['benign_requests'] += 1
        
        # Update user stats
        if user:
            self.user_stats[user]['total_requests'] += 1
            self.user_stats[user]['last_activity'] = log_entry['timestamp']
            if attack_type:
                self.user_stats[user]['attacks_detected'] += 1
                if blocked:
                    self.user_stats[user]['attacks_blocked'] += 1
    
    def _calculate_severity(self, attack_type: str) -> str:
        """Calculate severity level for attack type"""
        critical_attacks = ['SQL Injection', 'Command Injection', 'SSRF', 'RCE']
        high_attacks = ['XSS', 'XXE', 'Deserialization', 'CSRF']
        medium_attacks = ['Path Traversal', 'IDOR', 'Information Disclosure']
        
        if any(critical in attack_type for critical in critical_attacks):
            return 'CRITICAL'
        elif any(high in attack_type for high in high_attacks):
            return 'HIGH'
        elif any(medium in attack_type for medium in medium_attacks):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_summary(self, hours: int = 24) -> Dict:
        """Get attack summary for last N hours"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent_attacks = [log for log in self.attack_logs if log['timestamp'] >= cutoff]
        
        if not recent_attacks:
            return {
                'period_hours': hours,
                'total_attacks': 0,
                'attacks_blocked': 0,
                'unique_attack_types': 0,
                'message': 'No attacks detected in this period'
            }
        
        attack_types = Counter(log['attack_type'] for log in recent_attacks)
        targeted_endpoints = Counter(log['endpoint'] for log in recent_attacks)
        severity_distribution = Counter(log['severity'] for log in recent_attacks)
        
        # Calculate attack rate (attacks per hour)
        attack_rate = len(recent_attacks) / hours if hours > 0 else 0
        
        # Get peak attack hour
        hourly_breakdown = self._get_hourly_breakdown(recent_attacks)
        peak_hour = max(hourly_breakdown.items(), key=lambda x: x[1]) if hourly_breakdown else (None, 0)
        
        # Block rate
        blocked_count = sum(1 for log in recent_attacks if log['blocked'])
        block_rate = (blocked_count / len(recent_attacks) * 100) if recent_attacks else 0
        
        return {
            'period_hours': hours,
            'total_attacks': len(recent_attacks),
            'attacks_blocked': blocked_count,
            'block_rate_percentage': round(block_rate, 2),
            'unique_attack_types': len(attack_types),
            'attack_rate_per_hour': round(attack_rate, 2),
            'attack_types_breakdown': dict(attack_types.most_common()),
            'top_targeted_endpoints': dict(targeted_endpoints.most_common(10)),
            'severity_distribution': dict(severity_distribution),
            'hourly_breakdown': hourly_breakdown,
            'peak_attack_hour': peak_hour[0].isoformat() if peak_hour[0] else None,
            'peak_attack_count': peak_hour[1]
        }
    
    def _get_hourly_breakdown(self, attacks: List[Dict]) -> Dict[str, int]:
        """Group attacks by hour"""
        hourly = {}
        for attack in attacks:
            hour = attack['timestamp'].replace(minute=0, second=0, microsecond=0)
            hour_key = hour.isoformat()
            hourly[hour_key] = hourly.get(hour_key, 0) + 1
        return dict(sorted(hourly.items()))
    
    def get_endpoint_analytics(self, endpoint: Optional[str] = None) -> Dict:
        """Get analytics for specific endpoint or all endpoints"""
        if endpoint:
            if endpoint not in self.endpoint_stats:
                return {'error': 'Endpoint not found'}
            
            stats = self.endpoint_stats[endpoint]
            attack_rate = (stats['attack_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
            
            return {
                'endpoint': endpoint,
                'total_requests': stats['total_requests'],
                'attack_requests': stats['attack_requests'],
                'benign_requests': stats['benign_requests'],
                'attack_rate_percentage': round(attack_rate, 2),
                'attack_types': dict(stats['attack_types'])
            }
        else:
            # Return all endpoints sorted by attack count
            all_stats = []
            for ep, stats in self.endpoint_stats.items():
                attack_rate = (stats['attack_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                all_stats.append({
                    'endpoint': ep,
                    'total_requests': stats['total_requests'],
                    'attack_requests': stats['attack_requests'],
                    'attack_rate_percentage': round(attack_rate, 2)
                })
            
            all_stats.sort(key=lambda x: x['attack_requests'], reverse=True)
            return {
                'total_endpoints': len(all_stats),
                'endpoints': all_stats
            }
    
    def get_user_analytics(self, username: Optional[str] = None) -> Dict:
        """Get analytics for specific user or all users"""
        if username:
            if username not in self.user_stats:
                return {'error': 'User not found'}
            
            stats = self.user_stats[username]
            attack_rate = (stats['attacks_detected'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
            block_rate = (stats['attacks_blocked'] / stats['attacks_detected'] * 100) if stats['attacks_detected'] > 0 else 0
            
            return {
                'username': username,
                'total_requests': stats['total_requests'],
                'attacks_detected': stats['attacks_detected'],
                'attacks_blocked': stats['attacks_blocked'],
                'attack_rate_percentage': round(attack_rate, 2),
                'block_rate_percentage': round(block_rate, 2),
                'last_activity': stats['last_activity'].isoformat() if stats['last_activity'] else None
            }
        else:
            # Return top users by attack count
            all_users = []
            for user, stats in self.user_stats.items():
                all_users.append({
                    'username': user,
                    'total_requests': stats['total_requests'],
                    'attacks_detected': stats['attacks_detected'],
                    'attacks_blocked': stats['attacks_blocked']
                })
            
            all_users.sort(key=lambda x: x['attacks_detected'], reverse=True)
            return {
                'total_users': len(all_users),
                'top_users': all_users[:20]  # Top 20 users
            }
    
    def get_attack_timeline(self, hours: int = 24, interval_minutes: int = 60) -> Dict:
        """Get attack timeline with configurable intervals"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent_attacks = [log for log in self.attack_logs if log['timestamp'] >= cutoff]
        
        # Group attacks by interval
        timeline = defaultdict(lambda: {'total': 0, 'by_type': Counter(), 'by_severity': Counter()})
        
        for attack in recent_attacks:
            # Round timestamp to interval
            interval_start = attack['timestamp'].replace(second=0, microsecond=0)
            minutes = (interval_start.minute // interval_minutes) * interval_minutes
            interval_start = interval_start.replace(minute=minutes)
            
            key = interval_start.isoformat()
            timeline[key]['total'] += 1
            timeline[key]['by_type'][attack['attack_type']] += 1
            timeline[key]['by_severity'][attack['severity']] += 1
        
        # Convert to list format
        timeline_list = [
            {
                'timestamp': ts,
                'total_attacks': data['total'],
                'attack_types': dict(data['by_type']),
                'severity': dict(data['by_severity'])
            }
            for ts, data in sorted(timeline.items())
        ]
        
        return {
            'period_hours': hours,
            'interval_minutes': interval_minutes,
            'data_points': len(timeline_list),
            'timeline': timeline_list
        }
    
    def get_threat_intelligence(self) -> Dict:
        """Get threat intelligence insights"""
        if not self.attack_logs:
            return {'message': 'No threat data available'}
        
        # Get recent attacks (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        recent_attacks = [log for log in self.attack_logs if log['timestamp'] >= cutoff]
        
        # Attack trend (comparing last 24h vs previous 24h)
        now = datetime.utcnow()
        last_24h = [log for log in self.attack_logs if log['timestamp'] >= now - timedelta(hours=24)]
        prev_24h = [log for log in self.attack_logs if now - timedelta(hours=48) <= log['timestamp'] < now - timedelta(hours=24)]
        
        trend = 'increasing' if len(last_24h) > len(prev_24h) else 'decreasing' if len(last_24h) < len(prev_24h) else 'stable'
        trend_percentage = ((len(last_24h) - len(prev_24h)) / len(prev_24h) * 100) if prev_24h else 0
        
        # Most common attack patterns
        attack_patterns = Counter()
        for attack in recent_attacks:
            # Extract pattern from payload (simplified)
            if 'select' in attack['payload'].lower() and 'union' in attack['payload'].lower():
                attack_patterns['UNION-based SQLi'] += 1
            elif 'script' in attack['payload'].lower():
                attack_patterns['Script injection'] += 1
            elif '../' in attack['payload']:
                attack_patterns['Path traversal'] += 1
        
        # Risk assessment
        critical_count = sum(1 for log in last_24h if log['severity'] == 'CRITICAL')
        high_count = sum(1 for log in last_24h if log['severity'] == 'HIGH')
        
        risk_score = (critical_count * 10 + high_count * 5) / max(len(last_24h), 1)
        risk_level = 'CRITICAL' if risk_score >= 7 else 'HIGH' if risk_score >= 4 else 'MEDIUM' if risk_score >= 2 else 'LOW'
        
        return {
            'last_7_days_attacks': len(recent_attacks),
            'last_24h_attacks': len(last_24h),
            'trend': trend,
            'trend_percentage': round(trend_percentage, 2),
            'risk_assessment': {
                'level': risk_level,
                'score': round(risk_score, 2),
                'critical_attacks_24h': critical_count,
                'high_attacks_24h': high_count
            },
            'top_attack_patterns': dict(attack_patterns.most_common(10)),
            'recommendations': self._get_recommendations(recent_attacks)
        }
    
    def _get_recommendations(self, attacks: List[Dict]) -> List[str]:
        """Generate security recommendations based on attack patterns"""
        recommendations = []
        
        attack_types = Counter(log['attack_type'] for log in attacks)
        
        if attack_types.get('SQL Injection', 0) > 10:
            recommendations.append('High SQL injection activity detected. Review and strengthen database query parameterization.')
        
        if attack_types.get('XSS', 0) > 10:
            recommendations.append('Significant XSS attempts detected. Ensure output encoding and CSP headers are properly implemented.')
        
        if attack_types.get('Command Injection', 0) > 5:
            recommendations.append('Command injection attempts detected. Review all subprocess calls and implement command whitelisting.')
        
        # Check if attacks are blocked
        unblocked = sum(1 for log in attacks if not log['blocked'])
        if unblocked > len(attacks) * 0.1:  # More than 10% unblocked
            recommendations.append('Some attacks are not being blocked. Review and strengthen input validation.')
        
        # Check for diverse attack types
        if len(attack_types) > 5:
            recommendations.append('Multiple attack vectors detected. Consider implementing a comprehensive WAF solution.')
        
        if not recommendations:
            recommendations.append('Continue monitoring. Current security posture is adequate.')
        
        return recommendations


# Flask app for analytics API
app = Flask(__name__)
analytics = SecurityAnalytics()


# Seed some sample data for demonstration
def seed_sample_data():
    """Seed sample attack data for demonstration"""
    import random
    
    endpoints = [
        '/api/injection/sqli/boolean',
        '/api/xss/reflected',
        '/api/access/idor/1',
        '/api/auth/login',
        '/api/injection/command'
    ]
    
    attack_types = [
        'SQL Injection',
        'XSS',
        'IDOR',
        'Brute Force',
        'Command Injection'
    ]
    
    users = ['user1', 'user2', 'attacker', 'scanner_bot']
    
    # Generate attacks for the last 7 days
    now = datetime.utcnow()
    for i in range(100):
        hours_ago = random.randint(0, 168)  # 7 days
        timestamp = now - timedelta(hours=hours_ago)
        
        analytics.log_attack(
            endpoint=random.choice(endpoints),
            payload=f"malicious_payload_{i}",
            attack_type=random.choice(attack_types),
            user=random.choice(users),
            blocked=random.random() > 0.1,  # 90% blocked
            timestamp=timestamp
        )


# Seed data on startup
seed_sample_data()


@app.route('/api/analytics/summary', methods=['GET'])
def get_analytics_summary():
    """Get security analytics summary"""
    hours = request.args.get('hours', 24, type=int)
    summary = analytics.get_summary(hours=hours)
    return jsonify({
        'ok': True,
        'summary': summary
    }), 200


@app.route('/api/analytics/endpoints', methods=['GET'])
def get_endpoint_analytics():
    """Get endpoint analytics"""
    endpoint = request.args.get('endpoint')
    data = analytics.get_endpoint_analytics(endpoint=endpoint)
    return jsonify({
        'ok': True,
        'data': data
    }), 200


@app.route('/api/analytics/users', methods=['GET'])
def get_user_analytics():
    """Get user analytics"""
    username = request.args.get('username')
    data = analytics.get_user_analytics(username=username)
    return jsonify({
        'ok': True,
        'data': data
    }), 200


@app.route('/api/analytics/timeline', methods=['GET'])
def get_attack_timeline():
    """Get attack timeline"""
    hours = request.args.get('hours', 24, type=int)
    interval = request.args.get('interval', 60, type=int)
    timeline = analytics.get_attack_timeline(hours=hours, interval_minutes=interval)
    return jsonify({
        'ok': True,
        'timeline': timeline
    }), 200


@app.route('/api/analytics/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """Get threat intelligence insights"""
    intel = analytics.get_threat_intelligence()
    return jsonify({
        'ok': True,
        'intelligence': intel
    }), 200


@app.route('/api/analytics/log-attack', methods=['POST'])
def log_attack():
    """Log a new attack (for integration with other systems)"""
    data = request.get_json() or {}
    
    analytics.log_attack(
        endpoint=data.get('endpoint', '/unknown'),
        payload=data.get('payload', ''),
        attack_type=data.get('attack_type', 'Unknown'),
        user=data.get('user'),
        blocked=data.get('blocked', True)
    )
    
    return jsonify({
        'ok': True,
        'message': 'Attack logged successfully'
    }), 200


@app.route('/api/analytics/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'ok': True,
        'service': 'AegisForge Analytics Dashboard',
        'version': '2.0',
        'total_attacks_logged': len(analytics.attack_logs)
    }), 200


if __name__ == '__main__':
    print("=" * 70)
    print("📊 AegisForge Analytics Dashboard Starting...")
    print(f"   Sample Data: {len(analytics.attack_logs)} attacks logged")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5003, debug=False)
