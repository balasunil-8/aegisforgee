"""
AegisForge CTF Leaderboard System
Manages CTF challenges, flag submissions, and rankings
Version: 2.0
"""

from flask import Flask, jsonify, request
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json
import hashlib
import os


class Challenge:
    """Represents a single CTF challenge"""
    
    def __init__(self, challenge_id: str, name: str, points: int, flag: str, 
                 category: str, description: str, difficulty: str):
        self.challenge_id = challenge_id
        self.name = name
        self.points = points
        self.flag = flag
        self.category = category
        self.description = description
        self.difficulty = difficulty
        self.solves = 0
    
    def to_dict(self, include_flag: bool = False) -> dict:
        """Convert challenge to dictionary"""
        data = {
            'id': self.challenge_id,
            'name': self.name,
            'points': self.points,
            'category': self.category,
            'description': self.description,
            'difficulty': self.difficulty,
            'solves': self.solves
        }
        if include_flag:
            data['flag'] = self.flag
        return data


class LeaderboardManager:
    """Manages CTF leaderboard, scoring, and challenge submissions"""
    
    def __init__(self):
        self.challenges: Dict[str, Challenge] = {}
        self.scores: Dict[str, dict] = {}  # {username: {score, solves, last_solve_time, solves_details}}
        self.load_challenges()
    
    def load_challenges(self):
        """Load CTF challenges from configuration"""
        # Define challenges based on AegisForge vulnerabilities
        challenges_data = [
            {
                'id': 'sqli-001',
                'name': 'SQL Injection - Boolean Based',
                'points': 100,
                'flag': 'AEGIS{b00l34n_sql1_m4st3r}',
                'category': 'SQL Injection',
                'description': 'Exploit the boolean-based SQL injection vulnerability to extract data',
                'difficulty': 'Easy'
            },
            {
                'id': 'sqli-002',
                'name': 'SQL Injection - Time Based',
                'points': 150,
                'flag': 'AEGIS{t1m3_b4s3d_bl1nd_sqli}',
                'category': 'SQL Injection',
                'description': 'Use time-based blind SQL injection to extract sensitive information',
                'difficulty': 'Medium'
            },
            {
                'id': 'sqli-003',
                'name': 'SQL Injection - UNION Attack',
                'points': 200,
                'flag': 'AEGIS{un10n_s3l3ct_pwn3d}',
                'category': 'SQL Injection',
                'description': 'Perform a UNION-based SQL injection to extract data from other tables',
                'difficulty': 'Medium'
            },
            {
                'id': 'xss-001',
                'name': 'Cross-Site Scripting - Reflected',
                'points': 100,
                'flag': 'AEGIS{r3fl3ct3d_xss_f0und}',
                'category': 'XSS',
                'description': 'Execute JavaScript code via reflected XSS vulnerability',
                'difficulty': 'Easy'
            },
            {
                'id': 'xss-002',
                'name': 'Cross-Site Scripting - Stored',
                'points': 150,
                'flag': 'AEGIS{st0r3d_xss_p3rs1st3nt}',
                'category': 'XSS',
                'description': 'Store malicious JavaScript that executes for all users',
                'difficulty': 'Medium'
            },
            {
                'id': 'idor-001',
                'name': 'Insecure Direct Object Reference',
                'points': 150,
                'flag': 'AEGIS{1d0r_n0_auth_ch3ck}',
                'category': 'Access Control',
                'description': 'Access other users\' data by manipulating object identifiers',
                'difficulty': 'Easy'
            },
            {
                'id': 'bola-001',
                'name': 'Broken Object Level Authorization',
                'points': 150,
                'flag': 'AEGIS{b0l4_0w4sp_4p1_top10}',
                'category': 'Access Control',
                'description': 'Access messages belonging to other users due to missing authorization',
                'difficulty': 'Easy'
            },
            {
                'id': 'priv-001',
                'name': 'Privilege Escalation',
                'points': 200,
                'flag': 'AEGIS{m4ss_4ss1gnm3nt_pr1v_3sc}',
                'category': 'Access Control',
                'description': 'Escalate your privileges from regular user to admin',
                'difficulty': 'Medium'
            },
            {
                'id': 'auth-001',
                'name': 'Weak Authentication',
                'points': 100,
                'flag': 'AEGIS{w34k_p4ssw0rds_b4d}',
                'category': 'Authentication',
                'description': 'Bypass authentication using weak password storage',
                'difficulty': 'Easy'
            },
            {
                'id': 'auth-002',
                'name': 'Brute Force Attack',
                'points': 150,
                'flag': 'AEGIS{n0_r4t3_l1m1t_brut3}',
                'category': 'Authentication',
                'description': 'Exploit missing rate limiting to brute force credentials',
                'difficulty': 'Medium'
            },
            {
                'id': 'cmdi-001',
                'name': 'Command Injection',
                'points': 200,
                'flag': 'AEGIS{c0mm4nd_1nj3ct10n_pwn}',
                'category': 'Injection',
                'description': 'Execute arbitrary OS commands via command injection',
                'difficulty': 'Medium'
            },
            {
                'id': 'xxe-001',
                'name': 'XML External Entity Injection',
                'points': 250,
                'flag': 'AEGIS{xx3_f1l3_r34d_vuln}',
                'category': 'Injection',
                'description': 'Use XXE to read local files from the server',
                'difficulty': 'Hard'
            },
            {
                'id': 'ssrf-001',
                'name': 'Server-Side Request Forgery',
                'points': 200,
                'flag': 'AEGIS{ssrf_1nt3rn4l_4cc3ss}',
                'category': 'SSRF',
                'description': 'Use SSRF to access internal resources',
                'difficulty': 'Medium'
            },
            {
                'id': 'deser-001',
                'name': 'Insecure Deserialization',
                'points': 300,
                'flag': 'AEGIS{p1ckl3_rc3_d4ng3r0us}',
                'category': 'Deserialization',
                'description': 'Achieve remote code execution via insecure deserialization',
                'difficulty': 'Hard'
            },
            {
                'id': 'logic-001',
                'name': 'Business Logic Flaw',
                'points': 150,
                'flag': 'AEGIS{c0up0n_st4ck1ng_pr0f1t}',
                'category': 'Business Logic',
                'description': 'Exploit coupon stacking to get items for free',
                'difficulty': 'Medium'
            },
            {
                'id': 'race-001',
                'name': 'Race Condition',
                'points': 250,
                'flag': 'AEGIS{r4c3_c0nd1t10n_t0ct0u}',
                'category': 'Business Logic',
                'description': 'Exploit race condition to duplicate funds',
                'difficulty': 'Hard'
            },
            {
                'id': 'info-001',
                'name': 'Information Disclosure',
                'points': 100,
                'flag': 'AEGIS{v3rb0s3_3rr0rs_l34k}',
                'category': 'Information Disclosure',
                'description': 'Extract sensitive information from verbose error messages',
                'difficulty': 'Easy'
            },
            {
                'id': 'csrf-001',
                'name': 'Cross-Site Request Forgery',
                'points': 150,
                'flag': 'AEGIS{csrf_n0_t0k3n_v4l1d4t10n}',
                'category': 'CSRF',
                'description': 'Execute unauthorized actions via CSRF',
                'difficulty': 'Medium'
            }
        ]
        
        # Load challenges into manager
        for challenge_data in challenges_data:
            challenge = Challenge(**challenge_data)
            self.challenges[challenge.challenge_id] = challenge
    
    def verify_flag(self, challenge_id: str, submitted_flag: str) -> bool:
        """Verify if submitted flag is correct"""
        if challenge_id not in self.challenges:
            return False
        
        # Case-insensitive comparison, strip whitespace
        correct_flag = self.challenges[challenge_id].flag.strip().lower()
        submitted_flag = submitted_flag.strip().lower()
        
        return correct_flag == submitted_flag
    
    def submit_flag(self, username: str, challenge_id: str, flag: str) -> Tuple[bool, int, str]:
        """
        Process flag submission and update leaderboard
        Returns: (success, points_awarded, message)
        """
        # Check if challenge exists
        if challenge_id not in self.challenges:
            return False, 0, "Challenge not found"
        
        challenge = self.challenges[challenge_id]
        
        # Verify flag
        if not self.verify_flag(challenge_id, flag):
            return False, 0, "Incorrect flag"
        
        # Initialize user if not exists
        if username not in self.scores:
            self.scores[username] = {
                'score': 0,
                'solves': [],
                'last_solve': None,
                'solves_details': []
            }
        
        # Check if already solved
        if challenge_id in self.scores[username]['solves']:
            return False, 0, "Challenge already solved by this user"
        
        # Award points
        points = challenge.points
        self.scores[username]['score'] += points
        self.scores[username]['solves'].append(challenge_id)
        self.scores[username]['last_solve'] = datetime.utcnow()
        self.scores[username]['solves_details'].append({
            'challenge_id': challenge_id,
            'challenge_name': challenge.name,
            'points': points,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Update challenge solve count
        challenge.solves += 1
        
        return True, points, "Correct flag! Points awarded."
    
    def get_challenge_points(self, challenge_id: str) -> int:
        """Get points for a challenge"""
        if challenge_id in self.challenges:
            return self.challenges[challenge_id].points
        return 0
    
    def get_rankings(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get sorted leaderboard rankings
        Sorted by: score (descending), then by last solve time (ascending)
        """
        ranked = sorted(
            self.scores.items(),
            key=lambda x: (-x[1]['score'], x[1]['last_solve'] if x[1]['last_solve'] else datetime.max)
        )
        
        rankings = []
        for i, (username, data) in enumerate(ranked):
            rankings.append({
                'rank': i + 1,
                'username': username,
                'score': data['score'],
                'solves': len(data['solves']),
                'last_solve': data['last_solve'].isoformat() if data['last_solve'] else None
            })
        
        if limit:
            return rankings[:limit]
        return rankings
    
    def get_user_stats(self, username: str) -> Optional[dict]:
        """Get detailed stats for a specific user"""
        if username not in self.scores:
            return None
        
        user_data = self.scores[username]
        
        # Get rankings to find user's rank
        rankings = self.get_rankings()
        user_rank = next((r['rank'] for r in rankings if r['username'] == username), None)
        
        return {
            'username': username,
            'rank': user_rank,
            'score': user_data['score'],
            'total_solves': len(user_data['solves']),
            'last_solve': user_data['last_solve'].isoformat() if user_data['last_solve'] else None,
            'solves_details': user_data['solves_details']
        }
    
    def get_all_challenges(self, include_flags: bool = False) -> List[dict]:
        """Get list of all challenges"""
        return [challenge.to_dict(include_flag=include_flags) 
                for challenge in self.challenges.values()]
    
    def get_challenge_by_id(self, challenge_id: str, include_flag: bool = False) -> Optional[dict]:
        """Get a specific challenge by ID"""
        if challenge_id in self.challenges:
            return self.challenges[challenge_id].to_dict(include_flag=include_flag)
        return None
    
    def get_challenges_by_category(self, category: str) -> List[dict]:
        """Get all challenges in a specific category"""
        return [challenge.to_dict() 
                for challenge in self.challenges.values() 
                if challenge.category == category]
    
    def get_statistics(self) -> dict:
        """Get overall CTF statistics"""
        total_challenges = len(self.challenges)
        total_players = len(self.scores)
        total_solves = sum(len(data['solves']) for data in self.scores.values())
        
        # Calculate average points per player
        avg_score = sum(data['score'] for data in self.scores.values()) / total_players if total_players > 0 else 0
        
        # Most solved challenge
        most_solved = max(self.challenges.values(), key=lambda c: c.solves, default=None)
        
        # Category breakdown
        categories = {}
        for challenge in self.challenges.values():
            if challenge.category not in categories:
                categories[challenge.category] = {
                    'count': 0,
                    'total_points': 0,
                    'total_solves': 0
                }
            categories[challenge.category]['count'] += 1
            categories[challenge.category]['total_points'] += challenge.points
            categories[challenge.category]['total_solves'] += challenge.solves
        
        return {
            'total_challenges': total_challenges,
            'total_players': total_players,
            'total_solves': total_solves,
            'average_score': round(avg_score, 2),
            'most_solved_challenge': most_solved.to_dict() if most_solved else None,
            'categories': categories
        }


# Flask app for leaderboard API
app = Flask(__name__)
leaderboard_manager = LeaderboardManager()


@app.route('/api/ctf/challenges', methods=['GET'])
def get_challenges():
    """Get list of all CTF challenges"""
    category = request.args.get('category')
    
    if category:
        challenges = leaderboard_manager.get_challenges_by_category(category)
    else:
        challenges = leaderboard_manager.get_all_challenges()
    
    return jsonify({
        'ok': True,
        'challenges': challenges,
        'count': len(challenges)
    }), 200


@app.route('/api/ctf/challenges/<challenge_id>', methods=['GET'])
def get_challenge(challenge_id):
    """Get a specific challenge"""
    challenge = leaderboard_manager.get_challenge_by_id(challenge_id)
    
    if challenge:
        return jsonify({
            'ok': True,
            'challenge': challenge
        }), 200
    
    return jsonify({
        'ok': False,
        'error': 'Challenge not found'
    }), 404


@app.route('/api/ctf/submit', methods=['POST'])
def submit_flag():
    """Submit a CTF flag for verification"""
    data = request.get_json() or {}
    username = data.get('username')
    challenge_id = data.get('challenge_id')
    flag = data.get('flag')
    
    if not username or not challenge_id or not flag:
        return jsonify({
            'ok': False,
            'error': 'Missing required fields: username, challenge_id, flag'
        }), 400
    
    success, points, message = leaderboard_manager.submit_flag(username, challenge_id, flag)
    
    if success:
        return jsonify({
            'ok': True,
            'points_awarded': points,
            'message': message,
            'new_score': leaderboard_manager.scores[username]['score']
        }), 200
    else:
        return jsonify({
            'ok': False,
            'message': message
        }), 400


@app.route('/api/ctf/leaderboard', methods=['GET'])
def get_leaderboard():
    """Get current CTF leaderboard"""
    limit = request.args.get('limit', type=int)
    
    rankings = leaderboard_manager.get_rankings(limit=limit)
    
    return jsonify({
        'ok': True,
        'leaderboard': rankings,
        'total_players': len(leaderboard_manager.scores)
    }), 200


@app.route('/api/ctf/user/<username>', methods=['GET'])
def get_user_stats(username):
    """Get stats for a specific user"""
    stats = leaderboard_manager.get_user_stats(username)
    
    if stats:
        return jsonify({
            'ok': True,
            'user': stats
        }), 200
    
    return jsonify({
        'ok': False,
        'error': 'User not found'
    }), 404


@app.route('/api/ctf/statistics', methods=['GET'])
def get_statistics():
    """Get overall CTF statistics"""
    stats = leaderboard_manager.get_statistics()
    
    return jsonify({
        'ok': True,
        'statistics': stats
    }), 200


@app.route('/api/ctf/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'ok': True,
        'service': 'AegisForge CTF Leaderboard',
        'version': '2.0',
        'total_challenges': len(leaderboard_manager.challenges),
        'total_players': len(leaderboard_manager.scores)
    }), 200


if __name__ == '__main__':
    print("=" * 70)
    print("🏆 AegisForge CTF Leaderboard System Starting...")
    print(f"   Total Challenges: {len(leaderboard_manager.challenges)}")
    print(f"   Total Points Available: {sum(c.points for c in leaderboard_manager.challenges.values())}")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5002, debug=False)
