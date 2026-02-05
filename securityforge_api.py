"""
SecurityForge Pro - Comprehensive Security Learning Platform
Phase 1: Modular API Backend with Learning Integration
"""

from flask import Flask, jsonify, request, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
import time

# Initialize Flask app
app = Flask('SecurityForge API')
app.config['SECRET_KEY'] = 'dev-key-securityforge-pro-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securityforge_pro.db'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-securityforge-pro-2026'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    """User model with roles and progress tracking"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20), default='student')  # student, instructor, admin
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=1000)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'email': self.email,
            'role': self.role, 'is_admin': self.is_admin, 'balance': self.balance
        }

class LearningProgress(db.Model):
    """Track student progress through vulnerabilities"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    vulnerability_id = db.Column(db.String(50))
    status = db.Column(db.String(20), default='not_started')  # not_started, in_progress, completed
    exploits_attempted = db.Column(db.Integer, default=0)
    remediation_completed = db.Column(db.Boolean, default=False)
    score = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'vulnerability_id': self.vulnerability_id, 'status': self.status,
            'exploits_attempted': self.exploits_attempted,
            'remediation_completed': self.remediation_completed,
            'score': self.score
        }

class ExploitLog(db.Model):
    """Audit trail for exploit attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    vulnerability_id = db.Column(db.String(50))
    event_type = db.Column(db.String(50))
    endpoint = db.Column(db.String(200))
    payload = db.Column(db.Text)
    success = db.Column(db.Boolean)
    ip = db.Column(db.String(50))
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()))
    
    def to_dict(self):
        return {
            'id': self.id, 'user_id': self.user_id,
            'vulnerability_id': self.vulnerability_id,
            'event_type': self.event_type, 'endpoint': self.endpoint,
            'success': self.success, 'ip': self.ip, 'timestamp': self.timestamp
        }

# ============================================================================
# VULNERABILITY DATABASE LOADER
# ============================================================================

class VulnerabilityManager:
    """Manages vulnerability data from JSON database"""
    
    def __init__(self, json_path='vulnerabilities_db.json'):
        self.vulnerabilities = {}
        self.load_vulnerabilities(json_path)
    
    def load_vulnerabilities(self, json_path):
        """Load vulnerabilities from JSON file"""
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                for vuln in data.get('vulnerabilities', []):
                    self.vulnerabilities[vuln['id']] = vuln
        except FileNotFoundError:
            print(f"Warning: {json_path} not found")
    
    def get_all(self, vuln_type=None):
        """Get all vulnerabilities, optionally filtered by type"""
        if vuln_type:
            return {k: v for k, v in self.vulnerabilities.items() if v.get('type') == vuln_type}
        return self.vulnerabilities
    
    def get(self, vuln_id):
        """Get specific vulnerability"""
        return self.vulnerabilities.get(vuln_id)
    
    def get_by_type(self, vuln_type):
        """Get vulnerabilities by type (API or WEB)"""
        return {k: v for k, v in self.vulnerabilities.items() if v.get('type') == vuln_type}
    
    def get_beginner_guide(self, vuln_id):
        """Get beginner explanation for vulnerability"""
        vuln = self.get(vuln_id)
        if vuln:
            return {
                'title': vuln.get('title'),
                'explanation': vuln.get('beginner_explanation'),
                'why_it_happens': vuln.get('why_it_happens'),
                'real_world_impact': vuln.get('real_world_impact'),
                'difficulty': vuln.get('difficulty')
            }
        return None

# Initialize vulnerability manager
vuln_manager = VulnerabilityManager('vulnerabilities_db.json')

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def log_exploit(user_id, vulnerability_id, event_type, endpoint, success, payload=None):
    """Log exploit attempts for audit trail"""
    log = ExploitLog(
        user_id=user_id,
        vulnerability_id=vulnerability_id,
        event_type=event_type,
        endpoint=endpoint,
        payload=payload or '',
        success=success,
        ip=request.remote_addr or '0.0.0.0'
    )
    db.session.add(log)
    db.session.commit()

def get_or_create_progress(user_id, vulnerability_id):
    """Get or create learning progress record"""
    progress = LearningProgress.query.filter_by(
        user_id=user_id, vulnerability_id=vulnerability_id
    ).first()
    
    if not progress:
        progress = LearningProgress(user_id=user_id, vulnerability_id=vulnerability_id)
        db.session.add(progress)
        db.session.commit()
    
    return progress

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and user.password == data.get('password'):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'ok': True,
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
    
    return {'ok': False, 'error': 'Invalid credentials'}, 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json()
    
    if User.query.filter_by(email=data.get('email')).first():
        return {'ok': False, 'error': 'Email already exists'}, 400
    
    user = User(
        name=data.get('name'),
        email=data.get('email'),
        password=data.get('password'),
        role='student'
    )
    db.session.add(user)
    db.session.commit()
    
    return {'ok': True, 'message': 'User created successfully'}, 201

# ============================================================================
# VULNERABILITY LEARNING ENDPOINTS
# ============================================================================

@app.route('/api/vulnerabilities', methods=['GET'])
@jwt_required()
def get_vulnerabilities():
    """Get all vulnerabilities with filtering options"""
    vuln_type = request.args.get('type')  # 'API', 'WEB', or None for all
    
    if vuln_type:
        vulns = vuln_manager.get_by_type(vuln_type)
    else:
        vulns = vuln_manager.get_all()
    
    return {
        'ok': True,
        'count': len(vulns),
        'vulnerabilities': list(vulns.values())
    }, 200

@app.route('/api/vulnerabilities/<vulnerability_id>', methods=['GET'])
@jwt_required()
def get_vulnerability(vulnerability_id):
    """Get complete vulnerability information"""
    vuln = vuln_manager.get(vulnerability_id)
    
    if not vuln:
        return {'ok': False, 'error': 'Vulnerability not found'}, 404
    
    current_user = get_jwt_identity()
    progress = get_or_create_progress(current_user, vulnerability_id)
    
    return {
        'ok': True,
        'vulnerability': vuln,
        'user_progress': progress.to_dict()
    }, 200

@app.route('/api/vulnerabilities/<vulnerability_id>/beginner-guide', methods=['GET'])
@jwt_required()
def get_beginner_guide(vulnerability_id):
    """Get beginner-friendly guide for vulnerability"""
    guide = vuln_manager.get_beginner_guide(vulnerability_id)
    
    if not guide:
        return {'ok': False, 'error': 'Vulnerability not found'}, 404
    
    return {'ok': True, 'guide': guide}, 200

@app.route('/api/vulnerabilities/<vulnerability_id>/exploit-guide', methods=['GET'])
@jwt_required()
def get_exploit_guide(vulnerability_id):
    """Get intermediate exploit guide"""
    vuln = vuln_manager.get(vulnerability_id)
    
    if not vuln:
        return {'ok': False, 'error': 'Vulnerability not found'}, 404
    
    current_user = get_jwt_identity()
    progress = get_or_create_progress(current_user, vulnerability_id)
    progress.status = 'in_progress'
    progress.last_accessed = datetime.utcnow()
    db.session.commit()
    
    return {
        'ok': True,
        'steps': vuln.get('exploit_steps', []),
        'postman_requests': vuln.get('postman_requests', []),
        'burp_payloads': vuln.get('burp_payloads', {}),
        'test_cases': vuln.get('test_cases', [])
    }, 200

@app.route('/api/vulnerabilities/<vulnerability_id>/remediation', methods=['GET'])
@jwt_required()
def get_remediation(vulnerability_id):
    """Get remediation and defensive strategies"""
    vuln = vuln_manager.get(vulnerability_id)
    
    if not vuln:
        return {'ok': False, 'error': 'Vulnerability not found'}, 404
    
    return {
        'ok': True,
        'vulnerable_code': vuln.get('vulnerable_code', []),
        'secure_code': vuln.get('secure_code', []),
        'best_practices': vuln.get('remediation', {}).get('best_practices', []),
        'security_controls': vuln.get('remediation', {}).get('security_controls', []),
        'testing_strategy': vuln.get('remediation', {}).get('testing_strategy', [])
    }, 200

# ============================================================================
# PROGRESS & ANALYTICS ENDPOINTS
# ============================================================================

@app.route('/api/progress/<vulnerability_id>', methods=['GET'])
@jwt_required()
def get_progress(vulnerability_id):
    """Get student progress for specific vulnerability"""
    current_user = get_jwt_identity()
    progress = LearningProgress.query.filter_by(
        user_id=current_user,
        vulnerability_id=vulnerability_id
    ).first()
    
    if not progress:
        return {'ok': False, 'error': 'No progress found'}, 404
    
    return {'ok': True, 'progress': progress.to_dict()}, 200

@app.route('/api/progress/update/<vulnerability_id>', methods=['POST'])
@jwt_required()
def update_progress(vulnerability_id):
    """Update learning progress"""
    current_user = get_jwt_identity()
    data = request.get_json()
    
    progress = get_or_create_progress(current_user, vulnerability_id)
    
    if 'status' in data:
        progress.status = data['status']
    if 'exploits_attempted' in data:
        progress.exploits_attempted += data['exploits_attempted']
    if 'remediation_completed' in data:
        progress.remediation_completed = data['remediation_completed']
    if 'score' in data:
        progress.score = data['score']
    
    progress.last_accessed = datetime.utcnow()
    db.session.commit()
    
    return {'ok': True, 'message': 'Progress updated'}, 200

@app.route('/api/progress/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard():
    """Get overall progress dashboard"""
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    
    all_progress = LearningProgress.query.filter_by(user_id=current_user).all()
    
    total_vulns = len(vuln_manager.get_all())
    completed = len([p for p in all_progress if p.status == 'completed'])
    in_progress = len([p for p in all_progress if p.status == 'in_progress'])
    remediation_completed = len([p for p in all_progress if p.remediation_completed])
    total_score = sum([p.score for p in all_progress])
    
    return {
        'ok': True,
        'user': user.to_dict(),
        'statistics': {
            'total_vulnerabilities': total_vulns,
            'completed': completed,
            'in_progress': in_progress,
            'not_started': total_vulns - completed - in_progress,
            'remediation_completed': remediation_completed,
            'total_score': total_score,
            'completion_percentage': round((completed / total_vulns * 100), 2)
        },
        'recent_progress': [p.to_dict() for p in all_progress[-5:]]
    }, 200

# ============================================================================
# ADMIN AUDIT LOGS
# ============================================================================

@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    """Get audit logs (admin only)"""
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    
    if not user or not user.is_admin:
        return {'ok': False, 'error': 'Unauthorized'}, 403
    
    limit = request.args.get('limit', 100, type=int)
    logs = ExploitLog.query.order_by(ExploitLog.timestamp.desc()).limit(limit).all()
    
    return {
        'ok': True,
        'count': len(logs),
        'logs': [log.to_dict() for log in logs]
    }, 200

# ============================================================================
# VULNERABLE ENDPOINTS (Educational - For Security Testing)
# ============================================================================

# NOTE: These endpoints are INTENTIONALLY vulnerable for learning purposes
# Never use this code in production!

@app.route('/api/search', methods=['GET'])
def vulnerable_search():
    """
    VULNERABLE: SQL Injection - Boolean Based, Time-Based, UNION Based
    This endpoint takes a search parameter and builds an unsafe SQL query
    """
    search_query = request.args.get('q', '')
    
    # VULNERABLE: Direct string concatenation (SQL Injection!)
    sql = f"SELECT * FROM user WHERE name LIKE '%{search_query}%' OR email LIKE '%{search_query}%'"
    
    try:
        # Time-based blind SQLi test
        if 'SLEEP' in search_query.upper() or 'BENCHMARK' in search_query.upper():
            time.sleep(5)  # Simulate delay for time-based blind SQLi
        
        # For demo purposes, return mock results
        if "'OR'" in search_query or "'" in search_query:
            return {
                'ok': True,
                'results': [
                    {'id': 1, 'name': 'Alice Jones', 'email': 'alice@example.com'},
                    {'id': 2, 'name': 'Bob Smith', 'email': 'bob@example.com'},
                    {'id': 3, 'name': 'Charlie Brown', 'email': 'charlie@example.com'},
                    {'id': 4, 'name': 'Admin User', 'email': 'admin@example.com'}
                ],
                'query': search_query  # Exposed for demo
            }, 200
        else:
            users = User.query.filter(
                (User.name.like(f'%{search_query}%')) |
                (User.email.like(f'%{search_query}%'))
            ).all()
            return {
                'ok': True,
                'results': [u.to_dict() for u in users],
                'query': search_query
            }, 200
    except Exception as e:
        # VULNERABLE: Detailed error messages that leak information
        return {
            'ok': False,
            'error': str(e),
            'sql_query': sql,  # Exposed for learning
            'query': search_query
        }, 500

@app.route('/api/products', methods=['GET'])
def vulnerable_products():
    """
    VULNERABLE: SQL Injection with Filter Parameter
    """
    filter_param = request.args.get('filter', '')
    
    # VULNERABLE: Unsafe query building
    products = [
        {'id': 1, 'name': 'Laptop', 'price': 1200, 'stock': 50},
        {'id': 2, 'name': 'Mouse', 'price': 25, 'stock': 500},
        {'id': 3, 'name': 'Keyboard', 'price': 75, 'stock': 250},
        {'id': 4, 'name': 'Headphones', 'price': 150, 'stock': 100},
    ]
    
    # Filter products based on parameter (VULNERABLE to injection)
    if filter_param:
        try:
            # Evaluating filter as expression (very dangerous!)
            filtered = [p for p in products if eval(f"p['price'] {filter_param}")]
            return {'ok': True, 'products': filtered}, 200
        except:
            return {'ok': True, 'products': products}, 200
    
    return {'ok': True, 'products': products}, 200

@app.route('/api/comments', methods=['POST', 'GET'])
def vulnerable_comments():
    """
    VULNERABLE: Stored XSS - Comments not sanitized
    """
    if request.method == 'POST':
        data = request.get_json()
        comment_text = data.get('text', '')
        
        # VULNERABLE: No sanitization or encoding
        # In production, must use html.escape() or similar
        return {
            'ok': True,
            'message': 'Comment posted',
            'comment': {
                'text': comment_text,  # Stored as-is (XSS vector!)
                'user': get_jwt_identity() if request.headers.get('Authorization') else 'anonymous'
            }
        }, 201
    
    # GET endpoint returns comments (with XSS payload intact)
    comments = [
        {'id': 1, 'text': '<img src=x onerror="alert(\'Stored XSS\')">', 'user': 'evil_user'},
        {'id': 2, 'text': 'Good comment', 'user': 'good_user'}
    ]
    
    return {'ok': True, 'comments': comments}, 200

@app.route('/api/display-message', methods=['GET'])
def vulnerable_reflected_xss():
    """
    VULNERABLE: Reflected XSS
    User input is reflected back in HTML without escaping
    """
    message = request.args.get('msg', '')
    
    # VULNERABLE: Directly embedding user input in response
    html_response = f"""
    <html>
        <body>
            <h1>Your message: {message}</h1>
        </body>
    </html>
    """
    
    return html_response, 200, {'Content-Type': 'text/html'}

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT'])
def vulnerable_bola_user(user_id):
    """
    VULNERABLE: Broken Object Level Authorization (BOLA/IDOR)
    No check that current user owns the resource
    """
    # Get user (any user can access any user_id)
    user = User.query.get(user_id)
    
    if not user:
        return {'ok': False, 'error': 'User not found'}, 404
    
    if request.method == 'GET':
        # VULNERABLE: No authorization check - returns other users' data
        return {
            'ok': True,
            'user': user.to_dict(),
            'sensitive': {
                'balance': user.balance,
                'role': user.role,
                'email': user.email,
                'password': user.password  # REALLY bad - expose password!
            }
        }, 200
    
    elif request.method == 'PUT':
        # VULNERABLE: No authorization - anyone can modify any user
        data = request.get_json()
        
        if 'name' in data:
            user.name = data['name']
        if 'role' in data:
            user.role = data['role']  # Can escalate to admin!
        if 'is_admin' in data:
            user.is_admin = data['is_admin']  # Mass assignment!
        
        db.session.commit()
        
        return {'ok': True, 'message': 'User updated', 'user': user.to_dict()}, 200

@app.route('/api/users/<int:user_id>/orders', methods=['GET'])
def vulnerable_bola_orders(user_id):
    """
    VULNERABLE: BOLA on Orders - No ownership check
    """
    # VULNERABLE: No check that current_user owns these orders
    orders = [
        {'id': 1, 'user_id': user_id, 'total': 1200, 'items': ['Laptop']},
        {'id': 2, 'user_id': user_id, 'total': 150, 'items': ['Headphones']},
        {'id': 3, 'user_id': user_id, 'total': 100, 'items': ['Mouse']}
    ]
    
    return {
        'ok': True,
        'user_id': user_id,
        'orders': orders,
        'sensitive': {
            'payment_method': '****5678',
            'shipping_address': 'Visible to any authenticated user!'
        }
    }, 200

@app.route('/api/fetch-resource', methods=['POST'])
def vulnerable_ssrf():
    """
    VULNERABLE: Server-Side Request Forgery (SSRF)
    Server fetches user-supplied URL without validation
    """
    data = request.get_json()
    target_url = data.get('url', '')
    
    # VULNERABLE: No validation, fetches any URL
    try:
        import urllib.request
        
        # Check for cloud metadata endpoints (for demo)
        if 'metadata' in target_url.lower() or 'localhost' in target_url:
            # In real SSRF, would actually fetch
            return {
                'ok': True,
                'url': target_url,
                'content': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            }, 200
        
        return {'ok': True, 'url': target_url, 'content': 'Resource content'}, 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500

@app.route('/api/config', methods=['GET'])
def vulnerable_config_exposure():
    """
    VULNERABLE: Configuration and Sensitive Data Exposure
    """
    # VULNERABLE: Exposes sensitive configuration
    return {
        'ok': True,
        'configuration': {
            'debug': True,  # DEBUG MODE ON!
            'secret_key': app.config['SECRET_KEY'],
            'database': 'sqlite:///securityforge_pro.db',
            'jwt_secret': app.config['JWT_SECRET_KEY'],
            'admin_email': 'admin@example.com',
            'admin_password': 'Admin123'
        },
        'version': '2.0',
        'api_endpoints': ['/api/search', '/api/products', '/api/users', '/api/config']
    }, 200

@app.route('/api/weak-auth', methods=['POST'])
def vulnerable_weak_auth():
    """
    VULNERABLE: Weak Authentication (Default Credentials)
    """
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    
    # VULNERABLE: Allows default credentials without warning
    # VULNERABLE: No rate limiting (brute force possible)
    
    user = User.query.filter_by(email=email, password=password).first()
    
    if user:
        token = create_access_token(identity=user.id)
        return {
            'ok': True,
            'message': 'Login successful',
            'access_token': token,
            'user': user.to_dict()
        }, 200
    
    return {'ok': False, 'error': 'Invalid credentials'}, 401

# ============================================================================
# SYSTEM ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return {
        'ok': True,
        'service': 'SecurityForge Pro API',
        'version': 'v2.0',
        'timestamp': int(time.time())
    }, 200

@app.route('/api/setup/reset', methods=['POST'])
def reset_database():
    """Reset database and seed data (development only)"""
    db.drop_all()
    db.create_all()
    
    # Create sample users
    users = [
        User(name='Alice Jones', email='alice@example.com', password='AlicePass1!', role='student'),
        User(name='Bob Smith', email='bob@example.com', password='BobPass2!', role='student'),
        User(name='Instructor', email='instructor@example.com', password='InstructorPass123', role='instructor'),
        User(name='Admin', email='admin@example.com', password='Admin123', role='admin', is_admin=True),
    ]
    
    for user in users:
        db.session.add(user)
    
    db.session.commit()
    
    return {'ok': True, 'message': 'Database reset and seeded'}, 200

@app.route('/')
def index():
    """Serve main dashboard"""
    return render_template_string(open('Dashboard_Interactive.html').read()) if os.path.exists('Dashboard_Interactive.html') else 'SecurityForge Pro API'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

