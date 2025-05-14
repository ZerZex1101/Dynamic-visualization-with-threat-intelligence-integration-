from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file
import re
import datetime
import os
import json
import hashlib
import uuid
import logging
from functools import wraps
from models import db, User, Threat, Vulnerability, Incident, Product
import psutil
import platform
import socket
import subprocess
import requests
import geoip2.database
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Configure logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_monitor')

# AlienVault OTX API configuration
OTX_API_KEY = "0ff29c21f01e9dc8fdc8ed7b73a651b2892c1ae03a18f47c016f3197cbacb423"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# GeoIP2 configuration
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# Function to log all requests
def log_request(request_type='Normal Request', severity='Low', payload=None):
    timestamp = datetime.datetime.now()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    endpoint = request.path
    method = request.method
    user_id = session.get('user_id')
    
    # Log to database
    incident = Incident(
        timestamp=timestamp,
        type=request_type,
        severity=severity,
        source_ip=ip_address,
        details=payload,
        status='logged'
    )
    db.session.add(incident)
    db.session.commit()
    
    # Also log to file
    logger.info(f"Request logged - IP: {ip_address}, Type: {request_type}, Severity: {severity}, Endpoint: {endpoint}")

# Function to log attacks
def log_attack(attack_type, severity, payload):
    log_request(request_type=attack_type, severity=severity, payload=payload)
    logger.warning(f"Attack detected - Type: {attack_type}, Severity: {severity}, Payload: {payload}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    # Get threat statistics
    total_threats = Threat.query.count()
    active_vulnerabilities = Vulnerability.query.filter_by(status='active').count()
    critical_incidents = Incident.query.filter_by(severity='critical').count()
    
    # Calculate threat score (0-100)
    threat_score = min(100, (total_threats * 10 + active_vulnerabilities * 20 + critical_incidents * 30))
    
    # Get protected systems count (placeholder)
    protected_systems = 5
    
    return render_template('index.html',
                         threat_score=threat_score,
                         vulnerabilities=active_vulnerabilities,
                         protected=protected_systems)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check for SQL injection attempts
        if detect_sql_injection(username) or detect_sql_injection(password):
            log_attack('SQL Injection', 'High', f"Username: {username}, Password: {password}")
            error = 'Invalid credentials. Please try again.'
            return render_template('login.html', error=error)
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            user = User.query.filter_by(username=username, password=hashed_password).first()
            
            if user:
                session['user_id'] = user.id
                session['username'] = username
                session['role'] = user.role
                
                # Update last login time
                user.last_login = datetime.datetime.now()
                db.session.commit()
                
                # Log successful login
                log_request(request_type='Login Success', severity='Low', 
                           payload=f"User: {username}")
                
                return redirect(url_for('dashboard'))
            else:
                # Log failed login attempt
                log_request(request_type='Login Failed', severity='Medium', 
                           payload=f"Failed attempt for user: {username}")
                error = 'Invalid credentials. Please try again.'
        except Exception as e:
            error = f'Database error: {str(e)}'
            logger.error(f"Database error during login: {str(e)}")
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check for SQL injection attempts
        if detect_sql_injection(username) or detect_sql_injection(password):
            log_attack('SQL Injection', 'High', f"Username: {username}, Password: {password}")
            error = 'Invalid input detected. Please try again.'
            return render_template('register.html', error=error)
        
        if password != confirm_password:
            error = 'Passwords do not match.'
        else:
            try:
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                new_user = User(username=username, password=hashed_password, role='user')
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                error = 'Username already exists. Please choose a different one.'
    
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get threat statistics
    total_threats = Threat.query.count()
    blocked_attacks = Threat.query.filter_by(status='blocked').count()
    active_vulnerabilities = Vulnerability.query.filter_by(status='active').count()
    critical_incidents = Incident.query.filter_by(severity='critical').count()

    # Get recent incidents
    recent_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
    
    # Get threat intelligence feed
    threat_intel = [
        {
            'title': 'New SQL Injection Campaign',
            'description': 'Active SQL injection campaign targeting e-commerce platforms',
            'date': '2024-03-15',
            'severity': 'High',
            'severity_color': 'danger'
        },
        {
            'title': 'XSS Vulnerability in Popular CMS',
            'description': 'Critical XSS vulnerability discovered in WordPress plugins',
            'date': '2024-03-14',
            'severity': 'Critical',
            'severity_color': 'danger'
        },
        {
            'title': 'Ransomware Group Activity',
            'description': 'New ransomware group targeting healthcare sector',
            'date': '2024-03-13',
            'severity': 'High',
            'severity_color': 'warning'
        }
    ]

    return render_template('dashboard.html',
                         total_threats=total_threats,
                         blocked_attacks=blocked_attacks,
                         active_vulnerabilities=active_vulnerabilities,
                         critical_incidents=critical_incidents,
                         recent_incidents=recent_incidents,
                         threat_intel=threat_intel)

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get latest security logs
    latest_logs = Incident.query.order_by(Incident.timestamp.desc()).limit(50).all()
    
    # Get attack statistics
    attack_stats = db.session.query(
        Incident.type, 
        db.func.count(Incident.id)
    ).filter(Incident.type != 'Normal Request').group_by(Incident.type).all()
    
    # Get severity statistics
    severity_stats = db.session.query(
        Incident.severity, 
        db.func.count(Incident.id)
    ).group_by(Incident.severity).all()
    
    # Get recent login attempts
    login_attempts = Incident.query.filter(
        Incident.type.in_(['Login Success', 'Login Failed'])
    ).order_by(Incident.timestamp.desc()).limit(20).all()
    
    return render_template('admin_dashboard.html', 
                          username=session.get('username'),
                          latest_logs=latest_logs,
                          attack_stats=json.dumps([{'type': t, 'count': c} for t, c in attack_stats]),
                          severity_stats=json.dumps([{'severity': s, 'count': c} for s, c in severity_stats]),
                          login_attempts=login_attempts)

@app.route('/logs')
@admin_required
def view_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get logs with pagination
    logs = Incident.query.order_by(Incident.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('logs.html', 
                          logs=logs.items, 
                          page=page, 
                          total_pages=logs.pages)

@app.route('/api/logs')
@admin_required
def api_logs():
    logs = Incident.query.order_by(Incident.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': log.id,
        'timestamp': log.timestamp.isoformat(),
        'type': log.type,
        'severity': log.severity,
        'source_ip': log.source_ip,
        'details': log.details,
        'status': log.status
    } for log in logs])

@app.route('/api/stats')
@admin_required
def api_stats():
    # Get attack statistics
    attack_stats = db.session.query(
        Incident.type, 
        db.func.count(Incident.id)
    ).filter(Incident.type != 'Normal Request').group_by(Incident.type).all()
    
    # Get severity statistics
    severity_stats = db.session.query(
        Incident.severity, 
        db.func.count(Incident.id)
    ).group_by(Incident.severity).all()
    
    # Get logs count by day for the last 7 days
    time_stats = db.session.query(
        db.func.date(Incident.timestamp),
        db.func.count(Incident.id)
    ).filter(
        Incident.timestamp >= datetime.datetime.now() - datetime.timedelta(days=7)
    ).group_by(db.func.date(Incident.timestamp)).all()
    
    return jsonify({
        'attack_stats': [{'type': t, 'count': c} for t, c in attack_stats],
        'severity_stats': [{'severity': s, 'count': c} for s, c in severity_stats],
        'time_stats': [{'day': d.isoformat(), 'count': c} for d, c in time_stats]
    })

@app.route('/threats')
@admin_required
def view_threats():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    threats = Threat.query.order_by(Threat.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('threats.html', 
                          threats=threats.items, 
                          page=page, 
                          total_pages=threats.pages)

@app.route('/threats/add', methods=['GET', 'POST'])
@admin_required
def add_threat():
    if request.method == 'POST':
        threat = Threat(
            type=request.form['type'],
            severity=request.form['severity'],
            status=request.form['status'],
            source_ip=request.form['source_ip'],
            details=request.form['details']
        )
        db.session.add(threat)
        db.session.commit()
        return redirect(url_for('view_threats'))
    
    return render_template('add_threat.html')

@app.route('/threats/edit/<int:id>', methods=['POST'])
@admin_required
def edit_threat(id):
    threat = Threat.query.get_or_404(id)
    
    threat.type = request.form['type']
    threat.severity = request.form['severity']
    threat.status = request.form['status']
    threat.source_ip = request.form['source_ip']
    threat.details = request.form['details']
    
    db.session.commit()
    return redirect(url_for('view_threats'))

@app.route('/threats/delete/<int:id>', methods=['POST'])
@admin_required
def delete_threat(id):
    threat = Threat.query.get_or_404(id)
    db.session.delete(threat)
    db.session.commit()
    return redirect(url_for('view_threats'))

@app.route('/vulnerabilities')
@admin_required
def view_vulnerabilities():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('vulnerabilities.html', 
                          vulnerabilities=vulnerabilities.items, 
                          page=page, 
                          total_pages=vulnerabilities.pages)

@app.route('/vulnerabilities/add', methods=['GET', 'POST'])
@admin_required
def add_vulnerability():
    if request.method == 'POST':
        vulnerability = Vulnerability(
            name=request.form['name'],
            description=request.form['description'],
            severity=request.form['severity'],
            status=request.form['status']
        )
        db.session.add(vulnerability)
        db.session.commit()
        return redirect(url_for('view_vulnerabilities'))
    
    return render_template('add_vulnerability.html')

@app.route('/incidents')
@admin_required
def view_incidents():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    incidents = Incident.query.order_by(Incident.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('incidents.html', 
                          incidents=incidents.items, 
                          page=page, 
                          total_pages=incidents.pages)

@app.route('/incidents/add', methods=['GET', 'POST'])
@admin_required
def add_incident():
    if request.method == 'POST':
        incident = Incident(
            type=request.form['type'],
            severity=request.form['severity'],
            source_ip=request.form['source_ip'],
            details=request.form['details'],
            status=request.form['status']
        )
        db.session.add(incident)
        db.session.commit()
        return redirect(url_for('view_incidents'))
    
    return render_template('add_incident.html')

@app.route('/api/threats')
@admin_required
def api_threats():
    threats = Threat.query.order_by(Threat.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': threat.id,
        'timestamp': threat.timestamp.isoformat(),
        'type': threat.type,
        'severity': threat.severity,
        'status': threat.status,
        'source_ip': threat.source_ip,
        'details': threat.details
    } for threat in threats])

@app.route('/api/vulnerabilities')
@admin_required
def api_vulnerabilities():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).limit(50).all()
    return jsonify([{
        'id': vuln.id,
        'name': vuln.name,
        'description': vuln.description,
        'severity': vuln.severity,
        'status': vuln.status,
        'discovered_at': vuln.discovered_at.isoformat()
    } for vuln in vulnerabilities])

@app.route('/api/incidents')
@admin_required
def api_incidents():
    incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': incident.id,
        'timestamp': incident.timestamp.isoformat(),
        'type': incident.type,
        'severity': incident.severity,
        'source_ip': incident.source_ip,
        'details': incident.details,
        'status': incident.status
    } for incident in incidents])

# Helper function to detect SQL injection
def detect_sql_injection(payload):
    if not payload:
        return False
        
    # Common SQL injection patterns
    sql_patterns = [
        r"(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|INTO|EXEC|\bOR\b|\bAND\b)(\s|$)",
        r"(--|#|/\*|\*/)",
        r"('|\")((\s|=|<|>|\+|%|&|\||!|\^|-|\(|\)|\d+)+)('|\")",
        r";.+",
        r"(('|\"|\s)+(OR|AND)('|\"|\s)+('|\"|\s)*\w+('|\"|\s)*=('|\"|\s)*\w+)",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*--",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*--",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+\s*#",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'\s*#",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*#",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*#",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+\s*/\*",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'\s*/\*",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*\*/",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*/\*",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+\s*\*/",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'\s*\*/",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*\*/",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*\*/",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+\s*;",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'\s*;",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*;",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*;",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+\s*$",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*'[^']*'\s*$",
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*'[^']*'\s*$",
        r"(\bOR\b|\bAND\b)\s+'[^']*'\s*=\s*\d+\s*$"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

# Call setup at startup
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password=hashlib.sha256('admin123'.encode()).hexdigest(),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

# --------------------------------------------
# VICTIM APPLICATION (Vulnerable to various attacks)
# --------------------------------------------

@app.route('/victim')
def victim_site():
    return render_template('victim/index.html')

@app.route('/victim/products')
def victim_products():
    # Get all products
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    products = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('victim/products.html', products=products)

@app.route('/victim/search', methods=['GET'])
def victim_search():
    query = request.args.get('q', '')
    
    # Log the request
    log_request(request_type='Search Request', severity='Low', payload=query)
    
    # Log if SQL injection is detected
    if detect_sql_injection(query):
        log_attack('SQL Injection', 'High', query)
    
    # VULNERABILITY: Direct string concatenation
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    try:
        # Intentionally vulnerable to SQL injection
        sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
        c.execute(sql_query)
        products = [dict(row) for row in c.fetchall()]
        return render_template('victim/search_results.html', products=products, query=query)
    except sqlite3.Error as e:
        # Log the error
        log_request(request_type='Database Error', severity='High', 
                   payload=f"Error: {str(e)}, Query: {query}")
        return render_template('victim/search_results.html', error=str(e), query=query)
    finally:
        conn.close()

@app.route('/victim/product/<int:product_id>')
def victim_product_detail(product_id):
    # Log the request
    log_request(request_type='Product View', severity='Low', 
               payload=f"Product ID: {product_id}")
    
    # VULNERABILITY: String formatting in SQL query
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    product_id_str = str(product_id)
    if detect_sql_injection(product_id_str):
        log_attack('SQL Injection', 'High', product_id_str)
    
    try:
        # Intentionally vulnerable
        sql_query = f"SELECT * FROM products WHERE id = {product_id}"
        c.execute(sql_query)
        product = dict(c.fetchone() or {})
        
        if not product:
            log_request(request_type='Product Not Found', severity='Low', 
                       payload=f"Product ID: {product_id}")
            return "Product not found", 404
            
        return render_template('victim/product_detail.html', product=product)
    except sqlite3.Error as e:
        # Log the error
        log_request(request_type='Database Error', severity='High', 
                   payload=f"Error: {str(e)}, Product ID: {product_id}")
        return f"Database error: {str(e)}", 500
    finally:
        conn.close()

# New vulnerable routes

# 1. Local File Inclusion (LFI) Vulnerability
@app.route('/victim/view')
def victim_view():
    file = request.args.get('file', '')
    
    # Log the request
    log_request(request_type='File View Request', severity='Low', payload=file)
    
    # VULNERABILITY: Direct file inclusion without proper validation
    try:
        with open(file, 'r') as f:
            content = f.read()
        return render_template('victim/view.html', content=content, filename=file)
    except Exception as e:
        log_request(request_type='File Access Error', severity='High', 
                   payload=f"Error: {str(e)}, File: {file}")
        return render_template('victim/view.html', error=str(e), filename=file)

# 2. Cross-Site Scripting (XSS) Vulnerability
@app.route('/victim/comment', methods=['GET', 'POST'])
def victim_comment():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        name = request.form.get('name', '')
        
        # Log the request
        log_request(request_type='Comment Submission', severity='Low', 
                   payload=f"Name: {name}, Comment: {comment}")
        
        # VULNERABILITY: No XSS filtering
        return render_template('victim/comments.html', 
                             comments=[{'name': name, 'comment': comment}])
    
    return render_template('victim/comments.html', comments=[])

# 3. Command Injection Vulnerability
@app.route('/victim/ping', methods=['GET', 'POST'])
def victim_ping():
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # Log the request
        log_request(request_type='Ping Request', severity='Low', payload=host)
        
        # VULNERABILITY: Command injection through os.system
        try:
            # Intentionally vulnerable to command injection
            result = os.popen(f'ping -c 1 {host}').read()
            return render_template('victim/ping.html', result=result)
        except Exception as e:
            log_request(request_type='Command Execution Error', severity='High', 
                       payload=f"Error: {str(e)}, Command: ping -c 1 {host}")
            return render_template('victim/ping.html', error=str(e))
    
    return render_template('victim/ping.html')

# 4. Path Traversal Vulnerability
@app.route('/victim/download')
def victim_download():
    filename = request.args.get('file', '')
    
    # Log the request
    log_request(request_type='File Download Request', severity='Low', payload=filename)
    
    # VULNERABILITY: Path traversal through direct file access
    try:
        # Intentionally vulnerable to path traversal
        return send_file(filename, as_attachment=True)
    except Exception as e:
        log_request(request_type='File Download Error', severity='High', 
                   payload=f"Error: {str(e)}, File: {filename}")
        return render_template('victim/error.html', error=str(e))

# Helper function to detect various attacks
def detect_attack(payload):
    if not payload:
        return False, None
        
    # SQL Injection patterns (existing)
    sql_patterns = [
        r"(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|INTO|EXEC|\bOR\b|\bAND\b)(\s|$)",
        r"(--|#|/\*|\*/)",
        r"('|\")((\s|=|<|>|\+|%|&|\||!|\^|-|\(|\)|\d+)+)('|\")",
        r";.+",
        r"(('|\"|\s)+(OR|AND)('|\"|\s)+('|\"|\s)*\w+('|\"|\s)*=('|\"|\s)*\w+)",
    ]
    
    # XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"alert\s*\(",
        r"document\.cookie",
    ]
    
    # Command Injection patterns
    cmd_patterns = [
        r"[;&|]",
        r"`.*`",
        r"\$\(.*\)",
        r"eval\s*\(",
        r"exec\s*\(",
    ]
    
    # Path Traversal patterns
    path_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
    ]
    
    # Check for SQL Injection
    for pattern in sql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, 'SQL Injection'
    
    # Check for XSS
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, 'XSS'
    
    # Check for Command Injection
    for pattern in cmd_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, 'Command Injection'
    
    # Check for Path Traversal
    for pattern in path_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, 'Path Traversal'
    
    return False, None

@app.route('/vulnerabilities/sql-injection')
@login_required
def sql_injection():
    return render_template('vulnerabilities/sql_injection.html')

@app.route('/vulnerabilities/xss')
@login_required
def xss():
    return render_template('vulnerabilities/xss.html')

@app.route('/vulnerabilities/lfi')
@login_required
def lfi():
    return render_template('vulnerabilities/lfi.html')

@app.route('/vulnerabilities/command-injection')
@login_required
def command_injection():
    return render_template('vulnerabilities/command_injection.html')

@app.route('/vulnerabilities/path-traversal')
@login_required
def path_traversal():
    return render_template('vulnerabilities/path_traversal.html')

@app.route('/system-status')
@admin_required
def system_status():
    # Get system metrics
    cpu_usage = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    memory_usage = memory.percent
    disk = psutil.disk_usage('/')
    disk_usage = disk.percent

    # Get network speed (simplified)
    network_speed = 100  # Placeholder
    download_speed = 50  # Placeholder
    upload_speed = 50    # Placeholder

    # System requirements check
    python_version = platform.python_version()
    python_version_ok = float(python_version.split('.')[0] + '.' + python_version.split('.')[1]) >= 3.8
    ram_total = round(psutil.virtual_memory().total / (1024**3), 2)  # Convert to GB
    ram_ok = ram_total >= 4
    disk_total = round(psutil.disk_usage('/').total / (1024**3), 2)  # Convert to GB
    disk_ok = disk_total >= 10
    cpu_cores = psutil.cpu_count()
    cpu_cores_ok = cpu_cores >= 2

    # Get firewall ports (simplified)
    firewall_ports = [
        {'number': 80, 'service': 'HTTP', 'status': 'Open'},
        {'number': 443, 'service': 'HTTPS', 'status': 'Open'},
        {'number': 22, 'service': 'SSH', 'status': 'Closed'},
        {'number': 3306, 'service': 'MySQL', 'status': 'Closed'}
    ]

    # Get file permissions (simplified)
    file_permissions = [
        {
            'path': '/etc/passwd',
            'owner': 'root',
            'group': 'root',
            'permissions': '644',
            'secure': True
        },
        {
            'path': '/etc/shadow',
            'owner': 'root',
            'group': 'shadow',
            'permissions': '640',
            'secure': True
        }
    ]

    # Get network status
    active_connections = []
    for conn in psutil.net_connections():
        if conn.status == 'ESTABLISHED':
            active_connections.append({
                'protocol': 'TCP',
                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                'state': conn.status
            })

    # Get network interfaces
    network_interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                network_interfaces.append({
                    'name': iface,
                    'ip': addr.address,
                    'status': 'UP' if psutil.net_if_stats()[iface].isup else 'DOWN',
                    'speed': psutil.net_if_stats()[iface].speed
                })

    return render_template('system_status.html',
                         cpu_usage=cpu_usage,
                         memory_usage=memory_usage,
                         disk_usage=disk_usage,
                         network_speed=network_speed,
                         download_speed=download_speed,
                         upload_speed=upload_speed,
                         python_version=python_version,
                         python_version_ok=python_version_ok,
                         ram_total=ram_total,
                         ram_ok=ram_ok,
                         disk_total=disk_total,
                         disk_ok=disk_ok,
                         cpu_cores=cpu_cores,
                         cpu_cores_ok=cpu_cores_ok,
                         firewall_ports=firewall_ports,
                         file_permissions=file_permissions,
                         active_connections=active_connections,
                         network_interfaces=network_interfaces)

@app.route('/api/firewall/toggle/<int:port>', methods=['POST'])
@admin_required
def toggle_firewall_port(port):
    try:
        # Implement actual firewall port toggle logic here
        # This is a placeholder that always succeeds
        return jsonify({'success': True, 'message': f'Port {port} toggled successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/products')
@login_required
def view_products():
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/api/products', methods=['POST'])
@admin_required
def add_product():
    try:
        product = Product(
            name=request.form['name'],
            description=request.form['description'],
            price=float(request.form['price']),
            stock=int(request.form['stock'])
        )
        db.session.add(product)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/products/<int:id>', methods=['DELETE'])
@admin_required
def delete_product(id):
    try:
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/products/<int:id>', methods=['PUT'])
@admin_required
def update_product(id):
    try:
        product = Product.query.get_or_404(id)
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.stock = int(request.form['stock'])
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

def get_geoip_info(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
    except Exception as e:
        return None

def get_otx_info(ip):
    try:
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        response = requests.get(f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general", headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                'reputation': data.get('reputation', 0),
                'threat_score': data.get('threat_score', 0),
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown')
            }
    except Exception as e:
        return None

@app.route('/api/ip-info/<ip>')
@admin_required
def get_ip_info(ip):
    geoip_info = get_geoip_info(ip)
    otx_info = get_otx_info(ip)
    
    return jsonify({
        'geoip': geoip_info,
        'otx': otx_info
    })

@app.route('/vulnerability-scan', methods=['GET', 'POST'])
@admin_required
def vulnerability_scan():
    if request.method == 'POST':
        try:
            target = request.form.get('target')
            scan_type = request.form.get('scan_type')
            
            if not target:
                raise ValueError("Target URL or IP is required")
            
            # Log the scan request
            log_request(request_type='Vulnerability Scan', severity='Medium', 
                       payload=f"Target: {target}, Type: {scan_type}")
            
            # Simulate scan results (in a real app, this would use actual scanning tools)
            scan_results = {
                'target': target,
                'timestamp': datetime.datetime.now().isoformat(),
                'findings': [
                    {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'Potential SQL injection vulnerability detected in login form',
                        'location': '/login',
                        'recommendation': 'Use parameterized queries'
                    },
                    {
                        'type': 'XSS',
                        'severity': 'Medium',
                        'description': 'Reflected XSS vulnerability in search functionality',
                        'location': '/search',
                        'recommendation': 'Implement proper input sanitization'
                    },
                    {
                        'type': 'Path Traversal',
                        'severity': 'High',
                        'description': 'Directory traversal vulnerability in file download',
                        'location': '/download',
                        'recommendation': 'Implement proper path validation'
                    }
                ]
            }
            
            return render_template('vulnerability_scan.html', results=scan_results)
        except ValueError as e:
            return render_template('vulnerability_scan.html', error=str(e))
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {str(e)}")
            return render_template('vulnerability_scan.html', error="An error occurred during the scan")
    
    return render_template('vulnerability_scan.html')

@app.route('/network-monitor')
@admin_required
def network_monitor():
    # Get network statistics
    network_stats = {
        'total_connections': len(psutil.net_connections()),
        'active_connections': len([conn for conn in psutil.net_connections() if conn.status == 'ESTABLISHED']),
        'listening_ports': len([conn for conn in psutil.net_connections() if conn.status == 'LISTEN']),
        'interfaces': []
    }
    
    # Get interface statistics
    for iface, stats in psutil.net_if_stats().items():
        if stats.isup:
            network_stats['interfaces'].append({
                'name': iface,
                'speed': stats.speed,
                'mtu': stats.mtu,
                'duplex': stats.duplex
            })
    
    # Get recent network events
    recent_events = Incident.query.filter(
        Incident.type.in_(['Network Connection', 'Port Scan', 'Firewall Event'])
    ).order_by(Incident.timestamp.desc()).limit(20).all()
    
    return render_template('network_monitor.html', 
                         network_stats=network_stats,
                         recent_events=recent_events)

@app.route('/security-report')
@admin_required
def security_report():
    # Generate security report data
    report_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'threats': {
            'total': Threat.query.count(),
            'active': Threat.query.filter_by(status='active').count(),
            'blocked': Threat.query.filter_by(status='blocked').count()
        },
        'vulnerabilities': {
            'total': Vulnerability.query.count(),
            'critical': Vulnerability.query.filter_by(severity='critical').count(),
            'high': Vulnerability.query.filter_by(severity='high').count(),
            'medium': Vulnerability.query.filter_by(severity='medium').count(),
            'low': Vulnerability.query.filter_by(severity='low').count()
        },
        'incidents': {
            'total': Incident.query.count(),
            'last_24h': Incident.query.filter(
                Incident.timestamp >= datetime.datetime.now() - datetime.timedelta(days=1)
            ).count(),
            'by_type': db.session.query(
                Incident.type, 
                db.func.count(Incident.id)
            ).group_by(Incident.type).all()
        },
        'system_status': {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }
    }
    
    return render_template('security_report.html', report=report_data)

@app.route('/api/network-stats')
@admin_required
def api_network_stats():
    # Get network statistics
    network_stats = {
        'total_connections': len(psutil.net_connections()),
        'active_connections': len([conn for conn in psutil.net_connections() if conn.status == 'ESTABLISHED']),
        'listening_ports': len([conn for conn in psutil.net_connections() if conn.status == 'LISTEN']),
        'interfaces': []
    }
    
    # Get interface statistics
    for iface, stats in psutil.net_if_stats().items():
        if stats.isup:
            network_stats['interfaces'].append({
                'name': iface,
                'speed': stats.speed,
                'mtu': stats.mtu,
                'duplex': stats.duplex
            })
    
    return jsonify(network_stats)

@app.route('/threat-intelligence')
@admin_required
def threat_intelligence():
    try:
        # Get threat intelligence data
        threats = Threat.query.order_by(Threat.timestamp.desc()).all()
        return render_template('test/threat_intelligence.html', threats=threats)
    except Exception as e:
        logger.error(f"Error in threat intelligence: {str(e)}")
        return render_template('error.html', error="Error loading threat intelligence data")

@app.route('/vulnerability-data')
@admin_required
def vulnerability_data():
    try:
        # Get vulnerability data
        vulnerabilities = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).all()
        return render_template('test/data.html', vulnerabilities=vulnerabilities)
    except Exception as e:
        logger.error(f"Error in vulnerability data: {str(e)}")
        return render_template('error.html', error="Error loading vulnerability data")

@app.route('/incident-data')
@admin_required
def incident_data():
    try:
        # Get incident data
        incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
        return render_template('test/threat.html', incidents=incidents)
    except Exception as e:
        logger.error(f"Error in incident data: {str(e)}")
        return render_template('error.html', error="Error loading incident data")

@app.route('/analytics')
@admin_required
def analytics():
    try:
        # Get analytics data
        threat_stats = db.session.query(
            Threat.type,
            db.func.count(Threat.id).label('count')
        ).group_by(Threat.type).all()
        
        vulnerability_stats = db.session.query(
            Vulnerability.severity,
            db.func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.severity).all()
        
        incident_stats = db.session.query(
            Incident.type,
            db.func.count(Incident.id).label('count')
        ).group_by(Incident.type).all()
        
        return render_template('analytics.html',
                             threat_stats=threat_stats,
                             vulnerability_stats=vulnerability_stats,
                             incident_stats=incident_stats)
    except Exception as e:
        logger.error(f"Error in analytics: {str(e)}")
        return render_template('error.html', error="Error loading analytics data")

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
