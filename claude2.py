from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, flash
import sqlite3
import pandas as pd
import requests
import json
import os
import logging
import time
from datetime import datetime
import random
import psutil
import platform
from werkzeug.middleware.proxy_fix import ProxyFix
import io

# Configuration
DB_PATH = "access_logs.db"
LOG_PATH = "soc_system.log"
BLOCKED_IPS_FILE = "blocked_ips.json"

# Flask App
app = Flask(__name__, template_folder='templates')
app.secret_key = 'super secret key'  # Required for flash messages

# Apply ProxyFix for handling X-Forwarded-For headers correctly
app.wsgi_app = ProxyFix(app.wsgi_app)

# Setup Logging
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_system')

# Setup SQLite Database
def setup_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    destination_ip TEXT,
                    method TEXT,
                    status_code INTEGER,
                    attack_type TEXT,
                    payload TEXT,
                    user_agent TEXT,
                    country TEXT,
                    threat_score INTEGER,
                    threat_intel TEXT
                )''')

        # Adding indexes for better query performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON logs(source_ip)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON logs(attack_type)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')

        conn.commit()
        conn.close()
        logger.info("Database setup completed successfully")
    except Exception as e:
        logger.error(f"Database setup failed: {str(e)}")

# Load blocked IPs
def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load blocked IPs: {str(e)}")
            return set()
    else:
        return set()

# Save blocked IPs
def save_blocked_ips(blocked_ips):
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(list(blocked_ips), f)
    except Exception as e:
        logger.error(f"Failed to save blocked IPs: {str(e)}")

# Attack Detection with improved pattern matching
def detect_attack(payload, path=None, query_string=None):
    # Convert payload to string for checking
    payload_str = json.dumps(payload).lower() if payload else ""
    path_str = str(path).lower() if path else ""
    query_str = str(query_string).lower() if query_string else ""

    # Combine all data for comprehensive checking
    full_data = f"{payload_str} {path_str} {query_str}"

    # More comprehensive attack patterns
    sqli_patterns = ["'", "--", "/*", "union", "select", "drop", "insert", "update",
                    "exec", "execute", "xp_", ";", "waitfor", "delay", "benchmark"]
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "onmouseover",
                   "onfocus", "alert(", "<img", "<iframe", "src=", "eval("]
    lfi_patterns = ["../", "..\\", "/etc/passwd", "C:\\windows\\", "boot.ini", "/proc/self/",
                   "file://", "php://input", "data://", "zip://", "phar://"]
    cmdi_patterns = [";", "&&", "||", "`", "$(", "system(", "exec(", "shell_exec", "passthru"]

    # Check for each type of attack
    if any(x in full_data for x in sqli_patterns):
        return "SQL Injection"
    if any(x in full_data for x in xss_patterns):
        return "XSS"
    if any(x in full_data for x in lfi_patterns):
        return "LFI"
    if any(x in full_data for x in cmdi_patterns):
        return "Command Injection"

    # Calculate threat score based on unusual characters or patterns
    unusual_chars = ['~', '!', '@', '#', '$', '%', '^', '*', '(', ')', '{', '}', '|']
    if any(x in full_data for x in unusual_chars) and len(full_data) > 20:
        return "Suspicious Request"

    return "Normal Request"

# Enhanced threat scoring using multiple factors
def calculate_threat_score(attack_type, ip, user_agent):
    base_score = {
        "Normal Request": random.randint(0, 10),
        "Suspicious Request": random.randint(20, 40),
        "SQL Injection": random.randint(70, 95),
        "XSS": random.randint(60, 85),
        "LFI": random.randint(75, 90),
        "Command Injection": random.randint(80, 98)
    }.get(attack_type, random.randint(10, 30))

    # Adjust score based on user agent
    if user_agent and any(x in user_agent.lower() for x in ["curl", "wget", "python-requests", "go-http-client", "bot"]):
        base_score += random.randint(10, 20)

    # Cap the score at 100
    return min(base_score, 100)

# Fetch System Properties
def get_system_info():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor(),
            "cpu_usage": f"{cpu_percent}%",
            "ram_total": f"{round(memory.total / (1024 * 1024 * 1024), 2)} GB",
            "ram_used": f"{round(memory.used / (1024 * 1024 * 1024), 2)} GB",
            "ram_percent": f"{memory.percent}%",
            "disk_total": f"{round(disk.total / (1024 * 1024 * 1024), 2)} GB",
            "disk_used": f"{round(disk.used / (1024 * 1024 * 1024), 2)} GB",
            "disk_percent": f"{disk.percent}%"
        }
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return {
            "os": platform.system() + " " + platform.release(),
            "cpu": platform.processor(),
            "ram": "Error fetching data"
        }

# Log Requests with enhanced data collection
def log_request():
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        destination_ip = request.host
        method = request.method
        path = request.path
        query_string = request.query_string.decode('utf-8', errors='ignore') if request.query_string else ""

        # Get data based on request method
        if request.method == "GET":
            payload = dict(request.args)
        elif request.is_json:
            payload = request.get_json(silent=True) or {}
        else:
            payload = dict(request.form)

        user_agent = request.headers.get('User-Agent', "Unknown")
        referer = request.headers.get('Referer', "None")

        # Detect attack type
        attack_type = detect_attack(payload, path, query_string)

        # Calculate threat score
        threat_score = calculate_threat_score(attack_type, ip, user_agent)

        # Get country from IP (simplified for now)
        country = "Unknown"  # Simplified without GeoIP

        # Create log data
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "destination_ip": destination_ip,
            "method": method,
            "path": path,
            "query_string": query_string,
            "status_code": 200,  # Will be updated after response
            "attack_type": attack_type,
            "payload": json.dumps(payload),
            "user_agent": user_agent,
            "referer": referer,
            "country": country,
            "threat_score": threat_score
        }

        # Store in SQLite
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""INSERT INTO logs (source_ip, destination_ip, method, status_code, attack_type, payload, user_agent, country, threat_score, timestamp)
                    VALUES (:source_ip, :destination_ip, :method, :status_code, :attack_type, :payload, :user_agent, :country, :threat_score, :timestamp)""",
                log_data)
        conn.commit()
        conn.close()

        logger.info(f"Request logged from IP: {ip}, Attack Type: {attack_type}, Threat Score: {threat_score}")
        
        return log_data

    except Exception as e:
        logger.error(f"Logging error: {str(e)}")
        return None

# Block IP Function
blocked_ips = load_blocked_ips()

def block_ip(ip):
    blocked_ips.add(ip)
    save_blocked_ips(blocked_ips)
    logger.info(f"IP blocked: {ip}")

def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        save_blocked_ips(blocked_ips)
        logger.info(f"IP unblocked: {ip}")

def is_ip_blocked(ip):
    return ip in blocked_ips

# Victim App Routes
@app.route('/victim', methods=['GET', 'POST'])
def index():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_ip_blocked(ip):
         return render_template('blocked.html', ip=ip), 403
    log_request()  # Log every request
    if request.method == 'POST':
        # Simulate processing data
        data = request.form.get('data')
        logger.info(f"Data received: {data} from IP: {ip}")
        return render_template('success.html', data=data)
    return render_template('index.html')

@app.route('/victim/login', methods=['GET', 'POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_ip_blocked(ip):
         return render_template('blocked.html', ip=ip), 403
    log_request()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulate login attempt
        logger.info(f"Login attempt with username: {username} from IP: {ip}")
        if username == "admin" and password == "password":
            return "Login successful"
        else:
            return "Login failed"
    return render_template('login.html')

@app.route('/victim/api/data', methods=['GET'])
def api_data():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_ip_blocked(ip):
         return render_template('blocked.html', ip=ip), 403
    log_request()
    data = {"message": "This is some sensitive data."}
    return jsonify(data)

@app.route('/victim/download')
def download():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_ip_blocked(ip):
         return render_template('blocked.html', ip=ip), 403
    log_request()
    # Serve a dummy file
    file_data = io.BytesIO(b"This is a dummy file for testing.")
    return send_file(
        file_data,
        mimetype='text/plain',
        as_attachment=True,
        download_name='dummy.txt'
    )

# SOC Dashboard Routes
@app.route('/')
def dashboard():
    system_info = get_system_info()
    
    # Get recent logs for dashboard
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10"
    logs_df = pd.read_sql_query(query, conn)
    conn.close()
    
    recent_logs = logs_df.to_dict('records')
    
    # Get attack statistics
    conn = sqlite3.connect(DB_PATH)
    attack_stats_query = """
    SELECT attack_type, COUNT(*) as count 
    FROM logs 
    GROUP BY attack_type 
    ORDER BY count DESC
    """
    attack_stats_df = pd.read_sql_query(attack_stats_query, conn)
    conn.close()
    
    attack_stats = attack_stats_df.to_dict('records')
    
    return render_template('dashboard.html', 
                          system_info=system_info, 
                          recent_logs=recent_logs,
                          attack_stats=attack_stats)

@app.route('/logs')
def view_logs():
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100"
    logs_df = pd.read_sql_query(query, conn)
    conn.close()

    logs = logs_df.to_dict('records')
    return render_template('logs.html', logs=logs)

@app.route('/system_info')
def system_information():
    system_info = get_system_info()
    return jsonify(system_info)

@app.route('/block_ip', methods=['POST'])
def block():
    ip_to_block = request.form.get('ip')
    block_ip(ip_to_block)
    flash(f"IP {ip_to_block} blocked!", 'success')
    return redirect(url_for('dashboard'))

@app.route('/unblock_ip', methods=['POST'])
def unblock():
    ip_to_unblock = request.form.get('ip')
    unblock_ip(ip_to_unblock)
    flash(f"IP {ip_to_unblock} unblocked!", 'success')
    return redirect(url_for('dashboard'))

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    log_request()
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal Server Error: {str(e)}")
    log_request()
    return render_template('500.html'), 500

# Initialize the database
setup_db()

# Start Application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
