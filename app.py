import os
import json
import requests
import time
import hashlib
import hmac
import re
import secrets
import base64
from datetime import datetime, date, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, session, redirect, jsonify, flash, make_response, abort
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading
import socket
import uuid
from urllib.parse import urlparse
from collections import OrderedDict

SECRET_KEY = os.environ.get("SECRET_KEY", "aditya_dark0_master_secure_key_2026_change_me_in_production")
CSRF_SECRET = os.environ.get("CSRF_SECRET", secrets.token_hex(32))

PBKDF2_ITERATIONS = 600000
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15
MAX_REQUEST_SIZE = 1024 * 1024

SESSION_TIMEOUT_DAYS = 30
SESSION_TIMEOUT_HOURS = SESSION_TIMEOUT_DAYS * 24

_OWNER_SECRET = os.environ.get("OWNER_SECRET", "adityamasterapibypass")
_ADMIN_PASSWORD_ENV = os.environ.get("ADMIN_PASSWORD", "admin")
_ALLOWED_IPS_ENV = os.environ.get("ALLOWED_IPS", "")
_CUSTOM_APIS_ENV = os.environ.get("CUSTOM_APIS", "")
_API_KEYS_ENV = os.environ.get("API_KEYS", "")

MONGO_URI = os.environ.get("MONGO_URI", "")
DB_NAME = os.environ.get("DB_NAME", "api_master")

BLOCKED_USER_AGENTS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster',
    'wpscan', 'burpsuite', 'acunetix', 'nessus', 'openvas',
    'scrapy', 'httrack', 'libwww-perl', 'lwp-trivial'
]

ALLOWED_URL_SCHEMES = ['http', 'https']

BLOCKED_IP_RANGES = [
    '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '169.254.', '0.'
]

_executor = ThreadPoolExecutor(max_workers=4)

_session = requests.Session()
_session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive'
})
_session.mount('https://', requests.adapters.HTTPAdapter(
    pool_connections=10, pool_maxsize=10, max_retries=1, pool_block=False
))

class LRUCache:
    def __init__(self, maxsize=200):
        self.cache = OrderedDict()
        self.maxsize = maxsize
    def get(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            value, timestamp = self.cache[key]
            return value, timestamp
        return None, None
    def set(self, key, value, timestamp):
        if key in self.cache:
            self.cache.move_to_end(key)
        elif len(self.cache) >= self.maxsize:
            self.cache.popitem(last=False)
        self.cache[key] = (value, timestamp)
    def clear(self):
        self.cache.clear()

api_cache = LRUCache(maxsize=200)

IST = timedelta(hours=5, minutes=30)

def get_ist_time():
    return datetime.utcnow() + IST

def get_ist_time_str():
    return get_ist_time().strftime('%Y-%m-%d %H:%M:%S')

def get_ist_time_iso():
    return get_ist_time().isoformat()

def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(32)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), PBKDF2_ITERATIONS)
    return hash_bytes.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)

def hash_for_log(data: str) -> str:
    if not data:
        return "****"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()[:16]

def generate_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token: str) -> bool:
    if not token:
        return False
    stored_token = session.get('csrf_token')
    if not stored_token:
        return False
    return hmac.compare_digest(token, stored_token)

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not validate_csrf_token(token):
                abort(403, description="CSRF token validation failed")
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(value: str, max_length: int = 255, allow_html: bool = False) -> str:
    if not value:
        return ""
    value = value[:max_length]
    if not allow_html:
        value = re.sub(r'<[^>]+>', '', value)
        value = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        value = value.replace('"', '&quot;').replace("'", '&#x27;')
    value = value.replace('\x00', '')
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t\r')
    return value.strip()

def validate_api_name(name: str) -> tuple:
    if not name:
        return False, "", "API name is required"
    name = name.strip().lower()
    if len(name) < 2 or len(name) > 50:
        return False, "", "API name must be between 2 and 50 characters"
    if not re.match(r'^[a-z][a-z0-9_]*$', name):
        return False, "", "API name must start with a letter and contain only letters, numbers, and underscores"
    dangerous_patterns = ['..', '/', '\\', '%2e', '%2f', '%5c']
    for pattern in dangerous_patterns:
        if pattern in name.lower():
            return False, "", "API name contains invalid characters"
    reserved = ['admin', 'api', 'login', 'logout', 'static', 'assets', 'public', 'private', 'system', 'config']
    if name in reserved:
        return False, "", f"'{name}' is a reserved name"
    return True, name, ""

def validate_url_template(url: str) -> tuple:
    if not url:
        return False, "", "URL is required"
    url = url.strip()
    if len(url) > 2000:
        return False, "", "URL is too long (max 2000 characters)"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "", "Invalid URL format"
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        return False, "", f"URL scheme must be one of: {', '.join(ALLOWED_URL_SCHEMES)}"
    if not parsed.hostname:
        return False, "", "URL must have a valid hostname"
    hostname = parsed.hostname.lower()
    if hostname in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
        return False, "", "Localhost URLs are not allowed"
    for blocked_range in BLOCKED_IP_RANGES:
        if hostname.startswith(blocked_range):
            return False, "", "Internal/private IP addresses are not allowed"
    internal_patterns = ['.local', '.internal', '.corp', '.private', '.lan']
    for pattern in internal_patterns:
        if hostname.endswith(pattern):
            return False, "", "Internal hostnames are not allowed"
    metadata_hosts = ['169.254.169.254', 'metadata.google.internal', 'metadata.aws.internal']
    if hostname in metadata_hosts:
        return False, "", "Cloud metadata endpoints are not allowed"
    if '?' not in url and '=' not in url:
        url = url.rstrip('/') + '?query='
    return True, url, ""

def validate_ip_address(ip: str) -> tuple:
    if not ip:
        return False, "IP address is required"
    ip = ip.strip()
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(ipv4_pattern, ip)
    if not match:
        return False, "Invalid IP address format"
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False, f"Invalid IP address: octet {octet} is out of range (0-255)"
    return True, ""

def is_bot_request() -> bool:
    user_agent = request.headers.get('User-Agent', '').lower()
    for bot_pattern in BLOCKED_USER_AGENTS:
        if bot_pattern in user_agent:
            return True
    return False

def validate_origin() -> bool:
    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '')
    host = request.host
    if origin:
        try:
            parsed = urlparse(origin)
            if parsed.netloc == host:
                return True
        except:
            pass
    if referer:
        try:
            parsed = urlparse(referer)
            if parsed.netloc == host:
                return True
        except:
            pass
    if not origin and not referer:
        return True
    return False

def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def check_request_size():
    content_length = request.content_length
    if content_length and content_length > MAX_REQUEST_SIZE:
        abort(413, description="Request too large")

_login_attempts = {}
_login_attempts_lock = threading.Lock()

def check_login_lockout(ip: str) -> tuple:
    with _login_attempts_lock:
        if ip not in _login_attempts:
            return False, 0
        data = _login_attempts[ip]
        locked_until = data.get('locked_until', 0)
        if locked_until > time.time():
            return True, int(locked_until - time.time())
        if locked_until > 0 and locked_until <= time.time():
            del _login_attempts[ip]
        return False, 0

def record_login_attempt(ip: str, success: bool = False):
    with _login_attempts_lock:
        current_time = time.time()
        if success:
            if ip in _login_attempts:
                del _login_attempts[ip]
            return
        if ip not in _login_attempts:
            _login_attempts[ip] = {'count': 1, 'first_attempt': current_time, 'locked_until': 0}
        else:
            data = _login_attempts[ip]
            if current_time - data['first_attempt'] > LOGIN_LOCKOUT_MINUTES * 60:
                data['count'] = 1
                data['first_attempt'] = current_time
                data['locked_until'] = 0
            else:
                data['count'] += 1
                if data['count'] >= MAX_LOGIN_ATTEMPTS:
                    data['locked_until'] = current_time + (LOGIN_LOCKOUT_MINUTES * 60)

def get_login_attempts(ip: str) -> int:
    with _login_attempts_lock:
        if ip not in _login_attempts:
            return 0
        return _login_attempts[ip].get('count', 0)

_mongo_client = None
_db = None
_mongo_available = False
_mongo_initialized = False
_mongo_last_check = 0
_MONGO_CHECK_INTERVAL = 60

def init_mongo():
    global _mongo_client, _db, _mongo_available, _mongo_initialized, _mongo_last_check
    
    if not MONGO_URI:
        _mongo_available = False
        _mongo_initialized = True
        return None
    
    if _mongo_initialized and is_mongo_available():
        return _db
    current_time = time.time()
    if _mongo_initialized and (current_time - _mongo_last_check < _MONGO_CHECK_INTERVAL):
        return _db
    _mongo_last_check = current_time
    _mongo_initialized = True
    try:
        from pymongo import MongoClient
        _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000, socketTimeoutMS=5000)
        _mongo_client.admin.command('ping', serverSelectionTimeoutMS=2000)
        _db = _mongo_client[DB_NAME]
        _mongo_available = True
        try:
            _db.api_keys.create_index("key_id", unique=True)
            _db.custom_apis.create_index("api_name", unique=True)
            _db.api_logs.create_index("timestamp")
            _db.allowed_ips.create_index("ip", unique=True)
            _db.browser_ips.create_index("browser_id", unique=True)
            _db.whitelisted_browsers.create_index("browser_id", unique=True)
            _db.failed_logins.create_index("timestamp")
            _db.audit_logs.create_index("timestamp")
        except:
            pass
        return _db
    except Exception as e:
        _mongo_available = False
        return None

def get_db():
    return init_mongo()

def is_mongo_available():
    return _mongo_available

_initial_password_hash, _initial_salt = hash_password(_ADMIN_PASSWORD_ENV)

_memory_db = {
    "admin_password": {"hash": _initial_password_hash, "salt": _initial_salt, "version": 1, "last_changed": get_ist_time_str()},
    "api_keys": {},
    "api_settings": {
        "maintenance_mode": False, "allow_public_access": True, "rate_limit_per_minute": 60,
        "enable_logging": True, "cache_enabled": True, "cache_duration": 300, "blacklist_enabled": True,
        "auto_block_threshold": 50, "enable_credit": True, "credit_text": "@Aditya_dark0",
        "log_enabled": True, "max_logs": 1000, "ip_whitelist_enabled": True, "browser_ip_auto_add": True,
        "bot_blocking_enabled": True, "https_enforcement": True
    },
    "analytics": {"total_requests": 0, "daily_requests": {}, "api_usage": {}, "error_logs": [], "user_agents": {}, "top_ips": {}},
    "blacklist": {"ips": [], "keys": []},
    "rate_limits": {},
    "custom_apis": {},
    "api_logs": [],
    "allowed_ips": [],
    "browser_ips": {},
    "whitelisted_browsers": {},
    "failed_logins": [],
    "audit_logs": []
}

_cache = {
    "keys": None, "keys_time": 0, "custom_apis": None, "custom_apis_time": 0,
    "allowed_ips": None, "allowed_ips_time": 0, "browser_ips": None, "browser_ips_time": 0,
    "whitelisted_browsers": None, "whitelisted_browsers_time": 0
}
CACHE_TTL = 10

def log_audit_event(event_type: str, details: dict, admin: str = "admin"):
    db = get_db()
    event = {
        "event_type": event_type,
        "timestamp": get_ist_time_iso(),
        "ip": get_client_ip_from_request(),
        "user_agent": request.headers.get('User-Agent', 'Unknown')[:200] if request else 'Unknown',
        "admin": admin,
        "details": details
    }
    audit_logs = _memory_db.get("audit_logs", [])
    audit_logs.append(event)
    if len(audit_logs) > 1000:
        audit_logs = audit_logs[-1000:]
    _memory_db["audit_logs"] = audit_logs
    if is_mongo_available():
        def async_save():
            try:
                db.audit_logs.insert_one(event)
            except:
                pass
        _executor.submit(async_save)
    return event

def get_audit_logs(limit: int = 200) -> list:
    db = get_db()
    if is_mongo_available():
        try:
            logs = list(db.audit_logs.find({}, projection={"_id": 0}).sort("timestamp", -1).limit(limit))
            if logs:
                return logs
        except:
            pass
    return _memory_db.get("audit_logs", [])[-limit:]

def get_browser_id():
    browser_id = request.cookies.get('browser_id')
    if not browser_id:
        browser_id = str(uuid.uuid4())
    return browser_id

def set_browser_cookie(response, browser_id):
    response.set_cookie('browser_id', browser_id, max_age=30*24*60*60, path='/',
        httponly=True, secure=request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https', samesite='Lax')
    return response

def get_browser_ips():
    db = get_db()
    if _cache["browser_ips"] is not None and time.time() - _cache["browser_ips_time"] < CACHE_TTL:
        return _cache["browser_ips"]
    if is_mongo_available():
        try:
            docs = db.browser_ips.find({}, projection={"_id": 0})
            browser_ips = {}
            for doc in docs:
                browser_id = doc.get("browser_id")
                if browser_id:
                    browser_ips[browser_id] = doc.get("ip")
            _cache["browser_ips"] = browser_ips
            _cache["browser_ips_time"] = time.time()
            _memory_db["browser_ips"] = browser_ips
            return browser_ips
        except:
            pass
    return _memory_db.get("browser_ips", {})

def save_browser_ip(browser_id, ip):
    db = get_db()
    browser_ips = get_browser_ips()
    browser_ips[browser_id] = ip
    if is_mongo_available():
        try:
            db.browser_ips.update_one({"browser_id": browser_id},
                {"$set": {"browser_id": browser_id, "ip": ip, "updated_at": get_ist_time_iso()}}, upsert=True)
        except:
            pass
    _memory_db["browser_ips"] = browser_ips
    _cache["browser_ips"] = browser_ips
    _cache["browser_ips_time"] = time.time()
    return True

def delete_browser_ip(browser_id):
    db = get_db()
    browser_ips = get_browser_ips()
    if browser_id in browser_ips:
        del browser_ips[browser_id]
    if is_mongo_available():
        try:
            db.browser_ips.delete_one({"browser_id": browser_id})
        except:
            pass
    _memory_db["browser_ips"] = browser_ips
    _cache["browser_ips"] = browser_ips
    _cache["browser_ips_time"] = time.time()
    return True

def get_ip_for_browser(browser_id):
    browser_ips = get_browser_ips()
    return browser_ips.get(browser_id)

def get_whitelisted_browsers():
    db = get_db()
    if _cache["whitelisted_browsers"] is not None and time.time() - _cache["whitelisted_browsers_time"] < CACHE_TTL:
        return _cache["whitelisted_browsers"]
    if is_mongo_available():
        try:
            docs = db.whitelisted_browsers.find({}, projection={"_id": 0})
            browsers = {}
            for doc in docs:
                browser_id = doc.get("browser_id")
                if browser_id:
                    browsers[browser_id] = {"ip": doc.get("ip"), "added_at": doc.get("added_at"), "added_by": doc.get("added_by")}
            _cache["whitelisted_browsers"] = browsers
            _cache["whitelisted_browsers_time"] = time.time()
            _memory_db["whitelisted_browsers"] = browsers
            return browsers
        except:
            pass
    return _memory_db.get("whitelisted_browsers", {})

def add_whitelisted_browser(browser_id, ip, added_by="admin"):
    db = get_db()
    whitelisted = get_whitelisted_browsers()
    if browser_id in whitelisted:
        return True
    data = {"browser_id": browser_id, "ip": ip, "added_at": get_ist_time_iso(), "added_by": added_by}
    whitelisted[browser_id] = data
    if is_mongo_available():
        try:
            db.whitelisted_browsers.update_one({"browser_id": browser_id}, {"$set": data}, upsert=True)
        except:
            pass
    _memory_db["whitelisted_browsers"] = whitelisted
    _cache["whitelisted_browsers"] = whitelisted
    _cache["whitelisted_browsers_time"] = time.time()
    return True

def is_browser_whitelisted(browser_id):
    whitelisted = get_whitelisted_browsers()
    return browser_id in whitelisted

def remove_whitelisted_browser(browser_id):
    db = get_db()
    whitelisted = get_whitelisted_browsers()
    if browser_id not in whitelisted:
        return False
    del whitelisted[browser_id]
    if is_mongo_available():
        try:
            db.whitelisted_browsers.delete_one({"browser_id": browser_id})
        except:
            pass
    _memory_db["whitelisted_browsers"] = whitelisted
    _cache["whitelisted_browsers"] = whitelisted
    _cache["whitelisted_browsers_time"] = time.time()
    return True

def remove_browsers_by_ip(ip):
    db = get_db()
    removed_count = 0
    whitelisted = get_whitelisted_browsers()
    browsers_to_remove = []
    for browser_id, data in whitelisted.items():
        if data.get("ip") == ip:
            browsers_to_remove.append(browser_id)
    browser_ips = get_browser_ips()
    for browser_id, browser_ip in browser_ips.items():
        if browser_ip == ip and browser_id not in browsers_to_remove:
            browsers_to_remove.append(browser_id)
    for browser_id in browsers_to_remove:
        if browser_id in whitelisted:
            del whitelisted[browser_id]
            if is_mongo_available():
                try:
                    db.whitelisted_browsers.delete_one({"browser_id": browser_id})
                except:
                    pass
        if browser_id in browser_ips:
            del browser_ips[browser_id]
            if is_mongo_available():
                try:
                    db.browser_ips.delete_one({"browser_id": browser_id})
                except:
                    pass
        removed_count += 1
    _memory_db["whitelisted_browsers"] = whitelisted
    _memory_db["browser_ips"] = browser_ips
    _cache["whitelisted_browsers"] = whitelisted
    _cache["whitelisted_browsers_time"] = time.time()
    _cache["browser_ips"] = browser_ips
    _cache["browser_ips_time"] = time.time()
    return removed_count

def get_client_ip_from_request():
    if request:
        ip = request.headers.get('x-forwarded-for', '')
        if ip:
            return ip.split(',')[0].strip()
        ip = request.headers.get('x-real-ip', '')
        if ip:
            return ip.strip()
        ip = request.headers.get('x-vercel-ip', '')
        if ip:
            return ip.strip()
        return request.remote_addr
    return '0.0.0.0'

def get_server_ip():
    try:
        vercel_url = os.environ.get('VERCEL_URL', '')
        if vercel_url:
            try:
                ip = socket.gethostbyname(vercel_url.replace('https://', '').replace('http://', '').split('/')[0])
                if ip and ip != '127.0.0.1':
                    return ip
            except:
                pass
    except:
        pass
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if response.status_code == 200:
            ip = response.json().get('ip')
            if ip:
                return ip
    except:
        pass
    return '127.0.0.1'

def get_allowed_ips():
    db = get_db()
    if _cache["allowed_ips"] is not None and time.time() - _cache["allowed_ips_time"] < CACHE_TTL:
        return _cache["allowed_ips"]
    if is_mongo_available():
        try:
            docs = db.allowed_ips.find({}, projection={"_id": 0, "ip": 1})
            ips = [doc.get("ip") for doc in docs if doc.get("ip")]
            _cache["allowed_ips"] = ips
            _cache["allowed_ips_time"] = time.time()
            _memory_db["allowed_ips"] = ips
            return ips
        except:
            pass
    return _memory_db.get("allowed_ips", [])

def add_allowed_ip(ip):
    db = get_db()
    ip = ip.strip()
    if not ip or ip == '0.0.0.0':
        return False
    is_valid, error = validate_ip_address(ip)
    if not is_valid:
        return False
    current_ips = get_allowed_ips()
    if ip in current_ips:
        return True
    if is_mongo_available():
        try:
            db.allowed_ips.update_one({"ip": ip}, {"$set": {"ip": ip, "added_at": get_ist_time_iso()}}, upsert=True)
        except:
            pass
    current_ips.append(ip)
    _memory_db["allowed_ips"] = current_ips
    _cache["allowed_ips"] = current_ips
    _cache["allowed_ips_time"] = time.time()
    return True

def remove_allowed_ip(ip):
    db = get_db()
    ip = ip.strip()
    if not ip:
        return False
    current_ips = get_allowed_ips()
    if ip not in current_ips:
        return False
    if is_mongo_available():
        try:
            db.allowed_ips.delete_one({"ip": ip})
        except:
            pass
    current_ips.remove(ip)
    _memory_db["allowed_ips"] = current_ips
    _cache["allowed_ips"] = current_ips
    _cache["allowed_ips_time"] = time.time()
    return True

def remove_allowed_ip_and_browsers(ip):
    ip = ip.strip()
    if not ip:
        return False, 0
    remove_allowed_ip(ip)
    browsers_removed = remove_browsers_by_ip(ip)
    _cache["allowed_ips"] = None
    _cache["allowed_ips_time"] = 0
    _cache["browser_ips"] = None
    _cache["browser_ips_time"] = 0
    _cache["whitelisted_browsers"] = None
    _cache["whitelisted_browsers_time"] = 0
    return True, browsers_removed

def is_ip_allowed(ip):
    settings = get_settings()
    if not settings.get("ip_whitelist_enabled", True):
        return True
    if not ip or ip == '0.0.0.0':
        return False
    if ip == '127.0.0.1':
        return True
    allowed_ips = get_allowed_ips()
    if ip in allowed_ips:
        return True
    return False

def auto_add_server_ip():
    server_ip = get_server_ip()
    if server_ip and server_ip != '127.0.0.1':
        if add_allowed_ip(server_ip):
            return True
    return False

def handle_browser_ip_auto_add():
    settings = get_settings()
    if not settings.get("browser_ip_auto_add", True):
        return False
    client_ip = get_client_ip_from_request()
    if not client_ip or client_ip == '0.0.0.0':
        return False
    browser_id = get_browser_id()
    if not is_browser_whitelisted(browser_id):
        return False
    existing_ip = get_ip_for_browser(browser_id)
    if existing_ip != client_ip:
        save_browser_ip(browser_id, client_ip)
        add_allowed_ip(client_ip)
        return True
    if not is_ip_allowed(client_ip):
        add_allowed_ip(client_ip)
        return True
    return False

def login_ip_check():
    client_ip = get_client_ip_from_request()
    if not client_ip or client_ip == '0.0.0.0':
        return False
    settings = get_settings()
    
    owner_access = request.args.get('owner_access', '')
    if owner_access and owner_access == _OWNER_SECRET:
        browser_id = get_browser_id()
        add_allowed_ip(client_ip)
        add_whitelisted_browser(browser_id, client_ip, "owner_bypass")
        log_audit_event("owner_bypass_used", {"ip": client_ip})
        return True
    
    if not settings.get('ip_whitelist_enabled', True):
        return True
    
    browser_id = get_browser_id()
    if is_browser_whitelisted(browser_id):
        if settings.get('browser_ip_auto_add', True):
            handle_browser_ip_auto_add()
        if is_ip_allowed(client_ip):
            return True
    if is_ip_allowed(client_ip):
        return True
    return False

def log_failed_login(ip, password_attempt=None):
    db = get_db()
    log_entry = {
        "ip": ip,
        "timestamp": get_ist_time_iso(),
        "password_hash": hash_for_log(password_attempt),
        "user_agent": request.headers.get('User-Agent', 'Unknown')[:200] if request else 'Unknown'
    }
    failed_logs = _memory_db.get("failed_logins", [])
    failed_logs.append(log_entry)
    if len(failed_logs) > 500:
        failed_logs = failed_logs[-500:]
    _memory_db["failed_logins"] = failed_logs
    if is_mongo_available():
        def async_save():
            try:
                db.failed_logins.insert_one(log_entry)
            except:
                pass
        _executor.submit(async_save)
    return True

def get_failed_logins():
    db = get_db()
    if is_mongo_available():
        try:
            logs = list(db.failed_logins.find({}, projection={"_id": 0}).sort("timestamp", -1).limit(200))
            if logs:
                _memory_db["failed_logins"] = logs
                return logs
        except:
            pass
    return _memory_db.get("failed_logins", [])[-200:]

def clear_failed_logins():
    db = get_db()
    _memory_db["failed_logins"] = []
    if is_mongo_available():
        try:
            db.failed_logins.delete_many({})
        except:
            pass
    return True

def get_admin_password_hash():
    db = get_db()
    if is_mongo_available():
        try:
            doc = db.settings.find_one({"_id": "admin_password"}, projection={"hash": 1, "salt": 1, "version": 1})
            if doc:
                return doc.get("hash"), doc.get("salt"), doc.get("version", 1)
        except:
            pass
    return (_memory_db["admin_password"].get("hash"), _memory_db["admin_password"].get("salt"), _memory_db["admin_password"].get("version", 1))

def get_admin_password_version():
    _, _, version = get_admin_password_hash()
    return version

def set_admin_password(new_password):
    db = get_db()
    new_hash, new_salt = hash_password(new_password)
    current_version = get_admin_password_version()
    new_version = current_version + 1
    data = {"_id": "admin_password", "hash": new_hash, "salt": new_salt, "version": new_version, "last_changed": get_ist_time_str()}
    if is_mongo_available():
        try:
            db.settings.update_one({"_id": "admin_password"}, {"$set": data}, upsert=True)
        except:
            pass
    _memory_db["admin_password"] = data
    log_audit_event("password_changed", {"new_version": new_version})

def verify_admin_password(password):
    stored_hash, salt, _ = get_admin_password_hash()
    if not stored_hash or not salt:
        return False
    return verify_password(password, stored_hash, salt)

def get_keys():
    db = get_db()
    today_str = str(date.today())
    if _cache["keys"] is not None and time.time() - _cache["keys_time"] < CACHE_TTL:
        keys = _cache["keys"]
        for k_id, key_data in keys.items():
            if key_data.get('last_used_date') != today_str:
                key_data['used'] = 0
                key_data['last_used_date'] = today_str
        return keys
    if is_mongo_available():
        try:
            keys_cursor = db.api_keys.find({}, projection={"_id": 0})
            keys = {}
            for doc in keys_cursor:
                key_id = doc.get("key_id")
                if not key_id:
                    key_name = doc.get("key_name")
                    api_type = doc.get("api_type")
                    if key_name and api_type:
                        key_id = f"{key_name}::{api_type}"
                    else:
                        continue
                keys[key_id] = doc
            _cache["keys"] = keys
            _cache["keys_time"] = time.time()
            _memory_db["api_keys"] = keys
            return keys
        except:
            pass
    keys = _memory_db.get("api_keys", {})
    for k_id, key_data in keys.items():
        key_data.setdefault('used', 0)
        key_data.setdefault('last_used_date', today_str)
        if key_data.get('last_used_date') != today_str:
            key_data['used'] = 0
            key_data['last_used_date'] = today_str
    return keys

def get_key(key_id):
    keys = get_keys()
    return keys.get(key_id)

def save_api_key(key_id, key_data):
    db = get_db()
    key_data['updated_at'] = get_ist_time_iso()
    key_data['key_id'] = key_id
    if is_mongo_available():
        def async_save():
            try:
                db.api_keys.update_one({"key_id": key_id}, {"$set": key_data}, upsert=True)
            except:
                pass
        _executor.submit(async_save)
    keys = _memory_db.get("api_keys", {})
    keys[key_id] = key_data.copy()
    _memory_db["api_keys"] = keys
    _cache["keys"] = keys
    _cache["keys_time"] = time.time()
    return True

def delete_api_key(key_id):
    db = get_db()
    if is_mongo_available():
        def async_delete():
            try:
                db.api_keys.delete_one({"key_id": key_id})
            except:
                pass
        _executor.submit(async_delete)
    keys = _memory_db.get("api_keys", {})
    if key_id in keys:
        del keys[key_id]
        _memory_db["api_keys"] = keys
        _cache["keys"] = keys
        _cache["keys_time"] = time.time()
        return True
    return False

def increment_key_usage(key_id):
    keys = _memory_db.get("api_keys", {})
    today_str = str(date.today())
    if key_id in keys:
        keys[key_id]['used'] = keys[key_id].get('used', 0) + 1
        keys[key_id]['last_used_date'] = today_str
        _memory_db["api_keys"] = keys
        db = get_db()
        if is_mongo_available():
            def async_update():
                try:
                    db.api_keys.update_one({"key_id": key_id}, {"$inc": {"used": 1}, "$set": {"last_used_date": today_str}})
                except:
                    pass
            _executor.submit(async_update)
        return True
    return False

def get_custom_apis():
    db = get_db()
    if _cache["custom_apis"] is not None and time.time() - _cache["custom_apis_time"] < CACHE_TTL:
        return _cache["custom_apis"]
    if is_mongo_available():
        try:
            docs = db.custom_apis.find({}, projection={"_id": 0})
            apis = {}
            for doc in docs:
                api_name = doc.get("api_name")
                if api_name:
                    apis[api_name] = doc.get("api_url", "")
            _cache["custom_apis"] = apis
            _cache["custom_apis_time"] = time.time()
            _memory_db["custom_apis"] = apis
            return apis
        except:
            pass
    return _memory_db.get("custom_apis", {})

def save_custom_api(api_name, api_url):
    db = get_db()
    api_url = api_url.strip()
    if not api_url.endswith('=') and not api_url.endswith('&') and not api_url.endswith('?'):
        if '?' in api_url:
            api_url += '&'
        else:
            api_url += '?'
    if is_mongo_available():
        def async_save():
            try:
                db.custom_apis.update_one({"api_name": api_name}, {"$set": {"api_name": api_name, "api_url": api_url}}, upsert=True)
            except:
                pass
        _executor.submit(async_save)
    apis = _memory_db.get("custom_apis", {})
    apis[api_name] = api_url
    _memory_db["custom_apis"] = apis
    _cache["custom_apis"] = apis
    _cache["custom_apis_time"] = time.time()
    return True

def delete_custom_api(api_name):
    db = get_db()
    if is_mongo_available():
        def async_delete():
            try:
                db.custom_apis.delete_one({"api_name": api_name})
            except:
                pass
        _executor.submit(async_delete)
    apis = _memory_db.get("custom_apis", {})
    if api_name in apis:
        del apis[api_name]
        _memory_db["custom_apis"] = apis
        _cache["custom_apis"] = apis
        _cache["custom_apis_time"] = time.time()
        return True
    return False

def get_settings():
    default = {
        "maintenance_mode": False, "allow_public_access": True, "rate_limit_per_minute": 60,
        "enable_logging": True, "cache_enabled": True, "cache_duration": 300, "blacklist_enabled": True,
        "auto_block_threshold": 50, "enable_credit": True, "credit_text": "@Aditya_dark0",
        "log_enabled": True, "max_logs": 1000, "ip_whitelist_enabled": True, "browser_ip_auto_add": True,
        "bot_blocking_enabled": True, "https_enforcement": True
    }
    settings = _memory_db.get("api_settings", {})
    return {**default, **settings}

def save_settings(settings):
    _memory_db["api_settings"] = settings

def get_analytics():
    default = {"total_requests": 0, "daily_requests": {}, "api_usage": {}, "error_logs": [], "user_agents": {}, "top_ips": {}}
    analytics = _memory_db.get("analytics", {})
    return {**default, **analytics}

def update_analytics(api_key, api_type, status, ip, user_agent):
    analytics = _memory_db.get("analytics", {})
    today = str(date.today())
    analytics["total_requests"] = analytics.get("total_requests", 0) + 1
    analytics["daily_requests"][today] = analytics["daily_requests"].get(today, 0) + 1
    analytics["api_usage"][api_type] = analytics["api_usage"].get(api_type, 0) + 1
    if user_agent:
        analytics["user_agents"][user_agent] = analytics["user_agents"].get(user_agent, 0) + 1
    if ip:
        analytics["top_ips"][ip] = analytics["top_ips"].get(ip, 0) + 1
    if len(analytics.get("top_ips", {})) > 1000:
        analytics["top_ips"] = dict(sorted(analytics["top_ips"].items(), key=lambda x: x[1], reverse=True)[:1000])
    if len(analytics.get("error_logs", [])) > 500:
        analytics["error_logs"] = analytics["error_logs"][-500:]
    _memory_db["analytics"] = analytics

def log_error(error_type, message, api_key=None, query=None):
    analytics = _memory_db.get("analytics", {})
    analytics["error_logs"].append({
        "timestamp": get_ist_time_iso(), "type": error_type, "message": message,
        "api_key": api_key, "query": query
    })
    if len(analytics["error_logs"]) > 500:
        analytics["error_logs"] = analytics["error_logs"][-500:]
    _memory_db["analytics"] = analytics

def save_api_log(log_entry):
    settings = get_settings()
    if not settings.get("log_enabled", True):
        return
    if 'timestamp' not in log_entry:
        log_entry['timestamp'] = get_ist_time_iso()
    max_logs = settings.get("max_logs", 1000)
    logs = _memory_db.get("api_logs", [])
    logs.append(log_entry)
    if len(logs) > max_logs:
        logs = logs[-max_logs:]
    _memory_db["api_logs"] = logs
    db = get_db()
    if is_mongo_available():
        def async_save_to_mongo():
            try:
                db.api_logs.insert_one(log_entry)
            except:
                pass
        _executor.submit(async_save_to_mongo)
    return True

def get_api_logs():
    settings = get_settings()
    max_logs = settings.get("max_logs", 1000)
    db = get_db()
    if is_mongo_available():
        try:
            logs = list(db.api_logs.find({}, projection={"_id": 0}).sort("timestamp", -1).limit(max_logs))
            if logs:
                return logs
        except:
            pass
    logs = _memory_db.get("api_logs", [])
    return logs[-max_logs:]

def clear_api_logs():
    _memory_db["api_logs"] = []
    db = get_db()
    if is_mongo_available():
        def async_clear():
            try:
                db.api_logs.delete_many({})
            except:
                pass
        _executor.submit(async_clear)
    return True

def log_api_request(api_key, api_type, query, ip, user_agent, status_code, response_time, success):
    def async_log():
        log_entry = {
            "api_key": api_key,
            "api_type": api_type,
            "query": query,
            "ip": ip,
            "user_agent": sanitize_input(user_agent, max_length=200) if user_agent else "Unknown",
            "status_code": status_code,
            "response_time_ms": round(response_time * 1000, 2),
            "success": success,
            "timestamp": get_ist_time_iso()
        }
        save_api_log(log_entry)
    _executor.submit(async_log)

def get_blacklist():
    default = {"ips": [], "keys": []}
    blacklist = _memory_db.get("blacklist", {})
    return {**default, **blacklist}

_rate_limits = {}
_RATE_LIMIT_CLEANUP = time.time()
_RATE_LIMIT_EXPIRE = 60

def rate_limit_check(ip):
    global _RATE_LIMIT_CLEANUP
    current_minute = int(time.time() / 60)
    settings = get_settings()
    limit = settings.get("rate_limit_per_minute", 60)
    key = f"{ip}:{current_minute}"
    count = _rate_limits.get(key, 0)
    if count >= limit:
        return False
    _rate_limits[key] = count + 1
    current_time = time.time()
    if current_time - _RATE_LIMIT_CLEANUP > _RATE_LIMIT_EXPIRE:
        _RATE_LIMIT_CLEANUP = current_time
        current_min = int(current_time / 60)
        for k in list(_rate_limits.keys()):
            try:
                k_min = int(k.split(':')[1])
                if current_min - k_min > 2:
                    del _rate_limits[k]
            except:
                pass
    return True

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=SESSION_TIMEOUT_DAYS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_PERMANENT'] = True
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['JSON_AS_ASCII'] = False

VERSION = "3.2.0"
MAX_KEYS_PER_USER = 100
API_NAME = "Aditya_dark0 Master"

@app.before_request
def security_middleware():
    check_request_size()
    settings = get_settings()
    if settings.get('bot_blocking_enabled', True):
        if is_bot_request() and not request.path.startswith('/api/v1/info'):
            abort(403, description="Access denied")
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        if not validate_origin():
            if not request.path.startswith('/api/v1/'):
                abort(403, description="Invalid request origin")

@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/login')
        session_ip = session.get('session_ip')
        current_ip = get_client_ip_from_request()
        if session_ip and session_ip != current_ip:
            session.clear()
            flash('Session expired due to IP change. Please login again.', 'warning')
            return redirect('/login')
        current_version = get_admin_password_version()
        session_version = session.get('admin_password_version')
        if session_version is None or session_version != current_version:
            session.clear()
            flash('Password changed. Please login again.', 'warning')
            return redirect('/login')
        login_time_str = session.get('login_time')
        if login_time_str:
            try:
                login_time = datetime.strptime(login_time_str, '%Y-%m-%d %H:%M:%S')
                if datetime.utcnow() - login_time > timedelta(days=SESSION_TIMEOUT_DAYS):
                    session.clear()
                    flash('Session expired. Please login again.', 'warning')
                    return redirect('/login')
            except:
                pass
        return f(*args, **kwargs)
    return decorated_function

def clean_response_with_details(data, key_info):
    if isinstance(data, dict) and 'result' in data:
        result_data = data['result']
    elif isinstance(data, dict) and 'data' in data:
        result_data = data['data']
    else:
        result_data = data

    metadata_keywords = {
        'credit', 'owner', 'powered', 'buy', 'support', 'channel',
        'telegram', 'author', 'created_by', 'api_by', 'developed_by', 'powered_by',
        'circle', 'total_records', 'additional_info', 'additonal_info',
        'response_parameters', 'api_version', 'server_time', 'cached',
        'response_time', 'req_left', 'req_total', 'expiry', 'duplicates_removed',
        'api_name', 'developer', 'developers', 'dev', 'devs',
        'sb-sakib', 'sakib', 'sakib01994', 'sb_sakib'
    }

    def clean_dict(d):
        if isinstance(d, dict):
            keys_to_delete = [k for k in d.keys() if any(kw in k.lower() for kw in metadata_keywords)]
            for key in keys_to_delete:
                del d[key]
            for key, value in d.items():
                if isinstance(value, (dict, list)):
                    clean_dict(value)
        elif isinstance(d, list):
            for item in d:
                if isinstance(item, dict):
                    clean_dict(item)
        return d

    cleaned_result = clean_dict(result_data) if isinstance(result_data, (dict, list)) else result_data

    limit = key_info.get('limit', 0)
    used = key_info.get('used', 0)
    remaining = limit - used if limit > 0 else "Unlimited"
    expiry_date = key_info.get('expiry_date', '2099-12-31')
    
    warning_message = None
    try:
        expiry_obj = datetime.strptime(expiry_date, '%Y-%m-%d').date()
        today_date = date.today()
        days_left = (expiry_obj - today_date).days
        status = "Active" if days_left >= 0 else "Expired"
        
        if days_left == 3:
            warning_message = "your key is expire on 3 days"
        elif days_left == 2:
            warning_message = "your key is expire on 2 days"
        elif days_left == 1:
            warning_message = "your key is expire on 1 day"
        elif days_left == 0:
            warning_message = "your key expires today!"
            
    except:
        status = "Unknown"

    final_response = {
        "result": cleaned_result,
        "key_details": {
            "daily_limit": limit, 
            "used_today": used, 
            "remaining": remaining,
            "expiry_date": expiry_date, 
            "api_type": key_info.get('api_type', 'N/A'), 
            "status": status
        }
    }
    
    if warning_message:
        final_response["warning"] = warning_message
        
    final_response["developer"] = "@Aditya_dark0"
    final_response["telegram"] = "https://t.me/AdityaXcyber"
    
    return json.dumps(final_response, ensure_ascii=False, indent=2), 200, {'Content-Type': 'application/json'}

BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ API Master · Aditya_dark0</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:opsz@14..32&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #0b1120; color: #e2e8f0; min-height: 100vh; background-image: radial-gradient(circle at 20% 30%, rgba(56, 189, 248, 0.04) 0%, transparent 60%), radial-gradient(circle at 80% 70%, rgba(250, 204, 21, 0.03) 0%, transparent 50%); }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.1); border-radius: 24px; padding: 24px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; flex-wrap: wrap; gap: 14px; margin-bottom: 28px; background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.1); border-radius: 40px; }
        .logo-area { display: flex; align-items: center; gap: 14px; }
        .logo-icon { width: 44px; height: 44px; background: linear-gradient(135deg, #38bdf8, #818cf8); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 22px; color: #0b1120; }
        .logo-text h1 { font-size: 22px; font-weight: 700; background: linear-gradient(to right, #38bdf8, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .logo-text span { font-size: 13px; color: #94a3b8; }
        .header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .status-badge { padding: 6px 16px; border-radius: 40px; font-size: 12px; font-weight: 600; background: rgba(52, 211, 153, 0.12); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.2); display: inline-flex; align-items: center; gap: 6px; }
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 8px 18px; border-radius: 40px; font-weight: 600; font-size: 13px; border: none; cursor: pointer; transition: all 0.2s; text-decoration: none; background: transparent; color: #e2e8f0; border: 1px solid rgba(56, 189, 248, 0.15); font-family: 'Inter', sans-serif; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(56, 189, 248, 0.15); }
        .btn-primary { background: #38bdf8; color: #0b1120; border-color: #38bdf8; }
        .btn-success { background: #10b981; color: #0b1120; border-color: #10b981; }
        .btn-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border-color: rgba(239, 68, 68, 0.25); }
        .btn-warning { background: rgba(250, 204, 21, 0.12); color: #fbbf24; border-color: rgba(250, 204, 21, 0.2); }
        .btn-info { background: rgba(56, 189, 248, 0.12); color: #38bdf8; border-color: rgba(56, 189, 248, 0.2); }
        .btn-outline { border: 1px solid rgba(148, 163, 184, 0.3); color: #cbd5e1; }
        .btn-sm { padding: 4px 14px; font-size: 12px; }
        .btn-block { width: 100%; justify-content: center; padding: 12px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 18px; margin-bottom: 28px; }
        .stat-card { background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(56, 189, 248, 0.07); border-radius: 20px; padding: 20px 16px; text-align: center; }
        .stat-card .stat-icon { font-size: 26px; color: #38bdf8; margin-bottom: 8px; }
        .stat-card .stat-number { font-size: 32px; font-weight: 700; color: #f8fafc; }
        .stat-card .stat-label { font-size: 12px; text-transform: uppercase; color: #94a3b8; margin-top: 4px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #94a3b8; margin-bottom: 6px; }
        .form-control { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.12); border-radius: 16px; color: #f1f5f9; font-size: 14px; font-family: 'Inter', sans-serif; }
        .form-control:focus { outline: none; border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15); }
        .form-control::placeholder { color: #475569; }
        .password-wrap { position: relative; }
        .password-wrap .form-control { padding-right: 48px; }
        .password-toggle { position: absolute; right: 14px; top: 50%; transform: translateY(-50%); background: none; border: none; color: #64748b; cursor: pointer; font-size: 16px; padding: 6px; z-index: 2; }
        .password-toggle:hover { color: #38bdf8; }
        .toggle { position: relative; display: inline-block; width: 48px; height: 28px; flex-shrink: 0; }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #334155; transition: 0.3s; border-radius: 40px; }
        .toggle .slider:before { content: ""; position: absolute; height: 20px; width: 20px; left: 4px; bottom: 4px; background: #94a3b8; transition: 0.3s; border-radius: 50%; }
        .toggle input:checked + .slider { background: #38bdf8; }
        .toggle input:checked + .slider:before { transform: translateX(20px); background: #0b1120; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px 14px; font-size: 11px; font-weight: 600; text-transform: uppercase; color: #94a3b8; border-bottom: 1px solid rgba(56, 189, 248, 0.08); }
        td { padding: 12px 14px; border-bottom: 1px solid rgba(56, 189, 248, 0.05); font-size: 13px; }
        .badge { display: inline-block; padding: 3px 12px; border-radius: 40px; font-size: 11px; font-weight: 600; }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-expired { background: rgba(239, 68, 68, 0.12); color: #f87171; }
        .badge-success { background: rgba(16, 185, 129, 0.12); color: #34d399; }
        .badge-danger { background: rgba(239, 68, 68, 0.12); color: #f87171; }
        .badge-custom { background: rgba(56, 189, 248, 0.1); color: #7dd3fc; }
        .badge-ip { background: rgba(250, 204, 21, 0.1); color: #fbbf24; }
        .badge-server { background: rgba(52, 211, 153, 0.1); color: #34d399; }
        .badge-browser { background: rgba(168, 85, 247, 0.1); color: #c084fc; }
        .badge-whitelisted { background: rgba(52, 211, 153, 0.12); color: #34d399; }
        .badge-not-whitelisted { background: rgba(239, 68, 68, 0.12); color: #f87171; }
        .badge-failed { background: rgba(239, 68, 68, 0.12); color: #f87171; }
        .url-display { background: rgba(15, 23, 42, 0.5); padding: 6px 12px; border-radius: 12px; font-size: 11px; font-family: monospace; word-break: break-all; border-left: 3px solid #38bdf8; max-width: 280px; color: #cbd5e1; margin-bottom: 6px; }
        .url-display .query-placeholder { color: #fbbf24; font-weight: 700; }
        .copy-btn { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 3px 14px; border-radius: 40px; font-size: 11px; cursor: pointer; font-family: 'Inter', sans-serif; }
        .copy-btn:hover { background: #38bdf8; color: #0b1120; }
        .copy-btn.copied { background: #10b981; color: #0b1120; }
        .log-container { max-height: 600px; overflow-y: auto; }
        .log-entry { display: flex; flex-wrap: wrap; gap: 12px 18px; padding: 12px 14px; border-bottom: 1px solid rgba(56, 189, 248, 0.05); font-size: 13px; align-items: center; }
        .log-entry:hover { background: rgba(56, 189, 248, 0.03); }
        .log-time { color: #94a3b8; font-size: 12px; min-width: 150px; }
        .log-key { color: #fbbf24; font-weight: 700; font-size: 12px; padding: 2px 10px; background: rgba(250, 204, 21, 0.08); border-radius: 20px; border: 1px solid rgba(250, 204, 21, 0.15); }
        .log-type { color: #7dd3fc; font-weight: 600; font-size: 12px; }
        .log-ip { color: #64748b; font-size: 12px; font-family: monospace; }
        .log-query { color: #34d399; font-weight: 700; font-size: 13px; padding: 3px 12px; background: rgba(52, 211, 153, 0.1); border-radius: 20px; border: 1px solid rgba(52, 211, 153, 0.2); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .log-response-time { color: #a78bfa; font-size: 12px; }
        .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .custom-api-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px; background: rgba(15, 23, 42, 0.4); border-radius: 16px; margin-bottom: 8px; border-left: 4px solid #38bdf8; flex-wrap: wrap; gap: 8px; }
        .custom-api-item .api-name { font-weight: 600; color: #f1f5f9; font-size: 14px; }
        .custom-api-item .api-url { color: #94a3b8; font-size: 12px; word-break: break-all; max-width: 55%; }
        .delete-api-btn { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.15); color: #f87171; padding: 4px 14px; border-radius: 40px; font-size: 12px; cursor: pointer; font-family: 'Inter', sans-serif; }
        .delete-api-btn:hover { background: #ef4444; color: #0b1120; }
        .alert { padding: 14px 20px; border-radius: 20px; margin-bottom: 20px; font-size: 14px; border: 1px solid transparent; }
        .alert-success { background: rgba(16, 185, 129, 0.12); color: #34d399; border-color: rgba(16, 185, 129, 0.15); }
        .alert-danger { background: rgba(239, 68, 68, 0.10); color: #f87171; border-color: rgba(239, 68, 68, 0.15); }
        .alert-info { background: rgba(56, 189, 248, 0.08); color: #7dd3fc; border-color: rgba(56, 189, 248, 0.12); }
        .alert-warning { background: rgba(250, 204, 21, 0.08); color: #fbbf24; border-color: rgba(250, 204, 21, 0.12); }
        .login-container { max-width: 420px; margin: 60px auto; padding: 0 16px; }
        .login-container .card { padding: 40px 32px; text-align: center; }
        .login-container .logo-icon-lg { font-size: 56px; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 16px; }
        .footer-text { text-align: center; margin-top: 36px; padding: 16px; color: #475569; font-size: 13px; border-top: 1px solid rgba(56, 189, 248, 0.06); }
        .footer-text .highlight { color: #38bdf8; }
        .toast { position: fixed; bottom: 30px; right: 30px; background: rgba(30, 41, 59, 0.9); color: #e2e8f0; padding: 16px 24px; border-radius: 40px; border: 1px solid rgba(56, 189, 248, 0.15); box-shadow: 0 8px 32px rgba(0,0,0,0.5); display: none; z-index: 999; font-size: 14px; font-family: 'Inter', sans-serif; align-items: center; gap: 10px; }
        .flex { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; }
        .flex-between { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .mb-20 { margin-bottom: 24px; }
        .text-muted { color: #94a3b8; font-size: 13px; }
        .section-title { font-size: 20px; font-weight: 600; color: #f1f5f9; margin-bottom: 20px; }
        .section-title i { color: #38bdf8; margin-right: 10px; }
        .fast-badge { display: inline-block; padding: 2px 10px; border-radius: 40px; font-size: 10px; font-weight: 700; background: linear-gradient(135deg, #10b981, #34d399); color: #0b1120; margin-left: 8px; }
        .mongo-status { display: inline-block; padding: 4px 12px; border-radius: 40px; font-size: 11px; font-weight: 600; background: rgba(52, 211, 153, 0.12); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.2); }
        .mongo-status.fallback { background: rgba(251, 191, 36, 0.12); color: #fbbf24; border-color: rgba(251, 191, 36, 0.2); }
        .edit-btn { background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 3px 14px; border-radius: 40px; font-size: 11px; cursor: pointer; font-family: 'Inter', sans-serif; }
        .edit-btn:hover { background: #38bdf8; color: #0b1120; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-content { background: rgba(30, 41, 59, 0.95); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 24px; padding: 32px; max-width: 500px; width: 90%; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h3 { font-size: 20px; color: #f1f5f9; }
        .modal-close { background: none; border: none; color: #94a3b8; font-size: 24px; cursor: pointer; padding: 0 8px; }
        .server-ip-box { background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 12px; padding: 10px 16px; margin-bottom: 16px; }
        .server-ip-box .label { color: #94a3b8; font-size: 12px; }
        .server-ip-box .ip { color: #34d399; font-weight: 600; font-family: monospace; font-size: 16px; }
        .ip-verified-badge { display: inline-block; background: rgba(52, 211, 153, 0.12); color: #34d399; padding: 4px 16px; border-radius: 40px; font-size: 13px; border: 1px solid rgba(52, 211, 153, 0.2); }
        .developer-name { color: #38bdf8; font-weight: 600; }
        .browser-status { display: inline-block; padding: 6px 16px; border-radius: 40px; font-size: 11px; font-weight: 600; }
        .browser-status.whitelisted { background: rgba(52, 211, 153, 0.12); color: #34d399; }
        .browser-status.not-whitelisted { background: rgba(239, 68, 68, 0.12); color: #f87171; }
        .nav-box { background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(56, 189, 248, 0.1); border-radius: 24px; padding: 18px; margin-bottom: 28px; }
        .nav-box .nav-title { font-size: 12px; font-weight: 600; text-transform: uppercase; color: #64748b; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
        .nav-box .nav-title i { color: #38bdf8; font-size: 14px; }
        .nav-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
        .nav-item { display: flex; align-items: center; gap: 12px; padding: 14px 18px; border-radius: 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.08); color: #94a3b8; text-decoration: none; font-weight: 600; font-size: 13px; }
        .nav-item:hover { background: rgba(56, 189, 248, 0.08); border-color: rgba(56, 189, 248, 0.25); color: #e2e8f0; }
        .nav-item.active { background: rgba(56, 189, 248, 0.12); border-color: #38bdf8; color: #38bdf8; }
        .nav-item .nav-icon { width: 36px; height: 36px; border-radius: 10px; background: rgba(56, 189, 248, 0.08); display: flex; align-items: center; justify-content: center; font-size: 15px; color: #38bdf8; }
        .nav-item .nav-label { display: flex; flex-direction: column; gap: 2px; }
        .nav-item .nav-label .nav-sub { font-size: 10px; font-weight: 400; color: #64748b; text-transform: uppercase; }
        @media (max-width: 900px) { .nav-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 480px) { .nav-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="container">
    {% if not logged_in %}
        {% block login_content %}{% endblock %}
    {% else %}
        <div class="header">
            <div class="logo-area">
                <div class="logo-icon"><i class="fas fa-bolt"></i></div>
                <div class="logo-text">
                    <h1>API Master <span class="fast-badge"><i class="fas fa-bolt"></i> SECURED</span></h1>
                    <span>v{{ version }} · Premium</span>
                </div>
            </div>
            <div class="header-actions">
                <span class="status-badge"><i class="fas fa-circle"></i> Online</span>
                <span class="browser-status {% if browser_whitelisted %}whitelisted{% else %}not-whitelisted{% endif %}">
                    <i class="fas fa-{% if browser_whitelisted %}check-circle{% else %}times-circle{% endif %}"></i> 
                    {% if browser_whitelisted %}Whitelisted{% else %}Not Whitelisted{% endif %}
                </span>
                <span class="mongo-status {% if mongo_status == 'connected' %}mongo-status{% else %}fallback{% endif %}">
                    <i class="fas fa-database"></i> {% if mongo_status == 'connected' %}MongoDB{% else %}Fallback{% endif %}
                </span>
                <button class="btn btn-outline btn-sm" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Refresh</button>
                <a href="/logout" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </div>

        <div class="nav-box">
            <div class="nav-title"><i class="fas fa-compass"></i> Navigation Menu</div>
            <div class="nav-grid">
                <a href="/dashboard" class="nav-item {% if active_page == 'dashboard' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-chart-pie"></i></div>
                    <div class="nav-label"><span>Dashboard</span><span class="nav-sub">Overview</span></div>
                </a>
                <a href="/keys" class="nav-item {% if active_page == 'keys' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-key"></i></div>
                    <div class="nav-label"><span>API Keys</span><span class="nav-sub">Manage</span></div>
                </a>
                <a href="/custom-apis" class="nav-item {% if active_page == 'custom_apis' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-plug"></i></div>
                    <div class="nav-label"><span>Custom APIs</span><span class="nav-sub">Endpoints</span></div>
                </a>
                <a href="/ip-security" class="nav-item {% if active_page == 'ip_security' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-shield-alt"></i></div>
                    <div class="nav-label"><span>IP Security</span><span class="nav-sub">Whitelist</span></div>
                </a>
                <a href="/logs" class="nav-item {% if active_page == 'logs' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-history"></i></div>
                    <div class="nav-label"><span>API Logs</span><span class="nav-sub">History</span></div>
                </a>
                <a href="/failed-logins" class="nav-item {% if active_page == 'failed_logins' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="nav-label"><span>Failed Logins</span><span class="nav-sub">Alerts</span></div>
                </a>
                <a href="/settings" class="nav-item {% if active_page == 'settings' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-cog"></i></div>
                    <div class="nav-label"><span>Settings</span><span class="nav-sub">Config</span></div>
                </a>
                <a href="/change_password" class="nav-item {% if active_page == 'change_password' %}active{% endif %}">
                    <div class="nav-icon"><i class="fas fa-key"></i></div>
                    <div class="nav-label"><span>Password</span><span class="nav-sub">Security</span></div>
                </a>
            </div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message|safe }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}

        <div class="footer-text">
            <i class="fas fa-bolt"></i> API Master v{{ version }} · 
            <span class="highlight">Developed by @Aditya_dark0</span><br>
            <a href="https://t.me/AdityaXcyber" target="_blank" style="color: #38bdf8; text-decoration: none; display: inline-block; margin-top: 8px;">
                <i class="fab fa-telegram"></i> Join Telegram Channel
            </a>
        </div>
    {% endif %}
</div>
<div id="toast" class="toast">
    <i class="fas fa-check-circle" style="color: #34d399;"></i> <span id="toastMessage">Copied!</span>
</div>
<script>
    function copyToClipboard(elementId, buttonElement) {
        const element = document.getElementById(elementId);
        let text = element.innerText.replace('{query}', '{query}');
        const isSecure = window.isSecureContext || location.protocol === 'https:';
        if (isSecure && navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('URL copied! ✅');
                if (buttonElement) {
                    buttonElement.classList.add('copied');
                    buttonElement.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        buttonElement.classList.remove('copied');
                        buttonElement.innerHTML = '<i class="fas fa-copy"></i> Copy';
                    }, 2000);
                }
            });
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showToast('URL copied! ✅');
        }
    }
    function showToast(message) {
        const toast = document.getElementById('toast');
        document.getElementById('toastMessage').textContent = message;
        toast.style.display = 'flex';
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => { toast.style.display = 'none'; }, 3000);
    }
    document.getElementById('toast').addEventListener('click', function() {
        this.style.display = 'none';
        clearTimeout(this._timeout);
    });
    function openEditModal(keyId, keyName, apiType, limit, expiry) {
        document.getElementById('edit_old_key_id').value = keyId;
        document.getElementById('edit_new_key_name').value = keyName;
        document.getElementById('edit_api_type').value = apiType;
        document.getElementById('edit_limit').value = limit;
        document.getElementById('edit_expiry').value = expiry;
        document.getElementById('editModal').classList.add('show');
    }
    function closeEditModal() {
        document.getElementById('editModal').classList.remove('show');
    }
    function togglePassword(inputId, buttonEl) {
        const input = document.getElementById(inputId);
        if (!input) return;
        if (input.type === 'password') {
            input.type = 'text';
            if (buttonEl) buttonEl.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            input.type = 'password';
            if (buttonEl) buttonEl.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            var editModal = document.getElementById('editModal');
            if (editModal) editModal.classList.remove('show');
        }
    });
</script>
</body>
</html>"""

LOGIN_TEMPLATE = BASE_HTML.replace(
    '{% block login_content %}{% endblock %}',
    '''{% block login_content %}
        <div class="login-container">
            <div class="card">
                <div class="logo-icon-lg"><i class="fas fa-bolt"></i></div>
                <h2 style="font-size: 28px; font-weight: 700; background: linear-gradient(135deg, #38bdf8, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">API Master</h2>
                <p style="color: #94a3b8; margin-bottom: 8px; font-size: 14px;">🔒 Secure · Fast · Intelligent</p>
                
                <div style="text-align: center; margin-bottom: 20px; min-height: 30px;">
                    {% if ip_verified %}
                        <span class="ip-verified-badge">
                            <i class="fas fa-check-circle"></i> Verified IP
                        </span>
                    {% endif %}
                </div>
                
                {% if locked_out %}
                    <div class="alert alert-danger" style="text-align: center;">
                        <i class="fas fa-lock"></i> Too many failed attempts.<br>
                        Try again in <strong>{{ lockout_seconds }}</strong> seconds.
                    </div>
                {% else %}
                    <form method="POST" action="/login">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <div class="form-group">
                            <div class="password-wrap">
                                <input type="password" name="password" id="login_password" class="form-control" placeholder="Enter admin password" required autocomplete="current-password">
                                <button type="button" class="password-toggle" onclick="togglePassword('login_password', this)"><i class="fas fa-eye"></i></button>
                            </div>
                        </div>
                        {% if login_attempts > 0 %}
                            <div style="font-size: 12px; color: #f87171; margin-bottom: 12px;">
                                <i class="fas fa-exclamation-triangle"></i> {{ login_attempts }} failed attempt(s)
                            </div>
                        {% endif %}
                        <button type="submit" class="btn btn-primary btn-block" style="padding: 14px;">
                            <i class="fas fa-lock"></i> Access Dashboard
                        </button>
                    </form>
                {% endif %}
                
                <div style="margin-top: 20px; font-size: 13px; color: #475569;">
                    <i class="fas fa-shield-alt"></i> Secured by <span class="developer-name">@Aditya_dark0</span><br>
                    <a href="https://t.me/AdityaXcyber" target="_blank" style="color: #38bdf8; text-decoration: none; display: inline-block; margin-top: 8px;">
                        <i class="fab fa-telegram"></i> Join Telegram Channel
                    </a>
                </div>
            </div>
        </div>
    {% endblock %}'''
)

@app.route('/')
def home():
    if session.get('admin'):
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = get_client_ip_from_request()
    browser_id = get_browser_id()
    
    is_locked, lockout_seconds = check_login_lockout(client_ip)
    
    response = None
    ip_verified = login_ip_check()
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    if request.method == 'GET':
        response = make_response(render_template_string(
            LOGIN_TEMPLATE, logged_in=False, version=VERSION,
            ip_verified=ip_verified, client_ip=client_ip, browser_id=browser_id,
            browser_whitelisted=browser_whitelisted, csrf_token=csrf_token,
            locked_out=is_locked, lockout_seconds=lockout_seconds,
            login_attempts=get_login_attempts(client_ip)
        ))
        return set_browser_cookie(response, browser_id)
    
    if request.method == 'POST':
        if is_locked:
            flash(f'Too many failed attempts. Try again in {lockout_seconds} seconds.', 'danger')
            response = make_response(render_template_string(
                LOGIN_TEMPLATE, logged_in=False, version=VERSION,
                ip_verified=ip_verified, client_ip=client_ip, browser_id=browser_id,
                browser_whitelisted=browser_whitelisted, csrf_token=csrf_token,
                locked_out=True, lockout_seconds=lockout_seconds,
                login_attempts=get_login_attempts(client_ip)
            ))
            return set_browser_cookie(response, browser_id)
        
        csrf_token_form = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token_form):
            abort(403, description="CSRF token validation failed")
        
        if not ip_verified:
            password_attempt = request.form.get('password', '')
            log_failed_login(client_ip, password_attempt)
            record_login_attempt(client_ip, success=False)
            flash('❌ IP not verified! Contact admin to whitelist your IP.', 'danger')
            response = make_response(render_template_string(
                LOGIN_TEMPLATE, logged_in=False, version=VERSION,
                ip_verified=False, client_ip=client_ip, browser_id=browser_id,
                browser_whitelisted=browser_whitelisted, csrf_token=generate_csrf_token(),
                locked_out=False, lockout_seconds=0,
                login_attempts=get_login_attempts(client_ip)
            ))
            return set_browser_cookie(response, browser_id)
        
        password = request.form.get('password')
        
        stored_hash, salt, version = get_admin_password_hash()
        if not stored_hash or not salt:
            flash('⚠️ Password not configured. Contact administrator.', 'danger')
            return redirect('/login')
        
        if verify_admin_password(password):
            record_login_attempt(client_ip, success=True)
            session.clear()
            session['admin'] = True
            session['login_time'] = get_ist_time_str()
            session['admin_password_version'] = get_admin_password_version()
            session['browser_id'] = browser_id
            session['session_ip'] = client_ip
            session.permanent = True
            session['csrf_token'] = secrets.token_hex(32)
            log_audit_event("successful_login", {"ip": client_ip})
            return redirect('/dashboard')
        else:
            log_failed_login(client_ip, password)
            record_login_attempt(client_ip, success=False)
            attempts = get_login_attempts(client_ip)
            remaining = MAX_LOGIN_ATTEMPTS - attempts
            if remaining <= 2 and remaining > 0:
                flash(f'❌ Wrong password! {remaining} attempt(s) left.', 'danger')
            else:
                flash('❌ Wrong password! Please try again.', 'danger')
    
    response = make_response(render_template_string(
        LOGIN_TEMPLATE, logged_in=False, version=VERSION,
        ip_verified=ip_verified, client_ip=client_ip, browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, csrf_token=generate_csrf_token(),
        locked_out=False, lockout_seconds=0,
        login_attempts=get_login_attempts(client_ip)
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/dashboard')
@admin_required
def dashboard():
    analytics = get_analytics()
    settings = get_settings()
    custom_apis = get_custom_apis()
    api_logs = get_api_logs()
    allowed_ips = get_allowed_ips()
    failed_logins = get_failed_logins()
    client_ip = get_client_ip_from_request()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    
    DASHBOARD_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-keys"></i></div><div class="stat-number">{{ keys|length }}</div><div class="stat-label">Total Keys</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-chart-line"></i></div><div class="stat-number">{{ analytics.total_requests|default(0) }}</div><div class="stat-label">Total Requests</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-calendar-day"></i></div><div class="stat-number">{{ analytics.daily_requests.get(today, 0)|default(0) }}</div><div class="stat-label">Today</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-plug"></i></div><div class="stat-number">{{ custom_apis|length }}</div><div class="stat-label">Custom APIs</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-history"></i></div><div class="stat-number">{{ api_logs|length }}</div><div class="stat-label">API Logs</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-shield-alt"></i></div><div class="stat-number">{{ allowed_ips|length }}</div><div class="stat-label">Allowed IPs</div></div>
            <div class="stat-card"><div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div><div class="stat-number">{{ failed_logins|length }}</div><div class="stat-label">Failed Logins</div></div>
        </div>

        <div class="card mb-20">
            <div class="flex-between">
                <h3 class="section-title" style="margin-bottom: 0;">
                    <i class="fas fa-{% if browser_whitelisted %}check-circle{% else %}times-circle{% endif %}"></i> Browser Status
                </h3>
                <span class="badge {% if browser_whitelisted %}badge-whitelisted{% else %}badge-not-whitelisted{% endif %}">
                    {% if browser_whitelisted %}Whitelisted{% else %}Not Whitelisted{% endif %}
                </span>
            </div>
            <div style="background: rgba(15,23,42,0.4); border-radius: 16px; padding: 16px;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                    <div>
                        <div style="font-size: 12px; color: #94a3b8;">Your IP</div>
                        <div style="font-family: monospace; font-size: 16px; color: #34d399; font-weight: 600;">{{ client_ip }}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #94a3b8;">Browser ID</div>
                        <div style="font-family: monospace; font-size: 13px; color: #94a3b8;">{{ browser_id[:8] }}...{{ browser_id[-8:] }}</div>
                    </div>
                </div>
            </div>
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        DASHBOARD_TEMPLATE, logged_in=True, keys=get_keys(), settings=settings,
        host_url=request.url_root, analytics=analytics, today=str(date.today()),
        version=VERSION, custom_apis=custom_apis, api_logs=api_logs,
        mongo_status="connected" if is_mongo_available() else "fallback",
        allowed_ips=allowed_ips, failed_logins=failed_logins, client_ip=client_ip,
        browser_id=browser_id, browser_whitelisted=browser_whitelisted,
        active_page='dashboard'
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/keys')
@admin_required
def keys_page():
    keys = get_keys()
    custom_apis = get_custom_apis()
    host_url = request.url_root
    today = str(date.today())
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    KEYS_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card mb-20">
            <h3 class="section-title"><i class="fas fa-plus-circle"></i> Generate New API Key</h3>
            <form method="POST" action="/generate">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>Select Services (Check all that apply)</label>
                        <div style="display: flex; gap: 12px; flex-wrap: wrap; background: rgba(15,23,42,0.6); padding: 12px; border-radius: 16px; border: 1px solid rgba(56,189,248,0.12);">
                            {% if custom_apis %}
                                {% for api_name in custom_apis.keys() %}
                                    <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #f1f5f9; text-transform: none;">
                                        <input type="checkbox" name="services" value="{{ api_name }}" style="width: 16px; height: 16px;"> 🔧 {{ api_name|upper }}
                                    </label>
                                {% endfor %}
                            {% else %}
                                <span style="color: #94a3b8; font-size: 13px;">No APIs available. Add custom APIs first.</span>
                            {% endif %}
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Key Name (Base Name)</label>
                        <input type="text" name="key_name" class="form-control" placeholder="premium_user" required pattern="[a-zA-Z0-9_]+" maxlength="50">
                    </div>
                    <div class="form-group">
                        <label>Daily Limit</label>
                        <input type="number" name="limit" class="form-control" placeholder="0 = Unlimited" required min="0">
                    </div>
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>Expiry Date</label>
                        <input type="date" name="expiry" class="form-control" required>
                    </div>
                    <div style="grid-column: 1 / -1;">
                        <button type="submit" class="btn btn-success btn-block" style="padding: 14px;">
                            <i class="fas fa-key"></i> Generate Keys for Selected Services
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <div class="card">
            <div class="flex-between mb-20">
                <h3 class="section-title" style="margin-bottom: 0;"><i class="fas fa-database"></i> Active API Keys</h3>
                <span class="text-muted">{{ keys|length }} keys</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Key Name</th>
                            <th>Service Type</th>
                            <th>Usage</th>
                            <th>Expiry</th>
                            <th>Status</th>
                            <th>Endpoint</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for k_id, v in keys.items() %}
                        <tr>
                            <td><strong style="color: #f1f5f9;">{{ v.key_name }}</strong></td>
                            <td><span class="badge badge-custom">{{ v.api_type|upper }}</span></td>
                            <td><strong>{{ v.used }}</strong> / {% if v.limit == 0 %}∞{% else %}{{ v.limit }}{% endif %}</td>
                            <td style="font-size: 12px;">{{ v.expiry_date }}</td>
                            <td>
                                {% if v.expiry_date < today %}
                                    <span class="badge badge-expired">Expired</span>
                                {% else %}
                                    <span class="badge badge-active">Active</span>
                                {% endif %}
                            </td>
                            <td>
                                <div class="url-display" id="url_{{ loop.index }}">
                                    {{ host_url }}api/v1/info?service={{ v.api_type }}&key={{ v.key_name }}&query=<span class="query-placeholder">{query}</span>
                                </div>
                                <button class="copy-btn" onclick="copyToClipboard('url_{{ loop.index }}', this)">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            </td>
                            <td>
                                <button class="edit-btn" onclick="openEditModal('{{ k_id }}', '{{ v.key_name }}', '{{ v.api_type }}', '{{ v.limit }}', '{{ v.expiry_date }}')">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <form method="POST" action="/delete_key" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                    <input type="hidden" name="key_id" value="{{ k_id }}">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete?')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div id="editModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-edit"></i> Update Key</h3>
                    <button class="modal-close" onclick="closeEditModal()">&times;</button>
                </div>
                <form method="POST" action="/update_key">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="hidden" name="old_key_id" id="edit_old_key_id">
                    <div class="form-group">
                        <label>Key Name</label>
                        <input type="text" name="new_key_name" id="edit_new_key_name" class="form-control" required pattern="[a-zA-Z0-9_]+">
                    </div>
                    <div class="form-group">
                        <label>API Type</label>
                        <select name="api_type" id="edit_api_type" class="form-control" required>
                            {% for api_name in custom_apis.keys() %}
                                <option value="{{ api_name }}">{{ api_name|upper }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Daily Limit</label>
                        <input type="number" name="limit" id="edit_limit" class="form-control" required min="0">
                    </div>
                    <div class="form-group">
                        <label>Expiry</label>
                        <input type="date" name="expiry_date" id="edit_expiry" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-success btn-block">Update</button>
                </form>
            </div>
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        KEYS_TEMPLATE, logged_in=True, keys=keys, custom_apis=custom_apis,
        host_url=host_url, today=today, version=VERSION,
        mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='keys', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/custom-apis')
@admin_required
def custom_apis_page():
    custom_apis = get_custom_apis()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    CUSTOM_APIS_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card mb-20">
            <h3 class="section-title"><i class="fas fa-plug"></i> Add Custom API</h3>
            <form method="POST" action="/add_custom_api">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; align-items: end;">
                    <div class="form-group">
                        <label>API Name</label>
                        <input type="text" name="api_name" class="form-control" placeholder="number" required pattern="[a-z][a-z0-9_]*" maxlength="50">
                    </div>
                    <div class="form-group">
                        <label>API URL</label>
                        <input type="url" name="api_url" class="form-control" placeholder="https://api.example.com?query=" required maxlength="2000">
                    </div>
                    <button type="submit" class="btn btn-info" style="height: 48px; padding: 0 24px;">
                        <i class="fas fa-plus"></i> Add
                    </button>
                </div>
            </form>
        </div>

        <div class="card">
            <h3 class="section-title"><i class="fas fa-list"></i> Custom APIs</h3>
            {% if custom_apis %}
                {% for api_name, api_url in custom_apis.items() %}
                    <div class="custom-api-item">
                        <span class="api-name">{{ api_name|upper }}</span>
                        <span class="api-url">{{ api_url }}</span>
                        <form method="POST" action="/delete_custom_api" style="display: inline;">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                            <input type="hidden" name="api_name" value="{{ api_name }}">
                            <button type="submit" class="delete-api-btn" onclick="return confirm('Delete?')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </form>
                    </div>
                {% endfor %}
            {% else %}
                <div style="text-align: center; color: #475569; padding: 40px 0;">
                    <i class="fas fa-info-circle"></i> No custom APIs yet.
                </div>
            {% endif %}
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        CUSTOM_APIS_TEMPLATE, logged_in=True, custom_apis=custom_apis,
        version=VERSION, mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='custom_apis', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/ip-security')
@admin_required
def ip_security_page():
    allowed_ips = get_allowed_ips()
    server_ip = get_server_ip()
    client_ip = get_client_ip_from_request()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    settings = get_settings()
    whitelisted_browsers_map = get_whitelisted_browsers()
    csrf_token = generate_csrf_token()
    
    IP_SECURITY_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card mb-20">
            <h3 class="section-title"><i class="fas fa-shield-alt"></i> IP Whitelist</h3>
            <div class="server-ip-box">
                <div class="label"><i class="fas fa-server"></i> Server IP</div>
                <div class="ip">{{ server_ip }}</div>
            </div>
            <form method="POST" action="/add_ip" style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <div style="flex: 1; min-width: 200px;">
                    <input type="text" name="ip_address" class="form-control" placeholder="Enter IP" required pattern="^(\\d{1,3}\\.){3}\\d{1,3}$">
                </div>
                <button type="submit" class="btn btn-success">Add IP</button>
                <button type="submit" name="whitelist_browser" value="true" class="btn btn-info">Add & Whitelist Browser</button>
            </form>
            {% if allowed_ips %}
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>IP</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>
                            {% for ip in allowed_ips %}
                            <tr>
                                <td><span style="font-family: monospace; color: #e2e8f0;">{{ ip }}</span></td>
                                <td>
                                    {% if ip == server_ip %}
                                        <span class="badge badge-server">Server IP</span>
                                    {% elif ip == client_ip %}
                                        <span class="badge badge-ip">Your IP</span>
                                    {% else %}
                                        <span class="badge badge-ip">Allowed</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if ip != server_ip %}
                                        <form method="POST" action="/remove_ip" style="display: inline;">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                            <input type="hidden" name="ip_address" value="{{ ip }}">
                                            <input type="hidden" name="full_remove" value="true">
                                            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Remove?')">
                                                <i class="fas fa-trash"></i> Remove
                                            </button>
                                        </form>
                                    {% else %}
                                        <span style="color: #64748b;"><i class="fas fa-lock"></i> Protected</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            {% endif %}
        </div>

        <div class="card">
            <h3 class="section-title"><i class="fas fa-globe"></i> Whitelisted Browsers ({{ whitelisted_browsers_map|length }})</h3>
            {% if whitelisted_browsers_map %}
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Browser ID</th><th>IP</th><th>Added By</th><th>Action</th></tr></thead>
                        <tbody>
                            {% for bid, bdata in whitelisted_browsers_map.items() %}
                            <tr>
                                <td><span style="font-family: monospace; color: #c084fc; font-size: 12px;">{{ bid[:16] }}...</span></td>
                                <td><span style="font-family: monospace; color: #34d399;">{{ bdata.ip }}</span></td>
                                <td><span class="badge badge-browser">{{ bdata.added_by|default('admin') }}</span></td>
                                <td>
                                    <form method="POST" action="/remove_browser" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                        <input type="hidden" name="browser_id" value="{{ bid }}">
                                        <button type="submit" class="btn btn-danger btn-sm">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            {% else %}
                <div style="text-align: center; color: #475569; padding: 20px 0;">No whitelisted browsers</div>
            {% endif %}
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        IP_SECURITY_TEMPLATE, logged_in=True, allowed_ips=allowed_ips,
        server_ip=server_ip, client_ip=client_ip, browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, settings=settings, version=VERSION,
        mongo_status="connected" if is_mongo_available() else "fallback",
        whitelisted_browsers_map=whitelisted_browsers_map,
        active_page='ip_security', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/logs')
@admin_required
def logs_page():
    api_logs = get_api_logs()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    LOGS_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card">
            <div class="flex-between mb-20">
                <h3 class="section-title" style="margin-bottom: 0;"><i class="fas fa-history"></i> API Logs</h3>
                <div class="flex">
                    <span class="text-muted">{{ api_logs|length }} logs</span>
                    <form method="POST" action="/clear_logs" style="display: inline;" onsubmit="return confirm('Clear all?')">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash-alt"></i> Clear</button>
                    </form>
                </div>
            </div>
            {% if api_logs %}
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th style="min-width:150px;">Time (IST)</th>
                                <th style="min-width:120px;">Key Name</th>
                                <th style="min-width:90px;">Type</th>
                                <th style="min-width:200px;">🔍 Search Query</th>
                                <th style="min-width:120px;">IP</th>
                                <th style="min-width:80px;">Status</th>
                                <th style="min-width:70px;">Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in api_logs %}
                            <tr>
                                <td style="font-size: 12px; color: #94a3b8;">{{ log.timestamp[:19].replace('T', ' ') }}</td>
                                <td><span class="log-key">{{ log.api_key }}</span></td>
                                <td><span class="log-type">{{ log.api_type|upper }}</span></td>
                                <td>
                                    <div class="log-query" title="{{ log.query }}">🔍 {{ log.query }}</div>
                                </td>
                                <td><span class="log-ip">{{ log.ip }}</span></td>
                                <td>
                                    {% if log.success %}
                                        <span class="badge badge-success">✓ Success</span>
                                    {% else %}
                                        <span class="badge badge-danger">✗ Failed</span>
                                    {% endif %}
                                </td>
                                <td><span class="log-response-time">{{ log.response_time_ms }}ms</span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            {% else %}
                <div style="text-align: center; color: #475569; padding: 40px 0;">No logs yet</div>
            {% endif %}
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        LOGS_TEMPLATE, logged_in=True, api_logs=api_logs, version=VERSION,
        mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='logs', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/failed-logins')
@admin_required
def failed_logins_page():
    failed_logins = get_failed_logins()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    FAILED_LOGINS_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card">
            <div class="flex-between mb-20">
                <h3 class="section-title" style="margin-bottom: 0;"><i class="fas fa-exclamation-triangle"></i> Failed Logins</h3>
                <div class="flex">
                    <span class="text-muted">{{ failed_logins|length }} attempts</span>
                    <form method="POST" action="/clear_failed_logins" style="display: inline;" onsubmit="return confirm('Clear all?')">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash-alt"></i> Clear</button>
                    </form>
                </div>
            </div>
            {% if failed_logins %}
                <div class="log-container">
                    {% for log in failed_logins %}
                        <div class="log-entry">
                            <span class="log-time"><i class="far fa-clock"></i> {{ log.timestamp[:19].replace('T', ' ') }}</span>
                            <span class="log-ip"><i class="fas fa-network-wired"></i> {{ log.ip }}</span>
                            <span class="badge badge-failed">Failed</span>
                            <span class="log-key" style="color: #f87171;"><i class="fas fa-key"></i> {{ log.password_hash }}</span>
                        </div>
                    {% endfor %}
                </div>
            {% else %}
                <div style="text-align: center; color: #475569; padding: 40px 0;">
                    <i class="fas fa-check-circle" style="color: #34d399; font-size: 32px;"></i>
                    <p>No failed attempts</p>
                </div>
            {% endif %}
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        FAILED_LOGINS_TEMPLATE, logged_in=True, failed_logins=failed_logins,
        version=VERSION, mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='failed_logins', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/settings')
@admin_required
def settings_page():
    settings = get_settings()
    analytics = get_analytics()
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    SETTINGS_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card">
            <h3 class="section-title"><i class="fas fa-cog"></i> Advanced Settings</h3>
            <div class="settings-grid">
                <div>
                    <h4 style="color: #94a3b8; margin-bottom: 16px; font-size: 14px;"><i class="fas fa-sliders-h"></i> System</h4>
                    <form method="POST" action="/update_config">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Maintenance Mode</label>
                                <label class="toggle"><input type="checkbox" name="maintenance_mode" {% if settings.maintenance_mode %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Enable Logging</label>
                                <label class="toggle"><input type="checkbox" name="enable_logging" {% if settings.enable_logging %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Enable Cache</label>
                                <label class="toggle"><input type="checkbox" name="cache_enabled" {% if settings.cache_enabled %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Enable API Logs</label>
                                <label class="toggle"><input type="checkbox" name="log_enabled" {% if settings.log_enabled %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">IP Whitelist</label>
                                <label class="toggle"><input type="checkbox" name="ip_whitelist_enabled" {% if settings.ip_whitelist_enabled %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Browser IP Auto-Add</label>
                                <label class="toggle"><input type="checkbox" name="browser_ip_auto_add" {% if settings.browser_ip_auto_add %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex-between">
                                <label style="margin-bottom: 0;">Bot Blocking</label>
                                <label class="toggle"><input type="checkbox" name="bot_blocking_enabled" {% if settings.bot_blocking_enabled %}checked{% endif %}><span class="slider"></span></label>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Rate Limit (req/min)</label>
                            <input type="number" name="rate_limit_per_minute" class="form-control" value="{{ settings.rate_limit_per_minute }}" min="10" max="1000">
                        </div>
                        <div class="form-group">
                            <label>Max Logs</label>
                            <input type="number" name="max_logs" class="form-control" value="{{ settings.max_logs }}" min="10" max="10000">
                        </div>
                        <button type="submit" class="btn btn-warning btn-block">Save</button>
                    </form>
                </div>
                <div>
                    <h4 style="color: #94a3b8; margin-bottom: 16px; font-size: 14px;"><i class="fas fa-chart-bar"></i> Analytics</h4>
                    <div style="background: rgba(15,23,42,0.4); padding: 16px; border-radius: 20px; max-height: 400px; overflow-y: auto;">
                        <strong style="color: #f1f5f9; font-size: 13px;">API Usage:</strong>
                        {% for api, count in analytics.api_usage.items() %}
                            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(56,189,248,0.04); font-size: 13px;">
                                <span>{{ api|upper }}</span><span style="color: #38bdf8;">{{ count }}</span>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        SETTINGS_TEMPLATE, logged_in=True, settings=settings, analytics=analytics,
        version=VERSION, mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='settings', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    browser_id = session.get('browser_id', get_browser_id())
    browser_whitelisted = is_browser_whitelisted(browser_id)
    csrf_token = generate_csrf_token()
    
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not validate_csrf_token(token):
            abort(403)
        
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        
        if not verify_admin_password(current):
            log_audit_event("failed_password_change", {"reason": "wrong_current"})
            flash('Current password is incorrect!', 'danger')
            return redirect('/change_password')
        
        if not new or len(new) < 8:
            flash('Password must be at least 8 characters!', 'danger')
            return redirect('/change_password')
        
        has_upper = any(c.isupper() for c in new)
        has_lower = any(c.islower() for c in new)
        has_digit = any(c.isdigit() for c in new)
        
        if not (has_upper and has_lower and has_digit):
            flash('Password needs uppercase, lowercase, and numbers!', 'danger')
            return redirect('/change_password')
        
        if new != confirm:
            flash('Passwords do not match!', 'danger')
            return redirect('/change_password')
        
        set_admin_password(new)
        flash('✅ Password changed! Please login again.', 'success')
        session.clear()
        return redirect('/login')
    
    CHANGE_PASSWORD_TEMPLATE = BASE_HTML.replace(
        '{% block content %}{% endblock %}',
        '''{% block content %}
        <div class="card" style="max-width: 500px; margin: 0 auto;">
            <h3 class="section-title" style="text-align: center;"><i class="fas fa-key"></i> Change Password</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <div class="form-group">
                    <label>Current Password</label>
                    <div class="password-wrap">
                        <input type="password" name="current_password" id="current_password" class="form-control" required autocomplete="current-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('current_password', this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <div class="password-wrap">
                        <input type="password" name="new_password" id="new_password" class="form-control" required minlength="8" autocomplete="new-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('new_password', this)"><i class="fas fa-eye"></i></button>
                    </div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 4px;">
                        <i class="fas fa-shield-alt"></i> Min 8 chars, uppercase + lowercase + number
                    </div>
                </div>
                <div class="form-group">
                    <label>Confirm Password</label>
                    <div class="password-wrap">
                        <input type="password" name="confirm_password" id="confirm_password" class="form-control" required minlength="8" autocomplete="new-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('confirm_password', this)"><i class="fas fa-eye"></i></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-success btn-block">Change Password</button>
            </form>
        </div>
        {% endblock %}'''
    )
    
    response = make_response(render_template_string(
        CHANGE_PASSWORD_TEMPLATE, logged_in=True, version=VERSION,
        mongo_status="connected" if is_mongo_available() else "fallback",
        client_ip=get_client_ip_from_request(), browser_id=browser_id,
        browser_whitelisted=browser_whitelisted, active_page='change_password', csrf_token=csrf_token
    ))
    return set_browser_cookie(response, browser_id)

@app.route('/logout')
def logout():
    log_audit_event("logout", {})
    session.clear()
    return redirect('/login')

@app.route('/add_ip', methods=['POST'])
@admin_required
@csrf_protect
def add_ip():
    ip = request.form.get('ip_address', '').strip()
    whitelist_browser = request.form.get('whitelist_browser') == 'true'
    is_valid, error = validate_ip_address(ip)
    if not is_valid:
        flash(f'❌ {error}', 'danger')
        return redirect('/ip-security')
    if add_allowed_ip(ip):
        log_audit_event("ip_added", {"ip": ip})
        flash(f'✅ IP "{ip}" added!', 'success')
    else:
        flash(f'⚠️ IP already exists', 'warning')
    if whitelist_browser:
        browser_id = get_browser_id()
        add_whitelisted_browser(browser_id, ip, "admin")
    return redirect('/ip-security')

@app.route('/remove_ip', methods=['POST'])
@admin_required
@csrf_protect
def remove_ip():
    ip = request.form.get('ip_address', '').strip()
    full_remove = request.form.get('full_remove', 'false') == 'true'
    if not ip:
        flash('Invalid IP!', 'danger')
        return redirect('/ip-security')
    if full_remove:
        success, browsers_removed = remove_allowed_ip_and_browsers(ip)
        log_audit_event("ip_full_removed", {"ip": ip, "browsers": browsers_removed})
        flash(f'✅ IP removed + {browsers_removed} browser(s)!', 'success')
    else:
        if remove_allowed_ip(ip):
            log_audit_event("ip_removed", {"ip": ip})
            flash(f'✅ IP removed!', 'success')
    return redirect('/ip-security')

@app.route('/remove_browser', methods=['POST'])
@admin_required
@csrf_protect
def remove_browser():
    browser_id = request.form.get('browser_id', '').strip()
    if not browser_id:
        flash('Invalid!', 'danger')
        return redirect('/ip-security')
    remove_whitelisted_browser(browser_id)
    delete_browser_ip(browser_id)
    log_audit_event("browser_removed", {"browser_id": browser_id[:16]})
    flash('✅ Browser removed!', 'success')
    return redirect('/ip-security')

@app.route('/generate', methods=['POST'])
@admin_required
@csrf_protect
def generate_web():
    keys = get_keys()
    key_name = sanitize_input(request.form.get('key_name', ''), max_length=50)
    if not key_name or not re.match(r'^[a-zA-Z0-9_]+$', key_name):
        flash('Invalid key name! Use only letters, numbers, and underscores.', 'danger')
        return redirect('/keys')
        
    services = request.form.getlist('services')
    if not services:
        flash('Please select at least one API service!', 'danger')
        return redirect('/keys')
        
    try:
        limit = int(request.form.get('limit', 0))
        if limit < 0:
            limit = 0
    except:
        limit = 0
        
    expiry = request.form.get('expiry', '')
    keys_created = 0
    
    for api_type in services:
        key_id = f"{key_name}::{api_type}"
        if len(keys) >= MAX_KEYS_PER_USER and key_id not in keys:
            flash(f'Max keys reached! Stopped after creating {keys_created} keys.', 'warning')
            break
            
        key_data = {
            "key_name": key_name,
            "limit": limit, 
            "used": 0, 
            "expiry_date": expiry,
            "api_type": api_type, 
            "last_used_date": str(date.today()),
            "created_at": get_ist_time_iso(), 
            "created_by": get_client_ip_from_request()
        }
        
        save_api_key(key_id, key_data)
        keys_created += 1
        
    log_audit_event("api_keys_created", {"key_name": key_name, "services": services})
    flash(f'✅ Successfully generated {keys_created} keys for "{key_name}"!', 'success')
    return redirect('/keys')

@app.route('/delete_key', methods=['POST'])
@admin_required
@csrf_protect
def delete_web():
    key_id = request.form.get('key_id', '')
    if key_id:
        delete_api_key(key_id)
        log_audit_event("api_key_deleted", {"key_id": key_id})
        flash(f'Key deleted!', 'warning')
    return redirect('/keys')

@app.route('/reset_key', methods=['POST'])
@admin_required
@csrf_protect
def reset_key():
    key_id = request.form.get('key_id', '')
    key_data = get_key(key_id)
    if key_data:
        key_data['used'] = 0
        key_data['last_used_date'] = str(date.today())
        save_api_key(key_id, key_data)
        flash(f'Key reset!', 'success')
    return redirect('/keys')

@app.route('/update_key', methods=['POST'])
@admin_required
@csrf_protect
def update_key():
    old_key_id = request.form.get('old_key_id', '')
    new_key_name = sanitize_input(request.form.get('new_key_name', ''), max_length=50)
    new_api_type = sanitize_input(request.form.get('api_type', ''), max_length=50)
    limit = request.form.get('limit', '0')
    expiry_date = request.form.get('expiry_date', '')
    
    if not old_key_id or not new_key_name:
        flash('Invalid key!', 'danger')
        return redirect('/keys')
        
    if not re.match(r'^[a-zA-Z0-9_]+$', new_key_name):
        flash('Invalid key name!', 'danger')
        return redirect('/keys')
        
    key_data = get_key(old_key_id)
    if not key_data:
        flash('Key not found!', 'danger')
        return redirect('/keys')
        
    new_key_id = f"{new_key_name}::{new_api_type}"
    
    if old_key_id != new_key_id:
        if get_key(new_key_id):
            flash('This exact key and service combination already exists!', 'danger')
            return redirect('/keys')
            
    try:
        limit_int = int(limit)
        if limit_int < 0:
            limit_int = 0
    except:
        limit_int = 0
        
    key_data['key_name'] = new_key_name
    key_data['api_type'] = new_api_type
    key_data['limit'] = limit_int
    key_data['expiry_date'] = expiry_date
    key_data['updated_at'] = get_ist_time_iso()
    
    if old_key_id != new_key_id:
        delete_api_key(old_key_id)
        save_api_key(new_key_id, key_data)
        log_audit_event("api_key_renamed", {"old": old_key_id, "new": new_key_id})
        flash(f'✅ Updated and Renamed!', 'success')
    else:
        save_api_key(old_key_id, key_data)
        flash(f'✅ Updated!', 'success')
        
    return redirect('/keys')

@app.route('/update_config', methods=['POST'])
@admin_required
@csrf_protect
def update_config():
    try:
        rate_limit = max(10, min(1000, int(request.form.get('rate_limit_per_minute', 60))))
    except:
        rate_limit = 60
    try:
        max_logs = max(10, min(10000, int(request.form.get('max_logs', 1000))))
    except:
        max_logs = 1000
    settings = {
        "maintenance_mode": 'maintenance_mode' in request.form,
        "enable_logging": 'enable_logging' in request.form,
        "cache_enabled": 'cache_enabled' in request.form,
        "log_enabled": 'log_enabled' in request.form,
        "ip_whitelist_enabled": 'ip_whitelist_enabled' in request.form,
        "browser_ip_auto_add": 'browser_ip_auto_add' in request.form,
        "bot_blocking_enabled": 'bot_blocking_enabled' in request.form,
        "rate_limit_per_minute": rate_limit,
        "max_logs": max_logs
    }
    save_settings(settings)
    log_audit_event("settings_updated", settings)
    flash('✅ Settings saved!', 'success')
    return redirect('/settings')

@app.route('/add_custom_api', methods=['POST'])
@admin_required
@csrf_protect
def add_custom_api():
    api_name_raw = request.form.get('api_name', '')
    api_url = request.form.get('api_url', '')
    is_valid, api_name, error = validate_api_name(api_name_raw)
    if not is_valid:
        flash(f'❌ {error}', 'danger')
        return redirect('/custom-apis')
    is_valid, api_url, error = validate_url_template(api_url)
    if not is_valid:
        flash(f'❌ {error}', 'danger')
        return redirect('/custom-apis')
    save_custom_api(api_name, api_url)
    log_audit_event("custom_api_added", {"api_name": api_name})
    flash(f'✅ API "{api_name}" added!', 'success')
    return redirect('/custom-apis')

@app.route('/delete_custom_api', methods=['POST'])
@admin_required
@csrf_protect
def delete_custom_api_route():
    api_name = sanitize_input(request.form.get('api_name', ''), max_length=50)
    if api_name and delete_custom_api(api_name):
        log_audit_event("custom_api_deleted", {"api_name": api_name})
        flash(f'Deleted!', 'warning')
    return redirect('/custom-apis')

@app.route('/clear_logs', methods=['POST'])
@admin_required
@csrf_protect
def clear_logs():
    clear_api_logs()
    log_audit_event("logs_cleared", {})
    flash('Logs cleared!', 'success')
    return redirect('/logs')

@app.route('/clear_failed_logins', methods=['POST'])
@admin_required
@csrf_protect
def clear_failed_logins_route():
    clear_failed_logins()
    log_audit_event("failed_logins_cleared", {})
    flash('✅ Cleared!', 'success')
    return redirect('/failed-logins')

@app.route('/api/v1/info', methods=['GET', 'POST'])
def api_endpoint():
    start_time = time.time()
    settings = get_settings()
    if settings.get('maintenance_mode', False):
        return jsonify({"error": "API is under maintenance."}), 503
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if not rate_limit_check(client_ip):
        return jsonify({"error": "Rate limit exceeded."}), 429
    
    api_key_name = request.args.get('key')
    query = request.args.get('query')
    service = request.args.get('service')
    
    if not api_key_name or not query or not service:
        return jsonify({"error": "Missing parameters! Usage: /api/v1/info?service=NAME&key=KEYNAME&query=DATA"}), 400
        
    api_key_name = sanitize_input(api_key_name, max_length=100)
    query = sanitize_input(query, max_length=500)
    service = sanitize_input(service, max_length=50)
    
    key_id = f"{api_key_name}::{service}"
    key_info = get_key(key_id)
    
    if not key_info:
        fallback_info = get_key(api_key_name)
        if fallback_info and fallback_info.get('api_type') == 'master':
            key_info = fallback_info
        else:
            return jsonify({"error": "Invalid API Key or Not Authorized for this service!"}), 401
            
    custom_apis = get_custom_apis()
    if service not in custom_apis:
        return jsonify({"error": f"API '{service}' not configured."}), 404
        
    cache_key = f"{key_id}:{query}"
    if settings.get('cache_enabled', True):
        cached_data, cache_time = api_cache.get(cache_key)
        if cached_data and time.time() - cache_time < settings.get('cache_duration', 300):
            increment_key_usage(key_id)
            log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), 200, time.time() - start_time, True)
            return clean_response_with_details(cached_data, key_info)
            
    if settings.get('blacklist_enabled', True):
        blacklist = get_blacklist()
        if key_id in blacklist.get('keys', []) or api_key_name in blacklist.get('keys', []):
            return jsonify({"error": "API Key revoked."}), 403
            
    expiry_date = key_info.get('expiry_date', '2099-12-31')
    try:
        if date.today() > datetime.strptime(expiry_date, '%Y-%m-%d').date():
            return jsonify({"error": "API Key Expired!"}), 403
    except:
        pass
        
    limit = key_info.get('limit', 0)
    used = key_info.get('used', 0)
    if limit != 0 and used >= limit:
        return jsonify({"error": "Daily Limit Reached!"}), 429
        
    base_url = custom_apis[service]
    if '?' in base_url:
        if base_url.endswith('=') or base_url.endswith('&') or base_url.endswith('?'):
            url = base_url + query
        else:
            url = base_url + '&' + query
    else:
        url = base_url + '?' + query
        
    is_valid, _, error = validate_url_template(url)
    if not is_valid:
        log_error("ssrf_blocked", error, api_key_name, query)
        return jsonify({"error": "URL validation failed"}), 403
        
    if request.host in base_url:
        return jsonify({"error": "Cannot call self."}), 500
        
    try:
        resp = _session.get(url, timeout=8)
        response_time = time.time() - start_time
        if 'text/html' in resp.headers.get('Content-Type', ''):
            return jsonify({"error": "Invalid response."}), 502
        if resp.status_code == 200:
            try:
                data = resp.json()
                if settings.get('cache_enabled', True):
                    api_cache.set(cache_key, data.copy(), time.time())
                increment_key_usage(key_id)
                if settings.get('enable_logging', True):
                    update_analytics(api_key_name, service, "success", client_ip, request.headers.get('User-Agent'))
                if settings.get('log_enabled', True):
                    log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), 200, response_time, True)
                key_info['used'] = used + 1
                return clean_response_with_details(data, key_info)
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON."}), 502
        if settings.get('log_enabled', True):
            log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), resp.status_code, response_time, False)
        return jsonify({"error": f"Backend status {resp.status_code}"}), 502
    except requests.exceptions.Timeout:
        log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), 504, time.time() - start_time, False)
        return jsonify({"error": "Timeout."}), 504
    except requests.exceptions.ConnectionError:
        log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), 504, time.time() - start_time, False)
        return jsonify({"error": "Connection failed."}), 504
    except Exception as e:
        log_api_request(api_key_name, service, query, client_ip, request.headers.get('User-Agent'), 504, time.time() - start_time, False)
        return jsonify({"error": f"Request failed."}), 504

@app.route('/api/analytics')
@admin_required
def get_analytics_endpoint():
    return jsonify(get_analytics())

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", "timestamp": get_ist_time_iso(),
        "version": VERSION, "owner": "@Aditya_dark0",
        "mongo_status": "connected" if is_mongo_available() else "fallback_mode",
        "mongo_configured": bool(MONGO_URI)
    })

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": str(e.description) if e.description else "Forbidden"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found. Use /api/v1/info"}), 404

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request too large."}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded."}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal error"}), 500

if __name__ == "__main__":
    init_mongo()
    auto_add_server_ip()
    app.run(host='0.0.0.0', port=5099, debug=False, threaded=True)