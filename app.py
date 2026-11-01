"""
Panther Data backend — real VTpass / Fatizara / Bilal + Paystack integration.
Holds API keys server-side (env vars). Never expose them to the frontend.

Env vars:
  ADMIN_KEY             (protects /api/admin/* — env only, never admin-editable)
  DATABASE_URL          (optional postgres://... ; defaults to local sqlite)
  FRONTEND_ORIGIN       (comma-separated allowed origins, default *)
  SMTP_USER             (Gmail address used to send verification codes, e.g. sweetvtu@gmail.com)
  SMTP_APP_PASSWORD     (Gmail *app password*, not the login password)
  SMTP_FROM_NAME        (sender name shown on emails, default Panther Data)
Provider keys (VTPASS_*, MONNIFY_*, BREVO_*, PAYSTACK_*) are seeded from env
into the settings table at startup, then editable from the admin panel.
  PORT
"""
import os, re, json, secrets, sqlite3, uuid, smtplib, hashlib, hmac, base64, time, threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from email.mime.text import MIMEText

import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- config ----------------
ADMIN_KEY       = os.environ.get('ADMIN_KEY', '')
DATABASE_URL    = os.environ.get('DATABASE_URL', '')
FRONTEND_ORIGIN = os.environ.get('FRONTEND_ORIGIN', '*')
SMTP_USER         = os.environ.get('SMTP_USER', '')
SMTP_APP_PASSWORD = os.environ.get('SMTP_APP_PASSWORD', '')
SMTP_FROM_NAME    = os.environ.get('SMTP_FROM_NAME', 'Panther Data')
# MONNIFY_BVN stays env-only (rarely changed, not admin-editable)
MONNIFY_BVN        = os.environ.get('MONNIFY_BVN', '').strip()

# ---------------- runtime settings (admin-editable, stored in DB) ----------------
# These 12 keys are seeded from env vars at startup, then editable from the
# admin panel. ADMIN_KEY intentionally stays env-only.
SETTINGS = {}
SETTINGS_META = {
    'VTPASS_API_KEY':     dict(group='VTpass',   label='API Key',      secret=True),
    'VTPASS_PUBLIC_KEY':  dict(group='VTpass',   label='Public Key',   secret=True),
    'VTPASS_SECRET_KEY':  dict(group='VTpass',   label='Secret Key',   secret=True),
    'VTPASS_SANDBOX':     dict(group='VTpass',   label='Sandbox mode — 1 = test, 0 = LIVE', secret=False),
    'PROVIDER':           dict(group='Provider', label='Active provider — vtpass, fatizara or bilal', secret=False),
    'FATIZARA_USERNAME':  dict(group='Fatizara', label='Fatizara username', secret=False),
    'FATIZARA_PASSWORD':  dict(group='Fatizara', label='Fatizara password', secret=True),
    'BILAL_USERNAME':     dict(group='Bilal',    label='Bilal username', secret=False),
    'BILAL_PASSWORD':     dict(group='Bilal',    label='Bilal password', secret=True),
    'MONNIFY_API_KEY':    dict(group='Monnify',  label='API Key',      secret=True),
    'MONNIFY_SECRET_KEY': dict(group='Monnify',  label='Secret Key',   secret=True),
    'MONNIFY_CONTRACT_CODE': dict(group='Monnify', label='Contract Code', secret=True),
    'MONNIFY_SANDBOX':    dict(group='Monnify',  label='Sandbox mode — 1 = test, 0 = LIVE', secret=False),
    'BREVO_API_KEY':      dict(group='Email',    label='Brevo API Key', secret=True),
    'BREVO_SENDER':       dict(group='Email',    label='Sender email', secret=False),
    'PAYSTACK_SECRET_KEY': dict(group='Paystack', label='Secret Key',  secret=True),
    'PAYSTACK_PUBLIC_KEY': dict(group='Paystack', label='Public Key',  secret=False),
}
SETTINGS_ALLOW = set(SETTINGS_META)

def S(key):
    """Read a runtime setting (call-time, so admin edits apply without restart)."""
    return SETTINGS.get(key, '')

def vt_sandbox():
    return S('VTPASS_SANDBOX') == '1'

def vt_base():
    return 'https://sandbox.vtpass.com/api' if vt_sandbox() else 'https://vtpass.com/api'

def monnify_sandbox():
    return S('MONNIFY_SANDBOX') == '1'

def monnify_base():
    return 'https://sandbox.monnify.com' if monnify_sandbox() else 'https://api.monnify.com'

def provider():
    """Active vending provider: 'vtpass' (default), 'fatizara' or 'bilal'.
    VTpass stays the default until the chosen provider is proven with test buys."""
    p = (S('PROVIDER') or 'vtpass').strip().lower()
    return p if p in ('vtpass', 'fatizara', 'bilal') else 'vtpass'

def fatizara_configured():
    return bool(S('FATIZARA_USERNAME') and S('FATIZARA_PASSWORD'))

def bilal_configured():
    return bool(S('BILAL_USERNAME') and S('BILAL_PASSWORD'))

LAGOS = timezone(timedelta(hours=1))

app = Flask(__name__)
CORS(app, origins=[o.strip() for o in FRONTEND_ORIGIN.split(',')])

# ---------------- rate limiting ----------------
# Protects auth, money and admin endpoints from brute force / abuse.
# Runs behind Render's proxy, so the real client IP comes from X-Forwarded-For.
from flask_limiter import Limiter

def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'

limiter = Limiter(
    key_func=_client_ip,
    app=app,
    default_limits=['240 per minute'],
    storage_uri='memory://',
    headers_enabled=True,
    strategy='fixed-window',
)

@app.errorhandler(429)
def _ratelimit_handler(e):
    return jsonify({'ok': False, 'error': 'Too many requests. Slow down and try again.'}), 429

# ---------------- db ----------------
USE_PG = DATABASE_URL.startswith('postgres')
_pg = None
if USE_PG:
    import psycopg2
    import psycopg2.extras

def db():
    if USE_PG:
        global _pg
        if _pg is None or _pg.closed:
            # Bound the wait: a suspended Neon can otherwise leave the
            # connect hanging for minutes, stalling the whole worker while
            # the phone has already given up. Fail fast so the caller can
            # retry against an awake database.
            _pg = psycopg2.connect(DATABASE_URL, connect_timeout=10)
            _pg.autocommit = False
        return _pg
    con = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'sweetvtu.db'))
    con.row_factory = sqlite3.Row
    return con

def _reset_pg():
    """Drop the cached Postgres connection so the next db() call reconnects.

    Neon's free compute suspends when idle and kills connections; a killed
    connection still looks open until used, so without this a worker keeps
    serving 500s on a dead connection until it is restarted."""
    global _pg
    try:
        if _pg is not None:
            _pg.close()
    except Exception:
        pass
    _pg = None

def q(sql, params=()):
    """SELECT helper -> list of dicts"""
    if USE_PG:
        sql = sql.replace('?', '%s')
        for attempt in range(2):
            try:
                cur = db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(sql, params)
                rows = cur.fetchall()
                # Commit after reads so the connection never sits idle-in-transaction
                # holding locks (this hung deploys waiting on ALTER TABLE).
                db().commit()
                cur.close()
                return [dict(r) for r in rows]
            except (psycopg2.OperationalError, psycopg2.InterfaceError):
                # Connection died (e.g. Neon suspend). Drop it and retry
                # the read once on a fresh connection.
                try:
                    cur.close()
                except Exception:
                    pass
                _reset_pg()
                if attempt == 1:
                    raise
            except Exception:
                try:
                    db().rollback()
                except Exception:
                    pass
                try:
                    cur.close()
                except Exception:
                    pass
                raise
    cur = db().cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    return rows

def run(sql, params=()):
    if USE_PG:
        sql = sql.replace('?', '%s')
        try:
            cur = db().cursor()
            cur.execute(sql, params)
            db().commit()
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            # Connection died (e.g. Neon suspend). Drop it so the next
            # request gets a fresh one; do NOT retry the write — its
            # outcome is unknown and retrying could double-apply it.
            _reset_pg()
            raise
        except Exception:
            # On Postgres a failed statement aborts the whole transaction;
            # roll back so the connection stays usable for the next statement.
            try:
                db().rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                cur.close()
            except Exception:
                pass
        return
    else:
        con = db()
        con.execute(sql, params)
        con.commit()
        con.close()


# ---------------- non-blocking security migration ----------------
# The tokens/users security columns are added with a short lock timeout so a
# blocked ALTER fails fast instead of hanging gunicorn startup (which made
# Render deploys time out). NEW_COLS_READY gates the new session/PIN logic;
# a background thread retries until the columns exist.
NEW_COLS_READY = False
_SECURITY_COLS = (
    ("expires_at TEXT", "tokens"),
    ("last_seen TEXT", "tokens"),
    ("pin_fails INTEGER DEFAULT 0", "users"),
    ("pin_locked_until TEXT", "users"),
    ("last_login_ip TEXT", "users"),
)

def _try_security_migration():
    """Try to add the security columns. Never blocks: uses a short lock
    timeout and never raises. Returns True if the columns are present."""
    global NEW_COLS_READY
    try:
        if USE_PG:
            try:
                run("SET lock_timeout = '8s'")
            except Exception:
                pass
        for col, tbl in _SECURITY_COLS:
            try:
                run(f"ALTER TABLE {tbl} ADD COLUMN {col}")
            except Exception:
                pass
        if USE_PG:
            try:
                run("SET lock_timeout = '0'")
            except Exception:
                pass
        # verify ALL security columns actually exist
        try:
            if USE_PG:
                rows = q("SELECT table_name, column_name FROM information_schema.columns "
                         "WHERE (table_name='tokens' AND column_name IN ('expires_at','last_seen')) "
                         "OR (table_name='users' AND column_name IN ('pin_fails','pin_locked_until','last_login_ip'))")
                found = {(r['table_name'], r['column_name']) for r in rows}
                need = {('tokens','expires_at'), ('tokens','last_seen'),
                        ('users','pin_fails'), ('users','pin_locked_until'), ('users','last_login_ip')}
            else:
                trows = [r['name'] for r in q("PRAGMA table_info(tokens)")]
                urows = [r['name'] for r in q("PRAGMA table_info(users)")]
                found = {('tokens',c) for c in trows} | {('users',c) for c in urows}
                need = {('tokens','expires_at'), ('tokens','last_seen'),
                        ('users','pin_fails'), ('users','pin_locked_until'), ('users','last_login_ip')}
            if need.issubset(found):
                NEW_COLS_READY = True
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False

def _start_migration_retry_thread():
    """Retry the security migration in the background until it succeeds."""
    import threading, time
    def loop():
        for _ in range(60):
            time.sleep(60)
            if NEW_COLS_READY:
                break
            try:
                if _try_security_migration():
                    break
            except Exception:
                pass
    try:
        threading.Thread(target=loop, daemon=True).start()
    except Exception:
        pass

def init_db():
    auto = "SERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS users(
             id {auto}, name TEXT, phone TEXT UNIQUE,
             email TEXT, pass_hash TEXT, tx_pin_hash TEXT,
             email_verified INTEGER DEFAULT 0,
             wallet REAL DEFAULT 0, created TEXT)""",
        """CREATE TABLE IF NOT EXISTS tokens(
             token TEXT PRIMARY KEY, user_id INTEGER, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS email_codes(
             id {auto}, user_id INTEGER,
             code_hash TEXT, purpose TEXT, expires_at TEXT, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS transactions(
             id {auto}, user_id INTEGER, type TEXT,
             service TEXT, description TEXT, amount REAL, direction TEXT,
             status TEXT DEFAULT 'successful', reference TEXT UNIQUE,
             provider_ref TEXT, meta TEXT, created TEXT)""",
        """CREATE TABLE IF NOT EXISTS plan_prices(
             variation_code TEXT PRIMARY KEY, sell_price REAL, cost_price REAL,
             label TEXT, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS fatizara_plans(
             plan_id TEXT PRIMARY KEY, service TEXT, network TEXT,
             name TEXT, cost REAL, sell REAL, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS fatizara_discos(
             disco_key TEXT PRIMARY KEY, fatizara_id TEXT, label TEXT, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS bilal_plans(
             plan_id TEXT PRIMARY KEY, service TEXT, network TEXT,
             name TEXT, cost REAL, sell REAL, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS bilal_discos(
             disco_key TEXT PRIMARY KEY, bilal_id TEXT, label TEXT, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT, updated_at TEXT)""",
    ]
    for s in stmts:
        run(s)
    # migrate older databases that lack the new columns
    for col, tbl in (("email_verified INTEGER DEFAULT 0", "users"),
                     ("tx_pin_hash TEXT", "users"),
                     ("username TEXT", "users"),
                     ("monnify_ref TEXT", "users"), ("monnify_acct TEXT", "users"),
                     ("monnify_bank TEXT", "users"), ("monnify_acct_name TEXT", "users"),
                     ("updated_at TEXT", "settings")):
        try:
            run(f"ALTER TABLE {tbl} ADD COLUMN {col}")
        except Exception:
            pass
    # New security columns are migrated separately (non-blocking) so a
    # locked ALTER can never hang the deploy. See _try_security_migration().
    _try_security_migration()
    _start_migration_retry_thread()
    # Each Monnify account reference must belong to exactly one user.
    # (NULLs are allowed multiple times on both SQLite and Postgres.)
    try:
        run("CREATE UNIQUE INDEX IF NOT EXISTS users_monnify_ref_uniq ON users(monnify_ref)")
    except Exception:
        pass
    # Usernames are unique when set (NULLs for pre-username accounts allowed).
    try:
        run("CREATE UNIQUE INDEX IF NOT EXISTS users_username_uniq ON users(username)")
    except Exception:
        pass
    if not q("SELECT v FROM settings WHERE k='margin'"):
        run("INSERT INTO settings(k,v) VALUES('margin','0')")

init_db()

def load_settings():
    """Load runtime settings from DB into memory; seed missing keys from env."""
    global SETTINGS
    try:
        rows = q("SELECT k, v FROM settings")
        SETTINGS = {r['k']: r['v'] for r in rows if r['v'] is not None}
    except Exception:
        SETTINGS = {}
    env_seed = {
        'VTPASS_API_KEY': os.environ.get('VTPASS_API_KEY', ''),
        'VTPASS_PUBLIC_KEY': os.environ.get('VTPASS_PUBLIC_KEY', ''),
        'VTPASS_SECRET_KEY': os.environ.get('VTPASS_SECRET_KEY', ''),
        'VTPASS_SANDBOX': os.environ.get('VTPASS_SANDBOX', '1'),
        'PROVIDER': os.environ.get('PROVIDER', 'vtpass'),
        'FATIZARA_USERNAME': os.environ.get('FATIZARA_USERNAME', ''),
        'FATIZARA_PASSWORD': os.environ.get('FATIZARA_PASSWORD', ''),
        'BILAL_USERNAME': os.environ.get('BILAL_USERNAME', ''),
        'BILAL_PASSWORD': os.environ.get('BILAL_PASSWORD', ''),
        'MONNIFY_API_KEY': os.environ.get('MONNIFY_API_KEY', '').strip(),
        'MONNIFY_SECRET_KEY': os.environ.get('MONNIFY_SECRET_KEY', '').strip(),
        'MONNIFY_CONTRACT_CODE': os.environ.get('MONNIFY_CONTRACT_CODE', '').strip(),
        'MONNIFY_SANDBOX': os.environ.get('MONNIFY_SANDBOX', '1'),
        'BREVO_API_KEY': os.environ.get('BREVO_API_KEY', '').strip(),
        'BREVO_SENDER': os.environ.get('BREVO_SENDER', 'sweetvtu@gmail.com').strip(),
        'PAYSTACK_SECRET_KEY': os.environ.get('PAYSTACK_SECRET_KEY', ''),
        'PAYSTACK_PUBLIC_KEY': os.environ.get('PAYSTACK_PUBLIC_KEY', ''),
    }
    for k, val in env_seed.items():
        if k not in SETTINGS and val:
            try:
                run("INSERT INTO settings(k,v,updated_at) VALUES(?,?,?)",
                    (k, val, now_iso()))
            except Exception:
                pass
            SETTINGS[k] = val

# ---------------- helpers ----------------
def now_iso():
    return datetime.now(LAGOS).isoformat(timespec='seconds')

# ---------------- session security ----------------
SESSION_ABS_DAYS = 30      # absolute max session lifetime
SESSION_IDLE_SECS = 180    # inactivity logout (3 minutes)
PIN_MAX_FAILS = 5          # wrong PIN attempts before lockout
PIN_LOCK_SECS = 900        # PIN lockout duration (15 minutes)

def new_session_token(uid):
    """Create a login token with absolute expiry and activity tracking."""
    tok = secrets.token_hex(24)
    now = now_iso()
    if NEW_COLS_READY:
        exp = (datetime.now(LAGOS) + timedelta(days=SESSION_ABS_DAYS)).isoformat(timespec='seconds')
        run("INSERT INTO tokens(token,user_id,created,expires_at,last_seen) VALUES(?,?,?,?,?)",
            (tok, uid, now, exp, now))
    else:
        run("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)", (tok, uid, now))
    return tok

load_settings()

def request_id():
    stamp = datetime.now(LAGOS).strftime('%Y%m%d%H%M')
    return stamp + secrets.token_hex(6)

def auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        tok = (request.headers.get('Authorization') or '').replace('Bearer ', '').strip()
        if not tok:
            return jsonify({'ok': False, 'error': 'Not signed in.'}), 401
        if NEW_COLS_READY:
            rows = q("SELECT user_id, expires_at, last_seen FROM tokens WHERE token=?", (tok,))
        else:
            # security migration pending: fall back to plain token check
            rows = q("SELECT user_id FROM tokens WHERE token=?", (tok,))
        if not rows:
            return jsonify({'ok': False, 'error': 'Session expired. Sign in again.'}), 401
        if NEW_COLS_READY:
            now = now_iso()
            # absolute session lifetime (30 days)
            if rows[0].get('expires_at') and rows[0]['expires_at'] < now:
                run("DELETE FROM tokens WHERE token=?", (tok,))
                return jsonify({'ok': False, 'error': 'Session expired. Sign in again.'}), 401
            # inactivity logout (3 minutes)
            cutoff = (datetime.now(LAGOS) - timedelta(seconds=SESSION_IDLE_SECS)).isoformat(timespec='seconds')
            if rows[0].get('last_seen') and rows[0]['last_seen'] < cutoff:
                run("DELETE FROM tokens WHERE token=?", (tok,))
                return jsonify({'ok': False, 'error': 'Signed out after 3 minutes of inactivity.'}), 401
            run("UPDATE tokens SET last_seen=? WHERE token=?", (now, tok))
        g.user_id = rows[0]['user_id']
        return f(*a, **kw)
    return wrapper

def admin_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not ADMIN_KEY or request.headers.get('X-Admin-Key') != ADMIN_KEY:
            return jsonify({'ok': False, 'error': 'Admin key required.'}), 403
        return f(*a, **kw)
    return wrapper

def get_user(uid):
    rows = q("SELECT id,name,username,phone,email,wallet,email_verified,created,monnify_ref,monnify_acct,monnify_bank,monnify_acct_name FROM users WHERE id=?", (uid,))
    return rows[0] if rows else None

# ---------------- email verification ----------------
def send_email(to_email, subject, body):
    """Send an email. Prefers Brevo HTTPS API (works on Render free, where
    outbound SMTP ports are blocked); falls back to Gmail SMTP otherwise.
    Returns True on success."""
    if S('BREVO_API_KEY'):
        try:
            r = requests.post(
                'https://api.brevo.com/v3/smtp/email',
                headers={'api-key': S('BREVO_API_KEY'), 'Content-Type': 'application/json',
                         'Accept': 'application/json'},
                json={'sender': {'name': SMTP_FROM_NAME, 'email': S('BREVO_SENDER')},
                      'to': [{'email': to_email}],
                      'subject': subject, 'textContent': body},
                timeout=20)
            return 200 <= r.status_code < 300
        except Exception:
            return False
    if not SMTP_USER or not SMTP_APP_PASSWORD:
        return False
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = f'{SMTP_FROM_NAME} <{SMTP_USER}>'
        msg['To'] = to_email
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=20) as s:
            s.starttls()
            # Gmail shows app passwords with spaces; strip them
            s.login(SMTP_USER, SMTP_APP_PASSWORD.replace(' ', ''))
            s.send_message(msg)
        return True
    except Exception:
        return False

def new_email_code(user_id, purpose='verify'):
    """Create a fresh 6-digit code (15-min expiry). Returns the plain code."""
    code = str(secrets.randbelow(900000) + 100000)
    chash = hashlib.sha256(code.encode()).hexdigest()
    exp = (datetime.now(LAGOS) + timedelta(minutes=15)).isoformat(timespec='seconds')
    run("DELETE FROM email_codes WHERE user_id=? AND purpose=?", (user_id, purpose))
    run("""INSERT INTO email_codes(user_id,code_hash,purpose,expires_at,created)
           VALUES(?,?,?,?,?)""", (user_id, chash, purpose, exp, now_iso()))
    return code

def send_verify_code(user):
    code = new_email_code(user['id'], 'verify')
    ok = send_email(
        user['email'], 'Your Panther Data verification code',
        f"Hello {user['name']},\n\nWelcome to Panther Data! Your email verification code is:\n\n"
        f"{code}\n\nEnter this code in the app to activate your account. "
        f"It expires in 15 minutes.\n\nIf you did not sign up, ignore this email.\n\n— Panther Data")
    return ok

def pin_required(f):
    """Decorator: the request JSON must carry the correct 4-digit transaction PIN."""
    @wraps(f)
    def wrapper(*a, **kw):
        d = request.get_json(force=True, silent=True) or {}
        if NEW_COLS_READY:
            rows = q("SELECT tx_pin_hash, pin_fails, pin_locked_until FROM users WHERE id=?", (g.user_id,))
        else:
            # security migration pending: plain PIN check, no lockout
            rows = q("SELECT tx_pin_hash FROM users WHERE id=?", (g.user_id,))
        if NEW_COLS_READY and rows and rows[0].get('pin_locked_until') and rows[0]['pin_locked_until'] > now_iso():
            return jsonify({'ok': False, 'error': 'Too many wrong PIN attempts. Try again in 15 minutes.'}), 403
        good = bool(rows and rows[0]['tx_pin_hash']) and \
            check_password_hash(rows[0]['tx_pin_hash'], str(d.get('pin') or ''))
        if not good:
            if not NEW_COLS_READY:
                return jsonify({'ok': False, 'error': 'Wrong transaction PIN.'}), 403
            fails = (rows[0].get('pin_fails') or 0) + 1 if rows else 1
            if fails >= PIN_MAX_FAILS:
                lock_until = (datetime.now(LAGOS) + timedelta(seconds=PIN_LOCK_SECS)).isoformat(timespec='seconds')
                run("UPDATE users SET pin_fails=0, pin_locked_until=? WHERE id=?", (lock_until, g.user_id))
                return jsonify({'ok': False, 'error': 'Too many wrong PIN attempts. Try again in 15 minutes.'}), 403
            run("UPDATE users SET pin_fails=? WHERE id=?", (fails, g.user_id))
            left = PIN_MAX_FAILS - fails
            return jsonify({'ok': False, 'error': f'Wrong transaction PIN. {left} attempt(s) left.'}), 403
        if NEW_COLS_READY:
            run("UPDATE users SET pin_fails=0, pin_locked_until=NULL WHERE id=?", (g.user_id,))
        return f(*a, **kw)
    return wrapper

# ---------------- VTpass client ----------------
def vt_get(path, params=None):
    r = requests.get(vt_base() + path, params=params,
                     headers={'api-key': S('VTPASS_API_KEY'), 'public-key': S('VTPASS_PUBLIC_KEY')},
                     timeout=30)
    return r.json()

def vt_post(path, payload):
    r = requests.post(vt_base() + path, json=payload,
                      headers={'api-key': S('VTPASS_API_KEY'), 'secret-key': S('VTPASS_SECRET_KEY')},
                      timeout=45)
    return r.json()

def vt_variations(service_id):
    try:
        data = vt_get('/service-variations', {'serviceID': service_id})
        varis = (data.get('content') or {}).get('variations') or []
        return varis
    except Exception:
        return []

# ---------------- Fatizara client ----------------
# Docs: https://app.fatizaradata.com/documentation (login-walled).
# Auth is a two-step token flow, NOT a static API key: POST /api/user with
# HTTP Basic auth (username:password) returns an AccessToken, then every
# vending call carries 'Authorization: Token <AccessToken>'.
# Fatizara publishes NO token lifetime and NO sandbox — every call is live
# and debits the real wallet. So a fresh token is minted per operation:
# one extra cheap call, zero stale-token failures on real-money purchases.
FATIZARA_BASE = 'https://fatizaradata.com/api'
FATIZARA_NETWORKS = {'mtn': 1, 'airtel': 2, 'glo': 3, 'etisalat': 4}
FATIZARA_CABLES = {'gotv': 1, 'dstv': 2, 'startimes': 3}
# Filled from the docs extraction before go-live (never ships as '' — the
# provider defaults to vtpass, so the Fatizara path cannot run until set).
# plan_type: the docs show only 'VTU' for airtime. Meter verify: the docs
# give GET /api/bill/bill-validation?meter_number&disco&meter_type.
FATIZARA_AIRTIME_PLAN_TYPE = 'VTU'
FATIZARA_METER_VERIFY_PATH = '/bill/bill-validation'

def fatizara_token():
    """Mint an AccessToken. Returns (token, full_auth_response)."""
    creds = base64.b64encode(f"{S('FATIZARA_USERNAME')}:{S('FATIZARA_PASSWORD')}".encode()).decode()
    r = requests.post(FATIZARA_BASE + '/user',
                      headers={'Authorization': f'Basic {creds}'}, timeout=30)
    j = r.json()
    tok = j.get('AccessToken')
    if not tok:
        raise RuntimeError('Fatizara auth failed: ' + str(j.get('status') or j)[:200])
    return tok, j

def _provider_json(r, name):
    """Parse a provider reply defensively. An empty or non-JSON body (e.g. a
    gateway error page) must never leak a parser exception string to the
    customer — it becomes a clean failed reply instead, and buys using it
    still auto-refund through the normal failed path."""
    try:
        return r.json()
    except ValueError:
        return {'status': 'failed',
                'message': f'{name} did not return a readable reply. Please try again.'}

def fatizara_post(path, payload):
    tok, _ = fatizara_token()
    r = requests.post(FATIZARA_BASE + path, json=payload,
                      headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                      timeout=45)
    return _provider_json(r, 'Fatizara')

def fatizara_get(path, params=None):
    tok, _ = fatizara_token()
    r = requests.get(FATIZARA_BASE + path, params=params,
                     headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                     timeout=30)
    return _provider_json(r, 'Fatizara')

# ---------------- Bilal Sada Sub ----------------
# Docs: https://docs.bilalsadasub.com (public).
# Same two-step token flow as Fatizara: POST /api/user with HTTP Basic auth
# (username:password) returns an AccessToken, then every vending call carries
# 'Authorization: Token <AccessToken>'. Bilal ALSO documents sandbox keys
# (sk_test_…) for simulated tests, but the docs never say how a sandbox key
# is obtained, so only the live path below is wired up; sandbox testing is
# a question for Bilal support, not a code branch.
# Bilal purchase responses carry status: 'success' | 'pending' | 'fail'.
# 'pending' is NOT a failure: the debit stays and the transaction stays
# pending until requery (GET /api/requery/{request-id}) or the admin
# transaction-resolve endpoint settles it. Never auto-refund a pending
# Bilal buy — the money may still deliver.
BILAL_BASE = 'https://bilalsadasub.com'
BILAL_NETWORKS = {'mtn': 1, 'airtel': 2, 'glo': 3, 'etisalat': 4}
BILAL_CABLES = {'gotv': 1, 'dstv': 2, 'startimes': 3}
# Dashboard disco mapping (2026-11-01): Bilal lists 10 discos; Enugu has no
# Bilal mapping and stays unmapped under this provider.
BILAL_DISCO_IDS = {'ikeja-electric': 1, 'eko-electric': 2, 'kano-electric': 3,
                   'portharcourt-electric': 4, 'jos-electric': 5, 'ibadan-electric': 6,
                   'kaduna-electric': 7, 'abuja-electric': 8, 'benin-electric': 9,
                   'yola-electric': 10}

def bilal_token():
    """Mint an AccessToken. Returns (token, full_auth_response)."""
    creds = base64.b64encode(f"{S('BILAL_USERNAME')}:{S('BILAL_PASSWORD')}".encode()).decode()
    r = requests.post(BILAL_BASE + '/api/user',
                      headers={'Authorization': f'Basic {creds}'}, timeout=30)
    j = r.json()
    tok = j.get('AccessToken')
    if not tok:
        raise RuntimeError('Bilal auth failed: ' + str(j.get('status') or j)[:200])
    return tok, j

def bilal_post(path, payload):
    tok, _ = bilal_token()
    # NOTE: every Bilal API route lives under /api — the auth call uses
    # '/api/user' and works, but these helpers used to call the bare website
    # paths (e.g. '/data'), which return HTML error pages Bilal's dashboard
    # never records. The '/api' prefix here is what makes buys reach Bilal.
    r = requests.post(BILAL_BASE + '/api' + path, json=payload,
                      headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                      timeout=45)
    return _provider_json(r, 'Bilal')

def bilal_get(path, params=None):
    tok, _ = bilal_token()
    # Same '/api' prefix rule as bilal_post (see note there).
    r = requests.get(BILAL_BASE + '/api' + path, params=params,
                     headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                     timeout=30)
    return _provider_json(r, 'Bilal')

def bl_phone(phone):
    """Bilal's live API demands an 11-digit number: its own error reply is
    'The phone must be 11 digits.' for 13-digit 234... numbers, even though
    the docs examples show international format. Keep the 11-digit 0...
    number exactly as the customer typed it."""
    return re.sub(r'\D', '', phone or '')

def bl_sell_price(plan_id, cost):
    """Sell price for a Bilal plan: admin-set sell price, else cost + margin."""
    rows = q("SELECT sell FROM bilal_plans WHERE plan_id=?", (plan_id,))
    if rows and rows[0]['sell'] is not None:
        return float(rows[0]['sell'])
    margin = float((q("SELECT v FROM settings WHERE k='margin'") or [{'v': '0'}])[0]['v'])
    return round(float(cost) * (1 + margin / 100), 2)

def fz_sell_price(plan_id, cost):
    """Sell price for a Fatizara plan: admin-set sell price, else cost + margin."""
    rows = q("SELECT sell FROM fatizara_plans WHERE plan_id=?", (plan_id,))
    if rows and rows[0]['sell'] is not None:
        return float(rows[0]['sell'])
    margin = float((q("SELECT v FROM settings WHERE k='margin'") or [{'v': '0'}])[0]['v'])
    return round(float(cost) * (1 + margin / 100), 2)

def sell_price(variation_code, cost):
    rows = q("SELECT sell_price FROM plan_prices WHERE variation_code=?", (variation_code,))
    if rows and rows[0]['sell_price'] is not None:
        return float(rows[0]['sell_price'])
    margin = float((q("SELECT v FROM settings WHERE k='margin'") or [{'v': '0'}])[0]['v'])
    return round(float(cost) * (1 + margin / 100), 2)

def _debit_wallet(user_id, amount, desc, tx_type, service):
    """Insert a pending 'out' transaction and debit the wallet atomically.
    Returns (ref, None) on success, (None, error_info) on insufficient funds.
    Shared by the VTpass and Fatizara buy paths so both refund identically."""
    ref = 'SV' + secrets.token_hex(5).upper()
    con = db()
    try:
        if USE_PG:
            cur = con.cursor(); cur.execute("SELECT wallet FROM users WHERE id=%s FOR UPDATE", (user_id,))
            bal = float(cur.fetchone()[0]); cur.close()
        else:
            con.isolation_level = None
            con.execute("BEGIN IMMEDIATE")
            bal = float(con.execute("SELECT wallet FROM users WHERE id=?", (user_id,)).fetchone()[0])
        if bal < amount:
            if not USE_PG: con.execute("ROLLBACK")
            else: con.rollback()
            return None, {'error': 'Insufficient wallet balance. Please fund your wallet.'}
        ts = now_iso()
        if USE_PG:
            cur = con.cursor()
            cur.execute("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
                         status,reference,created) VALUES(%s,%s,%s,%s,%s,'out','pending',%s,%s)""",
                        (user_id, tx_type, service, desc, amount, ref, ts))
            cur.execute("UPDATE users SET wallet=wallet-%s WHERE id=%s", (amount, user_id))
            con.commit(); cur.close()
        else:
            con.execute("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
                         status,reference,created) VALUES(?,?,?,?,?,'out','pending',?,?)""",
                        (user_id, tx_type, service, desc, amount, ref, ts))
            con.execute("UPDATE users SET wallet=wallet-? WHERE id=?", (amount, user_id))
            con.commit()
    finally:
        if not USE_PG: con.close()
    return ref, None

def _settle_wallet(user_id, ref, amount, ok, provider_ref, token, raw, err_text):
    """Mark the pending transaction successful, or refund + mark failed.
    Returns (ok, info) in the same shape as the old debit_and_buy."""
    if ok:
        run("UPDATE transactions SET status='successful', provider_ref=?, meta=? WHERE reference=?",
            (provider_ref, json.dumps({'token': token, 'raw': raw})[:4000], ref))
        return True, {'reference': ref, 'provider_ref': provider_ref, 'token': token}
    # failure -> refund
    con = db()
    try:
        if USE_PG:
            cur = con.cursor()
            cur.execute("UPDATE users SET wallet=wallet+%s WHERE id=%s", (amount, user_id))
            cur.execute("UPDATE transactions SET status='failed', provider_ref=%s, meta=%s WHERE reference=%s",
                        (provider_ref, json.dumps(raw)[:4000], ref))
            con.commit(); cur.close()
        else:
            con.execute("UPDATE users SET wallet=wallet+? WHERE id=?", (amount, user_id))
            con.execute("UPDATE transactions SET status='failed', provider_ref=?, meta=? WHERE reference=?",
                        (provider_ref, json.dumps(raw)[:4000], ref))
            con.commit()
    finally:
        if not USE_PG: con.close()
    return False, {'error': str(err_text)[:300], 'reference': ref}

def debit_and_buy(user_id, amount, desc, tx_type, service, vt_payload):
    """Debit wallet, call VTpass, refund on failure. Returns (ok, info)."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service)
    if err:
        return False, err
    vt_payload = dict(vt_payload); vt_payload['request_id'] = request_id()
    try:
        resp = vt_post('/pay', vt_payload)
    except Exception as e:
        resp = {'code': 'timeout', 'content': {'errors': str(e)}}
    code = str(resp.get('code', ''))
    ok = code in ('000', '200') or (resp.get('response_description') or '').lower() == 'transaction successful'
    content = resp.get('content') or {}
    txns = content.get('transactions') or {}
    provider_ref = txns.get('transactionId') or content.get('transactionId') or ''
    token = (txns.get('token') or content.get('token') or '')
    err_text = ((content.get('errors') or '') if isinstance(content, dict) else '') or resp.get('response_description') or 'Purchase failed.'
    return _settle_wallet(user_id, ref, amount, ok, provider_ref, token, resp, err_text)

def debit_and_buy_fatizara(user_id, amount, desc, tx_type, service, endpoint, fz_payload):
    """Debit wallet, call Fatizara, refund on failure. Same guarantees as
    debit_and_buy: a lost/failed provider reply can never double-charge.
    Fatizara has no sandbox, so this path only runs once the provider switch
    is on AND the Fatizara wallet is funded — every call is live."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service)
    if err:
        return False, err
    fz_payload = dict(fz_payload); fz_payload['request-id'] = request_id()
    try:
        resp = fatizara_post(endpoint, fz_payload)
    except Exception as e:
        resp = {'status': 'failed', 'message': str(e)}
    ok = (resp.get('status') or '').lower() in ('success', 'successful')
    provider_ref = resp.get('request-id') or resp.get('request_id') or ''
    token = resp.get('token') or ''
    err_text = resp.get('message') or resp.get('error') or 'Purchase failed.'
    return _settle_wallet(user_id, ref, amount, ok, provider_ref, token, resp, err_text)

def debit_and_buy_bilal(user_id, amount, desc, tx_type, service, endpoint, bl_payload):
    """Debit wallet, call Bilal, refund on failure. Same guarantees as
    debit_and_buy_fatizara, with one Bilal-specific rule: a 'pending' status
    is neither success nor failure — the debit stays and the transaction
    stays pending (see bilal-requery / transaction-resolve), because Bilal
    may still deliver it. Refunding a pending buy could double-spend if
    Bilal later delivers."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service)
    if err:
        return False, err
    rid = request_id()
    bl_payload = dict(bl_payload); bl_payload['request-id'] = rid
    try:
        resp = bilal_post(endpoint, bl_payload)
    except Exception as e:
        resp = {'status': 'failed', 'message': str(e)}
    status = (resp.get('status') or '').lower()
    provider_ref = resp.get('request-id') or resp.get('request_id') or rid
    token = resp.get('token') or ''
    if status == 'pending':
        # Keep the debit, keep the transaction pending, remember the Bilal
        # request-id as provider_ref so requery can find it later.
        run("UPDATE transactions SET provider_ref=?, meta=? WHERE reference=?",
            (provider_ref, json.dumps(resp)[:4000], ref))
        return False, {'pending': True, 'reference': ref,
                       'error': 'Purchase is processing at Bilal. It stays pending until confirmed — check back shortly.'}
    ok = status in ('success', 'successful')
    err_text = resp.get('message') or resp.get('error') or 'Purchase failed.'
    return _settle_wallet(user_id, ref, amount, ok, provider_ref, token, resp, err_text)

# ---------------- public ----------------
@app.get('/api/config')
def config():
    return jsonify({'ok': True, 'paystack_public_key': S('PAYSTACK_PUBLIC_KEY'),
                    'sandbox': vt_sandbox(), 'live': True,
                    'provider': provider(), 'fatizara_ready': fatizara_configured(),
                    'bilal_ready': bilal_configured(),
                    'email_via': 'brevo' if S('BREVO_API_KEY') else 'smtp',
                    'email_ready': bool(S('BREVO_API_KEY') or (SMTP_USER and SMTP_APP_PASSWORD)),
                    'monnify_ready': monnify_configured(),
                    'fund_method': 'monnify'})

@app.get('/api/ping')
def ping():
    """Keep-warm probe: touches the database with SELECT 1 and nothing else.
    A scheduled ping every few minutes keeps both Render and the Neon
    database awake, so shop loads stay fast. No customer data, no auth."""
    try:
        q("SELECT 1")
        return jsonify({'ok': True})
    except Exception:
        return jsonify({'ok': False}), 500

@app.post('/api/signup')
@limiter.limit('5 per minute')
def signup():
    d = request.get_json(force=True)
    name, phone, email, pw = (d.get('name') or '').strip(), (d.get('phone') or '').strip(), \
                             (d.get('email') or '').strip(), d.get('password') or ''
    username = (d.get('username') or '').strip()
    pin = str(d.get('pin') or '').strip()
    if len(name) < 3: return jsonify({'ok': False, 'error': 'Please enter your full name.'}), 400
    if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
        return jsonify({'ok': False, 'error': 'Choose a username (3–20 letters, numbers or _).'}), 400
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email): return jsonify({'ok': False, 'error': 'Enter a valid email address.'}), 400
    if not re.match(r'^0\d{10}$', phone): return jsonify({'ok': False, 'error': 'Enter a valid 11-digit phone number.'}), 400
    if not re.match(r'^\d{4}$', pin):
        return jsonify({'ok': False, 'error': 'Create a 4-digit transaction PIN.'}), 400
    if len(pw) < 8: return jsonify({'ok': False, 'error': 'Password must be at least 8 characters.'}), 400
    if q("SELECT id FROM users WHERE LOWER(username)=LOWER(?)", (username,)):
        return jsonify({'ok': False, 'error': 'This username is already taken.'}), 400
    if q("SELECT id FROM users WHERE phone=?", (phone,)):
        return jsonify({'ok': False, 'error': 'This number is already registered. Sign in instead.'}), 400
    run("""INSERT INTO users(name,username,phone,email,pass_hash,tx_pin_hash,email_verified,wallet,created)
           VALUES(?,?,?,?,?,?,0,0,?)""",
        (name, username, phone, email, generate_password_hash(pw), generate_password_hash(pin), now_iso()))
    uid = q("SELECT id FROM users WHERE phone=?", (phone,))[0]['id']
    user = get_user(uid)
    email_sent = send_verify_code(user)
    # no token yet — account opens only after the email code is verified
    return jsonify({'ok': True, 'verify_required': True, 'user_id': uid,
                    'email': email, 'email_sent': email_sent})

@app.post('/api/verify-email')
@limiter.limit('10 per minute')
def verify_email():
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    code = str(d.get('code') or '').strip()
    user = get_user(uid)
    if not user:
        return jsonify({'ok': False, 'error': 'Account not found. Sign up again.'}), 404
    if user.get('email_verified'):
        tok = new_session_token(uid)
        return jsonify({'ok': True, 'token': tok, 'user': user})
    rows = q("SELECT * FROM email_codes WHERE user_id=? AND purpose='verify'", (uid,))
    chash = hashlib.sha256(code.encode()).hexdigest()
    if not rows or rows[0]['code_hash'] != chash:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if rows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Tap resend for a new one.'}), 400
    run("UPDATE users SET email_verified=1 WHERE id=?", (uid,))
    run("DELETE FROM email_codes WHERE user_id=? AND purpose='verify'", (uid,))
    tok = new_session_token(uid)
    return jsonify({'ok': True, 'token': tok, 'user': get_user(uid)})

@app.post('/api/resend-code')
@limiter.limit('3 per minute')
def resend_code():
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    user = get_user(uid)
    if not user:
        return jsonify({'ok': False, 'error': 'Account not found. Sign up again.'}), 404
    if user.get('email_verified'):
        return jsonify({'ok': False, 'error': 'Email already verified. Sign in.'}), 400
    email_sent = send_verify_code(user)
    if not email_sent:
        return jsonify({'ok': False, 'error': 'Could not send the email. Try again in a minute.'}), 502
    return jsonify({'ok': True})

@app.post('/api/change-pin')
@limiter.limit('10 per minute')
@auth
def change_pin():
    d = request.get_json(force=True)
    old = str(d.get('old_pin') or '').strip()
    new = str(d.get('new_pin') or '').strip()
    rows = q("SELECT tx_pin_hash FROM users WHERE id=?", (g.user_id,))
    if not rows or not rows[0]['tx_pin_hash'] or not check_password_hash(rows[0]['tx_pin_hash'], old):
        return jsonify({'ok': False, 'error': 'Old PIN is wrong.'}), 403
    if not re.match(r'^\d{4}$', new):
        return jsonify({'ok': False, 'error': 'New PIN must be 4 digits.'}), 400
    run("UPDATE users SET tx_pin_hash=? WHERE id=?", (generate_password_hash(new), g.user_id))
    return jsonify({'ok': True})

@app.post('/api/login')
@limiter.limit('10 per minute')
def login():
    d = request.get_json(force=True)
    ident = (d.get('username') or d.get('phone') or '').strip()
    pw = d.get('password') or ''
    rows = q("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (ident,))
    if not rows and re.match(r'^0\d{10}$', ident):
        # Silent fallback for accounts created before usernames existed:
        # a phone number still signs in an account that has no username yet.
        cand = q("SELECT * FROM users WHERE phone=?", (ident,))
        if cand and not (cand[0].get('username') or ''):
            rows = cand
    if not rows or not check_password_hash(rows[0]['pass_hash'], pw):
        return jsonify({'ok': False, 'error': 'Wrong username or password. Try again.'}), 401
    if not rows[0].get('email_verified'):
        return jsonify({'ok': False, 'error': 'Please verify your email first — check your inbox for the code.',
                        'verify_required': True, 'user_id': rows[0]['id']}), 403
    tok = new_session_token(rows[0]['id'])
    # Login alert: email the user if this sign-in comes from a new IP address.
    try:
        if NEW_COLS_READY:
            fwd = (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
            ip = fwd or (request.remote_addr or '')
            prev_ip = rows[0].get('last_login_ip')
            if ip and prev_ip and ip != prev_ip and rows[0].get('email'):
                # Send in background so login stays fast.
                _em, _nm = rows[0]['email'], rows[0].get('name') or 'there'
                threading.Thread(target=send_email, args=(_em,
                           'New sign-in to your Panther Data account',
                           f"Hi {_nm},\n\n"
                           f"We noticed a new sign-in to your Panther Data account on {now_iso()} "
                           f"from IP address {ip}.\n\n"
                           f"If this was you, no action is needed. If you don't recognize this "
                           f"sign-in, change your password immediately and contact support."),
                           daemon=True).start()
            if ip:
                run("UPDATE users SET last_login_ip=? WHERE id=?", (ip, rows[0]['id']))
    except Exception:
        pass
    return jsonify({'ok': True, 'token': tok, 'user': get_user(rows[0]['id'])})

@app.post('/api/logout')
@auth
def logout():
    tok = (request.headers.get('Authorization') or '').replace('Bearer ', '').strip()
    run("DELETE FROM tokens WHERE token=?", (tok,))
    return jsonify({'ok': True})

@app.get('/api/me')
@auth
def me():
    return jsonify({'ok': True, 'user': get_user(g.user_id)})

@app.get('/api/history')
@auth
def history():
    rows = q("""SELECT type,service,description,amount,direction,status,reference,created
                FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 100""", (g.user_id,))
    return jsonify({'ok': True, 'transactions': rows})

# ---------------- wallet funding (Paystack) ----------------
@app.post('/api/fund/initialize')
@limiter.limit('20 per minute')
@auth
def fund_init():
    d = request.get_json(force=True)
    try: amount = int(d.get('amount') or 0)
    except: amount = 0
    if amount < 100:
        return jsonify({'ok': False, 'error': 'Minimum funding is ₦100.'}), 400
    user = get_user(g.user_id)
    ref = 'SVF' + secrets.token_hex(6).upper()
    try:
        r = requests.post('https://api.paystack.co/transaction/initialize',
                          json={'email': user['email'], 'amount': amount * 100,
                                'reference': ref,
                                'metadata': {'user_id': g.user_id, 'purpose': 'sweetvtu_wallet'}},
                          headers={'Authorization': f'Bearer {S("PAYSTACK_SECRET_KEY")}'}, timeout=30).json()
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Could not reach Paystack. Try again.'}), 502
    if not r.get('status'):
        return jsonify({'ok': False, 'error': 'Paystack error: ' + str(r.get('message'))}), 502
    run("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
           status,reference,created) VALUES(?, 'fund','paystack',?,?,'in','pending',?,?)""",
        (g.user_id, f'Wallet funding {ref}', amount, ref, now_iso()))
    return jsonify({'ok': True, 'authorization_url': r['data']['authorization_url'],
                    'reference': ref, 'paystack_public_key': S('PAYSTACK_PUBLIC_KEY')})

@app.post('/api/fund/verify')
@limiter.limit('20 per minute')
@auth
def fund_verify():
    d = request.get_json(force=True)
    ref = (d.get('reference') or '').strip()
    rows = q("SELECT * FROM transactions WHERE reference=? AND user_id=?", (ref, g.user_id))
    if not rows:
        return jsonify({'ok': False, 'error': 'Unknown funding reference.'}), 404
    tx = rows[0]
    if tx['status'] == 'successful':
        return jsonify({'ok': True, 'already': True, 'user': get_user(g.user_id)})
    try:
        r = requests.get(f'https://api.paystack.co/transaction/verify/{ref}',
                         headers={'Authorization': f'Bearer {S("PAYSTACK_SECRET_KEY")}'}, timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not verify with Paystack. Try again.'}), 502
    data = r.get('data') or {}
    if r.get('status') and data.get('status') == 'success':
        amount = int(data.get('amount', 0)) // 100
        run("UPDATE users SET wallet=wallet+? WHERE id=?", (amount, g.user_id))
        run("UPDATE transactions SET status='successful', provider_ref=? WHERE reference=?",
            (str(data.get('id')), ref))
        return jsonify({'ok': True, 'user': get_user(g.user_id)})
    run("UPDATE transactions SET status='failed' WHERE reference=?", (ref,))
    return jsonify({'ok': False, 'error': 'Payment was not successful.'}), 400

# ---------------- wallet funding (Monnify reserved virtual accounts) ----------------
# Keys/base now come from runtime settings: S('MONNIFY_*'), monnify_base().
_monnify = {'token': None, 'exp': 0}

def monnify_configured():
    return bool(S('MONNIFY_API_KEY') and S('MONNIFY_SECRET_KEY') and S('MONNIFY_CONTRACT_CODE'))

def monnify_token():
    """OAuth token for Monnify, cached until near expiry."""
    if _monnify['token'] and _monnify['exp'] > time.time() + 60:
        return _monnify['token']
    creds = base64.b64encode(f"{S('MONNIFY_API_KEY')}:{S('MONNIFY_SECRET_KEY')}".encode()).decode()
    r = requests.post(f'{monnify_base()}/api/v1/auth/login',
                      headers={'Authorization': f'Basic {creds}'}, timeout=20).json()
    body = r.get('responseBody') or {}
    tok = body.get('accessToken')
    if not tok:
        raise RuntimeError('Monnify auth failed: ' + str(r.get('responseMessage') or r))
    _monnify['token'] = tok
    try:
        _monnify['exp'] = time.time() + int(body.get('expiresIn', 3600))
    except Exception:
        _monnify['exp'] = time.time() + 3500
    return tok

@app.get('/api/monnify-status')
@auth
def monnify_status():
    return jsonify({'ok': True, 'configured': monnify_configured(),
                    'sandbox': monnify_sandbox()})

@app.post('/api/fund-account')
@limiter.limit('20 per minute')
@auth
def fund_account():
    """Return the user's personal Monnify virtual account, creating it on first use."""
    if not monnify_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    user = get_user(g.user_id)
    if user.get('monnify_acct'):
        return jsonify({'ok': True, 'account_number': user['monnify_acct'],
                        'bank_name': user['monnify_bank'],
                        'account_name': user['monnify_acct_name']})
    d = request.get_json(force=True, silent=True) or {}
    bvn = (d.get('bvn') or '').strip() or MONNIFY_BVN or ('22222222222' if monnify_sandbox() else '')
    if not bvn:
        return jsonify({'ok': False, 'need_bvn': True,
                        'error': 'Your BVN is required to create your personal funding account.'}), 400
    # Reference must be globally unique and NEVER reused across users, even if
    # the local database is wiped. A random UUID reference cannot collide the
    # way the old 'sweetvtu-{user_id}' scheme did.
    ref = (user.get('monnify_ref') or '').strip()
    if not ref:
        ref = 'sweetvtu-' + uuid.uuid4().hex[:20]
    try:
        tok = monnify_token()
        r = requests.post(
            f'{monnify_base()}/api/v2/bank-transfer/reserved-accounts',
            headers={'Authorization': f'Bearer {tok}', 'Content-Type': 'application/json'},
            json={'accountReference': ref,
                  'accountName': (user.get('name') or 'Panther Data Customer')[:40],
                  'currencyCode': 'NGN',
                  'contractCode': S('MONNIFY_CONTRACT_CODE'),
                  'customerEmail': user.get('email'),
                  'customerName': user.get('name'),
                  'bvn': bvn,
                  'getAllAvailableBanks': True},
            timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Monnify. Try again.'}), 502
    body = r.get('responseBody') or {}
    accts = body.get('accounts') or []
    if not r.get('requestSuccessful') or not accts:
        msg = str(r.get('responseMessage') or 'Monnify error')
        if 'bvn' in msg.lower():
            return jsonify({'ok': False, 'need_bvn': True,
                            'error': 'A valid BVN is required: ' + msg}), 400
        if 'same reference' in msg.lower():
            # This reference was reserved before (shouldn't happen with UUID
            # references, but kept as a safety net). Recover the reservation
            # only if Monnify returns the exact reference we asked for.
            try:
                g2 = requests.get(
                    f'{monnify_base()}/api/v2/bank-transfer/reserved-accounts/{ref}',
                    headers={'Authorization': f'Bearer {tok}'}, timeout=30).json()
                body2 = g2.get('responseBody') or {}
                accts2 = body2.get('accounts') or []
                got_ref = (body2.get('accountReference') or '').strip()
                if g2.get('requestSuccessful') and accts2 and got_ref == ref:
                    a2 = accts2[0]
                    run("""UPDATE users SET monnify_ref=?, monnify_acct=?, monnify_bank=?,
                           monnify_acct_name=? WHERE id=?""",
                        (got_ref, a2.get('accountNumber'),
                         a2.get('bankName'), a2.get('accountName'), g.user_id))
                    return jsonify({'ok': True, 'account_number': a2.get('accountNumber'),
                                    'bank_name': a2.get('bankName'),
                                    'account_name': a2.get('accountName')})
            except Exception:
                pass
            return jsonify({'ok': False, 'error': 'Monnify error: account reference conflict. Try again.'}), 502
        return jsonify({'ok': False, 'error': 'Monnify error: ' + msg}), 502
    a = accts[0]
    run("""UPDATE users SET monnify_ref=?, monnify_acct=?, monnify_bank=?, monnify_acct_name=?
           WHERE id=?""",
        (body.get('accountReference') or ref, a.get('accountNumber'),
         a.get('bankName'), a.get('accountName'), g.user_id))
    return jsonify({'ok': True, 'account_number': a.get('accountNumber'),
                    'bank_name': a.get('bankName'), 'account_name': a.get('accountName')})

def credit_wallet_atomic(uid, amount, tx_ref, description):
    """Insert a funding transaction and credit the wallet in ONE database
    transaction.

    Returns 'ok' (credited), 'duplicate' (transactionReference already seen -
    not an error), or 'error' (anything else - the credit did NOT happen).
    Callers must not treat 'error' as 'already credited'.
    """
    ins = """INSERT INTO transactions(user_id,type,service,description,amount,direction,
             status,reference,provider_ref,created)
             VALUES(?, 'fund','monnify',?,?,'in','successful',?,?,?)"""
    params = (uid, description, amount, tx_ref, tx_ref, now_iso())
    if USE_PG:
        cur = db().cursor()
        try:
            cur.execute(ins.replace('?', '%s'), params)
            cur.execute("UPDATE users SET wallet=wallet+%s WHERE id=%s", (amount, uid))
            if cur.rowcount != 1:
                db().rollback()
                return 'error'
            db().commit()
            return 'ok'
        except Exception as e:
            db().rollback()
            # 23505 = unique_violation -> the transaction was already credited
            if getattr(e, 'pgcode', '') == '23505':
                return 'duplicate'
            return 'error'
        finally:
            cur.close()
    con = db()
    try:
        con.execute(ins, params)
        cur2 = con.execute("UPDATE users SET wallet=wallet+? WHERE id=?", (amount, uid))
        if cur2.rowcount != 1:
            con.rollback()
            return 'error'
        con.commit()
        return 'ok'
    except sqlite3.IntegrityError:
        con.rollback()
        return 'duplicate'
    except Exception:
        con.rollback()
        return 'error'
    finally:
        con.close()

def _monnify_sig_ok(sig, secret, raw_body):
    """Verify the Monnify webhook signature.

    STRICT: only the official signature is accepted - HMAC-SHA512 of the RAW
    request body, keyed with the merchant secret key (per Monnify's own sample
    code). No legacy/alternative formulas are accepted.
    """
    sig = (sig or '').strip().lower()
    key = (secret or '').strip()
    if not sig or not key or not raw_body:
        return False
    h = hmac.new(key.encode('utf-8'), raw_body, hashlib.sha512).hexdigest().lower()
    return hmac.compare_digest(h, sig)


@app.post('/api/monnify-webhook')
@limiter.exempt
def monnify_webhook():
    """Monnify payment notification. Verifies HMAC-SHA512 signature, credits
    wallet exactly once. The customer is resolved ONLY by exact match of the
    stored monnify_ref - never by parsing a user ID out of the reference."""
    raw = request.get_data()  # raw bytes, exactly as Monnify sent them (for HMAC)
    d = request.get_json(force=True, silent=True) or {}
    ev = d.get('eventData') or {}
    sig = request.headers.get('monnify-signature') or d.get('transactionHash') or ''
    if not ev or not sig or not S('MONNIFY_SECRET_KEY'):
        return jsonify({'ok': False}), 400
    if not _monnify_sig_ok(sig, S('MONNIFY_SECRET_KEY'), raw):
        return jsonify({'ok': False}), 401
    if d.get('eventType') != 'SUCCESSFUL_TRANSACTION' or ev.get('paymentStatus') != 'PAID':
        return jsonify({'ok': True})
    prod = ev.get('product') or {}
    # Candidate account references from the payload; the customer is found by
    # exact lookup of the stored monnify_ref, never by parsing a user ID.
    candidates = [str(prod.get('reference') or '').strip(),
                  str(ev.get('accountReference') or '').strip(),
                  str(prod.get('accountReference') or '').strip()]
    uid = None
    for acct_ref in candidates:
        if not acct_ref:
            continue
        rows = q("SELECT id FROM users WHERE monnify_ref=?", (acct_ref,))
        if rows:
            uid = rows[0]['id']
            break
    if not uid:
        # Not one of our reserved accounts (or reservation unknown here).
        return jsonify({'ok': True})
    tx_ref = str(ev.get('transactionReference') or '')
    try:
        amount = float(ev.get('amountPaid') or 0)
    except Exception:
        amount = 0
    if amount <= 0 or not tx_ref:
        return jsonify({'ok': True})
    # idempotent + atomic: transactionReference is UNIQUE; duplicates are ignored
    status = credit_wallet_atomic(uid, amount, tx_ref, 'Wallet funding via bank transfer')
    return jsonify({'ok': True, 'status': status})

@app.post('/api/fund-sync')
@limiter.limit('20 per minute')
@auth
def fund_sync():
    """Pull the user's Monnify reserved-account transactions (server-to-server)
    and credit anything new. Works even when the Monnify webhook can't reach us."""
    if not monnify_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    user = get_user(g.user_id)
    if not user.get('monnify_acct'):
        return jsonify({'ok': False, 'error': 'No funding account yet.'}), 400
    # Resolve by the exact stored reference. Never reconstruct or guess the
    # reference from the user ID - that caused cross-customer attachment.
    acct_ref = (user.get('monnify_ref') or '').strip()
    if not acct_ref:
        return jsonify({'ok': False, 'error': 'No funding account yet.'}), 400
    items = None
    last_err = 'Monnify error: try again'
    try:
        tok = monnify_token()
        r = requests.get(
            f'{monnify_base()}/api/v1/bank-transfer/reserved-accounts/transactions',
            headers={'Authorization': f'Bearer {tok}'},
            params={'accountReference': acct_ref, 'page': 0, 'size': 20},
            timeout=30).json()
        if r.get('requestSuccessful'):
            items = (r.get('responseBody') or {}).get('content') or []
        else:
            last_err = 'Monnify error: ' + str(r.get('responseMessage') or 'try again')
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Monnify. Try again.'}), 502
    if items is None:
        return jsonify({'ok': False, 'error': last_err}), 502
    credited = 0.0
    count = 0
    for it in items:
        if (it.get('paymentStatus') or '') != 'PAID':
            continue
        tx_ref = str(it.get('transactionReference') or '')
        try:
            amount = float(it.get('amount') or 0)
        except Exception:
            amount = 0
        if not tx_ref or amount <= 0:
            continue
        if credit_wallet_atomic(g.user_id, amount, tx_ref, 'Wallet funding via bank transfer') == 'ok':
            credited += amount
            count += 1
    bal = get_user(g.user_id).get('wallet', 0)
    # If the Monnify pull found nothing new, the money may already have been
    # credited by the webhook a moment ago. Report the most recent funding so
    # the app can answer "already received" instead of "not found".
    recent = None
    if credited == 0:
        rows = q("""SELECT amount, created FROM transactions
                    WHERE user_id=? AND type='fund' AND status='successful'
                    ORDER BY id DESC LIMIT 1""", (g.user_id,))
        if rows:
            try:
                age = (datetime.now(LAGOS) - datetime.fromisoformat(rows[0]['created'])).total_seconds()
            except Exception:
                age = 10 ** 9
            if age <= 1800:
                recent = {'amount': rows[0]['amount'], 'created': rows[0]['created']}
    return jsonify({'ok': True, 'credited': credited,
                    'new_transactions': count, 'balance': bal,
                    'recent_funding': recent})

# ---------------- VTpass services ----------------
NETWORKS = {'mtn': 'mtn', 'glo': 'glo', 'airtel': 'airtel', 'etisalat': 'etisalat'}
DATA_SVC = {'mtn': 'mtn-data', 'glo': 'glo-data', 'airtel': 'airtel-data', 'etisalat': 'etisalat-data'}
CABLE_SVC = {'dstv': 'dstv', 'gotv': 'gotv', 'startimes': 'startimes', 'showmax': 'showmax'}
DISCOS = [
    ('ikeja-electric', 'Ikeja Electric (IKEDC)'), ('eko-electric', 'Eko Electric (EKEDC)'),
    ('kano-electric', 'Kano Electric (KEDCO)'), ('portharcourt-electric', 'PH Electric (PHEDC)'),
    ('jos-electric', 'Jos Electric (JEDC)'), ('ibadan-electric', 'Ibadan Electric (IBEDC)'),
    ('kaduna-electric', 'Kaduna Electric (KAEDC)'), ('abuja-electric', 'Abuja Electric (AEDC)'),
    ('enugu-electric', 'Enugu Electric (EEDC)'), ('benin-electric', 'Benin Electric (BEDC)'),
]

@app.post('/api/buy/airtime')
@limiter.limit('20 per minute')
@auth
@pin_required
def buy_airtime():
    d = request.get_json(force=True)
    net = (d.get('network') or '').lower()
    phone = re.sub(r'\D', '', d.get('phone') or '')
    try: amount = int(d.get('amount') or 0)
    except: amount = 0
    if net not in NETWORKS: return jsonify({'ok': False, 'error': 'Choose a network.'}), 400
    if not re.match(r'^0\d{10}$', phone): return jsonify({'ok': False, 'error': 'Enter a valid 11-digit phone number.'}), 400
    if amount < 50: return jsonify({'ok': False, 'error': 'Minimum airtime is ₦50.'}), 400
    if provider() == 'fatizara':
        if not fatizara_configured():
            return jsonify({'ok': False, 'error': 'Fatizara is not set up yet.'}), 503
        ok, info = debit_and_buy_fatizara(
            g.user_id, amount, f'{net.upper()} airtime ₦{amount:,} → {phone}',
            'airtime', net, '/topup/',
            {'network': FATIZARA_NETWORKS[net], 'phone': phone,
             'plan_type': FATIZARA_AIRTIME_PLAN_TYPE, 'amount': amount, 'bypass': False})
        return jsonify({'ok': ok, **info})
    if provider() == 'bilal':
        if not bilal_configured():
            return jsonify({'ok': False, 'error': 'Bilal is not set up yet.'}), 503
        ok, info = debit_and_buy_bilal(
            g.user_id, amount, f'{net.upper()} airtime ₦{amount:,} → {phone}',
            'airtime', net, '/topup',
            {'network': BILAL_NETWORKS[net], 'phone': bl_phone(phone),
             'plan_type': 'VTU', 'amount': amount, 'bypass': False})
        return jsonify({'ok': ok, **info})
    ok, info = debit_and_buy(g.user_id, amount, f'{net.upper()} airtime ₦{amount:,} → {phone}',
                             'airtime', net,
                             {'serviceID': NETWORKS[net], 'amount': amount, 'phone': phone})
    return jsonify({'ok': ok, **info})

@app.get('/api/data/plans')
@auth
def data_plans():
    net = (request.args.get('network') or 'mtn').lower()
    if provider() == 'fatizara':
        # Same response shape as VTpass (variation_code = Fatizara plan id),
        # so the existing frontend works unchanged after the provider switch.
        rows = q("SELECT plan_id, name, cost FROM fatizara_plans "
                 "WHERE service='data' AND network=? ORDER BY cost", (net,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': fz_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
        return jsonify({'ok': True, 'plans': plans})
    if provider() == 'bilal':
        # Same shape again (variation_code = Bilal plan id).
        rows = q("SELECT plan_id, name, cost FROM bilal_plans "
                 "WHERE service='data' AND network=? ORDER BY cost", (net,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': bl_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
        return jsonify({'ok': True, 'plans': plans})
    svc = DATA_SVC.get(net, 'mtn-data')
    varis = vt_variations(svc)
    plans = []
    for v in varis:
        code = v.get('variation_code')
        cost = float(v.get('variation_amount') or 0)
        plans.append({'variation_code': code, 'name': v.get('name'),
                      'cost': cost, 'price': sell_price(code, cost)})
    return jsonify({'ok': True, 'plans': plans})

@app.post('/api/buy/data')
@limiter.limit('20 per minute')
@auth
@pin_required
def buy_data():
    d = request.get_json(force=True)
    net = (d.get('network') or 'mtn').lower()
    phone = re.sub(r'\D', '', d.get('phone') or '')
    code = (d.get('variation_code') or '').strip()
    if not re.match(r'^0\d{10}$', phone): return jsonify({'ok': False, 'error': 'Enter a valid 11-digit phone number.'}), 400
    if not code: return jsonify({'ok': False, 'error': 'Please select a data plan.'}), 400
    if provider() == 'fatizara':
        if not fatizara_configured():
            return jsonify({'ok': False, 'error': 'Fatizara is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM fatizara_plans "
                 "WHERE plan_id=? AND service='data' AND network=?", (code, net))
        if not rows:
            return jsonify({'ok': False, 'error': 'This plan is no longer available. Refresh plans.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = fz_sell_price(code, cost)
        ok, info = debit_and_buy_fatizara(
            g.user_id, price, f"{p['name']} → {phone}", 'data', net, '/data',
            {'network': FATIZARA_NETWORKS.get(net, 1), 'phone': phone,
             'data_plan': int(code) if code.isdigit() else code, 'bypass': False})
        return jsonify({'ok': ok, **info})
    if provider() == 'bilal':
        if not bilal_configured():
            return jsonify({'ok': False, 'error': 'Bilal is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM bilal_plans "
                 "WHERE plan_id=? AND service='data' AND network=?", (code, net))
        if not rows:
            return jsonify({'ok': False, 'error': 'This plan is no longer available. Refresh plans.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = bl_sell_price(code, cost)
        ok, info = debit_and_buy_bilal(
            g.user_id, price, f"{p['name']} → {phone}", 'data', net, '/data',
            {'network': BILAL_NETWORKS.get(net, 1), 'phone': bl_phone(phone),
             'data_plan': int(code) if code.isdigit() else code, 'bypass': False})
        return jsonify({'ok': ok, **info})
    svc = DATA_SVC.get(net, 'mtn-data')
    varis = {v.get('variation_code'): v for v in vt_variations(svc)}
    if code not in varis:
        return jsonify({'ok': False, 'error': 'This plan is no longer available. Refresh plans.'}), 400
    v = varis[code]
    cost = float(v.get('variation_amount') or 0)
    price = sell_price(code, cost)
    ok, info = debit_and_buy(g.user_id, price, f"{v.get('name')} → {phone}", 'data', net,
                             {'serviceID': svc, 'billersCode': phone,
                              'variation_code': code, 'amount': cost, 'phone': phone})
    return jsonify({'ok': ok, **info})

@app.get('/api/cable/plans')
@auth
def cable_plans():
    prov = (request.args.get('provider') or 'dstv').lower()
    if provider() == 'fatizara':
        rows = q("SELECT plan_id, name, cost FROM fatizara_plans "
                 "WHERE service='cable' AND network=? ORDER BY cost", (prov,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': fz_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
        return jsonify({'ok': True, 'plans': plans})
    if provider() == 'bilal':
        rows = q("SELECT plan_id, name, cost FROM bilal_plans "
                 "WHERE service='cable' AND network=? ORDER BY cost", (prov,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': bl_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
        return jsonify({'ok': True, 'plans': plans})
    svc = CABLE_SVC.get(prov, 'dstv')
    varis = vt_variations(svc)
    plans = [{'variation_code': v.get('variation_code'), 'name': v.get('name'),
              'cost': float(v.get('variation_amount') or 0),
              'price': sell_price(v.get('variation_code'), float(v.get('variation_amount') or 0))}
             for v in varis]
    return jsonify({'ok': True, 'plans': plans})

@app.post('/api/verify')
@limiter.limit('20 per minute')
@auth
def verify():
    d = request.get_json(force=True)
    service_id = (d.get('serviceID') or '').strip()
    billers = (d.get('billersCode') or '').strip()
    vtype = (d.get('type') or '').strip()
    if not service_id or len(billers) < 5:
        return jsonify({'ok': False, 'error': 'Enter a valid number.'}), 400
    if provider() == 'bilal':
        if not bilal_configured():
            return jsonify({'ok': False, 'error': 'Bilal is not set up yet.'}), 503
        try:
            if service_id in CABLE_SVC and service_id != 'showmax':
                resp = bilal_get('/cable/cable-validation',
                                 {'iuc': billers, 'cable': BILAL_CABLES[service_id]})
                if (resp.get('status') or '').lower() in ('success', 'successful') and resp.get('name'):
                    return jsonify({'ok': True, 'customer': resp.get('name'), 'raw': resp})
                return jsonify({'ok': False, 'error': 'Could not verify this number. Check and try again.'}), 400
            rows = q("SELECT bilal_id FROM bilal_discos WHERE disco_key=?", (service_id,))
            if rows:
                bl_disco = rows[0]['bilal_id']
                resp = bilal_get('/bill/bill-validation',
                                 {'meter_number': billers,
                                  'disco': int(bl_disco) if str(bl_disco).isdigit() else bl_disco,
                                  'meter_type': vtype or 'prepaid'})
                if (resp.get('status') or '').lower() in ('success', 'successful'):
                    name = resp.get('customer_name') or resp.get('name') or ''
                    return jsonify({'ok': True, 'customer': name, 'raw': resp})
                return jsonify({'ok': False, 'error': 'Could not verify this meter. Check and try again.'}), 400
        except Exception:
            return jsonify({'ok': False, 'error': 'Verification service unreachable.'}), 502
        return jsonify({'ok': False, 'error': 'Verification is not available for this service.'}), 400
    if provider() == 'fatizara':
        if not fatizara_configured():
            return jsonify({'ok': False, 'error': 'Fatizara is not set up yet.'}), 503
        try:
            if service_id in CABLE_SVC:
                resp = fatizara_get('/cable/cable-validation',
                                    {'iuc': billers, 'cable': FATIZARA_CABLES[service_id]})
                if (resp.get('status') or '').lower() in ('success', 'successful') and resp.get('name'):
                    return jsonify({'ok': True, 'customer': resp.get('name'), 'raw': resp})
                return jsonify({'ok': False, 'error': 'Could not verify this number. Check and try again.'}), 400
            if service_id in dict(DISCOS):
                if not FATIZARA_METER_VERIFY_PATH:
                    return jsonify({'ok': False, 'error': 'Meter verification is not set up for this disco yet.'}), 503
                rows = q("SELECT fatizara_id FROM fatizara_discos WHERE disco_key=?", (service_id,))
                if not rows:
                    return jsonify({'ok': False, 'error': 'This disco is not mapped yet.'}), 400
                resp = fatizara_get(FATIZARA_METER_VERIFY_PATH,
                                    {'meter_number': billers, 'disco': rows[0]['fatizara_id'],
                                     'meter_type': vtype or 'prepaid'})
                if (resp.get('status') or '').lower() in ('success', 'successful'):
                    name = resp.get('name') or resp.get('customer') or ''
                    return jsonify({'ok': True, 'customer': name, 'raw': resp})
                return jsonify({'ok': False, 'error': 'Could not verify this meter. Check and try again.'}), 400
        except Exception:
            return jsonify({'ok': False, 'error': 'Verification service unreachable.'}), 502
        return jsonify({'ok': False, 'error': 'Verification is not available for this service.'}), 400
    payload = {'serviceID': service_id, 'billersCode': billers}
    if vtype: payload['type'] = vtype
    try:
        resp = vt_post('/merchant-verify', payload)
    except Exception:
        return jsonify({'ok': False, 'error': 'Verification service unreachable.'}), 502
    content = resp.get('content') or {}
    if str(resp.get('code')) == '000' and content:
        name = content.get('Customer_Name') or content.get('customer_name') or ''
        return jsonify({'ok': True, 'customer': name, 'raw': content})
    return jsonify({'ok': False, 'error': 'Could not verify this number. Check and try again.'}), 400

@app.post('/api/buy/cable')
@limiter.limit('20 per minute')
@auth
@pin_required
def buy_cable():
    d = request.get_json(force=True)
    prov = (d.get('provider') or 'dstv').lower()
    billers = (d.get('billersCode') or '').strip()
    code = (d.get('variation_code') or '').strip()
    phone = re.sub(r'\D', '', d.get('phone') or '')
    svc = CABLE_SVC.get(prov, 'dstv')
    if len(billers) < 5: return jsonify({'ok': False, 'error': 'Enter a valid smartcard / IUC number.'}), 400
    if not code: return jsonify({'ok': False, 'error': 'Please select a package.'}), 400
    if provider() == 'fatizara':
        if not fatizara_configured():
            return jsonify({'ok': False, 'error': 'Fatizara is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM fatizara_plans "
                 "WHERE plan_id=? AND service='cable' AND network=?", (code, prov))
        if not rows:
            return jsonify({'ok': False, 'error': 'This package is no longer available.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = fz_sell_price(code, cost)
        # Seeded cable ids carry a 'c:' prefix (to avoid colliding with data
        # plan ids); Fatizara itself wants the plain numeric plan id.
        raw_plan = code[2:] if code.startswith('c:') else code
        ok, info = debit_and_buy_fatizara(
            g.user_id, price, f"{prov.upper()} {p['name']} → {billers}",
            'cable', prov, '/cable',
            {'cable': FATIZARA_CABLES.get(prov, 2), 'iuc': billers,
             'cable_plan': int(raw_plan) if raw_plan.isdigit() else raw_plan, 'bypass': False})
        return jsonify({'ok': ok, **info})
    if provider() == 'bilal':
        if not bilal_configured():
            return jsonify({'ok': False, 'error': 'Bilal is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM bilal_plans "
                 "WHERE plan_id=? AND service='cable' AND network=?", (code, prov))
        if not rows:
            return jsonify({'ok': False, 'error': 'This package is no longer available.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = bl_sell_price(code, cost)
        # Seeded cable ids carry a 'c:' prefix (same collision guard as
        # Fatizara); Bilal itself wants the plain numeric plan id.
        raw_plan = code[2:] if code.startswith('c:') else code
        ok, info = debit_and_buy_bilal(
            g.user_id, price, f"{prov.upper()} {p['name']} → {billers}",
            'cable', prov, '/cable',
            {'cable': BILAL_CABLES.get(prov, 2),
             'cable_plan': int(raw_plan) if raw_plan.isdigit() else raw_plan,
             'iuc': billers, 'bypass': 0})
        return jsonify({'ok': ok, **info})
    varis = {v.get('variation_code'): v for v in vt_variations(svc)}
    if code not in varis:
        return jsonify({'ok': False, 'error': 'This package is no longer available.'}), 400
    v = varis[code]
    cost = float(v.get('variation_amount') or 0)
    price = sell_price(code, cost)
    ok, info = debit_and_buy(g.user_id, price, f"{prov.upper()} {v.get('name')} → {billers}",
                             'cable', prov,
                             {'serviceID': svc, 'billersCode': billers, 'variation_code': code,
                              'amount': cost, 'phone': phone or billers})
    return jsonify({'ok': ok, **info})

@app.get('/api/power/discos')
@auth
def discos():
    if provider() == 'fatizara':
        rows = q("SELECT disco_key, label FROM fatizara_discos ORDER BY label")
        out = [{'serviceID': r['disco_key'], 'label': r['label'],
                'types': [{'variation_code': 'prepaid', 'name': 'Prepaid'},
                          {'variation_code': 'postpaid', 'name': 'Postpaid'}]} for r in rows]
        return jsonify({'ok': True, 'discos': out})
    if provider() == 'bilal':
        rows = q("SELECT disco_key, label FROM bilal_discos ORDER BY label")
        out = [{'serviceID': r['disco_key'], 'label': r['label'],
                'types': [{'variation_code': 'prepaid', 'name': 'Prepaid'},
                          {'variation_code': 'postpaid', 'name': 'Postpaid'}]} for r in rows]
        return jsonify({'ok': True, 'discos': out})
    out = []
    for svc, label in DISCOS:
        varis = vt_variations(svc)
        types = [{'variation_code': v.get('variation_code'), 'name': v.get('name')} for v in varis]
        out.append({'serviceID': svc, 'label': label, 'types': types})
    return jsonify({'ok': True, 'discos': out})

@app.post('/api/buy/power')
@limiter.limit('20 per minute')
@auth
@pin_required
def buy_power():
    d = request.get_json(force=True)
    svc = (d.get('serviceID') or '').strip()
    meter = (d.get('billersCode') or '').strip()
    vtype = (d.get('variation_code') or 'prepaid').strip()
    phone = re.sub(r'\D', '', d.get('phone') or '')
    try: amount = int(d.get('amount') or 0)
    except: amount = 0
    if len(meter) < 5: return jsonify({'ok': False, 'error': 'Enter a valid meter number.'}), 400
    if amount < 500: return jsonify({'ok': False, 'error': 'Minimum payment is ₦500.'}), 400
    if provider() == 'fatizara':
        if not fatizara_configured():
            return jsonify({'ok': False, 'error': 'Fatizara is not set up yet.'}), 503
        rows = q("SELECT fatizara_id FROM fatizara_discos WHERE disco_key=?", (svc,))
        if not rows:
            return jsonify({'ok': False, 'error': 'This disco is not mapped yet.'}), 400
        fz_disco = rows[0]['fatizara_id']
        ok, info = debit_and_buy_fatizara(
            g.user_id, amount, f'Electricity ₦{amount:,} ({vtype}) → {meter}',
            'power', svc, '/bill',
            {'disco': int(fz_disco) if str(fz_disco).isdigit() else fz_disco,
             'meter_type': vtype,
             'meter_number': meter, 'amount': amount, 'bypass': False})
        return jsonify({'ok': ok, **info})
    if provider() == 'bilal':
        if not bilal_configured():
            return jsonify({'ok': False, 'error': 'Bilal is not set up yet.'}), 503
        rows = q("SELECT bilal_id FROM bilal_discos WHERE disco_key=?", (svc,))
        if not rows:
            return jsonify({'ok': False, 'error': 'This disco is not mapped yet.'}), 400
        bl_disco = rows[0]['bilal_id']
        ok, info = debit_and_buy_bilal(
            g.user_id, amount, f'Electricity ₦{amount:,} ({vtype}) → {meter}',
            'power', svc, '/bill',
            {'disco': int(bl_disco) if str(bl_disco).isdigit() else bl_disco,
             'meter_type': vtype,
             'meter_number': meter, 'amount': amount})
        return jsonify({'ok': ok, **info})
    ok, info = debit_and_buy(g.user_id, amount, f'Electricity ₦{amount:,} ({vtype}) → {meter}',
                             'power', svc,
                             {'serviceID': svc, 'billersCode': meter, 'variation_code': vtype,
                              'amount': amount, 'phone': phone})
    return jsonify({'ok': ok, **info})

@app.post('/api/requery')
@limiter.limit('10 per minute')
@auth
def requery():
    d = request.get_json(force=True)
    ref = (d.get('reference') or '').strip()
    rows = q("SELECT * FROM transactions WHERE reference=? AND user_id=?", (ref, g.user_id))
    if not rows: return jsonify({'ok': False, 'error': 'Unknown reference.'}), 404
    return jsonify({'ok': True, 'status': rows[0]['status'], 'provider_ref': rows[0]['provider_ref']})

@app.get('/api/network-status')
@auth
def network_status():
    """Live network health derived from OUR OWN recent VTpass transactions
    (last 48h): per-network delivery success rate. Honest signal — no fake
    'all operational' when our own orders are failing."""
    cutoff = (datetime.now(LAGOS) - timedelta(hours=48)).isoformat(timespec='seconds')
    try:
        rows = q("""SELECT service, status, COUNT(*) AS c FROM transactions
                    WHERE type IN ('airtime','data') AND direction='out' AND created >= ?
                    GROUP BY service, status""", (cutoff,))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    agg = {}
    for r in rows:
        svc = (r.get('service') or '').lower()
        st = (r.get('status') or '').lower()
        n = agg.setdefault(svc, {'ok': 0, 'fail': 0})
        if st == 'successful':
            n['ok'] += r['c']
        elif st in ('failed', 'refunded'):
            n['fail'] += r['c']
    out = []
    for key, label in (('mtn', 'MTN'), ('airtel', 'Airtel'), ('glo', 'Glo'), ('etisalat', '9mobile')):
        n = agg.get(key, {'ok': 0, 'fail': 0})
        total = n['ok'] + n['fail']
        if total == 0:
            status, note = 'nodata', 'No recent orders'
        else:
            rate = n['ok'] / total
            if rate >= 0.9:
                status, note = 'operational', f'{n["ok"]}/{total} recent orders delivered'
            elif rate >= 0.5:
                status, note = 'degraded', f'{n["ok"]}/{total} recent orders delivered'
            else:
                status, note = 'down', f'{n["fail"]}/{total} recent orders failed'
        out.append({'key': key, 'network': label, 'status': status, 'note': note,
                    'ok': n['ok'], 'total': total})
    return jsonify({'ok': True, 'window': '48h', 'networks': out})

# ---------------- admin ----------------
@app.get('/api/admin/vtpass-balance')
@admin_auth
def vt_balance():
    try:
        raw = vt_get('/balance')
        bal = None
        if isinstance(raw, dict):
            for key in ('contents', 'content', 'data'):
                node = raw.get(key)
                if isinstance(node, dict) and node.get('balance') is not None:
                    bal = node.get('balance'); break
                if isinstance(node, list) and node and isinstance(node[0], dict) \
                        and node[0].get('balance') is not None:
                    bal = node[0].get('balance'); break
            if bal is None and raw.get('balance') is not None:
                bal = raw.get('balance')
        try: bal = float(bal)
        except (TypeError, ValueError): bal = None
        if bal is None:
            return jsonify({'ok': False, 'error': 'Could not read balance.'}), 502
        return jsonify({'ok': True, 'balance': bal})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502

@app.get('/api/admin/fatizara-balance')
@admin_auth
def fatizara_balance():
    """Fatizara wallet balance comes from the /api/user auth response."""
    if not fatizara_configured():
        return jsonify({'ok': False, 'error': 'Fatizara username / password missing.'}), 502
    try:
        _, auth_resp = fatizara_token()
        bal = auth_resp.get('balance')
        try: bal = float(bal)
        except (TypeError, ValueError): bal = None
        if bal is None:
            return jsonify({'ok': False, 'error': 'Could not read balance.'}), 502
        return jsonify({'ok': True, 'balance': bal})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)[:200]}), 502

@app.get('/api/admin/fatizara-plans')
@admin_auth
def fatizara_plans_admin():
    return jsonify({'ok': True, 'plans': q("SELECT * FROM fatizara_plans ORDER BY service, network, cost")})

@app.post('/api/admin/fatizara-plan')
@admin_auth
def fatizara_plan_save():
    d = request.get_json(force=True, silent=True) or {}
    plan_id = (d.get('plan_id') or '').strip()
    service = (d.get('service') or '').strip()
    network = (d.get('network') or '').strip()
    name = (d.get('name') or '').strip()
    if not plan_id or service not in ('data', 'cable') or not name:
        return jsonify({'ok': False, 'error': 'plan_id, service (data/cable) and name are required.'}), 400
    try: cost = float(d.get('cost'))
    except Exception: return jsonify({'ok': False, 'error': 'Enter a valid cost.'}), 400
    sell = d.get('sell')
    try: sell = None if sell in (None, '') else float(sell)
    except Exception: return jsonify({'ok': False, 'error': 'Enter a valid sell price.'}), 400
    run("""INSERT INTO fatizara_plans(plan_id,service,network,name,cost,sell,updated)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
           network=excluded.network, name=excluded.name, cost=excluded.cost,
           sell=excluded.sell, updated=excluded.updated""",
        (plan_id, service, network, name, cost, sell, now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/fatizara-discos')
@admin_auth
def fatizara_discos_admin():
    return jsonify({'ok': True, 'discos': q("SELECT * FROM fatizara_discos ORDER BY label")})

@app.post('/api/admin/fatizara-disco')
@admin_auth
def fatizara_disco_save():
    d = request.get_json(force=True, silent=True) or {}
    disco_key = (d.get('disco_key') or '').strip()
    fz_id = (d.get('fatizara_id') or '').strip()
    label = (d.get('label') or '').strip()
    if not disco_key or not fz_id or not label:
        return jsonify({'ok': False, 'error': 'disco_key, fatizara_id and label are required.'}), 400
    run("""INSERT INTO fatizara_discos(disco_key,fatizara_id,label,updated)
           VALUES(?,?,?,?)
           ON CONFLICT(disco_key) DO UPDATE SET fatizara_id=excluded.fatizara_id,
           label=excluded.label, updated=excluded.updated""",
        (disco_key, fz_id, label, now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/fatizara-cost-check')
@admin_auth
def fatizara_cost_check():
    """Plans whose sell price sits below Fatizara cost — same idea as cost-check."""
    out = []
    for r in q("SELECT plan_id, service, network, name, cost, sell FROM fatizara_plans"):
        cost = float(r['cost'] or 0)
        sell = fz_sell_price(r['plan_id'], cost)
        if sell < cost:
            out.append({'plan': r['name'], 'code': r['plan_id'], 'service': r['service'],
                        'cost': cost, 'sell': sell, 'loss': round(cost - sell, 2)})
    return jsonify({'ok': True, 'losing': out})

# Seed data transcribed from the Fatizara docs tables (2026-11-01).
# cost = what Fatizara charges; sell starts empty (cost + margin) until
# Mahmod sets retail prices in the admin panel. Re-seeding updates costs
# and names but never overwrites an admin-set sell price.
# Data rows: (plan_id, network, name, cost). Name carries plan type +
# validity because the same size appears at several prices.
FATIZARA_DATA_SEED = [
    ('3', 'mtn', '1GB GIFTING MONTHLY', 650),
    ('5', 'mtn', '2GB GIFTING MONTHLY', 1300),
    ('6', 'mtn', '3GB GIFTING MONTHLY', 1950),
    ('7', 'mtn', '5GB GIFTING MONTHLY', 3500),
    ('46', 'mtn', '5GB GIFTING MONTHLY', 3350),
    ('57', 'mtn', '2GB COOPERATE GIFTING +2mins Monthly Plan', 540),
    ('58', 'mtn', '5GB COOPERATE GIFTING MONTHLY 30 DAYS', 1350),
    ('59', 'mtn', '3GB COOPERATE GIFTING MONTHLY 30 DAYS', 810),
    ('61', 'mtn', '1GB COOPERATE GIFTING MONTHLY 30 DAYS', 270),
    ('62', 'mtn', '1GB SME MONTHLY', 370),
    ('63', 'mtn', '2GB SME MONTHLY', 740),
    ('64', 'mtn', '3GB SME MONTHLY', 1110),
    ('65', 'mtn', '5GB SME MONTHLY', 1900),
    ('66', 'mtn', '100GB SME 3 MONTHLY', 4000),
    ('67', 'mtn', '500MB SME MONTHLY', 400),
    ('68', 'mtn', '1GB SME MONTHLY 30 DAYS', 435),
    ('9', 'airtel', '1.5GB COOPERATE GIFTING 2DAYS', 600),
    ('10', 'airtel', '1GB COOPERATE GIFTING DAY', 500),
    ('11', 'airtel', '3.2GB COOPERATE GIFTING 2DAYS', 800),
    ('12', 'airtel', '6.5GB COOPERATE GIFTING Weekly', 1500),
    ('13', 'airtel', '10GB COOPERATE GIFTING MONTHLY', 3500),
    ('51', 'airtel', '3GB SME 7DAYS', 1100),
    ('14', 'glo', '1.3GB GIFTING MONTHLY', 500),
    ('15', 'glo', '2.9GB GIFTING MONTHLY', 1000),
    ('16', 'glo', '4.1GB GIFTING MONTHLY', 1500),
    ('17', 'glo', '5.2GB GIFTING MONTHLY', 2000),
    ('30', 'glo', '500MB COOPERATE GIFTING MONTHLY', 210),
    ('31', 'glo', '1GB COOPERATE GIFTING MONTHLY', 395),
    ('32', 'glo', '2GB COOPERATE GIFTING MONTHLY', 790),
    ('33', 'glo', '3GB COOPERATE GIFTING MONTHLY', 1185),
    ('34', 'glo', '5GB COOPERATE GIFTING MONTHLY', 1425),
    ('35', 'glo', '10GB COOPERATE GIFTING MONTHLY', 3950),
    ('36', 'glo', '200MB COOPERATE GIFTING 14Days', 85),
    ('18', 'etisalat', '1.5GB GIFTING MONTHLY', 1000),
    ('19', 'etisalat', '2GB GIFTING MONTHLY', 1150),
    ('20', 'etisalat', '3GB GIFTING MONTHLY', 1500),
    ('21', 'etisalat', '500MB GIFTING MONTHLY', 480),
    ('37', 'etisalat', '500MB COOPERATE GIFTING MONTHLY', 150),
    ('38', 'etisalat', '1.1GB COOPERATE GIFTING MONTHLY', 320),
    ('39', 'etisalat', '2.3GB COOPERATE GIFTING MONTHLY', 620),
    ('40', 'etisalat', '3.3GB COOPERATE GIFTING MONTHLY', 900),
    ('41', 'etisalat', '4.5GB COOPERATE GIFTING MONTHLY', 1400),
]
FATIZARA_CABLE_SEED = [
    # (plan_id, network, name, cost)
    ('3', 'gotv', 'Jinja', 2250),
    ('4', 'gotv', 'Gotv Jolli', 3300),
    ('5', 'gotv', 'Smallie-Monthly(Lite)', 1100),
    ('6', 'gotv', 'Max', 4850),
    ('7', 'gotv', 'Supa', 6400),
    ('8', 'startimes', 'Nova-1month', 1200),
    ('9', 'startimes', 'Basic(Antenna)-1 month', 2100),
    ('10', 'startimes', 'Smart(Dish)-1month', 2900),
    ('11', 'startimes', 'Classic(Antenna)-1month', 3100),
    ('12', 'startimes', 'Super', 5400),
    ('13', 'dstv', 'Padi', 2500),
    ('14', 'dstv', 'Yanga', 3500),
    ('15', 'dstv', 'Confam', 6200),
    ('16', 'dstv', 'Compart', 10500),
    ('17', 'dstv', 'Asia', 7100),
    ('18', 'dstv', 'Confam + ExtraView', 8200),
    ('19', 'dstv', 'Yanga + extra', 5850),
    ('20', 'dstv', 'Padi+extra view', 5050),
    ('21', 'dstv', 'HDPVR Access Service', 2900),
    ('22', 'dstv', 'Asia addon', 7100),
]
# NOTE: data plan id '3' and cable plan id '3' collide on plan_id alone —
# the seed below stores cable plans with a 'c:' prefix so the two tables
# never clash. (Plan lookups always filter by service, so the prefix is
# invisible to the frontend: it sends the plain docs id.)
FATIZARA_DISCO_SEED = [
    # (disco_key, fatizara_id, label) — Fatizara lists 8 discos; Enugu and
    # Benin have no Fatizara mapping and stay unmapped under this provider.
    ('ikeja-electric', '1', 'Ikeja Electric (IKEDC)'),
    ('eko-electric', '2', 'Eko Electric (EKEDC)'),
    ('kano-electric', '3', 'Kano Electric (KEDCO)'),
    ('portharcourt-electric', '4', 'PH Electric (PHEDC)'),
    ('jos-electric', '5', 'Jos Electric (JEDC)'),
    ('ibadan-electric', '6', 'Ibadan Electric (IBEDC)'),
    ('kaduna-electric', '7', 'Kaduna Electric (KAEDC)'),
    ('abuja-electric', '8', 'Abuja Electric (AEDC)'),
]

@app.post('/api/admin/fatizara-seed-plans')
@admin_auth
def fatizara_seed_plans():
    """Seed Fatizara plans + discos from the docs tables. Safe to re-run:
    updates cost/name, never overwrites an admin-set sell price."""
    n_plans = 0
    for plan_id, network, name, cost in FATIZARA_DATA_SEED:
        run("""INSERT INTO fatizara_plans(plan_id,service,network,name,cost,updated)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
               network=excluded.network, name=excluded.name, cost=excluded.cost,
               updated=excluded.updated""",
            (plan_id, 'data', network, name, cost, now_iso()))
        n_plans += 1
    for plan_id, network, name, cost in FATIZARA_CABLE_SEED:
        run("""INSERT INTO fatizara_plans(plan_id,service,network,name,cost,updated)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
               network=excluded.network, name=excluded.name, cost=excluded.cost,
               updated=excluded.updated""",
            ('c:' + plan_id, 'cable', network, name, cost, now_iso()))
        n_plans += 1
    n_discos = 0
    for disco_key, fz_id, label in FATIZARA_DISCO_SEED:
        run("""INSERT INTO fatizara_discos(disco_key,fatizara_id,label,updated)
               VALUES(?,?,?,?)
               ON CONFLICT(disco_key) DO UPDATE SET fatizara_id=excluded.fatizara_id,
               label=excluded.label, updated=excluded.updated""",
            (disco_key, fz_id, label, now_iso()))
        n_discos += 1
    return jsonify({'ok': True, 'plans': n_plans, 'discos': n_discos,
                    'note': 'Sell prices start at Fatizara cost — set retail prices in the admin panel before switching customers over.'})

@app.get('/api/admin/bilal-balance')
@admin_auth
def bilal_balance():
    """Bilal wallet balance comes from the /api/user auth response."""
    if not bilal_configured():
        return jsonify({'ok': False, 'error': 'Bilal username / password missing.'}), 502
    try:
        _, auth_resp = bilal_token()
        bal = auth_resp.get('balance')
        try: bal = float(str(bal).replace(',', ''))
        except (TypeError, ValueError): bal = None
        if bal is None:
            return jsonify({'ok': False, 'error': 'Could not read balance.'}), 502
        return jsonify({'ok': True, 'balance': bal})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)[:200]}), 502

@app.get('/api/admin/bilal-plans')
@admin_auth
def bilal_plans_admin():
    return jsonify({'ok': True, 'plans': q("SELECT * FROM bilal_plans ORDER BY service, network, cost")})

@app.post('/api/admin/bilal-plan')
@admin_auth
def bilal_plan_save():
    d = request.get_json(force=True, silent=True) or {}
    plan_id = (d.get('plan_id') or '').strip()
    service = (d.get('service') or '').strip()
    network = (d.get('network') or '').strip()
    name = (d.get('name') or '').strip()
    if not plan_id or service not in ('data', 'cable') or not name:
        return jsonify({'ok': False, 'error': 'plan_id, service (data/cable) and name are required.'}), 400
    try: cost = float(d.get('cost'))
    except Exception: return jsonify({'ok': False, 'error': 'Enter a valid cost.'}), 400
    sell = d.get('sell')
    try: sell = None if sell in (None, '') else float(sell)
    except Exception: return jsonify({'ok': False, 'error': 'Enter a valid sell price.'}), 400
    run("""INSERT INTO bilal_plans(plan_id,service,network,name,cost,sell,updated)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
           network=excluded.network, name=excluded.name, cost=excluded.cost,
           sell=excluded.sell, updated=excluded.updated""",
        (plan_id, service, network, name, cost, sell, now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/bilal-discos')
@admin_auth
def bilal_discos_admin():
    return jsonify({'ok': True, 'discos': q("SELECT * FROM bilal_discos ORDER BY label")})

@app.post('/api/admin/bilal-disco')
@admin_auth
def bilal_disco_save():
    d = request.get_json(force=True, silent=True) or {}
    disco_key = (d.get('disco_key') or '').strip()
    bl_id = (d.get('bilal_id') or '').strip()
    label = (d.get('label') or '').strip()
    if not disco_key or not bl_id or not label:
        return jsonify({'ok': False, 'error': 'disco_key, bilal_id and label are required.'}), 400
    run("""INSERT INTO bilal_discos(disco_key,bilal_id,label,updated)
           VALUES(?,?,?,?)
           ON CONFLICT(disco_key) DO UPDATE SET bilal_id=excluded.bilal_id,
           label=excluded.label, updated=excluded.updated""",
        (disco_key, bl_id, label, now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/bilal-cost-check')
@admin_auth
def bilal_cost_check():
    """Plans whose sell price sits below Bilal cost — same idea as cost-check."""
    out = []
    for r in q("SELECT plan_id, service, network, name, cost, sell FROM bilal_plans"):
        cost = float(r['cost'] or 0)
        sell = bl_sell_price(r['plan_id'], cost)
        if sell < cost:
            out.append({'plan': r['name'], 'code': r['plan_id'], 'service': r['service'],
                        'cost': cost, 'sell': sell, 'loss': round(cost - sell, 2)})
    return jsonify({'ok': True, 'losing': out})

# Seed: the dashboard disco mapping is known, but data/cable plan ids only
# come from the live catalog (the dashboard tables show names + prices, not
# ids), so the live pull below is the real seed. Safe to re-run: updates
# cost/name, never overwrites an admin-set sell price.
BILAL_DISCO_SEED = [
    ('ikeja-electric', 1, 'Ikeja Electric (IKEDC)'),
    ('eko-electric', 2, 'Eko Electric (EKEDC)'),
    ('kano-electric', 3, 'Kano Electric (KEDCO)'),
    ('portharcourt-electric', 4, 'PH Electric (PHEDC)'),
    ('jos-electric', 5, 'Jos Electric (JEDC)'),
    ('ibadan-electric', 6, 'Ibadan Electric (IBEDC)'),
    ('kaduna-electric', 7, 'Kaduna Electric (KAEDC)'),
    ('abuja-electric', 8, 'Abuja Electric (AEDC)'),
    ('benin-electric', 9, 'Benin Electric (BEDC)'),
    ('yola-electric', 10, 'Yola Electric (YEDC)'),
]
BILAL_CATALOG_NETWORKS = {'MTN': 'mtn', 'AIRTEL': 'airtel', 'GLO': 'glo',
                          '9MOBILE': 'etisalat', 'T2': 'etisalat'}
BILAL_CATALOG_CABLES = {'DSTV': 'dstv', 'GOTV': 'gotv', 'STARTIMES': 'startimes'}

@app.post('/api/admin/bilal-seed-plans')
@admin_auth
def bilal_seed_plans():
    """Seed Bilal discos from the dashboard mapping, then — if Bilal
    credentials are set — pull the live catalogs (data + cable plans at
    this account's tier price, discos) and upsert them."""
    n_discos = 0
    for disco_key, bl_id, label in BILAL_DISCO_SEED:
        run("""INSERT INTO bilal_discos(disco_key,bilal_id,label,updated)
               VALUES(?,?,?,?)
               ON CONFLICT(disco_key) DO UPDATE SET bilal_id=excluded.bilal_id,
               label=excluded.label, updated=excluded.updated""",
            (disco_key, str(bl_id), label, now_iso()))
        n_discos += 1
    n_plans = 0
    if bilal_configured():
        try:
            data = bilal_get('/v1/plans/data')
            for p in data.get('data') or []:
                net = BILAL_CATALOG_NETWORKS.get((p.get('network') or '').upper())
                if not net:
                    continue
                name = f"{p.get('plan_name')} {p.get('plan_type')} {p.get('plan_day')}".strip()
                run("""INSERT INTO bilal_plans(plan_id,service,network,name,cost,updated)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
                       network=excluded.network, name=excluded.name, cost=excluded.cost,
                       updated=excluded.updated""",
                    (str(p.get('plan_id')), 'data', net, name, float(p.get('amount') or 0), now_iso()))
                n_plans += 1
        except Exception:
            pass
        try:
            cable = bilal_get('/v1/plans/cable')
            for p in cable.get('data') or []:
                net = BILAL_CATALOG_CABLES.get((p.get('cable_name') or '').upper())
                if not net:
                    continue
                run("""INSERT INTO bilal_plans(plan_id,service,network,name,cost,updated)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
                       network=excluded.network, name=excluded.name, cost=excluded.cost,
                       updated=excluded.updated""",
                    ('c:' + str(p.get('plan_id')), 'cable', net, p.get('plan_name'),
                     float(p.get('plan_price') or 0), now_iso()))
                n_plans += 1
        except Exception:
            pass
        try:
            discos = bilal_get('/v1/plans/discos')
            for d in discos.get('data') or []:
                # Only refresh labels for discos already mapped; the catalog
                # gives no frontend key, so it cannot invent new mappings.
                run("UPDATE bilal_discos SET label=? WHERE bilal_id=?",
                    (d.get('disco_name'), str(d.get('plan_id'))))
        except Exception:
            pass
    synced = n_plans > 0
    return jsonify({'ok': True, 'plans': n_plans, 'discos': n_discos,
                    'catalog_synced': synced,
                    'note': ('Live catalog pulled.' if synced else
                             'Discos seeded. Add Bilal credentials, then re-run to pull live plans.') +
                    ' Sell prices start at Bilal cost — set retail prices in the admin panel before switching customers over.'})

@app.get('/api/admin/bilal-requery')
@admin_auth
def bilal_requery():
    """Resolve a pending Bilal transaction via GET /api/requery/{request-id}.
    Only applies to transactions still pending: success marks it successful,
    failed refunds it through the same settle path as a failed buy."""
    ref = (request.args.get('reference') or '').strip()
    rows = q("SELECT user_id, amount, status, provider_ref FROM transactions WHERE reference=?", (ref,))
    if not rows:
        return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404
    tx = rows[0]
    if tx['status'] != 'pending':
        return jsonify({'ok': False, 'error': f"Transaction is already {tx['status']}."}), 400
    rid = tx['provider_ref'] or ''
    if not rid:
        return jsonify({'ok': False, 'error': 'No Bilal request-id stored for this transaction.'}), 400
    try:
        resp = bilal_get('/requery/' + rid)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)[:200]}), 502
    data = resp.get('data') or {}
    tstatus = (data.get('transaction_status') or resp.get('status') or '').lower()
    if tstatus == 'success':
        run("UPDATE transactions SET status='successful', meta=? WHERE reference=?",
            (json.dumps(resp)[:4000], ref))
        return jsonify({'ok': True, 'status': 'successful'})
    if tstatus in ('failed', 'fail'):
        _settle_wallet(tx['user_id'], ref, float(tx['amount']), False, rid, '', resp, 'Bilal reports failed.')
        return jsonify({'ok': True, 'status': 'failed', 'refunded': True})
    return jsonify({'ok': True, 'status': tstatus or 'pending'})

@app.get('/api/admin/users')
@admin_auth
def admin_users():
    return jsonify({'ok': True, 'users': q(
        "SELECT id,name,phone,email,email_verified,wallet,created FROM users ORDER BY id DESC LIMIT 500")})

@app.post('/api/admin/wallet')
@admin_auth
def admin_wallet():
    d = request.get_json(force=True)
    phone = (d.get('phone') or '').strip()
    try: amount = float(d.get('amount') or 0)
    except: amount = 0
    action = d.get('action', 'add')
    rows = q("SELECT id FROM users WHERE phone=?", (phone,))
    if not rows: return jsonify({'ok': False, 'error': 'User not found.'}), 404
    delta = amount if action == 'add' else -amount
    run("UPDATE users SET wallet=wallet+? WHERE phone=?", (delta, phone))
    run("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
           status,reference,created) VALUES(?, 'fund','admin',?,?, 'in','successful',?,?)""",
        (rows[0]['id'], f'Admin wallet adjustment', amount,
         'SVA' + secrets.token_hex(5).upper(), now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/transactions')
@admin_auth
def admin_txs():
    return jsonify({'ok': True, 'transactions': q(
        """SELECT t.*, u.phone FROM transactions t LEFT JOIN users u ON u.id=t.user_id
           ORDER BY t.id DESC LIMIT 500""")})

@app.get('/api/admin/prices')
@admin_auth
def admin_prices():
    return jsonify({'ok': True, 'prices': q("SELECT * FROM plan_prices ORDER BY label")})

@app.post('/api/admin/price')
@admin_auth
def admin_price():
    d = request.get_json(force=True)
    code = (d.get('variation_code') or '').strip()
    try: price = float(d.get('sell_price'))
    except: return jsonify({'ok': False, 'error': 'Enter a valid price.'}), 400
    label = (d.get('label') or '').strip()
    # UPSERT works on both SQLite (3.24+) and Postgres
    run("""INSERT INTO plan_prices(variation_code,sell_price,label,updated) VALUES(?,?,?,?)
           ON CONFLICT(variation_code) DO UPDATE SET sell_price=excluded.sell_price,
           label=excluded.label, updated=excluded.updated""",
        (code, price, label, now_iso()))
    return jsonify({'ok': True})

@app.post('/api/admin/seed-prices')
@admin_auth
def seed_prices():
    """Match Mahmod's retail price list to live VTpass variations."""
    RETAIL = {
        'mtn-data':    {'500MB': 130, '1GB': 235, '2GB': 470, '3GB': 705, '5GB': 1175, '10GB': 2350},
        'airtel-data': {'500MB': 140, '1GB': 250, '2GB': 500, '5GB': 1250},
    }
    seeded, skipped = [], []
    for svc, pricelist in RETAIL.items():
        for v in vt_variations(svc):
            code, name = v.get('variation_code'), v.get('name') or ''
            cost = float(v.get('variation_amount') or 0)
            m = re.search(r'(\d+(?:\.\d+)?)\s*(MB|GB)', name, re.I)
            if not m:
                skipped.append(name); continue
            size = m.group(1).rstrip('0').rstrip('.') + m.group(2).upper()
            if size in pricelist:
                sell = pricelist[size]
                run("""INSERT INTO plan_prices(variation_code,sell_price,cost_price,label,updated)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(variation_code) DO UPDATE SET sell_price=excluded.sell_price,
                       cost_price=excluded.cost_price, label=excluded.label, updated=excluded.updated""",
                    (code, sell, cost, f"{svc} {name}", now_iso()))
                seeded.append({'plan': name, 'sell': sell, 'cost': cost,
                               'below_cost': sell < cost})
            else:
                skipped.append(name)
    return jsonify({'ok': True, 'seeded': seeded, 'unmatched': skipped,
                    'note': 'Plans marked below_cost lose money on every sale — raise them in Prices.'})

@app.get('/api/admin/cost-check')
@admin_auth
def cost_check():
    """Compare sell prices vs live VTpass cost for data plans."""
    out = []
    for svc in ('mtn-data', 'airtel-data', 'glo-data', 'etisalat-data'):
        for v in vt_variations(svc):
            code = v.get('variation_code')
            cost = float(v.get('variation_amount') or 0)
            sell = sell_price(code, cost)
            if sell < cost:
                out.append({'plan': v.get('name'), 'code': code,
                            'cost': cost, 'sell': sell, 'loss': round(cost - sell, 2)})
    return jsonify({'ok': True, 'losing': out})

# ---------------- runtime settings (admin-editable API keys) ----------------
@app.get('/api/admin/settings')
@admin_auth
def admin_settings():
    items = [{'key': k, 'group': m['group'], 'label': m['label'],
              'secret': m['secret'], 'value': S(k)}
             for k, m in SETTINGS_META.items()]
    return jsonify({'ok': True, 'settings': items})

@app.post('/api/admin/settings')
@admin_auth
def admin_settings_save():
    d = request.get_json(force=True, silent=True) or {}
    key = (d.get('key') or '').strip()
    value = d.get('value')
    if key not in SETTINGS_ALLOW:
        return jsonify({'ok': False, 'error': 'That setting cannot be changed here.'}), 400
    value = '' if value is None else str(value)
    if key.endswith('_SANDBOX') and value not in ('0', '1'):
        return jsonify({'ok': False, 'error': 'Sandbox must be 0 or 1.'}), 400
    if key == 'PROVIDER' and value not in ('vtpass', 'fatizara', 'bilal'):
        return jsonify({'ok': False, 'error': 'Provider must be vtpass, fatizara or bilal.'}), 400
    run("""INSERT INTO settings(k,v,updated_at) VALUES(?,?,?)
           ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at""",
        (key, value, now_iso()))
    SETTINGS[key] = value
    # Monnify caches its OAuth token per key-set; a key change must re-auth.
    if key.startswith('MONNIFY_'):
        _monnify['token'] = None
        _monnify['exp'] = 0
    return jsonify({'ok': True})

@app.post('/api/admin/test-connection')
@admin_auth
def admin_test_connection():
    d = request.get_json(force=True, silent=True) or {}
    service = (d.get('service') or '').strip().lower()
    try:
        if service == 'vtpass':
            if not (S('VTPASS_API_KEY') and S('VTPASS_PUBLIC_KEY')):
                return jsonify({'ok': False, 'detail': 'API key / public key missing.'})
            r = vt_get('/balance')
            bal = (r.get('content') or {}).get('balance', r)
            return jsonify({'ok': True, 'detail': f"Connected — wallet balance ₦{bal}."})
        if service == 'fatizara':
            if not fatizara_configured():
                return jsonify({'ok': False, 'detail': 'Fatizara username / password missing.'})
            try:
                _, auth_resp = fatizara_token()
                return jsonify({'ok': True, 'detail': f"Auth OK — wallet balance ₦{auth_resp.get('balance')}."})
            except Exception as e:
                return jsonify({'ok': False, 'detail': 'Auth failed: ' + str(e)[:120]})
        if service == 'bilal':
            if not bilal_configured():
                return jsonify({'ok': False, 'detail': 'Bilal username / password missing.'})
            try:
                _, auth_resp = bilal_token()
                return jsonify({'ok': True, 'detail': f"Auth OK — wallet balance ₦{auth_resp.get('balance')}."})
            except Exception as e:
                return jsonify({'ok': False, 'detail': 'Auth failed: ' + str(e)[:120]})
        if service == 'monnify':
            if not monnify_configured():
                return jsonify({'ok': False, 'detail': 'API key / secret / contract code missing.'})
            creds = base64.b64encode(
                f"{S('MONNIFY_API_KEY')}:{S('MONNIFY_SECRET_KEY')}".encode()).decode()
            r = requests.post(f'{monnify_base()}/api/v1/auth/login',
                              headers={'Authorization': f'Basic {creds}'},
                              timeout=20).json()
            tok = (r.get('responseBody') or {}).get('accessToken')
            if tok:
                mode = 'sandbox' if monnify_sandbox() else 'LIVE'
                return jsonify({'ok': True, 'detail': f'Auth OK ({mode}).'})
            return jsonify({'ok': False,
                            'detail': 'Auth failed: ' + str(r.get('responseMessage') or 'check keys')[:120]})
        if service == 'brevo':
            if not S('BREVO_API_KEY'):
                return jsonify({'ok': False, 'detail': 'Brevo API key missing.'})
            r = requests.get('https://api.brevo.com/v3/account',
                             headers={'api-key': S('BREVO_API_KEY')}, timeout=20)
            if r.status_code == 200:
                j = r.json()
                return jsonify({'ok': True,
                                'detail': f"Connected — account {j.get('email', 'ok')}."})
            return jsonify({'ok': False, 'detail': f'Brevo rejected the key (HTTP {r.status_code}).'})
        return jsonify({'ok': False, 'detail': 'Unknown service.'}), 400
    except Exception as e:
        return jsonify({'ok': False, 'detail': 'Connection error: ' + str(e)[:120]})

# ---------------- password reset ----------------
@app.post('/api/forgot-password')
@limiter.limit('5 per minute')
def forgot_password():
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip()
    rows = q("SELECT id, name, email FROM users WHERE email=?", (email,))
    if rows:
        user = rows[0]
        code = new_email_code(user['id'], 'reset')
        send_email(user['email'], 'Reset your Panther Data password',
                   f"Hello {user['name']},\n\nYour password reset code is:\n\n{code}\n\n"
                   f"Enter it in the app with your new password. It expires in 15 minutes.\n\n"
                   f"If you did not request this, ignore this email.\n\n— Panther Data")
    # always ok — never reveal whether the email is registered
    return jsonify({'ok': True})

@app.post('/api/reset-password')
@limiter.limit('10 per minute')
def reset_password():
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip()
    code = str(d.get('code') or '').strip()
    pw = d.get('new_password') or ''
    if len(pw) < 8:
        return jsonify({'ok': False, 'error': 'Password must be at least 8 characters.'}), 400
    rows = q("SELECT id FROM users WHERE email=?", (email,))
    if not rows:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    uid = rows[0]['id']
    chash = hashlib.sha256(code.encode()).hexdigest()
    grows = q("SELECT expires_at FROM email_codes WHERE user_id=? AND purpose='reset' AND code_hash=?",
              (uid, chash))
    if not grows:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if grows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Request a new one.'}), 400
    run("UPDATE users SET pass_hash=? WHERE id=?", (generate_password_hash(pw), uid))
    run("DELETE FROM email_codes WHERE user_id=? AND purpose='reset'", (uid,))
    run("DELETE FROM tokens WHERE user_id=?", (uid,))  # kill old sessions
    return jsonify({'ok': True})

# ---------------- admin: user detail / password / delete ----------------
@app.get('/api/admin/user')
@admin_auth
def admin_user():
    try: uid = int(request.args.get('id') or 0)
    except Exception: uid = 0
    rows = q("SELECT id,name,phone,email,email_verified,wallet,created,"
             "monnify_ref,monnify_acct,monnify_bank,monnify_acct_name "
             "FROM users WHERE id=?", (uid,))
    if not rows:
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    u = dict(rows[0])
    cnt = q("SELECT COUNT(*) c FROM transactions WHERE user_id=?", (uid,))
    u['tx_count'] = cnt[0]['c'] if cnt else 0
    u['recent'] = q("SELECT id,type,service,description,amount,direction,status,reference,created "
                    "FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 20", (uid,))
    return jsonify({'ok': True, 'user': u})

@app.post('/api/admin/user-password')
@admin_auth
def admin_user_password():
    d = request.get_json(force=True, silent=True) or {}
    try: uid = int(d.get('user_id') or 0)
    except Exception: uid = 0
    pw = d.get('new_password') or ''
    if len(pw) < 8:
        return jsonify({'ok': False, 'error': 'Password must be at least 8 characters.'}), 400
    if not q("SELECT id FROM users WHERE id=?", (uid,)):
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    run("UPDATE users SET pass_hash=? WHERE id=?", (generate_password_hash(pw), uid))
    run("DELETE FROM tokens WHERE user_id=?", (uid,))
    return jsonify({'ok': True})

@app.post('/api/admin/user-pin')
@admin_auth
def admin_user_pin():
    """Admin sets a user's 4-digit transaction PIN (forgotten / never set).
    Also clears any PIN lockout from wrong attempts. Sessions are NOT
    invalidated: a PIN reset is not a credential compromise, unlike a
    password reset. The admin types the new PIN in the admin page; it is
    never sent through chat."""
    d = request.get_json(force=True, silent=True) or {}
    try: uid = int(d.get('user_id') or 0)
    except Exception: uid = 0
    pin = str(d.get('new_pin') or '').strip()
    if not re.match(r'^\d{4}$', pin):
        return jsonify({'ok': False, 'error': 'PIN must be 4 digits.'}), 400
    if not q("SELECT id FROM users WHERE id=?", (uid,)):
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    if NEW_COLS_READY:
        run("UPDATE users SET tx_pin_hash=?, pin_fails=0, pin_locked_until=NULL WHERE id=?",
            (generate_password_hash(pin), uid))
    else:
        run("UPDATE users SET tx_pin_hash=? WHERE id=?", (generate_password_hash(pin), uid))
    return jsonify({'ok': True})

@app.post('/api/admin/transaction-resolve')
@admin_auth
def admin_transaction_resolve():
    """Resolve a transaction stuck in 'pending' (e.g. the buy request died
    after debit, before settle). The admin states the outcome proven from
    the provider's own record: 'failed' refunds the wallet, 'successful'
    only marks it. Refuses anything not pending, so settled transactions
    can never be rewritten through here."""
    d = request.get_json(force=True, silent=True) or {}
    ref = (d.get('reference') or '').strip()
    outcome = (d.get('outcome') or '').strip().lower()
    if outcome not in ('failed', 'successful'):
        return jsonify({'ok': False, 'error': "Outcome must be 'failed' or 'successful'."}), 400
    rows = q("SELECT user_id, amount, status FROM transactions WHERE reference=?", (ref,))
    if not rows:
        return jsonify({'ok': False, 'error': 'Transaction not found.'}), 404
    t = rows[0]
    if t['status'] != 'pending':
        return jsonify({'ok': False, 'error': 'Only pending transactions can be resolved.'}), 400
    note = json.dumps({'admin_resolved': outcome, 'note': 'Resolved by admin from provider record.'})
    con = db()
    try:
        if USE_PG:
            cur = con.cursor()
            if outcome == 'failed':
                cur.execute("UPDATE users SET wallet=wallet+%s WHERE id=%s", (t['amount'], t['user_id']))
            cur.execute("UPDATE transactions SET status=%s, meta=%s WHERE reference=%s", (outcome, note, ref))
            con.commit(); cur.close()
        else:
            if outcome == 'failed':
                con.execute("UPDATE users SET wallet=wallet+? WHERE id=?", (t['amount'], t['user_id']))
            con.execute("UPDATE transactions SET status=?, meta=? WHERE reference=?", (outcome, note, ref))
            con.commit()
    finally:
        if not USE_PG: con.close()
    bal = q("SELECT wallet FROM users WHERE id=?", (t['user_id'],))
    return jsonify({'ok': True, 'wallet': float(bal[0]['wallet']) if bal else None})

@app.delete('/api/admin/user')
@admin_auth
def admin_user_delete():
    d = request.get_json(force=True, silent=True) or {}
    try: uid = int(d.get('user_id') or 0)
    except Exception: uid = 0
    if not q("SELECT id FROM users WHERE id=?", (uid,)):
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    run("DELETE FROM transactions WHERE user_id=?", (uid,))
    run("DELETE FROM tokens WHERE user_id=?", (uid,))
    run("DELETE FROM email_codes WHERE user_id=?", (uid,))
    run("DELETE FROM users WHERE id=?", (uid,))
    return jsonify({'ok': True})

@app.get('/')
def index():
    return jsonify({'ok': True, 'service': 'Panther Data backend', 'sandbox': vt_sandbox()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
