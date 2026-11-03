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
BACKUP_KEY      = os.environ.get('BACKUP_KEY', '')
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
    'PROVIDER':           dict(group='Provider', label='Active provider — vtpass, fatizara, bilal or legitdataway', secret=False),
    'FATIZARA_USERNAME':  dict(group='Fatizara', label='Fatizara username', secret=False),
    'FATIZARA_PASSWORD':  dict(group='Fatizara', label='Fatizara password', secret=True),
    'BILAL_USERNAME':     dict(group='Bilal',    label='Bilal username', secret=False),
    'BILAL_PASSWORD':     dict(group='Bilal',    label='Bilal password', secret=True),
    'FUNDING_PROVIDER':   dict(group='Provider', label='Funding provider — monnify or xpouch', secret=False),
    'LEGITDATAWAY_USERNAME': dict(group='LegitDataWay', label='LegitDataWay username', secret=True),
    'LEGITDATAWAY_PASSWORD': dict(group='LegitDataWay', label='LegitDataWay password', secret=True),
    'MONNIFY_API_KEY':    dict(group='Monnify',  label='API Key',      secret=True),
    'MONNIFY_SECRET_KEY': dict(group='Monnify',  label='Secret Key',   secret=True),
    'MONNIFY_CONTRACT_CODE': dict(group='Monnify', label='Contract Code', secret=True),
    'XPOUCH_API_KEY':     dict(group='Xpouch',   label='API Key',      secret=True),
    'XPOUCH_SECRET':      dict(group='Xpouch',   label='API Secret',   secret=True),
    'XPOUCH_SANDBOX':     dict(group='Xpouch',   label='Sandbox mode — 1 = test, 0 = LIVE', secret=True),
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

def xpouch_sandbox():
    return S('XPOUCH_SANDBOX') == '1'

def xpouch_base():
    # Sandbox uses the same merchant credentials on a separate base path.
    return ('https://api.xpouch.co/api/merchant/sandbox/v1' if xpouch_sandbox()
            else 'https://api.xpouch.co/api/merchant/v1')

def xpouch_configured():
    return bool(S('XPOUCH_API_KEY') and S('XPOUCH_SECRET'))

def xpouch_headers():
    return {'X-API-Key': S('XPOUCH_API_KEY'), 'X-API-Secret': S('XPOUCH_SECRET'),
            'Accept': 'application/json', 'Content-Type': 'application/json'}

def funding_provider():
    """Active funding provider: 'monnify' (default) or 'xpouch'.
    Monnify stays the default until Xpouch funding is proven with tests,
    so flipping to Xpouch is a one-setting change, and back is one tap."""
    p = (S('FUNDING_PROVIDER') or 'monnify').strip().lower()
    return p if p in ('monnify', 'xpouch') else 'monnify'

def provider():
    """Active vending provider: 'vtpass' (default), 'fatizara', 'bilal' or 'legitdataway'.
    VTpass stays the default until the chosen provider is proven with test buys."""
    p = (S('PROVIDER') or 'vtpass').strip().lower()
    return p if p in ('vtpass', 'fatizara', 'bilal', 'legitdataway') else 'vtpass'

def fatizara_configured():
    return bool(S('FATIZARA_USERNAME') and S('FATIZARA_PASSWORD'))

def bilal_configured():
    return bool(S('BILAL_USERNAME') and S('BILAL_PASSWORD'))

def legitdataway_configured():
    return bool(S('LEGITDATAWAY_USERNAME') and S('LEGITDATAWAY_PASSWORD'))

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
# COST_COL_READY gates profit tracking: True once the transactions table
# has a cost_price column, so buys keep working on any worker where the
# ALTER has not landed yet (cost is then simply not recorded).
_SECURITY_COLS = (
    ("expires_at TEXT", "tokens"),
    ("last_seen TEXT", "tokens"),
    ("pin_fails INTEGER DEFAULT 0", "users"),
    ("pin_locked_until TEXT", "users"),
    ("last_login_ip TEXT", "users"),
    ("login_2fa INTEGER DEFAULT 0", "users"),
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
                         "OR (table_name='users' AND column_name IN ('pin_fails','pin_locked_until','last_login_ip','login_2fa'))")
                found = {(r['table_name'], r['column_name']) for r in rows}
                need = {('tokens','expires_at'), ('tokens','last_seen'),
                        ('users','pin_fails'), ('users','pin_locked_until'), ('users','last_login_ip'),
                        ('users','login_2fa')}
            else:
                trows = [r['name'] for r in q("PRAGMA table_info(tokens)")]
                urows = [r['name'] for r in q("PRAGMA table_info(users)")]
                found = {('tokens',c) for c in trows} | {('users',c) for c in urows}
                need = {('tokens','expires_at'), ('tokens','last_seen'),
                        ('users','pin_fails'), ('users','pin_locked_until'), ('users','last_login_ip'),
                        ('users','login_2fa')}
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
        f"""CREATE TABLE IF NOT EXISTS referral_rewards(
             id {auto}, referrer_id INTEGER, milestone INTEGER,
             amount REAL, created TEXT,
             UNIQUE(referrer_id, milestone))""",
        f"""CREATE TABLE IF NOT EXISTS email_codes(
             id {auto}, user_id INTEGER,
             code_hash TEXT, purpose TEXT, expires_at TEXT, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS transactions(
             id {auto}, user_id INTEGER, type TEXT,
             service TEXT, description TEXT, amount REAL, direction TEXT,
             status TEXT DEFAULT 'successful', reference TEXT UNIQUE,
             provider_ref TEXT, meta TEXT, created TEXT, cost_price REAL)""",
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
        """CREATE TABLE IF NOT EXISTS legitdataway_plans(
             plan_id TEXT PRIMARY KEY, service TEXT, network TEXT,
             name TEXT, cost REAL, sell REAL, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS legitdataway_discos(
             disco_key TEXT PRIMARY KEY, legitdataway_id TEXT, label TEXT, updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT, updated_at TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS admin_logs(
             id {auto}, action TEXT, detail TEXT, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS announcements(
             id {auto}, title TEXT, body TEXT, audience TEXT DEFAULT 'all',
             active INTEGER DEFAULT 1, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS admin_sessions(
             token TEXT PRIMARY KEY, created TEXT, expires_at TEXT, last_seen TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS admin_codes(
             id {auto}, code_hash TEXT, expires_at TEXT, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS invoice_fundings(
             id {auto}, reference TEXT UNIQUE, user_id INTEGER,
             amount REAL, account_number TEXT, bank_name TEXT, bank_code TEXT,
             account_name TEXT, checkout_url TEXT, expiry TEXT,
             status TEXT DEFAULT 'PENDING', created TEXT, paid_at TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS staff_users(
             id {auto}, email TEXT UNIQUE, role TEXT DEFAULT 'full',
             active INTEGER DEFAULT 1, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS staff_codes(
             id {auto}, email TEXT, code_hash TEXT,
             expires_at TEXT, created TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS staff_sessions(
             token TEXT PRIMARY KEY, staff_id INTEGER,
             created TEXT, expires_at TEXT, last_seen TEXT)""",
    ]
    for s in stmts:
        run(s)
    # Boss staff seat (shared code mailbox, full access minus secrets).
    # Soft-delete only: removing a staffer sets active=0, so a redeploy
    # can never resurrect access that the main admin revoked.
    # NOTE: now_iso() is defined below init_db(), so the seed uses a
    # plain UTC timestamp here instead of calling it.
    # NOTE 2: ON CONFLICT DO NOTHING works on both Postgres (live Neon)
    # and SQLite (scratch tests). INSERT OR IGNORE is SQLite-only and
    # silently failed on Postgres, which left the seed row missing live.
    try:
        run("""INSERT INTO staff_users(email,role,active,created)
               VALUES(?,?,?,?) ON CONFLICT(email) DO NOTHING""",
            ('pantherdata1@gmail.com', 'full', 1,
             datetime.now(timezone.utc).isoformat(timespec='seconds')))
    except Exception:
        pass
    # migrate older databases that lack the new columns
    for col, tbl in (("email_verified INTEGER DEFAULT 0", "users"),
                     ("tx_pin_hash TEXT", "users"),
                     ("username TEXT", "users"),
                     ("referred_by INTEGER", "users"),
                     ("monnify_ref TEXT", "users"), ("monnify_acct TEXT", "users"),
                     ("monnify_bank TEXT", "users"), ("monnify_acct_name TEXT", "users"),
                     ("xpouch_ref TEXT", "users"), ("xpouch_acct TEXT", "users"),
                     ("xpouch_bank TEXT", "users"), ("xpouch_acct_name TEXT", "users"),
                     ("cost_price REAL", "transactions"),
                     ("updated_at TEXT", "settings")):
        try:
            run(f"ALTER TABLE {tbl} ADD COLUMN {col}")
        except Exception:
            pass
    # Profit tracking: verify the cost_price column actually exists so the
    # buy paths know whether they can record the provider cost. A worker
    # where the ALTER did not land keeps selling normally, just without
    # cost recording, and the next deploy retries the migration.
    global COST_COL_READY
    try:
        if USE_PG:
            rows = q("SELECT column_name FROM information_schema.columns "
                     "WHERE table_name='transactions' AND column_name='cost_price'")
            COST_COL_READY = len(rows) > 0
        else:
            cols = [r['name'] for r in q("PRAGMA table_info(transactions)")]
            COST_COL_READY = 'cost_price' in cols
    except Exception:
        COST_COL_READY = False
    # Referrals: same pattern — the referred_by column gates referral
    # counting and rewards, so a worker where the ALTER has not landed
    # simply does not attach referrals yet, instead of failing signups.
    global REF_COL_READY
    try:
        if USE_PG:
            rows = q("SELECT column_name FROM information_schema.columns "
                     "WHERE table_name='users' AND column_name='referred_by'")
            REF_COL_READY = len(rows) > 0
        else:
            cols = [r['name'] for r in q("PRAGMA table_info(users)")]
            REF_COL_READY = 'referred_by' in cols
    except Exception:
        REF_COL_READY = False
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
    # Each Xpouch account reference must belong to exactly one user, same rule.
    try:
        run("CREATE UNIQUE INDEX IF NOT EXISTS users_xpouch_ref_uniq ON users(xpouch_ref)")
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
        'XPOUCH_API_KEY': os.environ.get('XPOUCH_API_KEY', '').strip(),
        'XPOUCH_SECRET': os.environ.get('XPOUCH_SECRET', '').strip(),
        'XPOUCH_SANDBOX': os.environ.get('XPOUCH_SANDBOX', '1'),
        'FUNDING_PROVIDER': os.environ.get('FUNDING_PROVIDER', 'monnify'),
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

def log_admin(action, detail=''):
    """Append one line to the server activity log. Never raises: logging
    must never break the admin action it records."""
    try:
        run("INSERT INTO admin_logs(action,detail,created) VALUES(?,?,?)",
            (action, (detail or '')[:500], now_iso()))
    except Exception:
        pass

def admin_email():
    """Where admin sign-in codes go. Set ADMIN_EMAIL on the server to
    choose the inbox; otherwise the business mailbox is used."""
    try:
        return os.environ.get('ADMIN_EMAIL', '') or SMTP_USER or S('BREVO_SENDER')
    except Exception:
        return os.environ.get('ADMIN_EMAIL', '') or SMTP_USER

def new_admin_session(remember):
    """Issue a session token after key + code. Remembered sessions last
    30 days like customer sessions; otherwise 12 hours."""
    tok = secrets.token_hex(32)
    exp = (datetime.now(LAGOS) + (timedelta(days=SESSION_ABS_DAYS) if remember
           else timedelta(hours=12))).isoformat(timespec='seconds')
    run("INSERT INTO admin_sessions(token,created,expires_at,last_seen) VALUES(?,?,?,?)",
        (tok, now_iso(), exp, now_iso()))
    return tok, exp

def admin_session_auth(f):
    """Admin endpoints require a verified session token, not the raw key.
    The key alone only opens the two code endpoints below; every other
    admin call must carry X-Admin-Session from a key + code sign-in, or
    from a staff email-code sign-in (staff tokens live in staff_sessions
    and set g.is_staff; staff can do everything except settings, test
    connections and staff management, which stay with the main admin —
    and secret settings values are never shown to staff)."""
    @wraps(f)
    def wrapper(*a, **kw):
        tok = (request.headers.get('X-Admin-Session') or '').strip()
        if not tok:
            return jsonify({'ok': False, 'error': 'Admin session required. Sign in again.'}), 403
        now = now_iso()
        rows = q("SELECT expires_at FROM admin_sessions WHERE token=?", (tok,))
        if rows:
            if rows[0].get('expires_at') and rows[0]['expires_at'] < now:
                run("DELETE FROM admin_sessions WHERE token=?", (tok,))
                return jsonify({'ok': False, 'error': 'Admin session expired. Sign in again.'}), 403
            run("UPDATE admin_sessions SET last_seen=? WHERE token=?", (now, tok))
            g.is_staff = False
            g.staff_role = None
            g.staff_email = None
            return f(*a, **kw)
        srows = q("SELECT staff_id, expires_at FROM staff_sessions WHERE token=?", (tok,))
        if not srows:
            return jsonify({'ok': False, 'error': 'Admin session required. Sign in again.'}), 403
        if srows[0].get('expires_at') and srows[0]['expires_at'] < now:
            run("DELETE FROM staff_sessions WHERE token=?", (tok,))
            return jsonify({'ok': False, 'error': 'Admin session expired. Sign in again.'}), 403
        urows = q("SELECT email, role, active FROM staff_users WHERE id=?", (srows[0]['staff_id'],))
        if not urows or not urows[0].get('active'):
            run("DELETE FROM staff_sessions WHERE token=?", (tok,))
            return jsonify({'ok': False, 'error': 'Admin session required. Sign in again.'}), 403
        run("UPDATE staff_sessions SET last_seen=? WHERE token=?", (now, tok))
        g.is_staff = True
        g.staff_role = urows[0].get('role')
        g.staff_email = urows[0].get('email')
        return f(*a, **kw)
    return wrapper

def _main_admin_only():
    """Refuse staff sessions on main-admin-only endpoints (settings,
    connection tests, staff management). Returns a 403 response, or
    None when the caller is the main admin."""
    if getattr(g, 'is_staff', False):
        return jsonify({'ok': False, 'error': 'Only the main admin can do this.'}), 403
    return None

def admin_export_auth(f):
    """Read-only export endpoints ONLY (users, transactions, prices, user
    detail — the four the daily backup script pulls). Accepts a verified
    admin session, a verified staff session (staff read the same lists
    the admin page shows — this is what makes staff sign-in work at
    all), or the separate BACKUP_KEY, which works on these four
    endpoints and nowhere else: it cannot adjust wallets, change prices
    or settings, reset passwords or PINs, delete users, or open the
    admin page. The admin key + code login is unchanged, and customer
    sign-in is untouched."""
    @wraps(f)
    def wrapper(*a, **kw):
        tok = (request.headers.get('X-Admin-Session') or '').strip()
        if tok:
            rows = q("SELECT expires_at FROM admin_sessions WHERE token=?", (tok,))
            if rows:
                now = now_iso()
                if not rows[0].get('expires_at') or rows[0]['expires_at'] >= now:
                    run("UPDATE admin_sessions SET last_seen=? WHERE token=?", (now, tok))
                    g.is_staff = False
                    g.staff_role = None
                    g.staff_email = None
                    return f(*a, **kw)
            srows = q("SELECT staff_id, expires_at FROM staff_sessions WHERE token=?", (tok,))
            if srows:
                now = now_iso()
                if not srows[0].get('expires_at') or srows[0]['expires_at'] >= now:
                    urows = q("SELECT email, role, active FROM staff_users WHERE id=?", (srows[0]['staff_id'],))
                    if urows and urows[0].get('active'):
                        run("UPDATE staff_sessions SET last_seen=? WHERE token=?", (now, tok))
                        g.is_staff = True
                        g.staff_role = urows[0].get('role')
                        g.staff_email = urows[0].get('email')
                        return f(*a, **kw)
        bkey = (request.headers.get('X-Backup-Key') or '').strip()
        if BACKUP_KEY and bkey and bkey == BACKUP_KEY:
            return f(*a, **kw)
        return jsonify({'ok': False, 'error': 'Admin session required. Sign in again.'}), 403
    return wrapper

def get_user(uid):
    try:
        rows = q("SELECT id,name,username,phone,email,wallet,email_verified,created,monnify_ref,monnify_acct,monnify_bank,monnify_acct_name,login_2fa FROM users WHERE id=?", (uid,))
    except Exception:
        # Column not migrated yet (migration pending): fall back without it.
        rows = q("SELECT id,name,username,phone,email,wallet,email_verified,created,monnify_ref,monnify_acct,monnify_bank,monnify_acct_name FROM users WHERE id=?", (uid,))
        if not rows:
            return None
        u = dict(rows[0])
        u['login_2fa'] = 0
        return u
    if not rows:
        return None
    u = dict(rows[0])
    # Old rows predate the column; treat a missing flag as off.
    u['login_2fa'] = 1 if u.get('login_2fa') else 0
    return u

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


# ---------------- LegitDataWay ----------------
# Docs: https://app.legitdataway.com/documentation/home (login-walled).
# Same two-step token flow as Bilal: POST /api/user with HTTP Basic auth
# (username:password) returns an AccessToken, then every vending call carries
# 'Authorization: Token <AccessToken>'. The AccessToken never expires per docs.
# Data/airtime/bill payloads mirror Bilal's; cable differs: LegitDataWay wants
# cablename + cableplan + smart_card_number (Bilal wants cable + cable_plan + iuc).
# Disco IDs match Bilal EXCEPT 9/10 are swapped: LegitDataWay 9=Yola, 10=Benin
# (Bilal 9=Benin, 10=Yola) — do NOT copy Bilal's disco map.
# Cable plan ids in our DB carry a 'c:' prefix (same collision guard as Bilal:
# numeric data and cable ids overlap); the prefix is stripped before sending.
# LegitDataWay publishes no cable slug list — whether /api/cable accepts the
# numeric plan id or a slug is proven by a live test buy before the switch
# flips (see switch notes). Final outcomes also arrive via webhook
# (request-id keyed); there is no documented requery endpoint, so a lost
# reply stays pending for the webhook or the admin transaction-resolve
# endpoint — it is NEVER auto-refunded.
LEGITDATAWAY_BASE = 'https://legitdataway.com'
LEGITDATAWAY_NETWORKS = {'mtn': 1, 'airtel': 2, 'glo': 3, 'etisalat': 4}
LEGITDATAWAY_CABLES = {'gotv': 1, 'dstv': 2, 'startimes': 3}
LEGITDATAWAY_DISCO_IDS = {'ikeja-electric': 1, 'eko-electric': 2, 'kano-electric': 3,
                          'portharcourt-electric': 4, 'jos-electric': 5, 'ibadan-electric': 6,
                          'kaduna-electric': 7, 'abuja-electric': 8, 'yola-electric': 9,
                          'benin-electric': 10}

def legitdataway_token():
    """Mint an AccessToken. Returns (token, full_auth_response)."""
    creds = base64.b64encode(f"{S('LEGITDATAWAY_USERNAME')}:{S('LEGITDATAWAY_PASSWORD')}".encode()).decode()
    r = requests.post(LEGITDATAWAY_BASE + '/api/user',
                      headers={'Authorization': f'Basic {creds}'}, timeout=30)
    j = r.json()
    tok = j.get('AccessToken')
    if not tok:
        raise RuntimeError('LegitDataWay auth failed: ' + str(j.get('status') or j)[:200])
    return tok, j

def legitdataway_post(path, payload):
    tok, _ = legitdataway_token()
    r = requests.post(LEGITDATAWAY_BASE + '/api' + path, json=payload,
                      headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                      timeout=45)
    return _provider_json(r, 'LegitDataWay')

def legitdataway_get(path, params=None):
    tok, _ = legitdataway_token()
    r = requests.get(LEGITDATAWAY_BASE + '/api' + path, params=params,
                     headers={'Authorization': f'Token {tok}', 'Content-Type': 'application/json'},
                     timeout=30)
    return _provider_json(r, 'LegitDataWay')

def lw_phone(phone):
    """LegitDataWay's live API demands an 11-digit number, same as Bilal."""
    return re.sub(r'\D', '', phone or '')

def lw_sell_price(plan_id, cost):
    """Sell price for a LegitDataWay plan: admin-set sell price, else cost + margin."""
    rows = q("SELECT sell FROM legitdataway_plans WHERE plan_id=?", (plan_id,))
    if rows and rows[0]['sell'] is not None:
        return float(rows[0]['sell'])
    margin = float((q("SELECT v FROM settings WHERE k='margin'") or [{'v': '0'}])[0]['v'])
    return round(float(cost) * (1 + margin / 100), 2)

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

def _debit_wallet(user_id, amount, desc, tx_type, service, cost_price=None):
    """Insert a pending 'out' transaction and debit the wallet atomically.
    Returns (ref, None) on success, (None, error_info) on insufficient funds.
    Shared by the VTpass and Fatizara buy paths so both refund identically.
    cost_price is the provider cost known at buy time (data/cable plan
    cost); airtime/power pass None so the admin never treats a guess as
    an exact cost. When the column is missing, the cost is skipped and
    the buy still succeeds exactly as before."""
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
            if COST_COL_READY and cost_price is not None:
                cur.execute("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
                             status,reference,created,cost_price) VALUES(%s,%s,%s,%s,%s,'out','pending',%s,%s,%s)""",
                            (user_id, tx_type, service, desc, amount, ref, ts, float(cost_price)))
            else:
                cur.execute("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
                             status,reference,created) VALUES(%s,%s,%s,%s,%s,'out','pending',%s,%s)""",
                            (user_id, tx_type, service, desc, amount, ref, ts))
            cur.execute("UPDATE users SET wallet=wallet-%s WHERE id=%s", (amount, user_id))
            con.commit(); cur.close()
        else:
            if COST_COL_READY and cost_price is not None:
                con.execute("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
                             status,reference,created,cost_price) VALUES(?,?,?,?,?,'out','pending',?,?,?)""",
                            (user_id, tx_type, service, desc, amount, ref, ts, float(cost_price)))
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

def debit_and_buy(user_id, amount, desc, tx_type, service, vt_payload, cost_price=None):
    """Debit wallet, call VTpass, refund on failure. Returns (ok, info)."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service, cost_price)
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

def debit_and_buy_fatizara(user_id, amount, desc, tx_type, service, endpoint, fz_payload, cost_price=None):
    """Debit wallet, call Fatizara, refund on failure. Same guarantees as
    debit_and_buy: a lost/failed provider reply can never double-charge.
    Fatizara has no sandbox, so this path only runs once the provider switch
    is on AND the Fatizara wallet is funded — every call is live."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service, cost_price)
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

def debit_and_buy_bilal(user_id, amount, desc, tx_type, service, endpoint, bl_payload, cost_price=None):
    """Debit wallet, call Bilal, refund on failure. Same guarantees as
    debit_and_buy_fatizara, with one Bilal-specific rule: a 'pending' status
    is neither success nor failure — the debit stays and the transaction
    stays pending (see bilal-requery / transaction-resolve), because Bilal
    may still deliver it. Refunding a pending buy could double-spend if
    Bilal later delivers."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service, cost_price)
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


def debit_and_buy_legitdataway(user_id, amount, desc, tx_type, service, endpoint, lw_payload, cost_price=None):
    """Debit wallet, call LegitDataWay, refund on clear failure. Same guarantees
    as debit_and_buy_bilal, with one LegitDataWay-specific rule: a LOST REPLY
    (transport exception, no provider response at all) is NOT a failure — the
    debit stays and the transaction stays pending, because LegitDataWay may
    still deliver and its webhook (or the admin transaction-resolve endpoint)
    settles it. Refunding a lost reply could double-spend if LegitDataWay
    later delivers. Only an explicit provider 'fail' status refunds."""
    ref, err = _debit_wallet(user_id, amount, desc, tx_type, service, cost_price)
    if err:
        return False, err
    rid = request_id()
    lw_payload = dict(lw_payload); lw_payload['request-id'] = rid
    try:
        resp = legitdataway_post(endpoint, lw_payload)
        replied = True
    except Exception as e:
        resp = {'status': 'failed', 'message': str(e)}
        replied = False
    status = (resp.get('status') or '').lower()
    provider_ref = resp.get('request-id') or resp.get('request_id') or rid
    token = resp.get('token') or ''
    if not replied or status == 'pending':
        # No reply, or provider says pending: keep the debit, keep pending.
        run("UPDATE transactions SET provider_ref=?, meta=? WHERE reference=?",
            (provider_ref, json.dumps(resp)[:4000], ref))
        msg = ('No reply from LegitDataWay yet. It stays pending until confirmed — check back shortly.'
               if not replied else
               'Purchase is processing at LegitDataWay. It stays pending until confirmed — check back shortly.')
        return False, {'pending': True, 'reference': ref, 'error': msg}
    ok = status in ('success', 'successful')
    err_text = resp.get('message') or resp.get('error') or 'Purchase failed.'
    ok, info = _settle_wallet(user_id, ref, amount, ok, provider_ref, token, resp, err_text)
    if ok and tx_type == 'power':
        # Electricity bills deduct amount + charges from the provider wallet
        # (docs example: ₦300 bill, charges ₦21, balance drop ₦321). Record the
        # true cost so profit stays exact instead of reading ₦0.
        try:
            charges = float(resp.get('charges') or 0)
        except Exception:
            charges = 0
        if charges:
            run("UPDATE transactions SET cost_price=? WHERE reference=?", (amount + charges, ref))
    return ok, info

# ---------------- public ----------------
@app.get('/api/config')
def config():
    return jsonify({'ok': True, 'paystack_public_key': S('PAYSTACK_PUBLIC_KEY'),
                    'sandbox': vt_sandbox(), 'live': True,
                    'provider': provider(), 'fatizara_ready': fatizara_configured(),
                    'bilal_ready': bilal_configured(),
                    'legitdataway_ready': legitdataway_configured(),
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
    ref_code = (d.get('ref') or '').strip()
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
    # Referral: the code is the referrer's username. Invalid codes and
    # self-referrals are ignored — signup never fails over a referral.
    referrer_id = None
    if REF_COL_READY and ref_code and ref_code.lower() != username.lower():
        rr = q("SELECT id FROM users WHERE LOWER(username)=LOWER(?)", (ref_code,))
        referrer_id = rr[0]['id'] if rr else None
    if REF_COL_READY:
        run("""INSERT INTO users(name,username,phone,email,pass_hash,tx_pin_hash,email_verified,wallet,created,referred_by)
               VALUES(?,?,?,?,?,?,0,0,?,?)""",
            (name, username, phone, email, generate_password_hash(pw), generate_password_hash(pin), now_iso(), referrer_id))
    else:
        run("""INSERT INTO users(name,username,phone,email,pass_hash,tx_pin_hash,email_verified,wallet,created)
               VALUES(?,?,?,?,?,?,0,0,?)""",
            (name, username, phone, email, generate_password_hash(pw), generate_password_hash(pin), now_iso()))
    uid = q("SELECT id FROM users WHERE phone=?", (phone,))[0]['id']
    user = get_user(uid)
    email_sent = send_verify_code(user)
    # no token yet — account opens only after the email code is verified
    return jsonify({'ok': True, 'verify_required': True, 'user_id': uid,
                    'email': email, 'email_sent': email_sent})

def credit_referral_milestones(referrer_id):
    """Credit ₦500 per 5 verified referrals. Idempotent: one reward row
    per (referrer, milestone), so a recount or retry never double-pays.
    Counts only verified referrals, so a signup counts once its email
    code is confirmed — no money needs to move from the referred person."""
    if not referrer_id or not REF_COL_READY:
        return
    try:
        rows = q("SELECT COUNT(*) AS n FROM users WHERE referred_by=? AND email_verified=1", (referrer_id,))
        count = (rows[0]['n'] if rows else 0) or 0
        for m in range(5, count + 1, 5):
            if q("SELECT id FROM referral_rewards WHERE referrer_id=? AND milestone=?", (referrer_id, m)):
                continue
            ref = 'REF-' + uuid.uuid4().hex[:12]
            run("UPDATE users SET wallet=wallet+500 WHERE id=?", (referrer_id,))
            run("""INSERT INTO transactions(user_id,type,service,description,amount,direction,status,reference,created)
                   VALUES(?, 'referral', 'referral', ?, 500, 'in', 'successful', ?, ?)""",
                (referrer_id, 'Referral reward — %d referrals' % m, ref, now_iso()))
            try:
                run("INSERT INTO referral_rewards(referrer_id,milestone,amount,created) VALUES(?,?,500,?)",
                    (referrer_id, m, now_iso()))
            except Exception:
                # Lost a race for this milestone: undo the credit so it
                # stays exactly one ₦500 per milestone.
                run("UPDATE users SET wallet=wallet-500 WHERE id=?", (referrer_id,))
                run("DELETE FROM transactions WHERE reference=?", (ref,))
    except Exception:
        pass

@app.get('/api/referral')
@auth
def referral_status():
    me = get_user(g.user_id)
    if not me:
        return jsonify({'ok': False, 'error': 'Account not found.'}), 404
    count = 0
    if REF_COL_READY:
        rows = q("SELECT COUNT(*) AS n FROM users WHERE referred_by=? AND email_verified=1", (g.user_id,))
        count = (rows[0]['n'] if rows else 0) or 0
    try:
        rewards = q("SELECT milestone, amount, created FROM referral_rewards WHERE referrer_id=? ORDER BY milestone", (g.user_id,))
    except Exception:
        rewards = []
    nxt = ((count // 5) + 1) * 5
    return jsonify({'ok': True, 'code': me.get('username') or '', 'count': count,
                    'next_milestone': nxt, 'to_go': nxt - count, 'rewards': rewards})

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
    try:
        if REF_COL_READY:
            rr = q("SELECT referred_by FROM users WHERE id=?", (uid,))
            if rr and rr[0].get('referred_by'):
                credit_referral_milestones(rr[0]['referred_by'])
    except Exception:
        pass
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
    # Login alert: email the user if this sign-in comes from a new IP address.
    # Runs on password success, before any second-factor step, so the owner
    # is alerted even if an attacker knows the password but not the code.
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
    # Optional second factor: password passed, but no session yet. The code
    # goes to the account's own email; the session token is only issued
    # after /api/verify-login-code succeeds.
    if rows[0].get('login_2fa'):
        code = new_email_code(rows[0]['id'], 'login')
        sent = send_email(rows[0]['email'], 'Your Panther Data sign-in code',
            f"Hello {rows[0].get('name') or 'there'},\n\nYour Panther Data sign-in code is:\n\n"
            f"{code}\n\nEnter this code to finish signing in. It expires in 15 minutes.\n\n"
            f"If you did not try to sign in, change your password immediately.\n\n— Panther Data")
        return jsonify({'ok': True, 'login_2fa_required': True, 'user_id': rows[0]['id'],
                        'email_sent': bool(sent)})
    tok = new_session_token(rows[0]['id'])
    return jsonify({'ok': True, 'token': tok, 'user': get_user(rows[0]['id'])})

@app.post('/api/verify-login-code')
@limiter.limit('10 per minute')
def verify_login_code():
    """Finish a sign-in for an account with login codes turned on."""
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    code = str(d.get('code') or '').strip()
    user = get_user(uid)
    if not user:
        return jsonify({'ok': False, 'error': 'Account not found. Sign in again.'}), 404
    rows = q("SELECT * FROM email_codes WHERE user_id=? AND purpose='login'", (uid,))
    chash = hashlib.sha256(code.encode()).hexdigest()
    if not rows or rows[0]['code_hash'] != chash:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if rows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Sign in again for a new one.'}), 400
    run("DELETE FROM email_codes WHERE user_id=? AND purpose='login'", (uid,))
    tok = new_session_token(uid)
    return jsonify({'ok': True, 'token': tok, 'user': get_user(uid)})

@app.post('/api/resend-login-code')
@limiter.limit('3 per minute')
def resend_login_code():
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    user = get_user(uid)
    if not user:
        return jsonify({'ok': False, 'error': 'Account not found. Sign in again.'}), 404
    if not user.get('login_2fa'):
        return jsonify({'ok': False, 'error': 'Sign-in codes are not turned on for this account.'}), 400
    code = new_email_code(uid, 'login')
    sent = send_email(user['email'], 'Your Panther Data sign-in code',
        f"Hello {user['name']},\n\nYour Panther Data sign-in code is:\n\n"
        f"{code}\n\nEnter this code to finish signing in. It expires in 15 minutes.\n\n— Panther Data")
    return jsonify({'ok': True, 'email_sent': bool(sent)})

@app.post('/api/login-2fa')
@limiter.limit('10 per minute')
@auth
def login_2fa():
    """Customer's own switch for optional sign-in codes. Off by default."""
    d = request.get_json(force=True)
    enabled = bool(d.get('enabled'))
    try:
        run("UPDATE users SET login_2fa=? WHERE id=?", (1 if enabled else 0, g.user_id))
    except Exception:
        return jsonify({'ok': False, 'error': 'Please try again in a minute.'}), 503
    user = get_user(g.user_id)
    try:
        sent = send_email(user['email'],
            'Panther Data sign-in codes ' + ('turned on' if enabled else 'turned off'),
            f"Hello {user['name']},\n\nSign-in codes by email have been "
            f"{'turned on' if enabled else 'turned off'} for your Panther Data account.\n\n"
            f"If this was not you, sign in and turn them back "
            f"{'off' if enabled else 'on'}, then change your password.\n\n— Panther Data")
    except Exception:
        sent = False
    return jsonify({'ok': True, 'login_2fa': enabled, 'email_sent': bool(sent)})

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
    if funding_provider() == 'xpouch':
        return fund_account_xpouch()
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

def credit_wallet_atomic(uid, amount, tx_ref, description, service='monnify'):
    """Insert a funding transaction and credit the wallet in ONE database
    transaction.

    Returns 'ok' (credited), 'duplicate' (transactionReference already seen -
    not an error), or 'error' (anything else - the credit did NOT happen).
    Callers must not treat 'error' as 'already credited'.
    """
    ins = """INSERT INTO transactions(user_id,type,service,description,amount,direction,
             status,reference,provider_ref,created)
             VALUES(?, 'fund',?,?,?,'in','successful',?,?,?)"""
    params = (uid, service, description, amount, tx_ref, tx_ref, now_iso())
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
        # Not a permanent reserved account — try a one-time invoice payment.
        # Resolve ONLY by exact match of a server-generated invoice reference
        # (never by parsing a user ID out of any field).
        inv_ref = None
        inv = None
        for cand in [str(ev.get('invoiceReference') or '').strip(),
                     str(prod.get('invoiceReference') or '').strip(),
                     str(prod.get('reference') or '').strip(),
                     str(ev.get('accountReference') or '').strip(),
                     str(prod.get('accountReference') or '').strip()]:
            if not cand:
                continue
            irows = q("SELECT user_id, amount, status FROM invoice_fundings WHERE reference=?",
                      (cand,))
            if irows:
                inv_ref = cand
                inv = irows[0]
                break
        if inv_ref and inv.get('status') != 'PAID':
            tx_ref = str(ev.get('transactionReference') or '') or ('INV-' + inv_ref)
            try:
                amount = float(ev.get('amountPaid') or 0)
            except Exception:
                amount = 0
            if amount <= 0:
                amount = float(inv.get('amount') or 0)
            if amount > 0:
                res = credit_wallet_atomic(inv['user_id'], amount, tx_ref,
                                           'Wallet funding via one-time account')
                if res in ('ok', 'duplicate'):
                    run("UPDATE invoice_fundings SET status='PAID', paid_at=? WHERE reference=?",
                        (now_iso(), inv_ref))
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
    if funding_provider() == 'xpouch':
        return fund_sync_xpouch()
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

# ---------------- wallet funding (Xpouch virtual accounts) ----------------
# Xpouch replaces Monnify as funding provider when FUNDING_PROVIDER='xpouch'.
# Unlike Monnify permanent accounts, Xpouch accounts need NO customer BVN or
# NIN: creation takes only customer_reference + customer_name, and every
# account is issued on 9PSB. Payments land in the merchant wallet and are
# reported via the payment_received webhook (HMAC-SHA256 over the canonical
# data object, keyed with the merchant API KEY). Monnify code stays intact
# so flipping FUNDING_PROVIDER back restores Monnify funding in one tap.
# RESPONSE SHAPES are verified against the sandbox: Xpouch field names are
# parsed tolerantly (snake_case or camelCase) because the docs' Stoplight
# pages do not render as plain text; sandbox tests pin the real shapes.

def _xpouch_pick(d, *names):
    for n in names:
        v = d.get(n)
        if v not in (None, ''):
            return v
    return None

def _xpouch_account_fields(data):
    """Extract (account_number, bank_name, account_name) from a virtual
    account object, tolerating the field-name variants Xpouch may use."""
    data = data or {}
    acct = _xpouch_pick(data, 'account_number', 'accountNumber', 'account_no', 'number')
    bank = _xpouch_pick(data, 'bank_name', 'bankName', 'bank') or '9PSB'
    name = _xpouch_pick(data, 'account_name', 'accountName', 'name')
    return acct, bank, name

def _xpouch_user_row(uid):
    rows = q("SELECT id,name,email,xpouch_ref,xpouch_acct,xpouch_bank,xpouch_acct_name"
             " FROM users WHERE id=?", (uid,))
    return dict(rows[0]) if rows else None

@app.get('/api/xpouch-status')
@auth
def xpouch_status():
    return jsonify({'ok': True, 'configured': xpouch_configured(),
                    'sandbox': xpouch_sandbox(), 'provider': funding_provider()})

def fund_account_xpouch():
    """Return the user's personal Xpouch virtual account, creating it on
    first use. No BVN or NIN is ever asked for."""
    if not xpouch_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    row = _xpouch_user_row(g.user_id)
    if not row:
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    if row.get('xpouch_acct'):
        return jsonify({'ok': True, 'provider': 'xpouch',
                        'account_number': row.get('xpouch_acct'),
                        'bank_name': row.get('xpouch_bank') or '9PSB',
                        'account_name': row.get('xpouch_acct_name') or row.get('name')})
    ref = (row.get('xpouch_ref') or '').strip()
    if not ref:
        ref = 'panther-' + uuid.uuid4().hex[:20]
    try:
        r = requests.post(f'{xpouch_base()}/virtual-accounts/create',
                          headers=xpouch_headers(),
                          json={'customer_reference': ref,
                                'customer_name': (row.get('name') or 'Panther Data Customer')[:100]},
                          timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Xpouch. Try again.'}), 502
    if not r.get('success'):
        return jsonify({'ok': False,
                        'error': 'Xpouch error: ' + str((r.get('errors') or r.get('message')) or 'try again')}), 502
    acct, bank, name = _xpouch_account_fields(r.get('data') or {})
    if not acct:
        return jsonify({'ok': False, 'error': 'Xpouch error: no account number returned.'}), 502
    run("""UPDATE users SET xpouch_ref=?, xpouch_acct=?, xpouch_bank=?,
           xpouch_acct_name=? WHERE id=?""",
        (ref, acct, bank, name or row.get('name'), g.user_id))
    return jsonify({'ok': True, 'provider': 'xpouch',
                    'account_number': acct, 'bank_name': bank,
                    'account_name': name or row.get('name')})

def _xpouch_canon_variants(data):
    """All deterministic canonical writings of an Xpouch data object that
    a sender could plausibly sign. Xpouch's docs say 'keys sorted,
    JSON-encoded with unescaped slashes/unicode' but do NOT say whether
    sorting is recursive: the live payload's nested payer object arrives
    in insertion order (account_number, account_name, bank_name — NOT
    alphabetical), so a signer that sorts only the top level writes a
    different string than a fully recursive sort. The dashboard's Test
    Signature tool also shows a flat 8-field sample. Accepting several
    variants does NOT weaken the check: every variant still requires the
    exact merchant API key and the exact data — a forger knowing none of
    them can satisfy no variant."""
    variants = []
    for seps in ((',', ':'), (', ', ': ')):
        # Fully recursive sort (original implementation).
        variants.append(json.dumps(data, sort_keys=True, ensure_ascii=False,
                                   separators=seps))
        # Top level sorted only, nested objects in arrival order.
        top_sorted = {k: data[k] for k in sorted(data.keys())}
        variants.append(json.dumps(top_sorted, ensure_ascii=False,
                                   separators=seps))
        # Arrival order entirely.
        variants.append(json.dumps(data, ensure_ascii=False, separators=seps))
    payer = data.get('payer') or {}
    flat = {
        'account_number': data.get('account_number'),
        'amount': data.get('amount'),
        'currency': data.get('currency'),
        'customer_reference': data.get('customer_reference'),
        'payer_account_name': payer.get('account_name') or payer.get('accountName'),
        'payer_account_number': payer.get('account_number') or payer.get('accountNumber'),
        'payer_bank_name': payer.get('bank_name') or payer.get('bankName'),
        'transaction_reference': data.get('transaction_reference'),
    }
    flat = {k: v for k, v in flat.items() if v is not None}
    for seps in ((',', ':'), (', ', ': ')):
        variants.append(json.dumps(flat, sort_keys=True, ensure_ascii=False,
                                   separators=seps))
    return variants

def _xpouch_sig_ok(sig, data):
    """Verify an Xpouch webhook signature: HMAC-SHA256 hex of the data
    object, keyed with the merchant API KEY. Several canonical writings
    are accepted (see _xpouch_canon_variants) because the sender's exact
    sorting depth is undocumented; all of them still require the key."""
    sig = (sig or '').strip().lower()
    key = (S('XPOUCH_API_KEY') or '').strip()
    if not sig or not key or data is None:
        return False
    for canon in _xpouch_canon_variants(data):
        h = hmac.new(key.encode('utf-8'), canon.encode('utf-8'),
                     hashlib.sha256).hexdigest().lower()
        if hmac.compare_digest(h, sig):
            return True
    return False

def _xpouch_credit_amount(d):
    """What actually lands in the merchant wallet. Xpouch deducts its 1%
    fee before the wallet: a ₦100 transfer arrives as amount=100, fee=1,
    settled_amount=99, net_amount=99. Crediting `amount` would over-credit
    by the fee on every funding, so prefer net, then settled, then amount."""
    for k in ('net_amount', 'settled_amount', 'amount'):
        try:
            v = float(d.get(k) or 0)
        except Exception:
            v = 0
        if v > 0:
            return v
    return 0

@app.post('/api/xpouch-webhook')
@limiter.exempt
def xpouch_webhook():
    """Xpouch payment notification. Verifies the HMAC-SHA256 signature,
    credits the wallet exactly once. The customer is resolved ONLY by exact
    match of the stored xpouch_ref or xpouch_acct — never by parsing a
    user ID out of any field. Retries are safe: credit_wallet_atomic
    dedupes on the event reference."""
    d = request.get_json(force=True, silent=True) or {}
    data = d.get('data') or {}
    sig = d.get('signature') or ''
    if not data or not sig or not S('XPOUCH_API_KEY'):
        return jsonify({'ok': False}), 400
    if not _xpouch_sig_ok(sig, data):
        return jsonify({'ok': False}), 401
    ev = (d.get('event') or d.get('event_type') or data.get('event') or '').strip()
    if ev != 'payment_received':
        return jsonify({'ok': True})
    uid = None
    cust_ref = str(data.get('customer_reference') or '').strip()
    if cust_ref:
        rows = q("SELECT id FROM users WHERE xpouch_ref=?", (cust_ref,))
        if rows:
            uid = rows[0]['id']
    if not uid:
        acct_no = str(data.get('account_number') or '').strip()
        if acct_no:
            rows = q("SELECT id FROM users WHERE xpouch_acct=?", (acct_no,))
            if rows:
                uid = rows[0]['id']
    if not uid:
        return jsonify({'ok': True})
    tx_ref = (str(data.get('event_reference') or '').strip()
              or str(data.get('transaction_reference') or '').strip()
              or str(data.get('reference') or '').strip())
    amount = _xpouch_credit_amount(data)
    if not tx_ref or amount <= 0:
        return jsonify({'ok': True})
    status = credit_wallet_atomic(uid, amount, tx_ref,
                                  'Wallet funding via bank transfer', service='xpouch')
    return jsonify({'ok': True, 'status': status})

def fund_sync_xpouch():
    """Pull the user's Xpouch virtual-account transactions (server-to-server)
    and credit anything new. Works even when the Xpouch webhook can't reach us."""
    if not xpouch_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    row = _xpouch_user_row(g.user_id)
    if not row or not row.get('xpouch_acct'):
        return jsonify({'ok': False, 'error': 'No funding account yet.'}), 400
    acct_no = row['xpouch_acct']
    try:
        lst = requests.get(f'{xpouch_base()}/virtual-accounts',
                           headers=xpouch_headers(), timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Xpouch. Try again.'}), 502
    items = []
    if lst.get('success'):
        entries = lst.get('data') or []
        if isinstance(entries, dict):
            entries = (entries.get('accounts') or entries.get('data')
                       or entries.get('virtual_accounts')
                       or entries.get('items') or entries.get('results') or [])
        acct_id = None
        for e in entries:
            if not isinstance(e, dict):
                continue
            if (str(e.get('customer_reference') or e.get('customerReference') or '') == (row.get('xpouch_ref') or '')
                    or str(_xpouch_pick(e, 'account_number', 'accountNumber') or '') == acct_no):
                acct_id = _xpouch_pick(e, 'id', 'account_id', 'accountId',
                                       'uuid', 'reference', 'virtual_account_id')
                break
        if acct_id:
            try:
                det = requests.get(f'{xpouch_base()}/virtual-accounts/{acct_id}',
                                   headers=xpouch_headers(), timeout=30).json()
            except Exception:
                return jsonify({'ok': False, 'error': 'Could not reach Xpouch. Try again.'}), 502
            ddata = det.get('data') if isinstance(det, dict) else None
            if isinstance(ddata, dict):
                items = (ddata.get('transactions') or ddata.get('items')
                         or ddata.get('history') or ddata.get('data') or [])
                if isinstance(items, dict):
                    items = items.get('transactions') or []
            elif isinstance(ddata, list):
                items = ddata
            elif isinstance(det, dict):
                items = det.get('transactions') or []
    credited = 0.0
    count = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        if str(it.get('status') or '').lower() not in ('success', 'successful', 'paid', 'completed', 'complete'):
            continue
        tx_ref = (str(it.get('event_reference') or '').strip()
                  or str(it.get('transaction_reference') or '').strip()
                  or str(it.get('reference') or '').strip())
        amount = _xpouch_credit_amount(it)
        if not tx_ref or amount <= 0:
            continue
        if credit_wallet_atomic(g.user_id, amount, tx_ref,
                                'Wallet funding via bank transfer', service='xpouch') == 'ok':
            credited += amount
            count += 1
    bal = get_user(g.user_id).get('wallet', 0)
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

# ---------------- one-time invoice funding (no BVN/NIN) ----------------
# Monnify dynamic invoices: each invoice gets its own virtual account that
# needs NO BVN or NIN (unlike permanent reserved accounts, which CBN rules
# tie to a BVN/NIN). The account is for this payment only and expires with
# the invoice. Crediting is idempotent: one credit per invoice, via the
# transactions.reference UNIQUE key, whether the money is confirmed by the
# webhook or by the customer's check-now tap. A row is only marked PAID
# after a successful credit, so a failed credit can always be retried.

def _invoice_expiry():
    # Monnify wants 'yyyy-MM-dd HH:mm:ss'; a day is plenty for one transfer.
    return (datetime.now(timezone.utc) + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')

@app.post('/api/fund/invoice')
@limiter.limit('20 per minute')
@auth
def fund_invoice():
    """Create a one-time Monnify invoice account for this user. No BVN/NIN."""
    if funding_provider() == 'xpouch':
        # Xpouch permanent accounts need no BVN, so one-time Monnify invoices
        # are never created while Xpouch is the funding provider. Pending
        # Monnify invoices from before the flip can still be checked.
        return jsonify({'ok': False,
                        'error': 'One-time accounts are not used with Xpouch — your permanent account needs no BVN.'}), 400
    if not monnify_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    d = request.get_json(force=True, silent=True) or {}
    try:
        amount = int(d.get('amount') or 0)
    except Exception:
        amount = 0
    if amount < 100:
        return jsonify({'ok': False, 'error': 'Minimum funding is ₦100.'}), 400
    user = get_user(g.user_id)
    ref = 'PDI' + uuid.uuid4().hex[:20]
    expiry = _invoice_expiry()
    try:
        tok = monnify_token()
        r = requests.post(
            f'{monnify_base()}/api/v1/invoice/create',
            headers={'Authorization': f'Bearer {tok}', 'Content-Type': 'application/json'},
            json={'amount': amount,
                  'invoiceReference': ref,
                  'description': 'Panther Data wallet funding',
                  'currencyCode': 'NGN',
                  'contractCode': S('MONNIFY_CONTRACT_CODE'),
                  'customerEmail': user.get('email'),
                  'customerName': user.get('name'),
                  'expiryDate': expiry,
                  'paymentMethods': ['ACCOUNT_TRANSFER'],
                  'apiKey': S('MONNIFY_API_KEY')},
            timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Monnify. Try again.'}), 502
    body = r.get('responseBody') or {}
    if not r.get('requestSuccessful') or not body.get('accountNumber'):
        return jsonify({'ok': False,
                        'error': 'Monnify error: ' + str(r.get('responseMessage') or 'try again')}), 502
    run("""INSERT INTO invoice_fundings(reference,user_id,amount,account_number,
             bank_name,bank_code,account_name,checkout_url,expiry,status,created)
             VALUES(?,?,?,?,?,?,?,?,?,'PENDING',?)""",
        (ref, g.user_id, amount, body.get('accountNumber'), body.get('bankName'),
         body.get('bankCode'), body.get('accountName'), body.get('checkoutUrl'),
         body.get('expiryDate') or expiry, now_iso()))
    return jsonify({'ok': True, 'reference': ref, 'amount': amount,
                    'account_number': body.get('accountNumber'),
                    'bank_name': body.get('bankName'),
                    'bank_code': body.get('bankCode'),
                    'account_name': body.get('accountName'),
                    'expiry': body.get('expiryDate') or expiry})

@app.post('/api/fund/invoice-check')
@limiter.limit('20 per minute')
@auth
def fund_invoice_check():
    """Check whether a one-time invoice was paid; credit once if so."""
    d = request.get_json(force=True, silent=True) or {}
    ref = (d.get('reference') or '').strip()
    rows = q("SELECT * FROM invoice_fundings WHERE reference=? AND user_id=?",
             (ref, g.user_id)) if ref else []
    if not rows:
        return jsonify({'ok': False, 'error': 'Invoice not found.'}), 404
    inv = rows[0]
    if inv.get('status') == 'PAID':
        return jsonify({'ok': True, 'paid': True,
                        'balance': get_user(g.user_id).get('wallet', 0)})
    if not monnify_configured():
        return jsonify({'ok': False, 'error': 'Bank funding is not set up yet. Try again later.'}), 503
    try:
        tok = monnify_token()
        r = requests.get(
            f'{monnify_base()}/api/v1/invoice/{ref}/details',
            headers={'Authorization': f'Bearer {tok}'}, timeout=30).json()
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not reach Monnify. Try again.'}), 502
    body = r.get('responseBody') or {}
    status = (body.get('invoiceStatus') or '').upper()
    if status == 'PAID':
        res = credit_wallet_atomic(g.user_id, inv['amount'], 'INV-' + ref,
                                   'Wallet funding via one-time account')
        if res == 'error':
            return jsonify({'ok': False,
                            'error': 'Could not credit wallet. Tap check again.'}), 502
        run("UPDATE invoice_fundings SET status='PAID', paid_at=? WHERE reference=?",
            (now_iso(), ref))
        return jsonify({'ok': True, 'paid': True, 'credited': res == 'ok',
                        'balance': get_user(g.user_id).get('wallet', 0)})
    if status == 'EXPIRED':
        run("UPDATE invoice_fundings SET status='EXPIRED' WHERE reference=?", (ref,))
        return jsonify({'ok': True, 'paid': False, 'expired': True})
    if not r.get('requestSuccessful'):
        return jsonify({'ok': False,
                        'error': 'Monnify error: ' + str(r.get('responseMessage') or 'try again')}), 502
    return jsonify({'ok': True, 'paid': False})

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
    if provider() == 'legitdataway':
        if not legitdataway_configured():
            return jsonify({'ok': False, 'error': 'LegitDataWay is not set up yet.'}), 503
        ok, info = debit_and_buy_legitdataway(
            g.user_id, amount, f'{net.upper()} airtime ₦{amount:,} → {phone}',
            'airtime', net, '/topup',
            {'network': LEGITDATAWAY_NETWORKS[net], 'phone': lw_phone(phone),
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
    if provider() == 'legitdataway':
        # Same shape again (variation_code = LegitDataWay plan id), so the
        # existing frontend works unchanged after the provider switch.
        rows = q("SELECT plan_id, name, cost FROM legitdataway_plans "
                 "WHERE service='data' AND network=? ORDER BY cost", (net,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': lw_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
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
             'data_plan': int(code) if code.isdigit() else code, 'bypass': False},
            cost_price=cost)
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
             'data_plan': int(code) if code.isdigit() else code, 'bypass': False},
            cost_price=cost)
        return jsonify({'ok': ok, **info})
    if provider() == 'legitdataway':
        if not legitdataway_configured():
            return jsonify({'ok': False, 'error': 'LegitDataWay is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM legitdataway_plans "
                 "WHERE plan_id=? AND service='data' AND network=?", (code, net))
        if not rows:
            return jsonify({'ok': False, 'error': 'This plan is no longer available. Refresh plans.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = lw_sell_price(code, cost)
        ok, info = debit_and_buy_legitdataway(
            g.user_id, price, f"{p['name']} → {phone}", 'data', net, '/data',
            {'network': LEGITDATAWAY_NETWORKS.get(net, 1), 'phone': phone,
             'data_plan': int(code) if code.isdigit() else code, 'bypass': False},
            cost_price=cost)
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
                              'variation_code': code, 'amount': cost, 'phone': phone},
                             cost_price=cost)
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
    if provider() == 'legitdataway':
        rows = q("SELECT plan_id, name, cost FROM legitdataway_plans "
                 "WHERE service='cable' AND network=? ORDER BY cost", (prov,))
        plans = [{'variation_code': r['plan_id'], 'name': r['name'],
                  'cost': float(r['cost'] or 0),
                  'price': lw_sell_price(r['plan_id'], float(r['cost'] or 0))} for r in rows]
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
    if provider() == 'legitdataway':
        if not legitdataway_configured():
            return jsonify({'ok': False, 'error': 'LegitDataWay is not set up yet.'}), 503
        try:
            if service_id in CABLE_SVC and service_id != 'showmax':
                resp = legitdataway_get('/cable/cable-validation',
                                        {'iuc': billers, 'cable': LEGITDATAWAY_CABLES[service_id]})
                if (resp.get('status') or '').lower() in ('success', 'successful') and resp.get('name'):
                    return jsonify({'ok': True, 'customer': resp.get('name'), 'raw': resp})
                return jsonify({'ok': False, 'error': 'Could not verify this number. Check and try again.'}), 400
            rows = q("SELECT legitdataway_id FROM legitdataway_discos WHERE disco_key=?", (service_id,))
            if rows:
                lw_disco = rows[0]['legitdataway_id']
                resp = legitdataway_get('/bill/bill-validation',
                                        {'meter_number': billers,
                                         'disco': int(lw_disco) if str(lw_disco).isdigit() else lw_disco,
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
             'cable_plan': int(raw_plan) if raw_plan.isdigit() else raw_plan, 'bypass': False},
            cost_price=cost)
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
             'iuc': billers, 'bypass': 0},
            cost_price=cost)
        return jsonify({'ok': ok, **info})
    if provider() == 'legitdataway':
        if not legitdataway_configured():
            return jsonify({'ok': False, 'error': 'LegitDataWay is not set up yet.'}), 503
        rows = q("SELECT plan_id, name, cost FROM legitdataway_plans "
                 "WHERE plan_id=? AND service='cable' AND network=?", (code, prov))
        if not rows:
            return jsonify({'ok': False, 'error': 'This package is no longer available.'}), 400
        p = rows[0]
        cost = float(p['cost'] or 0)
        price = lw_sell_price(code, cost)
        # Seeded cable ids carry a 'c:' prefix (same collision guard as
        # Bilal); LegitDataWay itself wants the plain numeric plan id.
        # NOTE: whether /api/cable accepts the numeric id or a slug is
        # unproven until a live test buy — see switch notes.
        raw_plan = code[2:] if code.startswith('c:') else code
        ok, info = debit_and_buy_legitdataway(
            g.user_id, price, f"{prov.upper()} {p['name']} → {billers}",
            'cable', prov, '/cable',
            {'cablename': prov,
             'cableplan': int(raw_plan) if raw_plan.isdigit() else raw_plan,
             'smart_card_number': billers},
            cost_price=cost)
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
                              'amount': cost, 'phone': phone or billers},
                             cost_price=cost)
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
    if provider() == 'legitdataway':
        rows = q("SELECT disco_key, label FROM legitdataway_discos ORDER BY label")
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
    if provider() == 'legitdataway':
        if not legitdataway_configured():
            return jsonify({'ok': False, 'error': 'LegitDataWay is not set up yet.'}), 503
        rows = q("SELECT legitdataway_id FROM legitdataway_discos WHERE disco_key=?", (svc,))
        if not rows:
            return jsonify({'ok': False, 'error': 'This disco is not mapped yet.'}), 400
        lw_disco = rows[0]['legitdataway_id']
        ok, info = debit_and_buy_legitdataway(
            g.user_id, amount, f'Electricity ₦{amount:,} ({vtype}) → {meter}',
            'power', svc, '/bill',
            {'disco': int(lw_disco) if str(lw_disco).isdigit() else lw_disco,
             'meter_type': vtype,
             'meter_number': meter, 'amount': amount, 'bypass': False})
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
@admin_session_auth
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
@admin_session_auth
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
@admin_session_auth
def fatizara_plans_admin():
    return jsonify({'ok': True, 'plans': q("SELECT * FROM fatizara_plans ORDER BY service, network, cost")})

@app.post('/api/admin/fatizara-plan')
@admin_session_auth
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
@admin_session_auth
def fatizara_discos_admin():
    return jsonify({'ok': True, 'discos': q("SELECT * FROM fatizara_discos ORDER BY label")})

@app.post('/api/admin/fatizara-disco')
@admin_session_auth
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
@admin_session_auth
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
@admin_session_auth
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
@admin_session_auth
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

@app.get('/api/admin/provider-balance')
@admin_session_auth
def provider_balance():
    """Wallet balance of the ACTIVE buying provider (Bilal, LegitDataWay
    or Fatizara). Staff may call it, like bilal-balance — unlike
    test-connection, which is main-admin-only and would log staff out."""
    prov = provider()
    try:
        if prov == 'bilal':
            if not bilal_configured():
                return jsonify({'ok': False, 'error': 'Bilal username / password missing.'}), 502
            _, auth_resp = bilal_token()
        elif prov == 'legitdataway':
            if not legitdataway_configured():
                return jsonify({'ok': False, 'error': 'LegitDataWay username / password missing.'}), 502
            _, auth_resp = legitdataway_token()
        elif prov == 'fatizara':
            if not fatizara_configured():
                return jsonify({'ok': False, 'error': 'Fatizara username / password missing.'}), 502
            _, auth_resp = fatizara_token()
        else:
            return jsonify({'ok': False, 'error': 'No wallet balance for provider ' + prov + '.'}), 502
        bal = auth_resp.get('balance')
        try: bal = float(str(bal).replace(',', ''))
        except (TypeError, ValueError): bal = None
        if bal is None:
            return jsonify({'ok': False, 'error': 'Could not read balance.'}), 502
        return jsonify({'ok': True, 'balance': bal, 'provider': prov})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Connection error: ' + str(e)[:120]}), 502

@app.get('/api/admin/bilal-plans')
@admin_session_auth
def bilal_plans_admin():
    return jsonify({'ok': True, 'plans': q("SELECT * FROM bilal_plans ORDER BY service, network, cost")})

@app.post('/api/admin/bilal-plan')
@admin_session_auth
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
    log_admin('price_save', f'Bilal {service}/{network} {name}: cost {cost}, sell {sell}')
    return jsonify({'ok': True})

@app.get('/api/admin/bilal-discos')
@admin_session_auth
def bilal_discos_admin():
    return jsonify({'ok': True, 'discos': q("SELECT * FROM bilal_discos ORDER BY label")})

@app.post('/api/admin/bilal-disco')
@admin_session_auth
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
@admin_session_auth
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


# ---------------- LegitDataWay admin ----------------
# NOTE: Yola=9, Benin=10 here — swapped vs Bilal. Do not "fix" to Bilal's order.
LEGITDATAWAY_DISCO_SEED = [
    ('ikeja-electric', 1, 'Ikeja Electric (IKEDC)'),
    ('eko-electric', 2, 'Eko Electric (EKEDC)'),
    ('kano-electric', 3, 'Kano Electric (KEDCO)'),
    ('portharcourt-electric', 4, 'PH Electric (PHEDC)'),
    ('jos-electric', 5, 'Jos Electric (JEDC)'),
    ('ibadan-electric', 6, 'Ibadan Electric (IBEDC)'),
    ('kaduna-electric', 7, 'Kaduna Electric (KAEDC)'),
    ('abuja-electric', 8, 'Abuja Electric (AEDC)'),
    ('yola-electric', 9, 'Yola Electric (YEDC)'),
    ('benin-electric', 10, 'Benin Electric (BEDC)'),
]
LW_DATA_SEED = [
    ('244', 'airtel', '250MB GIFTING 1 day', 50.0, 100.0),
    ('242', 'airtel', '75MB GIFTING 1 day', 74.0, 124.0),
    ('243', 'airtel', '110MB GIFTING 1 day', 98.0, 148.0),
    ('326', 'airtel', '1.2GB COOPERATE GIFTING 7days', 192.0, 242.0),
    ('247', 'airtel', '600MB GIFTING 2 days', 205.0, 255.0),
    ('327', 'airtel', '2GB COOPERATE GIFTING 7days', 288.0, 338.0),
    ('233', 'airtel', '1GB GIFTING 3 days', 290.0, 340.0),
    ('241', 'airtel', '1.5GB GIFTING 1 day', 405.0, 455.0),
    ('328', 'airtel', '3.2GB COOPERATE GIFTING 7days', 480.0, 530.0),
    ('329', 'airtel', '3.2GB COOPERATE GIFTING 30days', 480.0, 530.0),
    ('235', 'airtel', '500MB GIFTING 7 days', 490.0, 540.0),
    ('238', 'airtel', '1.5GB GIFTING 7 days', 490.0, 540.0),
    ('240', 'airtel', '1.5GB GIFTING 1 day', 505.0, 555.0),
    ('245', 'airtel', '2GB GIFTING 7 days', 570.0, 620.0),
    ('237', 'airtel', '3GB GIFTING 2 days', 735.0, 785.0),
    ('232', 'airtel', '1GB GIFTING 7 days', 780.0, 830.0),
    ('330', 'airtel', '6.5GB COOPERATE GIFTING 14days', 960.0, 1010.0),
    ('239', 'airtel', '1.5GB GIFTING 7 days', 980.0, 1030.0),
    ('234', 'airtel', '2GB GIFTING 30 days', 1425.0, 1475.0),
    ('250', 'airtel', '5GB GIFTING 7 days', 1470.0, 1520.0),
    ('236', 'airtel', '3GB GIFTING 30 days', 1960.0, 2010.0),
    ('248', 'airtel', '3GB GIFTING 30 days', 1960.0, 2010.0),
    ('296', 'airtel', '8GB GIFTING 30 days. ebony', 1960.0, 2010.0),
    ('249', 'airtel', '4GB GIFTING 30 days', 2450.0, 2500.0),
    ('331', 'airtel', '20GB COOPERATE GIFTING 30 days', 2880.0, 2930.0),
    ('251', 'airtel', '8GB GIFTING 30 days', 2970.0, 3020.0),
    ('231', 'airtel', '10GB GIFTING 30 days', 3000.0, 3050.0),
    ('252', 'airtel', '10GB GIFTING 30 days', 3920.0, 3970.0),
    ('253', 'airtel', '13GB GIFTING 30 days', 4900.0, 4950.0),
    ('254', 'airtel', '25GB GIFTING 30 days', 7840.0, 7890.0),
    ('255', 'airtel', '35GB GIFTING 30 days', 9800.0, 9850.0),
    ('297', 'airtel', '60GB GIFTING 1 year. Ebony plan', 9800.0, 9850.0),
    ('256', 'airtel', '60GB GIFTING 30 days', 14700.0, 14750.0),
    ('257', 'airtel', '100GB GIFTING 30 days', 19600.0, 19650.0),
    ('258', 'airtel', '300GB GIFTING 90 days', 49000.0, 49050.0),
    ('259', 'airtel', '350GB GIFTING 120 days', 58800.0, 58850.0),
    ('260', 'airtel', '685GB GIFTING 1 year', 98000.0, 98050.0),
    ('85', 'etisalat', '500MB COOPERATE GIFTING 30days', 250.0, 300.0),
    ('61', 'etisalat', '1.1GB SME 30 days', 400.0, 450.0),
    ('69', 'etisalat', '500MB GIFTING 30days', 450.0, 500.0),
    ('86', 'etisalat', '1GB COOPERATE GIFTING 30days', 500.0, 550.0),
    ('62', 'etisalat', '2GB SME 30 days', 800.0, 850.0),
    ('68', 'etisalat', '1.5GB GIFTING 30 days', 880.0, 930.0),
    ('87', 'etisalat', '2GB COOPERATE GIFTING 30days', 1000.0, 1050.0),
    ('88', 'etisalat', '3GB COOPERATE GIFTING 30days', 1500.0, 1550.0),
    ('89', 'etisalat', '4GB COOPERATE GIFTING 30days', 2000.0, 2050.0),
    ('90', 'etisalat', '5GB COOPERATE GIFTING 30days', 2500.0, 2550.0),
    ('91', 'etisalat', '10GB COOPERATE GIFTING 30days', 5000.0, 5050.0),
    ('298', 'glo', '45MB GIFTING 1 day', 45.0, 95.0),
    ('70', 'glo', '200MB COOPERATE GIFTING 30days', 90.0, 140.0),
    ('299', 'glo', '100MB GIFTING 1 day', 98.0, 148.0),
    ('300', 'glo', '200MB GIFTING 2 days', 196.0, 246.0),
    ('71', 'glo', '500MB COOPERATE GIFTING 30days', 200.0, 250.0),
    ('220', 'glo', '500MB SME 14 days', 205.0, 255.0),
    ('301', 'glo', '1.5GB GIFTING 1 day', 294.0, 344.0),
    ('222', 'glo', '1GB SME 3 days', 345.0, 395.0),
    ('221', 'glo', '1GB SME 14 days', 360.0, 410.0),
    ('223', 'glo', '1GB SME 7 days', 360.0, 410.0),
    ('72', 'glo', '1GB COOPERATE GIFTING 30 days', 410.0, 460.0),
    ('303', 'glo', '2.5GB GIFTING 2 days', 490.0, 540.0),
    ('304', 'glo', '1.5GB GIFTING 7 days', 490.0, 540.0),
    ('302', 'glo', '3GB GIFTING 2 days', 735.0, 785.0),
    ('73', 'glo', '2GB COOPERATE GIFTING 30days', 830.0, 880.0),
    ('305', 'glo', '2.6GB GIFTING 30 days', 980.0, 1030.0),
    ('224', 'glo', '3GB SME 3 days', 1030.0, 1080.0),
    ('225', 'glo', '3GB SME 7 days', 1071.0, 1121.0),
    ('226', 'glo', '3GB SME 14 days', 1071.0, 1121.0),
    ('74', 'glo', '3GB COOPERATE GIFTING 30 days', 1245.0, 1295.0),
    ('306', 'glo', '5GB GIFTING 30 days', 1470.0, 1520.0),
    ('227', 'glo', '5GB SME 3 days', 1700.0, 1750.0),
    ('228', 'glo', '5GB SME 7 days', 1780.0, 1830.0),
    ('229', 'glo', '5GB SME 14 days', 1780.0, 1830.0),
    ('307', 'glo', '6.15GB GIFTING 30 days', 1960.0, 2010.0),
    ('75', 'glo', '5GB COOPERATE GIFTING 30days', 2075.0, 2125.0),
    ('308', 'glo', '7.25GB GIFTING 30 days', 2450.0, 2500.0),
    ('309', 'glo', '10GB GIFTING 30 days', 2940.0, 2990.0),
    ('230', 'glo', '10GB SME 14 days', 3560.0, 3610.0),
    ('310', 'glo', '12.5GB GIFTING 30 days', 3920.0, 3970.0),
    ('76', 'glo', '10GB COOPERATE GIFTING 30days', 4150.0, 4200.0),
    ('311', 'glo', '16GB GIFTING 30 days', 4900.0, 4950.0),
    ('312', 'glo', '20GB GIFTING 30 days', 5880.0, 5930.0),
    ('314', 'glo', '28GB GIFTING 30 days', 7840.0, 7890.0),
    ('262', 'mtn', '75MB GIFTING 1 day', 73.5, 123.5),
    ('46', 'mtn', '1GB COOPERATE GIFTING 24 hours', 250.0, 300.0),
    ('322', 'mtn', '1GB COOPERATE GIFTING 30 days', 270.0, 320.0),
    ('36', 'mtn', '500MB SME 30 days', 300.0, 350.0),
    ('265', 'mtn', '500MB GIFTING 1 day', 343.0, 393.0),
    ('315', 'mtn', '1GB SME 30 days', 400.0, 450.0),
    ('37', 'mtn', '1GB SME 7 days', 400.0, 450.0),
    ('323', 'mtn', '2GB COOPERATE GIFTING 30 days', 470.0, 520.0),
    ('266', 'mtn', '1GB GIFTING 1 day', 490.0, 540.0),
    ('267', 'mtn', '1.5GB GIFTING 2 days', 588.0, 638.0),
    ('324', 'mtn', '3GB COOPERATE GIFTING 30 days', 690.0, 740.0),
    ('268', 'mtn', '2GB GIFTING 2 days', 735.0, 785.0),
    ('38', 'mtn', '2GB SME 30 days', 760.0, 810.0),
    ('269', 'mtn', '2.5GB GIFTING 2 days', 882.0, 932.0),
    ('270', 'mtn', '3.2GB GIFTING 2 days', 980.0, 1030.0),
    ('39', 'mtn', '3GB SME 30 days', 1110.0, 1160.0),
    ('325', 'mtn', '5GB COOPERATE GIFTING 30 days', 1400.0, 1450.0),
    ('271', 'mtn', '2GB GIFTING 30days', 1470.0, 1520.0),
    ('274', 'mtn', '3.5GB GIFTING 7 days', 1470.0, 1520.0),
    ('275', 'mtn', '1.8GB GIFTING 30 days', 1470.0, 1520.0),
    ('40', 'mtn', '5GB SME 30 days', 1660.0, 1710.0),
    ('277', 'mtn', '7GB GIFTING 2 days', 1764.0, 1814.0),
    ('272', 'mtn', '2.7GB GIFTING 30 days', 1960.0, 2010.0),
    ('273', 'mtn', '3.5GB GIFTING 30 days', 2450.0, 2500.0),
    ('278', 'mtn', '5.5GB GIFTING 30 days', 2940.0, 2990.0),
    ('276', 'mtn', '7GB GIFTING 30 days', 3430.0, 3480.0),
    ('280', 'mtn', '11GB GIFTING 7 days', 3430.0, 3480.0),
    ('279', 'mtn', '10GB GIFTING 30 days', 4410.0, 4460.0),
    ('282', 'mtn', '14.5GB GIFTING 30 days', 4900.0, 4950.0),
    ('281', 'mtn', '12.5GB GIFTING 30 days', 5390.0, 5440.0),
    ('283', 'mtn', '16.5GB GIFTING 30 days', 6370.0, 6420.0),
    ('285', 'mtn', '25GB GIFTING 30 days', 6860.0, 6910.0),
    ('284', 'mtn', '20GB GIFTING 30 days', 7350.0, 7400.0),
    ('286', 'mtn', '25GB GIFTING 30 days', 8820.0, 8870.0),
    ('289', 'mtn', '40GB GIFTING 60 days', 8820.0, 8870.0),
    ('287', 'mtn', '34GB GIFTING 30 days', 9800.0, 9850.0),
    ('288', 'mtn', '36GB GIFTING 30 days', 10780.0, 10830.0),
    ('290', 'mtn', '65GB GIFTING 30 days', 15680.0, 15730.0),
    ('291', 'mtn', '75GB GIFTING 30 days', 17600.0, 17650.0),
    ('292', 'mtn', '90GB GIFTING 60days', 24500.0, 24550.0),
    ('293', 'mtn', '165GB GIFTING 30 days', 34300.0, 34350.0),
    ('294', 'mtn', '250GB GIFTING 30 days', 53900.0, 53950.0),
    ('295', 'mtn', '800GB GIFTING 1 year', 122500.0, 122550.0),
]

LW_CABLE_SEED = [
    ('c:28', 'dstv', 'DStv HDPVR Access Service', 2500.0, 2500.0),
    ('c:94', 'dstv', 'Great wall standalone bouquet', 3800.0, 3800.0),
    ('c:1', 'dstv', 'DStv Padi', 4400.0, 4400.0),
    ('c:107', 'dstv', 'Yanga OTT Streaming subscription', 5100.0, 5100.0),
    ('c:87', 'dstv', 'Yanga', 6000.0, 6000.0),
    ('c:111', 'dstv', 'Yanga', 6000.0, 6000.0),
    ('c:32', 'dstv', 'ExtraView Access', 6050.0, 6050.0),
    ('c:2', 'dstv', 'DSTV -YANGA', 6100.0, 6100.0),
    ('c:110', 'dstv', 'Confam streaming subscription', 7450.0, 7450.0),
    ('c:31', 'dstv', 'DStv French Touch Add-on', 7500.0, 7500.0),
    ('c:96', 'dstv', 'Yanga + showmax', 8250.0, 8250.0),
    ('c:97', 'dstv', 'Great wall standalone bouquet + showmax', 8300.0, 8300.0),
    ('c:101', 'dstv', 'Padi + showmax', 8900.0, 8900.0),
    ('c:34', 'dstv', 'Dstv Confam', 9300.0, 9300.0),
    ('c:43', 'dstv', 'DStv Padi + ExtraView', 10400.0, 10400.0),
    ('c:33', 'dstv', 'DStv French 11', 11000.0, 11000.0),
    ('c:112', 'dstv', 'Confam', 11000.0, 11000.0),
    ('c:121', 'dstv', 'Confam streaming subscription', 11000.0, 11000.0),
    ('c:42', 'dstv', 'DStv Yanga + ExtraView', 12100.0, 12100.0),
    ('c:30', 'dstv', 'DStv Asian Add-on', 12400.0, 12400.0),
    ('c:109', 'dstv', 'Streaming subscription', 12550.0, 12550.0),
    ('c:99', 'dstv', 'Confam + showmax', 13250.0, 13250.0),
    ('c:118', 'dstv', 'Asia addon', 14900.0, 14900.0),
    ('c:122', 'dstv', 'DStv indian', 14900.0, 14900.0),
    ('c:6', 'dstv', 'DStv Asia', 15000.0, 15000.0),
    ('c:35', 'dstv', 'Compact', 15700.0, 15700.0),
    ('c:41', 'dstv', 'DStv Confam + ExtraView', 17100.0, 17100.0),
    ('c:4', 'dstv', 'DStv Compact', 19000.0, 19000.0),
    ('c:88', 'dstv', 'Compact', 19000.0, 19000.0),
    ('c:120', 'dstv', 'Compact streaming', 19000.0, 19000.0),
    ('c:29', 'dstv', 'DStv French Plus Add-on', 24500.0, 24500.0),
    ('c:14', 'dstv', 'DStv Compact + Extra View', 25100.0, 25100.0),
    ('c:15', 'dstv', 'DStv Compact + French Touch', 26100.0, 26100.0),
    ('c:108', 'dstv', 'Compact plus streaming subscription', 30000.0, 30000.0),
    ('c:38', 'dstv', 'DStv Compact Plus', 31000.0, 31000.0),
    ('c:91', 'dstv', 'Compact + French Touch + ExtraView', 32000.0, 32000.0),
    ('c:18', 'dstv', 'DStv Compact + French Touch + ExtraView', 32200.0, 32200.0),
    ('c:98', 'dstv', 'Compact plus + showmax', 32250.0, 32250.0),
    ('c:100', 'dstv', 'Compact + showmax', 32250.0, 32250.0),
    ('c:49', 'dstv', 'DStv Compact + Asia + ExtraView', 33100.0, 33100.0),
    ('c:13', 'dstv', 'DStv Compact + Asia', 34000.0, 34000.0),
    ('c:22', 'dstv', 'DStv Compact Plus + Extra View', 36000.0, 36000.0),
    ('c:21', 'dstv', 'DStv Compact Plus + French Touch', 37000.0, 37000.0),
    ('c:92', 'dstv', 'Compact plus + French Touch', 37000.0, 37000.0),
    ('c:105', 'dstv', 'DStv Premium Streaming subscription', 37000.0, 37000.0),
    ('c:48', 'dstv', 'DStv Compact Plus - Asia', 37400.0, 37400.0),
    ('c:19', 'dstv', 'DStv Compact + Asia + ExtraView', 40000.0, 40000.0),
    ('c:25', 'dstv', 'DStv Compact Plus + Asia + ExtraView', 42400.0, 42400.0),
    ('c:24', 'dstv', 'DStv Compact + French Plus', 43700.0, 43700.0),
    ('c:44', 'dstv', 'DStv Compact + Asia', 44000.0, 44000.0),
    ('c:104', 'dstv', 'Premium + showmax', 44500.0, 44500.0),
    ('c:5', 'dstv', 'DStv Premium', 44700.0, 44700.0),
    ('c:17', 'dstv', 'DStv Compact Plus + Asia', 45000.0, 45000.0),
    ('c:83', 'dstv', 'Premium', 45000.0, 45000.0),
    ('c:90', 'dstv', 'Premium + Extra View', 50500.0, 50500.0),
    ('c:102', 'dstv', 'Premium + Asia + showmax', 50500.0, 50500.0),
    ('c:9', 'dstv', 'DStv Premium-Asia', 51000.0, 51000.0),
    ('c:26', 'dstv', 'DStv Premium + Asia + Extra View', 54400.0, 54400.0),
    ('c:20', 'dstv', 'DStv Compact Plus + French Plus', 55000.0, 55000.0),
    ('c:16', 'dstv', 'DStv Premium - Extra View', 55700.0, 55700.0),
    ('c:23', 'dstv', 'DStv Compact Plus + FrenchPlus + Extra View', 61000.0, 61000.0),
    ('c:84', 'dstv', 'Premium-french', 69000.0, 69000.0),
    ('c:89', 'dstv', 'Premium-french', 69000.0, 69000.0),
    ('c:103', 'dstv', 'Premium + French + showmax', 69000.0, 69000.0),
    ('c:27', 'dstv', 'DStv Premium + French + Extra View', 75000.0, 75000.0),
    ('c:106', 'dstv', 'Prestige', 590200.0, 590200.0),
    ('c:119', 'dstv', 'Prestige', 850000.0, 850000.0),
    ('c:62', 'gotv', 'GOtv Smallie - monthly', 1900.0, 1900.0),
    ('c:61', 'gotv', 'GOtv Jinja', 3900.0, 3900.0),
    ('c:63', 'gotv', 'GOtv Smallie - quarterly', 5100.0, 5100.0),
    ('c:60', 'gotv', 'GOtv Jolli', 5800.0, 5800.0),
    ('c:59', 'gotv', 'GOtv Max', 8500.0, 8500.0),
    ('c:65', 'gotv', 'GOtv Supa - monthly', 11400.0, 11400.0),
    ('c:64', 'gotv', 'GOtv Smallie - yearly', 15000.0, 15000.0),
    ('c:123', 'gotv', 'Gotv Supa Plus - Monthly', 16900.0, 16900.0),
    ('c:81', 'startime', 'Nova 1day', 150.0, 150.0),
    ('c:71', 'startime', 'Nova - 1 Week', 700.0, 700.0),
    ('c:116', 'startime', 'Nova (dish) 1 week', 700.0, 700.0),
    ('c:72', 'startime', 'Basic (Antenna) - 1 Week', 1400.0, 1400.0),
    ('c:74', 'startime', 'Classic (Antenna) - 1 Week', 2000.0, 2000.0),
    ('c:66', 'startime', 'Nova - 1 Month', 2100.0, 2100.0),
    ('c:114', 'startime', 'Special (dish) 1 week', 2100.0, 2100.0),
    ('c:117', 'startime', 'Super (antenna) 1 week', 3200.0, 3200.0),
    ('c:75', 'startime', 'Super (Dish) - 1 Week', 3300.0, 3300.0),
    ('c:67', 'startime', 'Basic (Antenna) - 1 Month', 4000.0, 4000.0),
    ('c:115', 'startime', 'Special (dish) 1 month', 5600.0, 5600.0),
    ('c:69', 'startime', 'Classic (Antenna) - 1 Month', 6000.0, 6000.0),
    ('c:70', 'startime', 'Super (Dish) - 1 Month', 9800.0, 9800.0),
    ('c:113', 'startime', 'Chinese 1 month', 16000.0, 16000.0),
]
@app.get('/api/admin/legitdataway-plans')
@admin_session_auth
def legitdataway_plans_admin():
    return jsonify({'ok': True, 'plans': q("SELECT * FROM legitdataway_plans ORDER BY service, network, cost")})

@app.post('/api/admin/legitdataway-plan')
@admin_session_auth
def legitdataway_plan_save():
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
    run("""INSERT INTO legitdataway_plans(plan_id,service,network,name,cost,sell,updated)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,
           network=excluded.network, name=excluded.name, cost=excluded.cost,
           sell=excluded.sell, updated=excluded.updated""",
        (plan_id, service, network, name, cost, sell, now_iso()))
    log_admin('price_save', f'LegitDataWay {service}/{network} {name}: cost {cost}, sell {sell}')
    return jsonify({'ok': True})

@app.get('/api/admin/legitdataway-discos')
@admin_session_auth
def legitdataway_discos_admin():
    return jsonify({'ok': True, 'discos': q("SELECT * FROM legitdataway_discos ORDER BY label")})

@app.post('/api/admin/legitdataway-disco')
@admin_session_auth
def legitdataway_disco_save():
    d = request.get_json(force=True, silent=True) or {}
    disco_key = (d.get('disco_key') or '').strip()
    lw_id = (d.get('legitdataway_id') or '').strip()
    label = (d.get('label') or '').strip()
    if not disco_key or not lw_id or not label:
        return jsonify({'ok': False, 'error': 'disco_key, legitdataway_id and label are required.'}), 400
    run("""INSERT INTO legitdataway_discos(disco_key,legitdataway_id,label,updated)
           VALUES(?,?,?,?)
           ON CONFLICT(disco_key) DO UPDATE SET legitdataway_id=excluded.legitdataway_id,
           label=excluded.label, updated=excluded.updated""",
        (disco_key, lw_id, label, now_iso()))
    return jsonify({'ok': True})

@app.get('/api/admin/legitdataway-cost-check')
@admin_session_auth
def legitdataway_cost_check():
    """Plans whose sell price sits below LegitDataWay cost — same idea as cost-check."""
    out = []
    for r in q("SELECT plan_id, service, network, name, cost, sell FROM legitdataway_plans"):
        cost = float(r['cost'] or 0)
        sell = lw_sell_price(r['plan_id'], cost)
        if sell < cost:
            out.append({'plan': r['name'], 'code': r['plan_id'], 'service': r['service'],
                        'cost': cost, 'sell': sell, 'loss': round(cost - sell, 2)})
    return jsonify({'ok': True, 'losing': out})

def legitdataway_seed_data():
    """Seed discos + plans from the docs/dashboard tables captured 2026-11-03.
    Data sell = cost + ₦50 (Mahmod's rule); cable sell = cost (at cost).
    Vitel data plans are NOT seeded: LegitDataWay docs give them no network id.
    Safe to re-run: updates cost/name, never overwrites an admin-set sell price.
    Single transaction: the old per-row commits took 224 round trips and could
    outrun gunicorn's 30s worker timeout (admin tap showed 'Failed to fetch')."""
    ph = '%s' if USE_PG else '?'
    con = db()
    cur = con.cursor()
    try:
        cur.executemany(
            "INSERT INTO legitdataway_discos(disco_key,legitdataway_id,label,updated)"
            f" VALUES({ph},{ph},{ph},{ph})"
            " ON CONFLICT(disco_key) DO UPDATE SET legitdataway_id=excluded.legitdataway_id,"
            " label=excluded.label, updated=excluded.updated",
            [(k, str(i), label, now_iso()) for k, i, label in LEGITDATAWAY_DISCO_SEED])
        rows = ([(pid, 'data', net, name, cost, sell, now_iso())
                 for pid, net, name, cost, sell in LW_DATA_SEED]
                + [(pid, 'cable', net, name, cost, sell, now_iso())
                   for pid, net, name, cost, sell in LW_CABLE_SEED])
        cur.executemany(
            "INSERT INTO legitdataway_plans(plan_id,service,network,name,cost,sell,updated)"
            f" VALUES({ph},{ph},{ph},{ph},{ph},{ph},{ph})"
            " ON CONFLICT(plan_id) DO UPDATE SET service=excluded.service,"
            " network=excluded.network, name=excluded.name, cost=excluded.cost,"
            " updated=excluded.updated",
            rows)
        con.commit()
        return len(rows), len(LEGITDATAWAY_DISCO_SEED)
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass

@app.post('/api/admin/legitdataway-seed-plans')
@admin_session_auth
def legitdataway_seed_plans():
    n_plans, n_discos = legitdataway_seed_data()
    return jsonify({'ok': True, 'plans': n_plans, 'discos': n_discos,
                    'note': 'LegitDataWay plans seeded from docs tables. Data sells at cost + ₦50, cable at cost.'})

@app.post('/api/legitdataway/webhook')
def legitdataway_webhook():
    """LegitDataWay transaction-status callback. No signature is documented,
    so the only trust anchors are the request-id itself (timestamp + 12 random
    hex chars, unguessable) and the rule that ONLY pending transactions move:
    success marks delivered, fail refunds via the admin-resolve pattern.
    Anything else is ignored."""
    d = request.get_json(force=True, silent=True) or {}
    rid = d.get('request-id') or d.get('request_id') or ''
    status = (d.get('status') or '').lower()
    if not rid or status not in ('success', 'fail'):
        return jsonify({'ok': False}), 400
    rows = q("SELECT user_id, amount, reference FROM transactions WHERE provider_ref=? AND status='pending'", (rid,))
    if not rows:
        return jsonify({'ok': True, 'note': 'no pending transaction'}), 200
    t = rows[0]
    con = db()
    try:
        if USE_PG:
            cur = con.cursor()
            if status == 'fail':
                cur.execute("UPDATE users SET wallet=wallet+%s WHERE id=%s", (t['amount'], t['user_id']))
            cur.execute("UPDATE transactions SET status=%s, meta=%s WHERE reference=%s",
                        ('successful' if status == 'success' else 'failed', json.dumps(d)[:4000], t['reference']))
            con.commit(); cur.close()
        else:
            if status == 'fail':
                con.execute("UPDATE users SET wallet=wallet+? WHERE id=?", (t['amount'], t['user_id']))
            con.execute("UPDATE transactions SET status=?, meta=? WHERE reference=?",
                        ('successful' if status == 'success' else 'failed', json.dumps(d)[:4000], t['reference']))
            con.commit()
    finally:
        if not USE_PG: con.close()
    log_admin('lw_webhook', f"{t['reference']} -> {status} via LegitDataWay webhook")
    return jsonify({'ok': True})

@app.post('/api/admin/bilal-seed-plans')
@admin_session_auth
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
@admin_session_auth
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
@admin_export_auth
def admin_users():
    return jsonify({'ok': True, 'users': q(
        "SELECT id,name,username,phone,email,email_verified,wallet,created FROM users ORDER BY id DESC LIMIT 500")})

@app.post('/api/admin/wallet')
@admin_session_auth
def admin_wallet():
    d = request.get_json(force=True)
    phone = (d.get('phone') or '').strip()
    try: amount = float(d.get('amount') or 0)
    except: amount = 0
    action = d.get('action', 'add')
    note = (d.get('note') or '').strip()[:200]
    rows = q("SELECT id FROM users WHERE phone=?", (phone,))
    if not rows: return jsonify({'ok': False, 'error': 'User not found.'}), 404
    delta = amount if action == 'add' else -amount
    run("UPDATE users SET wallet=wallet+? WHERE phone=?", (delta, phone))
    desc = f'Admin wallet adjustment ({action})' + (f' — {note}' if note else '')
    run("""INSERT INTO transactions(user_id,type,service,description,amount,direction,
           status,reference,created) VALUES(?, 'fund','admin',?,?, 'in','successful',?,?)""",
        (rows[0]['id'], desc, amount,
         'SVA' + secrets.token_hex(5).upper(), now_iso()))
    log_admin('wallet_adjust', f'{action} {amount} for {phone}' + (f' — {note}' if note else ''))
    return jsonify({'ok': True})

@app.get('/api/admin/transactions')
@admin_export_auth
def admin_txs():
    return jsonify({'ok': True, 'transactions': q(
        """SELECT t.*, u.phone FROM transactions t LEFT JOIN users u ON u.id=t.user_id
           ORDER BY t.id DESC LIMIT 500""")})

@app.get('/api/admin/prices')
@admin_export_auth
def admin_prices():
    return jsonify({'ok': True, 'prices': q("SELECT * FROM plan_prices ORDER BY label")})

@app.post('/api/admin/price')
@admin_session_auth
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
@admin_session_auth
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
@admin_session_auth
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
@admin_session_auth
def admin_settings():
    # Staff sessions never see secret values: they come back blank.
    staff = getattr(g, 'is_staff', False)
    items = [{'key': k, 'group': m['group'], 'label': m['label'],
              'secret': m['secret'], 'value': ('' if (staff and m['secret']) else S(k))}
             for k, m in SETTINGS_META.items()]
    return jsonify({'ok': True, 'settings': items})

@app.post('/api/admin/settings')
@admin_session_auth
def admin_settings_save():
    blocked = _main_admin_only()
    if blocked:
        return blocked
    d = request.get_json(force=True, silent=True) or {}
    key = (d.get('key') or '').strip()
    value = d.get('value')
    if key not in SETTINGS_ALLOW:
        return jsonify({'ok': False, 'error': 'That setting cannot be changed here.'}), 400
    value = '' if value is None else str(value)
    if key.endswith('_SANDBOX') and value not in ('0', '1'):
        return jsonify({'ok': False, 'error': 'Sandbox must be 0 or 1.'}), 400
    if key == 'PROVIDER' and value not in ('vtpass', 'fatizara', 'bilal', 'legitdataway'):
        return jsonify({'ok': False, 'error': 'Provider must be vtpass, fatizara, bilal or legitdataway.'}), 400
    run("""INSERT INTO settings(k,v,updated_at) VALUES(?,?,?)
           ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at""",
        (key, value, now_iso()))
    SETTINGS[key] = value
    log_admin('setting_save', key)
    # Monnify caches its OAuth token per key-set; a key change must re-auth.
    if key.startswith('MONNIFY_'):
        _monnify['token'] = None
        _monnify['exp'] = 0
    return jsonify({'ok': True})

@app.post('/api/admin/test-connection')
@admin_session_auth
def admin_test_connection():
    blocked = _main_admin_only()
    if blocked:
        return blocked
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
        if service == 'legitdataway':
            if not legitdataway_configured():
                return jsonify({'ok': False, 'detail': 'LegitDataWay username / password missing.'})
            try:
                _, auth_resp = legitdataway_token()
                bal = auth_resp.get('balance')
                detail = f"Auth OK — wallet balance ₦{bal}." if bal is not None else 'Auth OK.'
                return jsonify({'ok': True, 'detail': detail})
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
        if service == 'xpouch':
            if not xpouch_configured():
                return jsonify({'ok': False, 'detail': 'API key / secret missing.'})
            try:
                r = requests.get(f'{xpouch_base()}/virtual-accounts',
                                 headers=xpouch_headers(), timeout=20)
                if r.status_code == 200 and r.json().get('success'):
                    mode = 'sandbox' if xpouch_sandbox() else 'LIVE'
                    return jsonify({'ok': True, 'detail': f'Auth OK ({mode}).'})
                return jsonify({'ok': False,
                                'detail': f'Xpouch rejected the key (HTTP {r.status_code}).'})
            except Exception as e:
                return jsonify({'ok': False, 'detail': 'Connection error: ' + str(e)[:120]})
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
@admin_export_auth
def admin_user():
    try: uid = int(request.args.get('id') or 0)
    except Exception: uid = 0
    try:
        rows = q("SELECT id,name,username,phone,email,email_verified,wallet,created,"
                 "monnify_ref,monnify_acct,monnify_bank,monnify_acct_name,login_2fa "
                 "FROM users WHERE id=?", (uid,))
    except Exception:
        rows = q("SELECT id,name,username,phone,email,email_verified,wallet,created,"
                 "monnify_ref,monnify_acct,monnify_bank,monnify_acct_name "
                 "FROM users WHERE id=?", (uid,))
    if not rows:
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    u = dict(rows[0])
    u['login_2fa'] = 1 if u.get('login_2fa') else 0
    cnt = q("SELECT COUNT(*) c FROM transactions WHERE user_id=?", (uid,))
    u['tx_count'] = cnt[0]['c'] if cnt else 0
    u['recent'] = q("SELECT id,type,service,description,amount,direction,status,reference,created "
                    "FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 20", (uid,))
    return jsonify({'ok': True, 'user': u})

@app.post('/api/admin/user-password')
@admin_session_auth
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
    log_admin('user_password', f'user {uid} password reset by admin')
    return jsonify({'ok': True})

@app.post('/api/admin/user-pin')
@admin_session_auth
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
    log_admin('user_pin', f'user {uid} PIN reset by admin')
    return jsonify({'ok': True})

@app.post('/api/admin/transaction-resolve')
@admin_session_auth
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
    log_admin('tx_resolve', f'{ref} -> {outcome}')
    return jsonify({'ok': True, 'wallet': float(bal[0]['wallet']) if bal else None})

@app.delete('/api/admin/user')
@admin_session_auth
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
    log_admin('user_delete', f'user {uid} deleted by admin')
    return jsonify({'ok': True})

# ---------------- admin: announcements + activity log (Admin v2) ----------------
@app.get('/api/announcements')
def announcements_public():
    """Active announcements for the shop app (no admin key needed)."""
    return jsonify({'ok': True, 'announcements': q(
        "SELECT id,title,body,audience,created FROM announcements "
        "WHERE active=1 ORDER BY id DESC LIMIT 20")})

@app.get('/api/admin/announcements')
@admin_session_auth
def admin_announcements():
    return jsonify({'ok': True, 'announcements': q(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 100")})

@app.post('/api/admin/announcements')
@admin_session_auth
def admin_announcement_create():
    d = request.get_json(force=True, silent=True) or {}
    title = (d.get('title') or '').strip()[:120]
    body = (d.get('body') or '').strip()[:1000]
    if not title or not body:
        return jsonify({'ok': False, 'error': 'Title and message are required.'}), 400
    run("INSERT INTO announcements(title,body,audience,active,created) VALUES(?,?,?,?,?)",
        (title, body, 'all', 1, now_iso()))
    log_admin('announcement', f'posted: {title}')
    return jsonify({'ok': True})

@app.post('/api/admin/announcements/toggle')
@admin_session_auth
def admin_announcement_toggle():
    d = request.get_json(force=True, silent=True) or {}
    try: aid = int(d.get('id') or 0)
    except Exception: aid = 0
    rows = q("SELECT active FROM announcements WHERE id=?", (aid,))
    if not rows:
        return jsonify({'ok': False, 'error': 'Announcement not found.'}), 404
    new = 0 if rows[0]['active'] else 1
    run("UPDATE announcements SET active=? WHERE id=?", (new, aid))
    log_admin('announcement', f"{'hid' if new == 0 else 'showed'} announcement {aid}")
    return jsonify({'ok': True, 'active': new})

@app.delete('/api/admin/announcements')
@admin_session_auth
def admin_announcement_delete():
    d = request.get_json(force=True, silent=True) or {}
    try: aid = int(d.get('id') or 0)
    except Exception: aid = 0
    if not q("SELECT id FROM announcements WHERE id=?", (aid,)):
        return jsonify({'ok': False, 'error': 'Announcement not found.'}), 404
    run("DELETE FROM announcements WHERE id=?", (aid,))
    log_admin('announcement', f'deleted announcement {aid}')
    return jsonify({'ok': True})

@app.post('/api/admin/request-code')
@admin_auth
@limiter.limit('3 per minute')
def admin_request_code():
    """Step 1 of admin sign-in: key already checked by admin_auth.
    Sends a 6-digit code (15-min expiry) to the admin inbox."""
    to = admin_email()
    if not to:
        return jsonify({'ok': False, 'error': 'Admin email is not set. Set ADMIN_EMAIL on the server.'}), 400
    code = str(secrets.randbelow(900000) + 100000)
    chash = hashlib.sha256(code.encode()).hexdigest()
    exp = (datetime.now(LAGOS) + timedelta(minutes=15)).isoformat(timespec='seconds')
    run("DELETE FROM admin_codes")
    run("INSERT INTO admin_codes(code_hash,expires_at,created) VALUES(?,?,?)",
        (chash, exp, now_iso()))
    sent = send_email(to, 'Your Panther Data admin sign-in code',
        f"Hello,\n\nYour Panther Data admin sign-in code is:\n\n{code}\n\n"
        f"Enter this code to open the admin area. It expires in 15 minutes.\n\n"
        f"If you did not try to sign in, change the admin key immediately.\n\n— Panther Data")
    return jsonify({'ok': True, 'email_sent': bool(sent)})

@app.post('/api/admin/verify-code')
@admin_auth
@limiter.limit('10 per minute')
def admin_verify_code():
    """Step 2 of admin sign-in: key + code -> session token. The raw key
    is never enough on its own for any other admin endpoint."""
    d = request.get_json(force=True)
    code = str(d.get('code') or '').strip()
    remember = bool(d.get('remember'))
    rows = q("SELECT * FROM admin_codes ORDER BY id DESC LIMIT 1")
    chash = hashlib.sha256(code.encode()).hexdigest()
    if not rows or rows[0]['code_hash'] != chash:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if rows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Request a new one.'}), 400
    run("DELETE FROM admin_codes")
    tok, exp = new_admin_session(remember)
    log_admin('admin_login', 'admin signed in with key + code')
    return jsonify({'ok': True, 'admin_session': tok, 'expires_at': exp})

@app.post('/api/admin/logout')
@admin_session_auth
def admin_logout():
    tok = (request.headers.get('X-Admin-Session') or '').strip()
    run("DELETE FROM admin_sessions WHERE token=?", (tok,))
    return jsonify({'ok': True})

# ---------------- staff sign-in (email code, no admin key) ----------------
# Staff accounts are allowlisted by email in staff_users. A staff sign-in
# is email + emailed code only: no admin key is ever given to staff.
# Staff sessions are 12 hours, and staff can do everything the main
# admin can except settings, connection tests and staff management
# (see _main_admin_only). Staff read the same four list endpoints the
# admin page uses (see admin_export_auth); they do not get the
# BACKUP_KEY, and the Backup button is hidden from them in the page.
@app.post('/api/staff/request-code')
@limiter.limit('3 per minute')
def staff_request_code():
    """Step 1 of staff sign-in: sends a 6-digit code (15-min expiry)
    to the staff email, but only when that email is an active staffer."""
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip().lower()
    if not email or not q("SELECT id FROM staff_users WHERE email=? AND active=1", (email,)):
        return jsonify({'ok': False, 'error': 'This email has no staff access.'}), 404
    code = str(secrets.randbelow(900000) + 100000)
    chash = hashlib.sha256(code.encode()).hexdigest()
    exp = (datetime.now(LAGOS) + timedelta(minutes=15)).isoformat(timespec='seconds')
    run("DELETE FROM staff_codes WHERE email=?", (email,))
    run("INSERT INTO staff_codes(email,code_hash,expires_at,created) VALUES(?,?,?,?)",
        (email, chash, exp, now_iso()))
    sent = send_email(email, 'Your Panther Data admin sign-in code',
        f"Hello,\n\nYour Panther Data admin sign-in code is:\n\n{code}\n\n"
        f"Enter this code to open the admin area. It expires in 15 minutes.\n\n"
        f"If you did not try to sign in, ignore this email.\n\n— Panther Data")
    return jsonify({'ok': True, 'email_sent': bool(sent)})

@app.post('/api/staff/verify-code')
@limiter.limit('10 per minute')
def staff_verify_code():
    """Step 2 of staff sign-in: email + code -> staff session token."""
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip().lower()
    code = str(d.get('code') or '').strip()
    rows = q("SELECT * FROM staff_codes WHERE email=? ORDER BY id DESC LIMIT 1", (email,))
    chash = hashlib.sha256(code.encode()).hexdigest()
    if not rows or rows[0]['code_hash'] != chash:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if rows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Request a new one.'}), 400
    urows = q("SELECT id, role FROM staff_users WHERE email=? AND active=1", (email,))
    if not urows:
        return jsonify({'ok': False, 'error': 'This email has no staff access.'}), 403
    run("DELETE FROM staff_codes WHERE email=?", (email,))
    tok = secrets.token_hex(32)
    exp = (datetime.now(LAGOS) + timedelta(hours=12)).isoformat(timespec='seconds')
    run("INSERT INTO staff_sessions(token,staff_id,created,expires_at,last_seen) VALUES(?,?,?,?,?)",
        (tok, urows[0]['id'], now_iso(), exp, now_iso()))
    log_admin('staff_login', f'staff {email} signed in with email code')
    return jsonify({'ok': True, 'staff_session': tok, 'expires_at': exp,
                    'role': urows[0]['role'], 'email': email})

@app.post('/api/staff/logout')
def staff_logout():
    tok = (request.headers.get('X-Admin-Session') or '').strip()
    run("DELETE FROM staff_sessions WHERE token=?", (tok,))
    return jsonify({'ok': True})

@app.get('/api/staff/me')
@admin_session_auth
def staff_me():
    """Who this session belongs to: main admin, or a staffer (role +
    email). The admin page uses it to hide main-admin-only pages."""
    return jsonify({'ok': True, 'is_staff': bool(getattr(g, 'is_staff', False)),
                    'role': getattr(g, 'staff_role', None),
                    'email': getattr(g, 'staff_email', None)})

@app.get('/api/admin/staff')
@admin_session_auth
def admin_staff_list():
    blocked = _main_admin_only()
    if blocked:
        return blocked
    return jsonify({'ok': True, 'staff': q(
        "SELECT email, role, active, created FROM staff_users ORDER BY id")})

@app.post('/api/admin/staff')
@admin_session_auth
def admin_staff_add():
    blocked = _main_admin_only()
    if blocked:
        return blocked
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'ok': False, 'error': 'Enter a valid email.'}), 400
    run("""INSERT INTO staff_users(email,role,active,created) VALUES(?,?,?,?)
           ON CONFLICT(email) DO UPDATE SET role=excluded.role, active=1""",
        (email, 'full', 1, now_iso()))
    log_admin('staff_add', email)
    return jsonify({'ok': True})

@app.post('/api/admin/staff/remove')
@admin_session_auth
def admin_staff_remove():
    blocked = _main_admin_only()
    if blocked:
        return blocked
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip().lower()
    run("UPDATE staff_users SET active=0 WHERE email=?", (email,))
    run("DELETE FROM staff_sessions WHERE staff_id IN (SELECT id FROM staff_users WHERE email=?)", (email,))
    log_admin('staff_remove', email)
    return jsonify({'ok': True})

@app.post('/api/admin/user-login-2fa')
@admin_session_auth
def admin_user_login_2fa():
    """Admin's way out for a customer who lost access to their email:
    switch that customer's sign-in codes off (or back on). Logged."""
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    enabled = bool(d.get('enabled'))
    if not q("SELECT id FROM users WHERE id=?", (uid,)):
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    try:
        run("UPDATE users SET login_2fa=? WHERE id=?", (1 if enabled else 0, uid))
    except Exception:
        return jsonify({'ok': False, 'error': 'Please try again in a minute.'}), 503
    log_admin('login_2fa', f'user {uid} sign-in codes -> {1 if enabled else 0} (by admin)')
    return jsonify({'ok': True, 'login_2fa': enabled})

@app.get('/api/admin/logs')
@admin_session_auth
def admin_logs():
    return jsonify({'ok': True, 'logs': q(
        "SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200")})

@app.get('/')
def index():
    return jsonify({'ok': True, 'service': 'Panther Data backend', 'sandbox': vt_sandbox()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
