"""
SWEETVTU backend — real VTpass + Paystack integration.
Holds API keys server-side (env vars). Never expose them to the frontend.

Env vars:
  ADMIN_KEY             (protects /api/admin/* — env only, never admin-editable)
  DATABASE_URL          (optional postgres://... ; defaults to local sqlite)
  FRONTEND_ORIGIN       (comma-separated allowed origins, default *)
  SMTP_USER             (Gmail address used to send verification codes, e.g. sweetvtu@gmail.com)
  SMTP_APP_PASSWORD     (Gmail *app password*, not the login password)
  SMTP_FROM_NAME        (sender name shown on emails, default SWEETVTU)
Provider keys (VTPASS_*, MONNIFY_*, BREVO_*, PAYSTACK_*) are seeded from env
into the settings table at startup, then editable from the admin panel.
  PORT
"""
import os, re, json, secrets, sqlite3, uuid, smtplib, hashlib, hmac, base64, time
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
SMTP_FROM_NAME    = os.environ.get('SMTP_FROM_NAME', 'SWEETVTU')
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

LAGOS = timezone(timedelta(hours=1))

app = Flask(__name__)
CORS(app, origins=[o.strip() for o in FRONTEND_ORIGIN.split(',')])

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
            _pg = psycopg2.connect(DATABASE_URL)
            _pg.autocommit = False
        return _pg
    con = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'sweetvtu.db'))
    con.row_factory = sqlite3.Row
    return con

def q(sql, params=()):
    """SELECT helper -> list of dicts"""
    if USE_PG:
        sql = sql.replace('?', '%s')
        cur = db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(sql, params)
            rows = cur.fetchall()
        except Exception:
            try:
                db().rollback()
            except Exception:
                pass
            raise
        finally:
            cur.close()
        return [dict(r) for r in rows]
    cur = db().cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    return rows

def run(sql, params=()):
    if USE_PG:
        sql = sql.replace('?', '%s')
        cur = db().cursor()
        try:
            cur.execute(sql, params)
            db().commit()
        except Exception:
            # On Postgres a failed statement aborts the whole transaction;
            # roll back so the connection stays usable for the next statement.
            try:
                db().rollback()
            except Exception:
                pass
            raise
        finally:
            cur.close()
        return
    else:
        con = db()
        con.execute(sql, params)
        con.commit()
        con.close()

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
        """CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT, updated_at TEXT)""",
    ]
    for s in stmts:
        run(s)
    # migrate older databases that lack the new columns
    for col, tbl in (("email_verified INTEGER DEFAULT 0", "users"),
                     ("tx_pin_hash TEXT", "users"),
                     ("monnify_ref TEXT", "users"), ("monnify_acct TEXT", "users"),
                     ("monnify_bank TEXT", "users"), ("monnify_acct_name TEXT", "users"),
                     ("updated_at TEXT", "settings")):
        try:
            run(f"ALTER TABLE {tbl} ADD COLUMN {col}")
        except Exception:
            pass
    # Each Monnify account reference must belong to exactly one user.
    # (NULLs are allowed multiple times on both SQLite and Postgres.)
    try:
        run("CREATE UNIQUE INDEX IF NOT EXISTS users_monnify_ref_uniq ON users(monnify_ref)")
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

load_settings()

# ---------------- helpers ----------------
def now_iso():
    return datetime.now(LAGOS).isoformat(timespec='seconds')

def request_id():
    stamp = datetime.now(LAGOS).strftime('%Y%m%d%H%M')
    return stamp + secrets.token_hex(6)

def auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        tok = (request.headers.get('Authorization') or '').replace('Bearer ', '').strip()
        if not tok:
            return jsonify({'ok': False, 'error': 'Not signed in.'}), 401
        rows = q("SELECT user_id FROM tokens WHERE token=?", (tok,))
        if not rows:
            return jsonify({'ok': False, 'error': 'Session expired. Sign in again.'}), 401
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
    rows = q("SELECT id,name,phone,email,wallet,email_verified,created,monnify_ref,monnify_acct,monnify_bank,monnify_acct_name FROM users WHERE id=?", (uid,))
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
        user['email'], 'Your SWEETVTU verification code',
        f"Hello {user['name']},\n\nWelcome to SWEETVTU! Your email verification code is:\n\n"
        f"{code}\n\nEnter this code in the app to activate your account. "
        f"It expires in 15 minutes.\n\nIf you did not sign up, ignore this email.\n\n— SWEETVTU")
    return ok

def pin_required(f):
    """Decorator: the request JSON must carry the correct 4-digit transaction PIN."""
    @wraps(f)
    def wrapper(*a, **kw):
        d = request.get_json(force=True, silent=True) or {}
        rows = q("SELECT tx_pin_hash FROM users WHERE id=?", (g.user_id,))
        good = bool(rows and rows[0]['tx_pin_hash']) and \
            check_password_hash(rows[0]['tx_pin_hash'], str(d.get('pin') or ''))
        if not good:
            return jsonify({'ok': False, 'error': 'Wrong transaction PIN.'}), 403
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

def sell_price(variation_code, cost):
    rows = q("SELECT sell_price FROM plan_prices WHERE variation_code=?", (variation_code,))
    if rows and rows[0]['sell_price'] is not None:
        return float(rows[0]['sell_price'])
    margin = float((q("SELECT v FROM settings WHERE k='margin'") or [{'v': '0'}])[0]['v'])
    return round(float(cost) * (1 + margin / 100), 2)

def debit_and_buy(user_id, amount, desc, tx_type, service, vt_payload):
    """Debit wallet, call VTpass, refund on failure. Returns (ok, info)."""
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
            return False, {'error': 'Insufficient wallet balance. Please fund your wallet.'}
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
    # call VTpass
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
    if ok:
        run("UPDATE transactions SET status='successful', provider_ref=?, meta=? WHERE reference=?",
            (provider_ref, json.dumps({'token': token, 'raw': resp})[:4000], ref))
        return True, {'reference': ref, 'provider_ref': provider_ref, 'token': token}
    # failure -> refund
    con = db()
    try:
        if USE_PG:
            cur = con.cursor()
            cur.execute("UPDATE users SET wallet=wallet+%s WHERE id=%s", (amount, user_id))
            cur.execute("UPDATE transactions SET status='failed', provider_ref=%s, meta=%s WHERE reference=%s",
                        (provider_ref, json.dumps(resp)[:4000], ref))
            con.commit(); cur.close()
        else:
            con.execute("UPDATE users SET wallet=wallet+? WHERE id=?", (amount, user_id))
            con.execute("UPDATE transactions SET status='failed', provider_ref=?, meta=? WHERE reference=?",
                        (provider_ref, json.dumps(resp)[:4000], ref))
            con.commit()
    finally:
        if not USE_PG: con.close()
    err = ((content.get('errors') or '') if isinstance(content, dict) else '') or resp.get('response_description') or 'Purchase failed.'
    return False, {'error': str(err)[:300], 'reference': ref}

# ---------------- public ----------------
@app.get('/api/config')
def config():
    return jsonify({'ok': True, 'paystack_public_key': S('PAYSTACK_PUBLIC_KEY'),
                    'sandbox': vt_sandbox(), 'live': True,
                    'email_via': 'brevo' if S('BREVO_API_KEY') else 'smtp',
                    'email_ready': bool(S('BREVO_API_KEY') or (SMTP_USER and SMTP_APP_PASSWORD)),
                    'monnify_ready': monnify_configured(),
                    'fund_method': 'monnify'})

@app.post('/api/signup')
def signup():
    d = request.get_json(force=True)
    name, phone, email, pw = (d.get('name') or '').strip(), (d.get('phone') or '').strip(), \
                             (d.get('email') or '').strip(), d.get('password') or ''
    pin = str(d.get('pin') or '').strip()
    if len(name) < 3: return jsonify({'ok': False, 'error': 'Please enter your full name.'}), 400
    if not re.match(r'^0\d{10}$', phone): return jsonify({'ok': False, 'error': 'Enter a valid 11-digit phone number.'}), 400
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email): return jsonify({'ok': False, 'error': 'Enter a valid email address.'}), 400
    if len(pw) < 4: return jsonify({'ok': False, 'error': 'Password must be at least 4 characters.'}), 400
    if not re.match(r'^\d{4}$', pin):
        return jsonify({'ok': False, 'error': 'Create a 4-digit transaction PIN.'}), 400
    if q("SELECT id FROM users WHERE phone=?", (phone,)):
        return jsonify({'ok': False, 'error': 'This number is already registered. Sign in instead.'}), 400
    run("""INSERT INTO users(name,phone,email,pass_hash,tx_pin_hash,email_verified,wallet,created)
           VALUES(?,?,?,?,?,0,0,?)""",
        (name, phone, email, generate_password_hash(pw), generate_password_hash(pin), now_iso()))
    uid = q("SELECT id FROM users WHERE phone=?", (phone,))[0]['id']
    user = get_user(uid)
    email_sent = send_verify_code(user)
    # no token yet — account opens only after the email code is verified
    return jsonify({'ok': True, 'verify_required': True, 'user_id': uid,
                    'email': email, 'email_sent': email_sent})

@app.post('/api/verify-email')
def verify_email():
    d = request.get_json(force=True)
    try: uid = int(d.get('user_id') or 0)
    except: uid = 0
    code = str(d.get('code') or '').strip()
    user = get_user(uid)
    if not user:
        return jsonify({'ok': False, 'error': 'Account not found. Sign up again.'}), 404
    if user.get('email_verified'):
        tok = secrets.token_hex(24)
        run("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)", (tok, uid, now_iso()))
        return jsonify({'ok': True, 'token': tok, 'user': user})
    rows = q("SELECT * FROM email_codes WHERE user_id=? AND purpose='verify'", (uid,))
    chash = hashlib.sha256(code.encode()).hexdigest()
    if not rows or rows[0]['code_hash'] != chash:
        return jsonify({'ok': False, 'error': 'Wrong code. Check the email and try again.'}), 400
    if rows[0]['expires_at'] < now_iso():
        return jsonify({'ok': False, 'error': 'Code expired. Tap resend for a new one.'}), 400
    run("UPDATE users SET email_verified=1 WHERE id=?", (uid,))
    run("DELETE FROM email_codes WHERE user_id=? AND purpose='verify'", (uid,))
    tok = secrets.token_hex(24)
    run("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)", (tok, uid, now_iso()))
    return jsonify({'ok': True, 'token': tok, 'user': get_user(uid)})

@app.post('/api/resend-code')
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
def login():
    d = request.get_json(force=True)
    phone, pw = (d.get('phone') or '').strip(), d.get('password') or ''
    rows = q("SELECT * FROM users WHERE phone=?", (phone,))
    if not rows or not check_password_hash(rows[0]['pass_hash'], pw):
        return jsonify({'ok': False, 'error': 'Wrong number or password. Try again.'}), 401
    if not rows[0].get('email_verified'):
        return jsonify({'ok': False, 'error': 'Please verify your email first — check your inbox for the code.',
                        'verify_required': True, 'user_id': rows[0]['id']}), 403
    tok = secrets.token_hex(24)
    run("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)", (tok, rows[0]['id'], now_iso()))
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
                  'accountName': (user.get('name') or 'SWEETVTU Customer')[:40],
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
def monnify_webhook():
    """Monnify payment notification. Verifies HMAC-SHA512 signature, credits
    wallet exactly once. The customer is resolved ONLY by exact match of the
    stored monnify_ref - never by parsing a user ID out of the reference."""
    raw = request.get_data()  # raw bytes, exactly as Monnify sent them (for HMAC)
    d = request.get_json(force=True, silent=True) or {}
    ev = d.get('eventData') or {}
    sig = request.headers.get('monnify-signature') or d.get('transactionHash') or ''
    if not ev or not sig or not MONNIFY_SECRET_KEY:
        return jsonify({'ok': False}), 400
    if not _monnify_sig_ok(sig, MONNIFY_SECRET_KEY, raw):
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
    ok, info = debit_and_buy(g.user_id, amount, f'{net.upper()} airtime ₦{amount:,} → {phone}',
                             'airtime', net,
                             {'serviceID': NETWORKS[net], 'amount': amount, 'phone': phone})
    return jsonify({'ok': ok, **info})

@app.get('/api/data/plans')
@auth
def data_plans():
    net = (request.args.get('network') or 'mtn').lower()
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
@auth
@pin_required
def buy_data():
    d = request.get_json(force=True)
    net = (d.get('network') or 'mtn').lower()
    phone = re.sub(r'\D', '', d.get('phone') or '')
    code = (d.get('variation_code') or '').strip()
    if not re.match(r'^0\d{10}$', phone): return jsonify({'ok': False, 'error': 'Enter a valid 11-digit phone number.'}), 400
    if not code: return jsonify({'ok': False, 'error': 'Please select a data plan.'}), 400
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
    svc = CABLE_SVC.get(prov, 'dstv')
    varis = vt_variations(svc)
    plans = [{'variation_code': v.get('variation_code'), 'name': v.get('name'),
              'cost': float(v.get('variation_amount') or 0),
              'price': sell_price(v.get('variation_code'), float(v.get('variation_amount') or 0))}
             for v in varis]
    return jsonify({'ok': True, 'plans': plans})

@app.post('/api/verify')
@auth
def verify():
    d = request.get_json(force=True)
    service_id = (d.get('serviceID') or '').strip()
    billers = (d.get('billersCode') or '').strip()
    vtype = (d.get('type') or '').strip()
    if not service_id or len(billers) < 5:
        return jsonify({'ok': False, 'error': 'Enter a valid number.'}), 400
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
    out = []
    for svc, label in DISCOS:
        varis = vt_variations(svc)
        types = [{'variation_code': v.get('variation_code'), 'name': v.get('name')} for v in varis]
        out.append({'serviceID': svc, 'label': label, 'types': types})
    return jsonify({'ok': True, 'discos': out})

@app.post('/api/buy/power')
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
    ok, info = debit_and_buy(g.user_id, amount, f'Electricity ₦{amount:,} ({vtype}) → {meter}',
                             'power', svc,
                             {'serviceID': svc, 'billersCode': meter, 'variation_code': vtype,
                              'amount': amount, 'phone': phone})
    return jsonify({'ok': ok, **info})

@app.post('/api/requery')
@auth
def requery():
    d = request.get_json(force=True)
    ref = (d.get('reference') or '').strip()
    rows = q("SELECT * FROM transactions WHERE reference=? AND user_id=?", (ref, g.user_id))
    if not rows: return jsonify({'ok': False, 'error': 'Unknown reference.'}), 404
    return jsonify({'ok': True, 'status': rows[0]['status'], 'provider_ref': rows[0]['provider_ref']})

# ---------------- admin ----------------
@app.get('/api/admin/vtpass-balance')
@admin_auth
def vt_balance():
    try:
        return jsonify({'ok': True, 'balance': vt_get('/balance')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502

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
def forgot_password():
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip()
    rows = q("SELECT id, name, email FROM users WHERE email=?", (email,))
    if rows:
        user = rows[0]
        code = new_email_code(user['id'], 'reset')
        send_email(user['email'], 'Reset your SWEETVTU password',
                   f"Hello {user['name']},\n\nYour password reset code is:\n\n{code}\n\n"
                   f"Enter it in the app with your new password. It expires in 15 minutes.\n\n"
                   f"If you did not request this, ignore this email.\n\n— SWEETVTU")
    # always ok — never reveal whether the email is registered
    return jsonify({'ok': True})

@app.post('/api/reset-password')
def reset_password():
    d = request.get_json(force=True, silent=True) or {}
    email = (d.get('email') or '').strip()
    code = str(d.get('code') or '').strip()
    pw = d.get('new_password') or ''
    if len(pw) < 4:
        return jsonify({'ok': False, 'error': 'Password must be at least 4 characters.'}), 400
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
    if len(pw) < 4:
        return jsonify({'ok': False, 'error': 'Password must be at least 4 characters.'}), 400
    if not q("SELECT id FROM users WHERE id=?", (uid,)):
        return jsonify({'ok': False, 'error': 'User not found.'}), 404
    run("UPDATE users SET pass_hash=? WHERE id=?", (generate_password_hash(pw), uid))
    run("DELETE FROM tokens WHERE user_id=?", (uid,))
    return jsonify({'ok': True})

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
    return jsonify({'ok': True, 'service': 'SWEETVTU backend', 'sandbox': vt_sandbox()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
