from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from flasgger import Swagger
import socket, time, os, functools, sqlite3, threading, logging, ipaddress, json
import hashlib, secrets, bcrypt

app = Flask(__name__, static_folder='static')

swagger_config = {
    'headers': [],
    'specs': [{'endpoint': 'apispec', 'route': '/apispec.json',
               'rule_filter': lambda rule: rule.rule.startswith('/api/'),
               'model_filter': lambda tag: True}],
    'static_url_path': '/flasgger_static',
    'swagger_ui': True,
    'specs_route': '/apidocs',
    'swagger_ui_config': {
        'tryItOutEnabled': True,
        'persistAuthorization': True,
        'displayRequestDuration': True,
    },
}
swagger_template = {
    'info': {'title': 'ExaBGP Route Manager API',
             'description': 'REST API for BGP route announcement via ExaBGP. '
                            'Authorize: enter token (Bearer prefix optional).',
             'version': '1.0'},
    'securityDefinitions': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'Enter your API token. Bearer prefix is optional.',
        }
    },
    'security': [{'Bearer': []}],
    'consumes': ['application/json'],
    'produces': ['application/json'],
}
Swagger(app, config=swagger_config, template=swagger_template)



app.secret_key    = os.environ.get('FLASK_SECRET_KEY', 'dev-secret')
PIPE_IN           = os.environ.get('EXABGP_PIPE_IN',  '/opt/exabgp/run/exabgp.in')
PIPE_OUT          = os.environ.get('EXABGP_PIPE_OUT', '/opt/exabgp/run/exabgp.out')
DB_PATH           = os.environ.get('DB_PATH', '/opt/exabgp/run/routes.db')
BGP_WAIT_TIMEOUT  = int(os.environ.get('BGP_WAIT_TIMEOUT', '120'))
BGP_POLL_INTERVAL = int(os.environ.get('BGP_POLL_INTERVAL', '5'))
RBTH_COMMUNITY    = os.environ.get('RBTH_COMMUNITY', '65000:666')

# ISP blackhole communities: BLACKHOLE_<name>=<community>
# e.g. BLACKHOLE_cogent=65001:100, BLACKHOLE_gtt=65001:200
BLACKHOLE_COMMUNITIES = {
    k[len('BLACKHOLE_'):].lower(): v.strip()
    for k, v in os.environ.items()
    if k.startswith('BLACKHOLE_') and v.strip()
}
ROUTE_COMMUNITY   = os.environ.get('ROUTE_COMMUNITY', '')   # default community for multi-nexthop routes
SIMPLE_COMMUNITY  = os.environ.get('SIMPLE_COMMUNITY', '')  # default community for simple routes
IPV6_SELF         = os.environ.get('IPV6_SELF', '')         # nexthop for IPv6 prefixes when "self" selected
HISTORY_DAYS      = int(os.environ.get('HISTORY_DAYS', '90'))

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')
ADMIN_TOKEN    = os.environ.get('ADMIN_TOKEN', 'changeme')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)
db_lock = threading.Lock()

_bgp_cache = {'established': False, 'socket_available': False, 'checked_at': None}
_bgp_cache_lock = threading.Lock()
BGP_CACHE_TTL = 10


# ── Named next-hops ───────────────────────────────────────────────────────────

def load_named_nexthops():
    items = []
    for key, val in os.environ.items():
        if key.startswith('NEXTHOP_'):
            name = key[len('NEXTHOP_'):]
            ips  = [v.strip() for v in val.strip().split(',') if v.strip()]
            ipv4 = next((v for v in ips if ':' not in v), None)
            ipv6 = next((v for v in ips if ':' in v), None)
            # 'ip' stays for backward compat — first value
            items.append({'name': name, 'ip': ips[0] if ips else '', 'ipv4': ipv4, 'ipv6': ipv6})
    items.sort(key=lambda x: x['name'])
    for i, item in enumerate(items, start=1):
        item['path_info'] = i
    return items

NAMED_NEXTHOPS = load_named_nexthops()


# ── IP helpers ────────────────────────────────────────────────────────────────

def normalize_ip(ip_str):
    try:
        if '/' not in ip_str:
            return None, 'IP must be in CIDR format (e.g. 10.0.0.0/24)'
        net = ipaddress.ip_network(ip_str, strict=False)
        return str(net), None
    except ValueError as e:
        return None, str(e)


# ── Auth helpers ──────────────────────────────────────────────────────────────

def hash_password(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def check_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token():
    return secrets.token_urlsafe(32)


# ── Database ──────────────────────────────────────────────────────────────────

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    with db_lock, db_connect() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS route_nexthops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL, nexthop TEXT NOT NULL,
            nexthop_name TEXT, path_info INTEGER NOT NULL DEFAULT 1,
            comment TEXT, community TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(prefix, nexthop))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS rbth_routes (
            ip TEXT PRIMARY KEY, comment TEXT, communities TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS flowspec_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT, destination_ip TEXT, protocol TEXT,
            source_port TEXT, destination_port TEXT,
            action TEXT NOT NULL, rate_limit_mbps REAL, comment TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(source_ip, destination_ip, protocol, source_port, destination_port, action))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            operation TEXT NOT NULL, type TEXT NOT NULL, target TEXT NOT NULL,
            details TEXT, comment TEXT, result TEXT NOT NULL DEFAULT 'ok')''')
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL DEFAULT 'readonly',
            created_at TEXT NOT NULL DEFAULT (datetime('now')))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS simple_routes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix      TEXT NOT NULL UNIQUE,
            nexthop     TEXT NOT NULL,
            local_pref  INTEGER,
            community   TEXT,
            as_path     TEXT,
            med         INTEGER,
            origin      TEXT,
            comment     TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')))''')
        try:
            conn.execute('ALTER TABLE history ADD COLUMN performed_by TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE rbth_routes ADD COLUMN communities TEXT')
        except Exception:
            pass
        for table in ('route_nexthops', 'rbth_routes', 'flowspec_rules', 'simple_routes'):
            try:
                conn.execute('ALTER TABLE {} ADD COLUMN performed_by TEXT'.format(table))
            except Exception:
                pass
        for table in ('route_nexthops', 'rbth_routes', 'flowspec_rules'):
            try:
                conn.execute('ALTER TABLE {} ADD COLUMN comment TEXT'.format(table))
            except Exception:
                pass
        try:
            conn.execute('ALTER TABLE route_nexthops ADD COLUMN community TEXT')
        except Exception:
            pass
        conn.commit()
    log.info('database initialized: %s', DB_PATH)
    _purge_old_history()


# ── User DB ───────────────────────────────────────────────────────────────────

def db_user_all():
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at').fetchall()
    return [dict(r) for r in rows]


def db_user_get_by_name(username):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    return dict(row) if row else None


def db_user_get_by_id(user_id):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    return dict(row) if row else None


def db_user_create(username, password, role):
    hashed = hash_password(password)
    try:
        with db_lock, db_connect() as conn:
            conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                         (username, hashed, role))
            conn.commit()
        return db_user_get_by_name(username)
    except sqlite3.IntegrityError:
        return None


def db_user_update(user_id, password, role):
    fields, params = [], []
    if password:
        fields.append('password_hash=?'); params.append(hash_password(password))
    if role:
        fields.append('role=?'); params.append(role)
    if not fields:
        return False
    params.append(user_id)
    with db_lock, db_connect() as conn:
        conn.execute('UPDATE users SET {} WHERE id=?'.format(', '.join(fields)), params)
        conn.commit()
    return True


def db_user_delete(user_id):
    with db_lock, db_connect() as conn:
        cur = conn.execute('DELETE FROM users WHERE id=?', (user_id,))
        conn.commit()
    return cur.rowcount > 0


# ── Token DB ──────────────────────────────────────────────────────────────────

def db_token_all():
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT id, name, role, created_at FROM tokens ORDER BY created_at').fetchall()
    return [dict(r) for r in rows]


def db_token_get_by_hash(token_hash):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM tokens WHERE token_hash=?', (token_hash,)).fetchone()
    return dict(row) if row else None


def db_token_create(name, token, role):
    thash = hash_token(token)
    try:
        with db_lock, db_connect() as conn:
            conn.execute('INSERT INTO tokens (name, token_hash, role) VALUES (?, ?, ?)',
                         (name, thash, role))
            conn.commit()
        with db_lock, db_connect() as conn:
            row = conn.execute('SELECT id, name, role, created_at FROM tokens WHERE name=?', (name,)).fetchone()
        return dict(row) if row else None
    except sqlite3.IntegrityError:
        return None


def db_token_delete(token_id):
    with db_lock, db_connect() as conn:
        cur = conn.execute('DELETE FROM tokens WHERE id=?', (token_id,))
        conn.commit()
    return cur.rowcount > 0


# ── Auth ──────────────────────────────────────────────────────────────────────

def authenticate_user(username, password):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {'username': username, 'role': 'admin'}
    row = db_user_get_by_name(username)
    if row and check_password(password, row['password_hash']):
        return {'username': username, 'role': row['role']}
    return None


def authenticate_token(token):
    if token == ADMIN_TOKEN:
        return {'username': ADMIN_USERNAME, 'role': 'admin'}
    thash = hash_token(token)
    row = db_token_get_by_hash(thash)
    if row:
        return {'username': row['name'], 'role': row['role']}
    return None


# ── Auth decorators ───────────────────────────────────────────────────────────

def require_session(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def require_admin_session(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


def _extract_token(auth_header):
    """Accept both 'Bearer <token>' and raw '<token>' (Swagger UI compat)."""
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return auth_header.strip() or None


def require_token(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth     = request.headers.get('Authorization', '')
        token    = _extract_token(auth)
        identity = authenticate_token(token) if token else None
        if not identity:
            return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
        return f(identity, *args, **kwargs)
    return decorated


def require_admin_token(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth     = request.headers.get('Authorization', '')
        token    = _extract_token(auth)
        identity = authenticate_token(token) if token else None
        if not identity:
            return jsonify({'status': 'error', 'message': 'unauthorized'}), 401
        if identity['role'] != 'admin':
            return jsonify({'status': 'error', 'message': 'forbidden'}), 403
        return f(identity, *args, **kwargs)
    return decorated


# ── History ───────────────────────────────────────────────────────────────────

def _purge_old_history():
    with db_lock, db_connect() as conn:
        conn.execute("DELETE FROM history WHERE timestamp < datetime('now', ?)",
                     ('-{} days'.format(HISTORY_DAYS),))
        conn.commit()
    log.info('history purged: keeping last %d days', HISTORY_DAYS)


def history_log(operation, type_, target, details=None, comment=None, result='ok', performed_by=None):
    with db_lock, db_connect() as conn:
        conn.execute('INSERT INTO history (operation, type, target, details, comment, result, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (operation, type_, target,
                      json.dumps(details) if details else None, comment, result, performed_by))
        conn.commit()


def history_get(type_filter=None, operation_filter=None, date_from=None, date_to=None, limit=500):
    clauses, params = [], []
    if type_filter and type_filter != 'all':
        clauses.append('type = ?'); params.append(type_filter)
    if operation_filter and operation_filter != 'all':
        clauses.append('operation = ?'); params.append(operation_filter)
    if date_from:
        clauses.append('timestamp >= ?'); params.append(date_from)
    if date_to:
        clauses.append('timestamp <= ?'); params.append(date_to + ' 23:59:59')
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with db_lock, db_connect() as conn:
        rows = conn.execute(
            'SELECT * FROM history {} ORDER BY timestamp DESC LIMIT ?'.format(where),
            params + [limit]).fetchall()
    return [dict(r) for r in rows]


# ── Route DB ──────────────────────────────────────────────────────────────────

def db_upsert(prefix, nexthop, path_info, nexthop_name=None, comment=None, community=None, performed_by=None):
    with db_lock, db_connect() as conn:
        conn.execute('''INSERT INTO route_nexthops (prefix, nexthop, nexthop_name, path_info, comment, community, performed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(prefix, nexthop) DO UPDATE SET
                nexthop_name=excluded.nexthop_name, path_info=excluded.path_info,
                comment=excluded.comment, community=excluded.community,
                performed_by=excluded.performed_by, created_at=datetime('now')''',
                     (prefix, nexthop, nexthop_name, path_info, comment, community, performed_by))
        conn.commit()


def db_delete_one(prefix, nexthop):
    with db_lock, db_connect() as conn:
        conn.execute('DELETE FROM route_nexthops WHERE prefix=? AND nexthop=?', (prefix, nexthop))
        conn.commit()


def db_delete_prefix(prefix):
    with db_lock, db_connect() as conn:
        conn.execute('DELETE FROM route_nexthops WHERE prefix=?', (prefix,))
        conn.commit()


def db_all_routes():
    with db_lock, db_connect() as conn:
        rows = conn.execute(
            'SELECT prefix, nexthop, nexthop_name, path_info, comment, community, performed_by, created_at FROM route_nexthops ORDER BY prefix, path_info'
        ).fetchall()
    return [dict(r) for r in rows]


def db_get_one(prefix, nexthop):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM route_nexthops WHERE prefix=? AND nexthop=?', (prefix, nexthop)).fetchone()
    return dict(row) if row else None


def db_get_prefix(prefix):
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT * FROM route_nexthops WHERE prefix=? ORDER BY path_info', (prefix,)).fetchall()
    return [dict(r) for r in rows]


def db_rbth_insert(ip, comment=None, performed_by=None, communities=None):
    comm_json = json.dumps(communities) if communities else None
    with db_lock, db_connect() as conn:
        conn.execute("INSERT OR REPLACE INTO rbth_routes (ip, comment, performed_by, communities, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                     (ip, comment, performed_by, comm_json))
        conn.commit()


def db_rbth_delete(ip):
    with db_lock, db_connect() as conn:
        conn.execute('DELETE FROM rbth_routes WHERE ip=?', (ip,))
        conn.commit()


def db_rbth_all():
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT ip, comment, performed_by, communities, created_at FROM rbth_routes ORDER BY created_at').fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['communities'] = json.loads(d['communities']) if d.get('communities') else []
        result.append(d)
    return result


def db_rbth_get(ip):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM rbth_routes WHERE ip=?', (ip,)).fetchone()
    if not row: return None
    d = dict(row)
    d['communities'] = json.loads(d['communities']) if d.get('communities') else []
    return d


def db_flowspec_insert(source_ip, destination_ip, protocol, source_port,
                       destination_port, action, rate_limit_mbps, comment=None, performed_by=None):
    with db_lock, db_connect() as conn:
        # NULL-safe duplicate check: SQLite NULL != NULL, ON CONFLICT çalışmaz.
        # COALESCE ile NULL → '' yapıp mevcut kaydı sorgula, varsa UPDATE yok.
        existing = conn.execute(
            """SELECT id FROM flowspec_rules WHERE
               COALESCE(source_ip,'')=COALESCE(?,'') AND
               COALESCE(destination_ip,'')=COALESCE(?,'') AND
               COALESCE(protocol,'')=COALESCE(?,'') AND
               COALESCE(source_port,'')=COALESCE(?,'') AND
               COALESCE(destination_port,'')=COALESCE(?,'') AND
               action=?""",
            (source_ip, destination_ip, protocol, source_port, destination_port, action)
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE flowspec_rules SET rate_limit_mbps=?, comment=?,
                   performed_by=?, created_at=datetime('now') WHERE id=?""",
                (rate_limit_mbps, comment, performed_by, existing['id'])
            )
        else:
            conn.execute(
                """INSERT INTO flowspec_rules
                   (source_ip, destination_ip, protocol, source_port, destination_port,
                    action, rate_limit_mbps, comment, performed_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (source_ip, destination_ip, protocol, source_port, destination_port,
                 action, rate_limit_mbps, comment, performed_by)
            )
        conn.commit()


def db_flowspec_delete(rule_id):
    with db_lock, db_connect() as conn:
        conn.execute('DELETE FROM flowspec_rules WHERE id=?', (rule_id,))
        conn.commit()


def db_flowspec_all():
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT * FROM flowspec_rules ORDER BY created_at').fetchall()
    return [dict(r) for r in rows]


def db_flowspec_get(rule_id):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM flowspec_rules WHERE id=?', (rule_id,)).fetchone()
    return dict(row) if row else None


# ── Simple Route DB ───────────────────────────────────────────────────────────

def db_simple_insert(prefix, nexthop, local_pref=None, community=None,
                     as_path=None, med=None, origin=None, comment=None, performed_by=None):
    with db_lock, db_connect() as conn:
        conn.execute('''INSERT OR IGNORE INTO simple_routes
            (prefix, nexthop, local_pref, community, as_path, med, origin, comment, performed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))''',
            (prefix, nexthop, local_pref, community, as_path, med, origin, comment, performed_by))
        conn.commit()


def db_simple_update(prefix, nexthop, local_pref=None, community=None,
                     as_path=None, med=None, origin=None, comment=None):
    with db_lock, db_connect() as conn:
        conn.execute('''UPDATE simple_routes SET
            nexthop=?, local_pref=?, community=?, as_path=?, med=?, origin=?, comment=?, created_at=datetime('now')
            WHERE prefix=?''',
            (nexthop, local_pref, community, as_path, med, origin, comment, prefix))
        conn.commit()


def db_simple_delete(prefix):
    with db_lock, db_connect() as conn:
        conn.execute('DELETE FROM simple_routes WHERE prefix=?', (prefix,))
        conn.commit()


def db_simple_all():
    with db_lock, db_connect() as conn:
        rows = conn.execute('SELECT * FROM simple_routes ORDER BY created_at').fetchall()
    return [dict(r) for r in rows]


def db_simple_get(prefix):
    with db_lock, db_connect() as conn:
        row = conn.execute('SELECT * FROM simple_routes WHERE prefix=?', (prefix,)).fetchone()
    return dict(row) if row else None


# ── Flowspec builder ──────────────────────────────────────────────────────────

def build_flowspec_cmd(source_ip=None, destination_ip=None, protocol=None,
                       source_port=None, destination_port=None,
                       action='discard', rate_limit_mbps=None, **_):
    parts = []
    if source_ip:
        ip, err = normalize_ip(source_ip)
        if err: return None, 'source_ip: ' + err
        parts.append('source ' + ip)
    if destination_ip:
        ip, err = normalize_ip(destination_ip)
        if err: return None, 'destination_ip: ' + err
        parts.append('destination ' + ip)
    if not parts:
        return None, 'at least one of source_ip or destination_ip is required'
    if protocol:
        parts.append('protocol [ ' + protocol.lower() + ' ]')
    if source_port:
        parts.append('source-port [ =' + source_port + ' ]')
    if destination_port:
        parts.append('destination-port [ =' + destination_port + ' ]')
    if action == 'discard':
        parts.append('discard')
    elif action == 'rate-limit':
        if not rate_limit_mbps:
            return None, 'rate_limit_mbps required for rate-limit action'
        parts.append('rate-limit ' + str(int(float(rate_limit_mbps) * 125000)))
    else:
        return None, 'unknown action: ' + action
    return ' '.join(parts), None


def flowspec_announce(rule):
    cmd, err = build_flowspec_cmd(**rule)
    if err: raise ValueError(err)
    return exabgp_cmd('announce flow route ' + cmd)


def flowspec_withdraw(rule):
    cmd, err = build_flowspec_cmd(**rule)
    if err: raise ValueError(err)
    return exabgp_cmd('withdraw flow route ' + cmd)


def flowspec_target(rule):
    parts = []
    if rule.get('source_ip'):        parts.append('src:' + rule['source_ip'])
    if rule.get('destination_ip'):   parts.append('dst:' + rule['destination_ip'])
    if rule.get('protocol'):         parts.append(rule['protocol'])
    if rule.get('destination_port'): parts.append('dport:' + rule['destination_port'])
    if rule.get('source_port'):      parts.append('sport:' + rule['source_port'])
    return ' '.join(parts)


# ── ExaBGP ────────────────────────────────────────────────────────────────────

def exabgp_cmd(cmd_str):
    """ExaBGP 5.x named pipe iletisimi.
    ExaBGP pipe'i surekli acik tutmaz (polling yapar), bu yuzden
    blocking write/read thread ile yapilir; deadlock onlenir.
    """
    import select as _select
    if not os.path.exists(PIPE_IN) or not os.path.exists(PIPE_OUT):
        raise FileNotFoundError(f'ExaBGP pipes not found: {PIPE_IN}, {PIPE_OUT}')

    response = []
    write_error = []

    def do_write():
        try:
            with open(PIPE_IN, 'w') as f:
                f.write(cmd_str + '\n')
                f.flush()
        except Exception as e:
            write_error.append(e)

    def do_read():
        try:
            fd = os.open(PIPE_OUT, os.O_RDONLY | os.O_NONBLOCK)
            try:
                buf = ''
                deadline = time.time() + 5
                while time.time() < deadline:
                    ready = _select.select([fd], [], [], 0.2)
                    if ready[0]:
                        chunk = os.read(fd, 65536).decode(errors='replace')
                        buf += chunk
                        if 'done' in buf or 'error' in buf:
                            break
                response.append(buf)
            finally:
                os.close(fd)
        except Exception:
            response.append('')

    t_read  = threading.Thread(target=do_read,  daemon=True)
    t_write = threading.Thread(target=do_write, daemon=True)

    t_read.start()
    time.sleep(0.05)
    t_write.start()

    t_write.join(timeout=6)
    t_read.join(timeout=6)

    if write_error:
        raise write_error[0]
    return response[0] if response else ''


def bgp_session_established():
    if not os.path.exists(PIPE_IN) or not os.path.exists(PIPE_OUT):
        return False, False
    # 2 deneme yap — pipe bazen ilk okumada boş dönebilir
    for attempt in range(2):
        try:
            resp = exabgp_cmd('show neighbor summary')
            if resp and ('established' in resp.lower() or 'up' in resp.lower()):
                return True, True
            if resp and 'done' in resp.lower():
                # ExaBGP cevap verdi ama session yok
                return True, False
        except Exception:
            pass
        if attempt == 0:
            time.sleep(0.3)
    return True, False


def get_bgp_status():
    with _bgp_cache_lock:
        now = time.time()
        if _bgp_cache['checked_at'] is None or now - _bgp_cache['checked_at'] > BGP_CACHE_TTL:
            sock_ok, established = bgp_session_established()
            _bgp_cache['socket_available'] = sock_ok
            _bgp_cache['established']      = established
            _bgp_cache['checked_at']       = now
        return {
            'established':      _bgp_cache['established'],
            'socket_available': _bgp_cache['socket_available'],
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S',
                          time.localtime(_bgp_cache['checked_at']))
        }


def wait_for_bgp_established(reason=''):
    tag = '[{}] '.format(reason) if reason else ''
    deadline = time.time() + BGP_WAIT_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        sock_ok, established = bgp_session_established()
        if not sock_ok:
            log.info('%sExaBGP socket not available yet... (%ds left)', tag, int(deadline - time.time()))
        elif established:
            log.info('%sBGP session established (attempt %d)', tag, attempt)
            return True
        else:
            log.info('%sBGP not established yet... (%ds left)', tag, int(deadline - time.time()))
        time.sleep(BGP_POLL_INTERVAL)
    log.warning('%sBGP not established after %ds — announcing anyway', tag, BGP_WAIT_TIMEOUT)
    return False


def _prefix_version(prefix):
    """Return 4 or 6 based on prefix address family."""
    try:
        return ipaddress.ip_network(prefix, strict=False).version
    except ValueError:
        return 4  # fallback


def resolve_nexthop(nexthop, prefix):
    """If nexthop is a named entry with dual-stack, pick the right IP for the prefix family."""
    version = _prefix_version(prefix)
    for named in NAMED_NEXTHOPS:
        if named['ip'] == nexthop or named.get('ipv4') == nexthop or named.get('ipv6') == nexthop:
            # named match — pick by family
            if version == 6 and named.get('ipv6'):
                return named['ipv6']
            if version == 4 and named.get('ipv4'):
                return named['ipv4']
    return nexthop  # plain IP — use as-is


def announce_one(prefix, nexthop, path_info, community=None):
    nh  = resolve_nexthop(nexthop, prefix)
    cmd = 'announce route {} next-hop {} path-information {}'.format(prefix, nh, path_info)
    # Merge ROUTE_COMMUNITY default with per-entry community
    user_comm = (community or '').strip()
    if user_comm and ROUTE_COMMUNITY:
        effective_comm = ROUTE_COMMUNITY + ' ' + user_comm
    elif user_comm:
        effective_comm = user_comm
    else:
        effective_comm = ROUTE_COMMUNITY
    if effective_comm:
        cmd += ' community [{}]'.format(effective_comm)
    return exabgp_cmd(cmd)


def withdraw_one(prefix, nexthop, path_info):
    nh = resolve_nexthop(nexthop, prefix)
    return exabgp_cmd('withdraw route {} next-hop {} path-information {}'.format(
        prefix, nh, path_info))


def resolve_self(prefix):
    """Return the correct nexthop for 'self' based on prefix family.
    IPv6 prefix + IPV6_SELF configured → use IPV6_SELF, otherwise 'self'."""
    if _prefix_version(prefix) == 6 and IPV6_SELF:
        return IPV6_SELF
    return 'self'


def rbth_split_communities(communities):
    """Split selected ISP communities into standard (X:Y) and large (X:Y:Z) lists.
    Returns (standard_list, large_list) of community value strings.
    Unknown ISP names are silently skipped.
    """
    standard, large = [], []
    for name in communities:
        val = BLACKHOLE_COMMUNITIES.get(name)
        if not val:
            continue
        # Sayilan ':' karakter sayisi: 1 = standard (X:Y), 2 = large (X:Y:Z)
        colons = val.count(':')
        if colons == 2:
            large.append(val)
        elif colons == 1:
            standard.append(val)
        # diger formatlar sessizce skip — startup validation gerekirse ayri eklenir
    return standard, large


def rbth_community_clauses(communities):
    """Build ExaBGP community clauses for RBTH announce.
    Returns the trailing portion of the command (after 'next-hop X').
    - No ISPs selected → 'community [<RBTH_COMMUNITY>]'
    - Standard only    → 'community [a b c]'
    - Large only       → 'large-community [a b c]'
    - Mixed            → 'community [a] large-community [b c]'
    """
    if not communities:
        return 'community [{}]'.format(RBTH_COMMUNITY)
    standard, large = rbth_split_communities(communities)
    if not standard and not large:
        return 'community [{}]'.format(RBTH_COMMUNITY)
    parts = []
    if standard:
        parts.append('community [{}]'.format(' '.join(standard)))
    if large:
        parts.append('large-community [{}]'.format(' '.join(large)))
    return ' '.join(parts)


def rbth_community_string(communities):
    """Human-readable summary of effective communities for an RBTH entry.
    Used in API responses, history details, GUI badges/tooltips.
    Examples:
      []                     → '65001:666'
      ['cogent']             → '65001:174:666'
      ['cogent', 'gtt-old']  → '65001:174:666 3257:666'
    """
    if not communities:
        return RBTH_COMMUNITY
    standard, large = rbth_split_communities(communities)
    if not standard and not large:
        return RBTH_COMMUNITY
    return ' '.join(standard + large)


def rbth_announce(ip, communities=None):
    nh      = resolve_self(ip)
    clauses = rbth_community_clauses(communities or [])
    return exabgp_cmd('announce route {} next-hop {} {}'.format(ip, nh, clauses))


def rbth_withdraw(ip):
    """Withdraw RBTH — community doesn't matter for withdraw in ExaBGP 5.x."""
    nh = resolve_self(ip)
    return exabgp_cmd('withdraw route {} next-hop {}'.format(ip, nh))


def simple_announce(row):
    """Build and send ExaBGP command for a simple route. row is a dict."""
    prefix  = row['prefix']
    nexthop = row['nexthop']
    # Resolve 'self' to IPV6_SELF for IPv6 prefixes if configured
    if nexthop == 'self':
        nexthop = resolve_self(prefix)
    parts   = ['announce route', prefix, 'next-hop', nexthop]
    if row.get('local_pref') is not None:
        parts += ['local-preference', str(row['local_pref'])]
    # Merge SIMPLE_COMMUNITY default with user community at announce time
    user_comm = (row.get('community') or '').strip()
    if user_comm and SIMPLE_COMMUNITY:
        effective_comm = SIMPLE_COMMUNITY + ' ' + user_comm
    elif user_comm:
        effective_comm = user_comm
    else:
        effective_comm = SIMPLE_COMMUNITY
    if effective_comm:
        parts += ['community [{}]'.format(effective_comm)]
    if row.get('as_path'):
        parts += ['as-path [{}]'.format(row['as_path'])]
    if row.get('med') is not None:
        parts += ['med', str(row['med'])]
    if row.get('origin'):
        parts += ['origin', row['origin']]
    return exabgp_cmd(' '.join(parts))


def simple_withdraw(row):
    """Send ExaBGP withdraw for a simple route."""
    nexthop = row['nexthop']
    if nexthop == 'self':
        nexthop = resolve_self(row['prefix'])
    return exabgp_cmd('withdraw route {} next-hop {}'.format(row['prefix'], nexthop))



def reannounce_all(reason='startup'):
    routes    = db_all_routes()
    rbths     = db_rbth_all()
    flowspecs = db_flowspec_all()
    simples   = db_simple_all()
    if not routes and not rbths and not flowspecs and not simples:
        log.info('[%s] no routes in database', reason)
        return
    log.info('[%s] waiting for BGP before re-announcing %d route(s), %d RBTH(s), %d flowspec(s), %d simple(s)...',
             reason, len(routes), len(rbths), len(flowspecs), len(simples))
    wait_for_bgp_established(reason=reason)
    for row in routes:
        try:
            result = announce_one(row['prefix'], row['nexthop'], row['path_info'], row.get('community'))
            log.info('[%s] route %s nh=%s -> %s', reason, row['prefix'], row['nexthop'], result.strip())
        except Exception as e:
            log.error('[%s] route failed %s: %s', reason, row['prefix'], e)
    for row in rbths:
        try:
            result = rbth_announce(row['ip'], row.get('communities') or [])
            log.info('[%s] rbth %s communities=%s -> %s', reason, row['ip'], row.get('communities'), result.strip())
        except Exception as e:
            log.error('[%s] rbth failed %s: %s', reason, row['ip'], e)
    for row in flowspecs:
        try:
            result = flowspec_announce(row)
            log.info('[%s] flowspec id=%s -> %s', reason, row['id'], result.strip())
        except Exception as e:
            log.error('[%s] flowspec failed id=%s: %s', reason, row['id'], e)
    for row in simples:
        try:
            result = simple_announce(row)
            log.info('[%s] simple %s -> %s', reason, row['prefix'], result.strip())
        except Exception as e:
            log.error('[%s] simple failed %s: %s', reason, row['prefix'], e)


def socket_watchdog():
    """BGP session state izler.
    Pipe'lar host'ta kalıcı olduğu için pipe varlığına bakamayız.
    Bunun yerine: pipe erişilebilir mi + BGP session state geçişleri izlenir.
    established→down→established geçişinde reannounce tetiklenir.
    """
    log.info('socket watchdog started')
    bgp_was_established = None   # None = henüz bilinmiyor (ilk kontrol)
    pipe_was_reachable  = None

    while True:
        # Pipe erişilebilirlik testi — ENXIO = ExaBGP okumuyor
        pipe_reachable = False
        if os.path.exists(PIPE_IN) and os.path.exists(PIPE_OUT):
            try:
                fd = os.open(PIPE_IN, os.O_WRONLY | os.O_NONBLOCK)
                os.close(fd)
                pipe_reachable = True
            except OSError:
                pipe_reachable = False

        sock_ok, established = bgp_session_established() if pipe_reachable else (False, False)

        with _bgp_cache_lock:
            _bgp_cache['socket_available'] = pipe_reachable
            _bgp_cache['established']      = established
            _bgp_cache['checked_at']       = time.time()

        if pipe_reachable and not pipe_was_reachable and pipe_was_reachable is not None:
            # Pipe yeniden erişilebilir oldu → ExaBGP restart
            log.info('ExaBGP pipe reachable again — will reannounce after BGP comes up')
            threading.Thread(target=reannounce_all, kwargs={'reason': 'startup'},
                             daemon=True, name='reannounce-restart').start()
        elif pipe_reachable and bgp_was_established is False and established:
            # BGP down→established geçişi
            log.info('BGP session established — triggering reannounce')
            threading.Thread(target=reannounce_all, kwargs={'reason': 'bgp-recovery'},
                             daemon=True, name='reannounce-bgp-recovery').start()
        elif not pipe_reachable and pipe_was_reachable:
            log.warning('ExaBGP pipe lost — ExaBGP may have restarted')

        bgp_was_established = established
        pipe_was_reachable  = pipe_reachable
        time.sleep(5)


# ── Shared logic ──────────────────────────────────────────────────────────────

def _do_announce(data, performed_by=None):
    prefix  = data.get('prefix', '').strip()
    entries = data.get('entries', [])
    comment = (data.get('comment') or '').strip() or None
    if not prefix:  return {'status': 'error', 'message': 'prefix required'}, 400
    prefix, err = normalize_ip(prefix)
    if err: return {'status': 'error', 'message': 'prefix: ' + err}, 400
    if not entries: return {'status': 'error', 'message': 'at least one nexthop entry required'}, 400
    results = []
    for entry in entries:
        nexthop      = entry.get('nexthop', '').strip()
        path_info    = int(entry.get('path_info', 1))
        nexthop_name = entry.get('nexthop_name') or None
        community    = (entry.get('community') or '').strip() or None
        if not nexthop: continue
        result = announce_one(prefix, nexthop, path_info, community)
        db_upsert(prefix, nexthop, path_info, nexthop_name, comment, community, performed_by)
        history_log('announce', 'route', prefix,
                    {'nexthop': nexthop, 'path_info': path_info, 'nexthop_name': nexthop_name, 'community': community},
                    comment, 'ok', performed_by)
        results.append({'nexthop': nexthop, 'path_info': path_info, 'community': community, 'result': result.strip()})
    return {'status': 'ok', 'prefix': prefix, 'results': results}, 200


def _do_withdraw_one(data, performed_by=None):
    prefix  = data.get('prefix', '').strip()
    nexthop = data.get('nexthop', '').strip()
    comment = (data.get('comment') or '').strip() or None
    if not prefix or not nexthop:
        return {'status': 'error', 'message': 'prefix and nexthop required'}, 400
    row = db_get_one(prefix, nexthop)
    if not row: return {'status': 'error', 'message': 'entry not found'}, 404
    result = withdraw_one(prefix, nexthop, row['path_info'])
    db_delete_one(prefix, nexthop)
    history_log('withdraw', 'route', prefix, {'nexthop': nexthop, 'path_info': row['path_info']}, comment, 'ok', performed_by)
    return {'status': 'ok', 'prefix': prefix, 'nexthop': nexthop, 'result': result.strip()}, 200


def _do_withdraw_prefix(data, performed_by=None):
    prefix  = data.get('prefix', '').strip()
    comment = (data.get('comment') or '').strip() or None
    if not prefix: return {'status': 'error', 'message': 'prefix required'}, 400
    rows = db_get_prefix(prefix)
    if not rows: return {'status': 'error', 'message': 'no entries found'}, 404
    results = []
    for row in rows:
        try:
            result = withdraw_one(prefix, row['nexthop'], row['path_info'])
            results.append({'nexthop': row['nexthop'], 'result': result.strip()})
            history_log('withdraw', 'route', prefix,
                        {'nexthop': row['nexthop'], 'path_info': row['path_info']}, comment, 'ok')
        except Exception as e:
            results.append({'nexthop': row['nexthop'], 'error': str(e)})
    db_delete_prefix(prefix)
    return {'status': 'ok', 'prefix': prefix, 'results': results}, 200


def _do_rbth_announce(data, performed_by=None):
    ip          = data.get('ip', '').strip()
    comment     = (data.get('comment') or '').strip() or None
    communities = data.get('communities') or []   # list of ISP names
    if not ip: return {'status': 'error', 'message': 'ip required'}, 400

    # Validate ISP names
    if communities:
        unknown = [c for c in communities if c not in BLACKHOLE_COMMUNITIES]
        if unknown:
            return {'status': 'error', 'message': 'unknown blackhole communities: ' + ', '.join(unknown)}, 400

    # Auto-append host prefix if omitted, detect IPv4 vs IPv6
    if '/' not in ip:
        try:
            addr = ipaddress.ip_address(ip)
            ip = ip + ('/128' if addr.version == 6 else '/32')
        except ValueError:
            return {'status': 'error', 'message': 'invalid IP address'}, 400

    # Validate: must be a host route (/32 for IPv4, /128 for IPv6)
    try:
        net = ipaddress.ip_network(ip, strict=True)
    except ValueError:
        return {'status': 'error', 'message': 'RBTH requires exact host address (/32 for IPv4, /128 for IPv6)'}, 400
    if net.version == 4 and net.prefixlen != 32:
        return {'status': 'error', 'message': 'IPv4 RBTH requires /32 prefix'}, 400
    if net.version == 6 and net.prefixlen != 128:
        return {'status': 'error', 'message': 'IPv6 RBTH requires /128 prefix'}, 400
    ip = str(net)

    comm_str = rbth_community_string(communities)
    result   = rbth_announce(ip, communities)
    db_rbth_insert(ip, comment, performed_by, communities)
    history_log('announce', 'rbth', ip, {'community': comm_str, 'communities': communities}, comment, 'ok', performed_by)
    return {'status': 'ok', 'ip': ip, 'community': comm_str, 'communities': communities, 'result': result.strip()}, 200


def _do_rbth_withdraw(data, performed_by=None):
    ip      = data.get('ip', '').strip()
    comment = (data.get('comment') or '').strip() or None
    if not ip: return {'status': 'error', 'message': 'ip required'}, 400
    if '/' not in ip:
        try:
            addr = ipaddress.ip_address(ip)
            ip = ip + ('/128' if addr.version == 6 else '/32')
        except ValueError:
            return {'status': 'error', 'message': 'invalid IP address'}, 400
    row = db_rbth_get(ip)
    if not row: return {'status': 'error', 'message': 'RBTH entry not found'}, 404
    comm_str = rbth_community_string(row.get('communities') or [])
    result   = rbth_withdraw(ip)
    db_rbth_delete(ip)
    history_log('withdraw', 'rbth', ip, {'community': comm_str}, comment, 'ok', performed_by)
    return {'status': 'ok', 'ip': ip, 'result': result.strip()}, 200


def _do_flowspec_announce(data, performed_by=None):
    source_ip        = (data.get('source_ip')        or '').strip() or None
    destination_ip   = (data.get('destination_ip')   or '').strip() or None
    protocol         = (data.get('protocol')         or '').strip() or None
    source_port      = (data.get('source_port')      or '').strip() or None
    destination_port = (data.get('destination_port') or '').strip() or None
    action           = data.get('action') or 'discard'
    rate_limit_mbps  = data.get('rate_limit_mbps') or None
    comment          = (data.get('comment') or '').strip() or None
    if source_ip:
        source_ip, err = normalize_ip(source_ip)
        if err: return {'status': 'error', 'message': 'source_ip: ' + err}, 400
    if destination_ip:
        destination_ip, err = normalize_ip(destination_ip)
        if err: return {'status': 'error', 'message': 'destination_ip: ' + err}, 400
    # Validation: source ve destination ikisi birden "any" olamaz
    _any = {'0.0.0.0/0', '::/0'}
    if source_ip in _any and destination_ip in _any:
        return {'status': 'error', 'message': 'source and destination cannot both be any (0.0.0.0/0 or ::/0)'}, 400
    rule = dict(source_ip=source_ip, destination_ip=destination_ip, protocol=protocol,
                source_port=source_port, destination_port=destination_port,
                action=action, rate_limit_mbps=rate_limit_mbps)
    try:
        result = flowspec_announce(rule)
    except ValueError as e:
        return {'status': 'error', 'message': str(e)}, 400
    db_flowspec_insert(source_ip, destination_ip, protocol, source_port,
                       destination_port, action, rate_limit_mbps, comment, performed_by)
    rows = db_flowspec_all()
    inserted = next((r for r in reversed(rows)
                     if r['source_ip'] == source_ip
                     and r['destination_ip'] == destination_ip
                     and r['action'] == action), None)
    history_log('announce', 'flowspec', flowspec_target(rule), rule, comment, 'ok', performed_by)
    return {'status': 'ok', 'rule': inserted, 'result': result.strip()}, 200


def _do_flowspec_withdraw(data, performed_by=None):
    rule_id = data.get('id')
    comment = (data.get('comment') or '').strip() or None
    if not rule_id: return {'status': 'error', 'message': 'id required'}, 400
    row = db_flowspec_get(int(rule_id))
    if not row: return {'status': 'error', 'message': 'flowspec rule not found'}, 404
    try:
        result = flowspec_withdraw(row)
    except ValueError as e:
        return {'status': 'error', 'message': str(e)}, 400
    db_flowspec_delete(int(rule_id))
    history_log('withdraw', 'flowspec', flowspec_target(row), dict(row), comment, 'ok', performed_by)
    return {'status': 'ok', 'id': rule_id, 'result': result.strip()}, 200




def _do_routes_export():
    """Export all routes, RBTH entries, flowspec rules, and simple routes as JSON."""
    routes    = db_all_routes()
    rbths     = db_rbth_all()
    flowspecs = db_flowspec_all()
    simples   = db_simple_all()
    return {
        'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'routes':   {'count': len(routes),    'entries': routes},
        'rbth':     {'count': len(rbths),     'entries': rbths},
        'flowspec': {'count': len(flowspecs), 'entries': flowspecs},
        'simple':   {'count': len(simples),   'entries': simples},
    }


def _do_routes_import(data, performed_by=None):
    """
    Import routes, RBTH entries, and flowspec rules from JSON.
    Each entry is upserted into DB and re-announced to ExaBGP.
    """
    summary = {
        'routes':   {'imported': 0, 'failed': 0, 'skipped': 0, 'details': []},
        'rbth':     {'imported': 0, 'failed': 0, 'skipped': 0, 'details': []},
        'flowspec': {'imported': 0, 'failed': 0, 'skipped': 0, 'details': []},
    }

    # ── Routes ────────────────────────────────────────────────────────────────
    for entry in data.get('routes', {}).get('entries', []):
        prefix       = (entry.get('prefix') or '').strip()
        nexthop      = (entry.get('nexthop') or '').strip()
        path_info    = int(entry.get('path_info') or 1)
        nexthop_name = entry.get('nexthop_name') or None
        comment      = entry.get('comment') or None
        community    = (entry.get('community') or '').strip() or None
        s = summary['routes']
        if not prefix or not nexthop:
            s['skipped'] += 1; continue
        try:
            result = announce_one(prefix, nexthop, path_info, community)
            db_upsert(prefix, nexthop, path_info, nexthop_name, comment, community, performed_by)
            history_log('announce', 'route', prefix,
                        {'nexthop': nexthop, 'path_info': path_info,
                         'community': community, 'via': 'import'}, comment, 'ok', performed_by)
            s['imported'] += 1
            s['details'].append({'prefix': prefix, 'nexthop': nexthop, 'status': 'ok', 'result': result.strip()})
        except Exception as e:
            s['failed'] += 1
            s['details'].append({'prefix': prefix, 'nexthop': nexthop, 'status': 'error', 'error': str(e)})

    # ── RBTH ──────────────────────────────────────────────────────────────────
    for entry in data.get('rbth', {}).get('entries', []):
        ip          = (entry.get('ip') or '').strip()
        comment     = entry.get('comment') or None
        communities = entry.get('communities') or []
        # Validate communities — skip unknowns silently on import
        communities = [c for c in communities if c in BLACKHOLE_COMMUNITIES]
        s = summary['rbth']
        if not ip:
            s['skipped'] += 1; continue
        if '/' not in ip: ip = ip + '/32'
        if not ip.endswith('/32') and not ip.endswith('/128'):
            s['skipped'] += 1; continue
        comm_str = rbth_community_string(communities)
        try:
            result = rbth_announce(ip, communities)
            db_rbth_insert(ip, comment, performed_by, communities)
            history_log('announce', 'rbth', ip, {'community': comm_str, 'communities': communities, 'via': 'import'}, comment, 'ok', performed_by)
            s['imported'] += 1
            s['details'].append({'ip': ip, 'status': 'ok', 'result': result.strip()})
        except Exception as e:
            s['failed'] += 1
            s['details'].append({'ip': ip, 'status': 'error', 'error': str(e)})

    # ── Flowspec ──────────────────────────────────────────────────────────────
    for entry in data.get('flowspec', {}).get('entries', []):
        source_ip        = (entry.get('source_ip')        or '').strip() or None
        destination_ip   = (entry.get('destination_ip')   or '').strip() or None
        protocol         = (entry.get('protocol')         or '').strip() or None
        source_port      = (entry.get('source_port')      or '').strip() or None
        destination_port = (entry.get('destination_port') or '').strip() or None
        action           = entry.get('action') or 'discard'
        rate_limit_mbps  = entry.get('rate_limit_mbps') or None
        comment          = entry.get('comment') or None
        s = summary['flowspec']
        if not source_ip and not destination_ip:
            s['skipped'] += 1; continue
        rule = dict(source_ip=source_ip, destination_ip=destination_ip,
                    protocol=protocol, source_port=source_port,
                    destination_port=destination_port, action=action,
                    rate_limit_mbps=rate_limit_mbps)
        try:
            result = flowspec_announce(rule)
            db_flowspec_insert(source_ip, destination_ip, protocol, source_port,
                               destination_port, action, rate_limit_mbps, comment, performed_by)
            history_log('announce', 'flowspec', flowspec_target(rule),
                        dict(rule, via='import'), comment, 'ok', performed_by)
            s['imported'] += 1
            s['details'].append({'target': flowspec_target(rule), 'status': 'ok', 'result': result.strip()})
        except Exception as e:
            s['failed'] += 1
            s['details'].append({'target': flowspec_target(rule), 'status': 'error', 'error': str(e)})

    # ── Simple Routes ─────────────────────────────────────────────────────────
    summary['simple'] = {'imported': 0, 'failed': 0, 'skipped': 0, 'details': []}
    for entry in data.get('simple', {}).get('entries', []):
        prefix     = (entry.get('prefix') or '').strip()
        nexthop    = (entry.get('nexthop') or '').strip()
        local_pref = entry.get('local_pref') or None
        community  = (entry.get('community') or '').strip() or None
        as_path    = (entry.get('as_path') or '').strip() or None
        med        = entry.get('med') or None
        origin     = (entry.get('origin') or '').strip() or None
        comment    = entry.get('comment') or None
        s = summary['simple']
        if not prefix or not nexthop:
            s['skipped'] += 1; continue
        # INSERT OR IGNORE: skip if prefix already exists
        existing = db_simple_get(prefix)
        if existing:
            s['skipped'] += 1
            s['details'].append({'prefix': prefix, 'status': 'skipped', 'reason': 'already exists'})
            continue
        row = dict(prefix=prefix, nexthop=nexthop, local_pref=local_pref,
                   community=community, as_path=as_path, med=med, origin=origin)
        try:
            result = simple_announce(row)
            db_simple_insert(prefix, nexthop, local_pref, community, as_path, med, origin, comment)
            history_log('announce', 'simple_route', prefix,
                        dict(row, via='import'), comment, 'ok')
            s['imported'] += 1
            s['details'].append({'prefix': prefix, 'status': 'ok', 'result': result.strip()})
        except Exception as e:
            s['failed'] += 1
            s['details'].append({'prefix': prefix, 'status': 'error', 'error': str(e)})

    total_imported = sum(summary[k]['imported'] for k in summary)
    total_failed   = sum(summary[k]['failed']   for k in summary)
    return {
        'status':   'ok',
        'imported': total_imported,
        'failed':   total_failed,
        'summary':  summary,
    }, 200

def _do_simple_announce(data, performed_by=None):
    prefix     = (data.get('prefix') or '').strip()
    nexthop    = (data.get('nexthop') or '').strip()
    local_pref = data.get('local_pref') or None
    community  = (data.get('community') or '').strip() or None
    as_path    = (data.get('as_path') or '').strip() or None
    med        = data.get('med') or None
    origin     = (data.get('origin') or '').strip() or None
    comment    = (data.get('comment') or '').strip() or None
    is_edit    = data.get('edit', False)

    if not prefix: return {'status': 'error', 'message': 'prefix required'}, 400
    prefix, err = normalize_ip(prefix)
    if err: return {'status': 'error', 'message': 'prefix: ' + err}, 400
    if not nexthop: return {'status': 'error', 'message': 'nexthop required'}, 400

    # Normalize numeric fields
    try: local_pref = int(local_pref) if local_pref is not None else None
    except (ValueError, TypeError): return {'status': 'error', 'message': 'local_pref must be integer'}, 400
    try: med = int(med) if med is not None else None
    except (ValueError, TypeError): return {'status': 'error', 'message': 'med must be integer'}, 400
    if origin and origin not in ('IGP', 'EGP', 'INCOMPLETE'):
        return {'status': 'error', 'message': 'origin must be IGP, EGP, or INCOMPLETE'}, 400

    existing = db_simple_get(prefix)
    if existing and not is_edit:
        return {'status': 'error', 'message': 'prefix already announced — use edit to update'}, 409

    row = dict(prefix=prefix, nexthop=nexthop, local_pref=local_pref,
               community=community, as_path=as_path, med=med, origin=origin)

    if is_edit and existing:
        # Withdraw old first
        try: simple_withdraw(existing)
        except Exception: pass
        result = simple_announce(row)
        db_simple_update(prefix, nexthop, local_pref, community, as_path, med, origin, comment)
        history_log('edit', 'simple_route', prefix, row, comment, 'ok', performed_by)
    else:
        result = simple_announce(row)
        db_simple_insert(prefix, nexthop, local_pref, community, as_path, med, origin, comment, performed_by)
        history_log('announce', 'simple_route', prefix, row, comment, 'ok', performed_by)

    return {'status': 'ok', 'prefix': prefix, 'result': result.strip()}, 200


def _do_simple_withdraw(data, performed_by=None):
    prefix  = (data.get('prefix') or '').strip()
    comment = (data.get('comment') or '').strip() or None
    if not prefix: return {'status': 'error', 'message': 'prefix required'}, 400
    row = db_simple_get(prefix)
    if not row: return {'status': 'error', 'message': 'simple route not found'}, 404
    result = simple_withdraw(row)
    db_simple_delete(prefix)
    history_log('withdraw', 'simple_route', prefix, {'nexthop': row['nexthop']}, comment, 'ok', performed_by)
    return {'status': 'ok', 'prefix': prefix, 'result': result.strip()}, 200


# ── GUI routes ────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        identity = authenticate_user(username, password)
        if identity:
            session['logged_in'] = True
            session['username']  = identity['username']
            session['role']      = identity['role']
            return redirect(url_for('index'))
        error = 'Invalid username or password'
    return _login_page(error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@require_session
def index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/history')
@require_session
def history_page():
    return send_from_directory(app.static_folder, 'history.html')


@app.route('/admin')
@require_admin_session
def admin_page():
    return send_from_directory(app.static_folder, 'admin.html')


@app.route('/me')
@require_session
def gui_me():
    return jsonify({'username': session.get('username'), 'role': session.get('role')})


@app.route('/api/me')
@require_token
def api_me(identity):
    """Get current token identity
    ---
    tags: [Auth]
    security: [{Bearer: []}]
    responses:
      200:
        description: Token identity
        schema:
          properties:
            username: {type: string}
            role: {type: string, enum: [admin, readonly]}
    """
    return jsonify(identity)


# ── REST API — read ───────────────────────────────────────────────────────────

@app.route('/api/status',    methods=['GET'])
@require_token
def api_status(identity):
    """BGP session status
    ---
    tags: [Status]
    security: [{Bearer: []}]
    responses:
      200:
        description: BGP status
        schema:
          properties:
            established: {type: boolean}
            socket_available: {type: boolean}
            checked_at: {type: string}
            poll_interval: {type: integer, description: "BGP poll interval in seconds"}
    """
    status = get_bgp_status()
    status['poll_interval'] = BGP_POLL_INTERVAL
    return jsonify(status)


@app.route('/api/nexthops',  methods=['GET'])
@require_token
def api_nexthops(identity):
    """List named next-hops
    ---
    tags: [Status]
    security: [{Bearer: []}]
    responses:
      200:
        description: Named next-hops with IPv4/IPv6 and path-information
    """
    return jsonify({'nexthops': NAMED_NEXTHOPS, 'route_community': ROUTE_COMMUNITY})


@app.route('/api/simple-routes', methods=['GET'])
@require_token
def api_simple_routes_list(identity):
    """List simple routes
    ---
    tags: [Simple Routes]
    security: [{Bearer: []}]
    responses:
      200:
        description: All active simple routes and default community
    """
    return jsonify({'simple_routes': db_simple_all(), 'default_community': SIMPLE_COMMUNITY})



@app.route('/api/routes',    methods=['GET'])
@require_token
def api_routes_list(identity):
    """List multi-nexthop routes
    ---
    tags: [Routes]
    security: [{Bearer: []}]
    responses:
      200:
        description: All active multi-nexthop routes
    """
    return jsonify({'routes': db_all_routes()})


@app.route('/api/blackhole-communities', methods=['GET'])
@require_token
def api_blackhole_communities(identity):
    """List ISP blackhole communities from .env
    ---
    tags: [RBTH]
    security: [{Bearer: []}]
    responses:
      200:
        description: Available ISP blackhole communities (standard X:Y or large X:Y:Z)
        schema:
          properties:
            communities:
              type: object
              description: "ISP name → community string. Standard format (X:Y) emits as `community [...]`, large format (X:Y:Z) emits as `large-community [...]`. Mix is allowed."
              example: {"cogent": "65001:174:666", "gtt": "65001:3257:666", "legacy": "3257:666"}
            default_community:
              type: string
              example: "65001:666"
    """
    return jsonify({'communities': BLACKHOLE_COMMUNITIES, 'default_community': RBTH_COMMUNITY})


@app.route('/api/rbth',      methods=['GET'])
@require_token
def api_rbth_list(identity):
    """List RBTH blackhole routes
    ---
    tags: [RBTH]
    security: [{Bearer: []}]
    responses:
      200:
        description: Active RBTH routes with community and ISP breakdown
    """
    return jsonify({'community': RBTH_COMMUNITY, 'blackhole_communities': BLACKHOLE_COMMUNITIES, 'routes': db_rbth_all()})


@app.route('/api/flowspec',  methods=['GET'])
@require_token
def api_flowspec_list(identity):
    """List flowspec rules
    ---
    tags: [Flowspec]
    security: [{Bearer: []}]
    responses:
      200:
        description: Active flowspec rules
    """
    return jsonify({'rules': db_flowspec_all()})


@app.route('/api/history',   methods=['GET'])
@require_token
def api_history(identity):
    """Operation history
    ---
    tags: [History]
    security: [{Bearer: []}]
    parameters:
      - {name: type, in: query, type: string, enum: [route, rbth, flowspec, simple_route]}
      - {name: operation, in: query, type: string, enum: [announce, withdraw, edit]}
      - {name: from, in: query, type: string, description: "YYYY-MM-DD"}
      - {name: to, in: query, type: string, description: "YYYY-MM-DD"}
      - {name: limit, in: query, type: integer, default: 500}
    responses:
      200:
        description: History records with performed_by field
    """
    rows = history_get(
        type_filter      = request.args.get('type'),
        operation_filter = request.args.get('operation'),
        date_from        = request.args.get('from'),
        date_to          = request.args.get('to'),
        limit            = int(request.args.get('limit', 500)))
    return jsonify({'count': len(rows), 'history': rows})


# ── REST API — write (admin token only) ───────────────────────────────────────

@app.route('/api/announce',          methods=['POST'])
@require_admin_token
def api_announce(identity):
    """Announce multi-nexthop route
    ---
    tags: [Routes]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [prefix, entries]
          properties:
            prefix: {type: string, example: "10.0.0.0/24"}
            entries:
              type: array
              items:
                properties:
                  nexthop: {type: string, example: "10.103.7.2"}
                  nexthop_name: {type: string, example: "ddos1"}
                  path_info: {type: integer, example: 1}
                  community: {type: string, example: "64000:400"}
            comment: {type: string}

    responses:
      200: {description: Announced}
      400: {description: Invalid input}
    """
    body, code = _do_announce(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/withdraw',          methods=['POST'])
@require_admin_token
def api_withdraw(identity):
    """Withdraw single next-hop
    ---
    tags: [Routes]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [prefix, nexthop]
          properties:
            prefix: {type: string, example: "10.0.0.0/24"}
            nexthop: {type: string, example: "10.103.7.2"}
            comment: {type: string}

    responses:
      200: {description: Withdrawn}
      404: {description: Not found}
    """
    body, code = _do_withdraw_one(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/withdraw/all',      methods=['POST'])
@require_admin_token
def api_withdraw_all(identity):
    """Withdraw all next-hops for a prefix
    ---
    tags: [Routes]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [prefix]
          properties:
            prefix: {type: string, example: "10.0.0.0/24"}
            comment: {type: string}

    responses:
      200: {description: All next-hops withdrawn}
      404: {description: Prefix not found}
    """
    body, code = _do_withdraw_prefix(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/rbth/announce',     methods=['POST'])
@require_admin_token
def api_rbth_announce(identity):
    """Announce RBTH blackhole
    ---
    tags: [RBTH]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [ip]
          properties:
            ip: {type: string, example: "10.30.1.1", description: "/32 or /128 added automatically"}
            communities:
              type: array
              items: {type: string}
              description: "ISP names from BLACKHOLE_* env vars. Each value may be standard (X:Y) or large (X:Y:Z); mixed selections emit both community and large-community blocks. Empty list = use default RBTH_COMMUNITY."
            comment: {type: string}

    responses:
      200: {description: Blackhole active}
      400: {description: Invalid IP or unknown community name}
    """
    body, code = _do_rbth_announce(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/rbth/withdraw',     methods=['POST'])
@require_admin_token
def api_rbth_withdraw(identity):
    """Withdraw RBTH blackhole
    ---
    tags: [RBTH]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [ip]
          properties:
            ip: {type: string, example: "10.30.1.1"}
            comment: {type: string}

    responses:
      200: {description: Withdrawn}
      404: {description: Not found}
    """
    body, code = _do_rbth_withdraw(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/flowspec/announce', methods=['POST'])
@require_admin_token
def api_flowspec_announce(identity):
    """Announce flowspec rule
    ---
    tags: [Flowspec]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [action]
          properties:
            source_ip: {type: string, example: "10.10.10.0/24", description: "Cannot be 0.0.0.0/0 if destination is also 0.0.0.0/0"}
            destination_ip: {type: string, example: "10.20.20.0/24"}
            protocol: {type: string, enum: [tcp, udp]}
            source_port: {type: string, example: "80"}
            destination_port: {type: string, example: "53"}
            action: {type: string, enum: [discard, rate-limit], example: "discard"}
            rate_limit_mbps: {type: number, example: 100, description: "Required when action is rate-limit"}
            comment: {type: string}

    responses:
      200: {description: Rule active}
      400: {description: Invalid input or both source and destination are any}
    """
    body, code = _do_flowspec_announce(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/flowspec/withdraw', methods=['POST'])
@require_admin_token
def api_flowspec_withdraw(identity):
    """Withdraw flowspec rule
    ---
    tags: [Flowspec]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [id]
          properties:
            id: {type: integer, example: 1}
            comment: {type: string}

    responses:
      200: {description: Withdrawn}
      404: {description: Rule not found}
    """
    body, code = _do_flowspec_withdraw(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/announce/simple',  methods=['POST'])
@require_admin_token
def api_simple_announce(identity):
    """Announce simple route
    ---
    tags: [Simple Routes]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [prefix, nexthop]
          properties:
            prefix: {type: string, example: "10.50.0.0/24"}
            nexthop: {type: string, example: "self", description: "IP address or 'self'"}
            local_pref: {type: integer, example: 200}
            community: {type: string, example: "64000:400", description: "Space-separated for multiple"}
            as_path: {type: string, example: "65001 65002"}
            med: {type: integer, example: 50}
            origin: {type: string, enum: [IGP, EGP, INCOMPLETE]}
            comment: {type: string}
            edit: {type: boolean, description: "Set true to update existing prefix"}

    responses:
      200: {description: Announced}
      400: {description: Invalid input}
    """
    body, code = _do_simple_announce(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/withdraw/simple',  methods=['POST'])
@require_admin_token
def api_simple_withdraw(identity):
    """Withdraw simple route
    ---
    tags: [Simple Routes]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [prefix]
          properties:
            prefix: {type: string, example: "10.50.0.0/24"}
            comment: {type: string}

    responses:
      200: {description: Withdrawn}
      404: {description: Not found}
    """
    body, code = _do_simple_withdraw(request.json or {}, performed_by=identity['username'])
    return jsonify(body), code


@app.route('/api/reannounce',        methods=['POST'])
@require_admin_token
def api_reannounce(identity):
    """Re-announce all routes from database
    ---
    tags: [Status]
    security: [{Bearer: []}]
    responses:
      200:
        description: Re-announce triggered
        schema:
          properties:
            status: {type: string}
            routes: {type: integer}
            rbths: {type: integer}
            flowspecs: {type: integer}
            simples: {type: integer}
    """
    threading.Thread(target=reannounce_all, kwargs={'reason': 'manual-api'},
                     daemon=True, name='reannounce-manual').start()
    return jsonify({'status': 'ok', 'routes': len(db_all_routes()),
                    'rbths': len(db_rbth_all()), 'flowspecs': len(db_flowspec_all()),
                    'simples': len(db_simple_all())})




@app.route('/api/routes/export',  methods=['GET'])
@require_token
def api_routes_export(identity):
    """Export all routes as JSON
    ---
    tags: [Export/Import]
    security: [{Bearer: []}]
    produces: [application/json]
    responses:
      200:
        description: JSON file with all routes, RBTH, flowspec, simple routes
    """
    from flask import Response
    payload = _do_routes_export()
    return Response(
        json.dumps(payload, indent=2), mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=exabgp-routes-{}.json'.format(
            time.strftime('%Y%m%d'))})


@app.route('/api/routes/import',  methods=['POST'])
@require_admin_token
def api_routes_import(identity):
    """Import routes from JSON
    ---
    tags: [Export/Import]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        description: JSON exported from /api/routes/export. Duplicate entries are skipped.
        schema:
          properties:
            routes: {type: object}
            rbth: {type: object}
            flowspec: {type: object}
            simple: {type: object}
    responses:
      200: {description: Import summary}
      400: {description: Invalid JSON}
    """
    body, code = _do_routes_import(request.json or {})
    return jsonify(body), code

# ── Admin API — users ─────────────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@require_admin_token
def api_admin_users_list(identity):
    """List all users
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    responses:
      200: {description: User list including env admin}
    """
    users = [{'id': 0, 'username': ADMIN_USERNAME, 'role': 'admin', 'created_at': '-', 'is_env': True}]
    users += [dict(u, is_env=False) for u in db_user_all()]
    return jsonify({'users': users})


@app.route('/api/admin/users', methods=['POST'])
@require_admin_token
def api_admin_users_create(identity):
    """Create user
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [username, password]
          properties:
            username: {type: string}
            password: {type: string}
            role: {type: string, enum: [admin, readonly], default: readonly}

    responses:
      201: {description: User created}
      409: {description: Username already exists}
    """
    data     = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'readonly')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'username and password required'}), 400
    if role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'role must be admin or readonly'}), 400
    if username == ADMIN_USERNAME:
        return jsonify({'status': 'error', 'message': 'cannot use env admin username'}), 409
    user = db_user_create(username, password, role)
    if not user:
        return jsonify({'status': 'error', 'message': 'username already exists'}), 409
    return jsonify({'status': 'ok', 'user': {k: user[k] for k in ('id', 'username', 'role', 'created_at')}}), 201


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_admin_token
def api_admin_users_update(identity, user_id):
    """Update user password or role
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - {name: user_id, in: path, type: integer, required: true}
      - in: body
        name: body
        schema:
          properties:
            password: {type: string}
            role: {type: string, enum: [admin, readonly]}

    responses:
      200: {description: Updated}
      404: {description: User not found}
    """
    data     = request.json or {}
    password = data.get('password', '').strip() or None
    role     = data.get('role') or None
    if role and role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'invalid role'}), 400
    if not db_user_update(user_id, password, role):
        return jsonify({'status': 'error', 'message': 'user not found or nothing to update'}), 404
    return jsonify({'status': 'ok'})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin_token
def api_admin_users_delete(identity, user_id):
    """Delete user
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - {name: user_id, in: path, type: integer, required: true}
    responses:
      200: {description: Deleted}
      404: {description: User not found}
    """
    if not db_user_delete(user_id):
        return jsonify({'status': 'error', 'message': 'user not found'}), 404
    return jsonify({'status': 'ok'})


# ── Admin API — tokens ────────────────────────────────────────────────────────

@app.route('/api/admin/tokens', methods=['GET'])
@require_admin_token
def api_admin_tokens_list(identity):
    """List all API tokens
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    responses:
      200: {description: Token list (hashed values not exposed)}
    """
    tokens = [{'id': 0, 'name': 'env-admin-token', 'role': 'admin', 'created_at': '-', 'is_env': True}]
    tokens += [dict(t, is_env=False) for t in db_token_all()]
    return jsonify({'tokens': tokens})


@app.route('/api/admin/tokens', methods=['POST'])
@require_admin_token
def api_admin_tokens_create(identity):
    """Create API token
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          required: [name]
          properties:
            name: {type: string, example: "automation-script"}
            role: {type: string, enum: [admin, readonly], default: readonly}

    responses:
      201:
        description: Token created — value shown once, store immediately
      409: {description: Name already exists}
    """
    data = request.json or {}
    name = data.get('name', '').strip()
    role = data.get('role', 'readonly')
    if not name:
        return jsonify({'status': 'error', 'message': 'name required'}), 400
    if role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'invalid role'}), 400
    token  = generate_token()
    result = db_token_create(name, token, role)
    if not result:
        return jsonify({'status': 'error', 'message': 'token name already exists'}), 409
    return jsonify({'status': 'ok', 'token': token, 'meta': result}), 201


@app.route('/api/admin/tokens/<int:token_id>', methods=['DELETE'])
@require_admin_token
def api_admin_tokens_delete(identity, token_id):
    """Revoke API token
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - {name: token_id, in: path, type: integer, required: true}
    responses:
      200: {description: Revoked}
      404: {description: Token not found}
    """
    if not db_token_delete(token_id):
        return jsonify({'status': 'error', 'message': 'token not found'}), 404
    return jsonify({'status': 'ok'})


# ── Admin API — export/import ─────────────────────────────────────────────────

@app.route('/api/admin/export', methods=['GET'])
@require_admin_token
def api_admin_export(identity):
    """Export users and tokens as JSON
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    produces: [application/json]
    responses:
      200: {description: Users and tokens JSON (passwords/tokens are hashed)}
    """
    with db_lock, db_connect() as conn:
        users  = [dict(r) for r in conn.execute(
            'SELECT username, password_hash, role, created_at FROM users').fetchall()]
        tokens = [dict(r) for r in conn.execute(
            'SELECT name, token_hash, role, created_at FROM tokens').fetchall()]
    payload = {
        'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'note': 'passwords and tokens are hashed',
        'users': users, 'tokens': tokens
    }
    from flask import Response
    return Response(
        json.dumps(payload, indent=2), mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=exabgp-users-{}.json'.format(
            time.strftime('%Y%m%d'))})


@app.route('/api/admin/import', methods=['POST'])
@require_admin_token
def api_admin_import(identity):
    """Import users and tokens from JSON
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        description: JSON exported from /api/admin/export
        schema:
          properties:
            users: {type: array}
            tokens: {type: array}
    responses:
      200: {description: Import summary}
    """
    data = request.json or {}
    users  = data.get('users',  [])
    tokens = data.get('tokens', [])
    imp_u = imp_t = skip_u = skip_t = 0
    with db_lock, db_connect() as conn:
        for u in users:
            username = u.get('username', '').strip()
            pw_hash  = u.get('password_hash', '').strip()
            role     = u.get('role', 'readonly')
            if not username or not pw_hash or username == ADMIN_USERNAME:
                skip_u += 1; continue
            conn.execute('''INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash, role=excluded.role''',
                (username, pw_hash, role, u.get('created_at', time.strftime('%Y-%m-%d %H:%M:%S'))))
            imp_u += 1
        for t in tokens:
            name       = t.get('name', '').strip()
            token_hash = t.get('token_hash', '').strip()
            role       = t.get('role', 'readonly')
            if not name or not token_hash:
                skip_t += 1; continue
            conn.execute('''INSERT INTO tokens (name, token_hash, role, created_at)
                VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET
                token_hash=excluded.token_hash, role=excluded.role''',
                (name, token_hash, role, t.get('created_at', time.strftime('%Y-%m-%d %H:%M:%S'))))
            imp_t += 1
        conn.commit()
    return jsonify({'status': 'ok', 'imported_users': imp_u, 'imported_tokens': imp_t,
                    'skipped_users': skip_u, 'skipped_tokens': skip_t})


# ── GUI-internal — session ────────────────────────────────────────────────────

@app.route('/status',            methods=['GET'])
@require_session
def gui_status():
    return jsonify(get_bgp_status())


@app.route('/nexthops',          methods=['GET'])
@require_session
def gui_nexthops():
    return jsonify({'nexthops': NAMED_NEXTHOPS, 'route_community': ROUTE_COMMUNITY})


@app.route('/routes',            methods=['GET'])
@require_session
def gui_list_routes():
    return jsonify({'routes': db_all_routes()})


@app.route('/rbth',              methods=['GET'])
@require_session
def gui_rbth_list():
    return jsonify({'community': RBTH_COMMUNITY, 'blackhole_communities': BLACKHOLE_COMMUNITIES, 'routes': db_rbth_all()})


@app.route('/flowspec',          methods=['GET'])
@require_session
def gui_flowspec_list():
    return jsonify({'rules': db_flowspec_all()})


@app.route('/history/data',      methods=['GET'])
@require_session
def gui_history():
    rows = history_get(
        type_filter      = request.args.get('type'),
        operation_filter = request.args.get('operation'),
        date_from        = request.args.get('from'),
        date_to          = request.args.get('to'),
        limit            = int(request.args.get('limit', 500)))
    return jsonify({'count': len(rows), 'history': rows})


@app.route('/announce',          methods=['POST'])
@require_admin_session
def gui_announce():
    body, code = _do_announce(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/withdraw',          methods=['POST'])
@require_admin_session
def gui_withdraw():
    body, code = _do_withdraw_one(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/withdraw/all',      methods=['POST'])
@require_admin_session
def gui_withdraw_all():
    body, code = _do_withdraw_prefix(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/rbth/announce',     methods=['POST'])
@require_admin_session
def gui_rbth_announce():
    body, code = _do_rbth_announce(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/rbth/withdraw',     methods=['POST'])
@require_admin_session
def gui_rbth_withdraw():
    body, code = _do_rbth_withdraw(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/flowspec/announce', methods=['POST'])
@require_admin_session
def gui_flowspec_announce():
    body, code = _do_flowspec_announce(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/flowspec/withdraw', methods=['POST'])
@require_admin_session
def gui_flowspec_withdraw():
    body, code = _do_flowspec_withdraw(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/simple-routes',       methods=['GET'])
@require_session
def gui_simple_routes_list():
    return jsonify({'simple_routes': db_simple_all(), 'default_community': SIMPLE_COMMUNITY})


@app.route('/announce/simple',     methods=['POST'])
@require_admin_session
def gui_simple_announce():
    body, code = _do_simple_announce(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/withdraw/simple',     methods=['POST'])
@require_admin_session
def gui_simple_withdraw():
    body, code = _do_simple_withdraw(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code


@app.route('/reannounce',        methods=['POST'])
@require_admin_session
def gui_reannounce():
    threading.Thread(target=reannounce_all, kwargs={'reason': 'manual-gui'},
                     daemon=True, name='reannounce-manual-gui').start()
    return jsonify({'status': 'ok', 'routes': len(db_all_routes()),
                    'rbths': len(db_rbth_all()), 'flowspecs': len(db_flowspec_all()),
                    'simples': len(db_simple_all())})




@app.route('/routes/export',      methods=['GET'])
@require_session
def gui_routes_export():
    from flask import Response
    payload = _do_routes_export()
    return Response(
        json.dumps(payload, indent=2), mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=exabgp-routes-{}.json'.format(
            time.strftime('%Y%m%d'))})


@app.route('/routes/import',      methods=['POST'])
@require_admin_session
def gui_routes_import():
    body, code = _do_routes_import(request.json or {}, performed_by=session.get('username'))
    return jsonify(body), code

# ── Admin GUI-internal ────────────────────────────────────────────────────────

@app.route('/admin/users',                   methods=['GET'])
@require_admin_session
def gui_admin_users_list():
    users = [{'id': 0, 'username': ADMIN_USERNAME, 'role': 'admin', 'created_at': '-', 'is_env': True}]
    users += [dict(u, is_env=False) for u in db_user_all()]
    return jsonify({'users': users})


@app.route('/admin/users',                   methods=['POST'])
@require_admin_session
def gui_admin_users_create():
    data     = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'readonly')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'username and password required'}), 400
    if role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'invalid role'}), 400
    if username == ADMIN_USERNAME:
        return jsonify({'status': 'error', 'message': 'cannot use env admin username'}), 409
    user = db_user_create(username, password, role)
    if not user:
        return jsonify({'status': 'error', 'message': 'username already exists'}), 409
    return jsonify({'status': 'ok', 'user': {k: user[k] for k in ('id', 'username', 'role', 'created_at')}}), 201


@app.route('/admin/users/<int:user_id>',     methods=['PUT'])
@require_admin_session
def gui_admin_users_update(user_id):
    data     = request.json or {}
    password = data.get('password', '').strip() or None
    role     = data.get('role') or None
    if role and role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'invalid role'}), 400
    if not db_user_update(user_id, password, role):
        return jsonify({'status': 'error', 'message': 'user not found or nothing to update'}), 404
    return jsonify({'status': 'ok'})


@app.route('/admin/users/<int:user_id>',     methods=['DELETE'])
@require_admin_session
def gui_admin_users_delete(user_id):
    if not db_user_delete(user_id):
        return jsonify({'status': 'error', 'message': 'user not found'}), 404
    return jsonify({'status': 'ok'})


@app.route('/admin/tokens',                  methods=['GET'])
@require_admin_session
def gui_admin_tokens_list():
    tokens = [{'id': 0, 'name': 'env-admin-token', 'role': 'admin', 'created_at': '-', 'is_env': True}]
    tokens += [dict(t, is_env=False) for t in db_token_all()]
    return jsonify({'tokens': tokens})


@app.route('/admin/tokens',                  methods=['POST'])
@require_admin_session
def gui_admin_tokens_create():
    data = request.json or {}
    name = data.get('name', '').strip()
    role = data.get('role', 'readonly')
    if not name:
        return jsonify({'status': 'error', 'message': 'name required'}), 400
    if role not in ('admin', 'readonly'):
        return jsonify({'status': 'error', 'message': 'invalid role'}), 400
    token  = generate_token()
    result = db_token_create(name, token, role)
    if not result:
        return jsonify({'status': 'error', 'message': 'token name already exists'}), 409
    return jsonify({'status': 'ok', 'token': token, 'meta': result}), 201


@app.route('/admin/tokens/<int:token_id>',   methods=['DELETE'])
@require_admin_session
def gui_admin_tokens_delete(token_id):
    if not db_token_delete(token_id):
        return jsonify({'status': 'error', 'message': 'token not found'}), 404
    return jsonify({'status': 'ok'})


@app.route('/admin/export',                  methods=['GET'])
@require_admin_session
def gui_admin_export():
    with db_lock, db_connect() as conn:
        users  = [dict(r) for r in conn.execute(
            'SELECT username, password_hash, role, created_at FROM users').fetchall()]
        tokens = [dict(r) for r in conn.execute(
            'SELECT name, token_hash, role, created_at FROM tokens').fetchall()]
    payload = {
        'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'note': 'passwords and tokens are hashed',
        'users': users, 'tokens': tokens
    }
    from flask import Response
    return Response(
        json.dumps(payload, indent=2), mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=exabgp-users-{}.json'.format(
            time.strftime('%Y%m%d'))})


@app.route('/admin/import',                  methods=['POST'])
@require_admin_session
def gui_admin_import():
    data = request.json or {}
    users  = data.get('users',  [])
    tokens = data.get('tokens', [])
    imp_u = imp_t = skip_u = skip_t = 0
    with db_lock, db_connect() as conn:
        for u in users:
            username = u.get('username', '').strip()
            pw_hash  = u.get('password_hash', '').strip()
            role     = u.get('role', 'readonly')
            if not username or not pw_hash or username == ADMIN_USERNAME:
                skip_u += 1; continue
            conn.execute('''INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash, role=excluded.role''',
                (username, pw_hash, role, u.get('created_at', time.strftime('%Y-%m-%d %H:%M:%S'))))
            imp_u += 1
        for t in tokens:
            name       = t.get('name', '').strip()
            token_hash = t.get('token_hash', '').strip()
            role       = t.get('role', 'readonly')
            if not name or not token_hash:
                skip_t += 1; continue
            conn.execute('''INSERT INTO tokens (name, token_hash, role, created_at)
                VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET
                token_hash=excluded.token_hash, role=excluded.role''',
                (name, token_hash, role, t.get('created_at', time.strftime('%Y-%m-%d %H:%M:%S'))))
            imp_t += 1
        conn.commit()
    return jsonify({'status': 'ok', 'imported_users': imp_u, 'imported_tokens': imp_t,
                    'skipped_users': skip_u, 'skipped_tokens': skip_t})


# ── Login page ────────────────────────────────────────────────────────────────

def _login_page(error=None):
    err_html = '<div class="error">{}</div>'.format(error) if error else ''
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ExaBGP Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--muted:#7d8590;--green:#3fb950;--green-dim:#1a4a1f;--red:#f85149}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:36px;width:360px}
.logo{display:flex;align-items:center;gap:10px;color:var(--green);font-size:15px;font-weight:600;margin-bottom:28px}
.logo-icon{width:28px;height:28px;background:var(--green-dim);border:1px solid var(--green);border-radius:6px;display:flex;align-items:center;justify-content:center}
label{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
input{width:100%;background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;margin-bottom:16px;transition:border-color .15s}
input:focus{border-color:var(--green)}
button{width:100%;background:var(--green-dim);border:1px solid var(--green);color:var(--green);padding:9px;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;transition:background .15s;margin-top:4px}
button:hover{background:#26663b}
.error{background:#4a1414;border:1px solid var(--red);color:var(--red);padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:16px}
</style>
</head>
<body>
<div class="card">
  <div class="logo"><div class="logo-icon">&#9658;</div>exabgp &middot; login</div>
  ''' + err_html + '''
  <form method="POST">
    <label>username</label>
    <input type="text" name="username" autocomplete="username" autofocus />
    <label>password</label>
    <input type="password" name="password" autocomplete="current-password" />
    <button type="submit">sign in &#8594;</button>
  </form>
</div>
</body>
</html>'''


# ── Startup ───────────────────────────────────────────────────────────────────

db_init()
threading.Thread(target=socket_watchdog, daemon=True, name='socket-watchdog').start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)