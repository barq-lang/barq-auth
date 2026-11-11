"""Framework part 3 (v0.11.0): authentication and authorization.

    Auth / auth()    Auth.attempt(#{"email": e, "password": p}), Auth.user(), Auth.logout(), auth("api").user()
    Guards           "web" (session, remember-me cookie) and "api" (Bearer tokens) — config/auth.bq
    API tokens       user.createToken("cli", #["posts:read"]), user.tokens(), user.tokenCan("posts:read")
    Gate             Gate.define("edit", fn), Gate.allows("update", post), Gate.authorize(...), policies
    Middleware       "auth", "auth:api", "guest", "can:update,post" (Route.alias() can replace them)

The current request comes from web.current_request(); outside a request
(scripts, tests) the guards keep the logged-in user in memory.
"""

import hashlib
import hmac
import json
import re
import secrets
import time

from barq.builtins import need
from barq.runtime import BarqClass, BarqFunction, BarqObject, BarqThrow, BoundMethod, NativeFunction, PropInfo, \
    to_display, type_name
from barq.stdlib import arg, module
from barq.stdlib2 import header_lookup, native_class, new_native


AUTH_DEFAULTS = {
    "default_guard": "web",
    "guards": {
        "web": {"driver": "session", "provider": "users"},
        "api": {"driver": "token", "provider": "users"},
    },
    "providers": {"users": {"driver": "orm", "model": "App\\Models\\User"}},
    "home": "/",                    # where "guest" sends logged-in users
    "login": None,                  # where "auth" sends guests (default: the route named "login")
    "remember_lifetime": 2592000,   # remember-me cookie, seconds (30 days)
    "token_expiration": None,       # API tokens expire after this many minutes (None: never)
}
TOKEN_TABLE = "personal_access_tokens"
GUARD_DRIVERS = ("session", "token")


# ===========================================================================
# settings
# ===========================================================================

def merged(base, extra):
    out = dict(base)
    for k, v in extra.items():
        out[k] = merged(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out


def settings(i):
    from barq.stdlib2 import config_lookup
    conf = config_lookup(i, "auth")
    return merged(AUTH_DEFAULTS, conf) if isinstance(conf, dict) else AUTH_DEFAULTS


def guard_config(i, name, n):
    cfg = settings(i)
    g = cfg["guards"].get(name)
    if not isinstance(g, dict):
        i.throw("AuthException", f'unknown auth guard "{name}" (guards: {", ".join(cfg["guards"])}) — add it to '
                f"config/auth.bq under \"guards\"", n)
    driver = g.get("driver", "session")
    if driver not in GUARD_DRIVERS:
        i.throw("AuthException", f'auth guard "{name}": driver must be "session" or "token", got '
                f"{to_display(driver, i, True)}", n)
    return driver, g.get("provider", "users")


def user_model(i, provider, n):
    """The model class a provider names (config providers.<name>.model: a class or its full name)."""
    cfg = settings(i)
    p = cfg["providers"].get(provider)
    if not isinstance(p, dict):
        i.throw("AuthException", f'unknown auth provider "{provider}" — add it to config/auth.bq under "providers"', n)
    model = p.get("model")
    cls = model
    if isinstance(model, str):
        cls = i.classes.get(model)
        if cls is None:
            try:
                cls = i.lookup_fqn(model, n, None, required=False)
            except BarqThrow:
                cls = None
        if cls is None and "\\" in model:
            cls = i.classes.get(model.rsplit("\\", 1)[1])
    from barq_framework.orm import model_class
    if not isinstance(cls, BarqClass) or not cls.is_subclass_of(model_class(i)):
        i.throw("AuthException", f"the auth user model {to_display(model, i, True)} was not found — create it, or set "
                f'"providers": #{{"{provider}": #{{"model": ...}}}} in config/auth.bq '
                "(Config.set(\"auth.providers.users.model\", User) works too)", n)
    return cls


def default_guard_name(i):
    from barq.web import current_request
    req = current_request(i)
    if req is not None and req.native.guard:
        return req.native.guard
    return settings(i)["default_guard"]


def login_url(i, n):
    url = settings(i).get("login")
    if url:
        return url
    from barq.web import router, route_url
    if "login" in router(i).names:
        return route_url(i, ["login"], n)
    return None


# ===========================================================================
# guards
# ===========================================================================

class GuardState:
    def __init__(self, name, driver, provider):
        self.name = name
        self.driver = driver
        self.provider = provider


def guard_obj(i, name, n):
    cache = i.__dict__.setdefault("_guards", {})
    driver, provider = guard_config(i, name, n)
    g = cache.get(name)
    if g is None or g.native.driver != driver or g.native.provider != provider:
        g = cache[name] = new_native(i, "Guard", GuardState(name, driver, provider))
    return g


def default_guard(i, n):
    return guard_obj(i, default_guard_name(i), n)


def users_of(i, req):
    """Where a guard keeps its user: the current request, or memory outside one."""
    if req is not None:
        return req.native.auth
    return i.__dict__.setdefault("_auth_users", {})


UNSET = object()


def model_key(i, user, n):
    from barq_framework.orm import meta, mstate
    return mstate(user).attrs.get(meta(i, user.cls, n).pk)


def find_user(i, g, key, n):
    from barq_framework.orm import mq_find, new_mq
    if key is None:
        return None
    return mq_find(i, [key], n, new_mq(i, user_model(i, g.provider, n), n))


def need_user(i, g, user, n, fname):
    from barq_framework.orm import is_model, mstate
    cls = user_model(i, g.provider, n)
    if not is_model(i, user) or not user.cls.is_subclass_of(cls):
        i.throw("TypeException", f"{fname}() needs a {cls.name} model, got {type_name(user)}", n)
    if not mstate(user).exists:
        i.throw("AuthException", f"{fname}(): save the {user.cls.name} before logging it in", n)
    return user


def session_key(g):
    return "_auth_" + g.name


def remember_cookie(g):
    return "remember_" + g.name


def fire(i, name, data, n):
    from barq_framework.framework import ev_fire, events
    st = events(i)
    if st.fake is not None or st.listeners or st.wildcards:
        ev_fire(i, [name, data], n)


def resolve_user(i, g, n):
    """The guard's user, worked out once per request."""
    from barq.web import current_request
    req = current_request(i)
    store = users_of(i, req)
    found = store.get(g.name, UNSET)
    if found is not UNSET:
        return found
    user = None
    if req is not None and g.driver == "session":
        user = session_user(i, g, req, n)
    elif req is not None and g.driver == "token":
        user = token_user(i, g, req, n)
    store[g.name] = user
    return user


def session_user(i, g, req, n):
    from barq.web import req_cookies, sdata, start_session
    session = start_session(i, req, n)
    key = sdata(session).get(session_key(g))
    user = find_user(i, g, key, n) if key is not None else None
    if user is not None:
        return user
    raw = req_cookies(req).get(remember_cookie(g))
    if raw and "|" in raw:
        from barq_framework.orm import mstate
        uid, _, token = raw.partition("|")
        user = find_user(i, g, int(uid) if uid.isdigit() else uid, n)
        saved = mstate(user).attrs.get("remember_token") if user is not None else None
        if isinstance(saved, str) and saved and hmac.compare_digest(saved, token):
            sdata(session)[session_key(g)] = model_key(i, user, n)
            fire(i, "auth.login", user, n)
            return user
    return None


def check_password(i, user, password, n):
    from barq_framework.orm import mstate
    from barq.stdlib import hash_verify
    stored = mstate(user).attrs.get("password")
    if not isinstance(stored, str) or not stored:
        return False
    if not stored.startswith("$pbkdf2-sha256$"):
        i.throw("AuthException", f"{user.cls.name}.password is not a hash — store Hash.password(plain) "
                "in the password column, never the plain password", n)
    return hash_verify(i, [password, stored], n)


def retrieve(i, g, creds, n, fname):
    """The user matching every credential except the password."""
    from barq_framework.orm import mq, mq_first, new_mq, meta
    from barq.stdlib2 import add_where, where_in
    need(i, creds, ("dict",), fname, 1, n)
    if "password" not in creds:
        i.throw("ValueException", f'{fname}() needs a "password" key (and one or more columns to find the user by)', n)
    if not isinstance(creds["password"], str):
        return None
    keys = [k for k in creds if k != "password"]
    if not keys:
        i.throw("ValueException", f'{fname}() needs a column to find the user by, e.g. #{{"email": e, "password": p}}', n)
    cls = user_model(i, g.provider, n)
    q = new_mq(i, cls, n)
    table = meta(i, cls, n).table
    for k in keys:
        if not isinstance(k, str):
            i.throw("TypeException", f"{fname}(): credential names must be strings, got {type_name(k)}", n)
        if isinstance(creds[k], list):
            where_in(False)(i, [f"{table}.{k}", creds[k]], n, mq(q).q)
        else:
            add_where(i, [f"{table}.{k}", creds[k]], n, mq(q).q, "AND", fname)
    return mq_first(i, [], n, q)


def valid_user(i, g, creds, n, fname):
    user = retrieve(i, g, creds, n, fname)
    if user is not None and check_password(i, user, creds["password"], n):
        return user
    fire(i, "auth.failed", {k: v for k, v in creds.items() if k != "password"}, n)
    return None


def set_user(i, g, user):
    from barq.web import current_request
    users_of(i, current_request(i))[g.name] = user


def do_login(i, g, user, remember, n, fname):
    from barq.web import current_request, s_regenerate, sdata, start_session, cookie_header
    need_user(i, g, user, n, fname)
    req = current_request(i)
    if req is not None and g.driver == "session":
        session = start_session(i, req, n)
        s_regenerate(i, [], n, session)            # a new session id stops session fixation
        sdata(session)[session_key(g)] = model_key(i, user, n)
        if remember:
            token = cycle_remember_token(i, user, n, fname)
            life = settings(i)["remember_lifetime"]
            req.native.queued.append(cookie_header(i, remember_cookie(g), f"{model_key(i, user, n)}|{token}",
                                                   {"maxAge": life, "httpOnly": True, "sameSite": "Lax"}, n, fname))
    elif remember:
        cycle_remember_token(i, user, n, fname)
    set_user(i, g, user)
    fire(i, "auth.login", user, n)
    return None


def cycle_remember_token(i, user, n, fname):
    from barq_framework.orm import meta, model_db, mstate, save, table_columns
    m = meta(i, user.cls, n)
    if "remember_token" not in table_columns(i, model_db(i, m, n), m.table, n):
        i.throw("AuthException", f'{fname}(): "remember me" needs a remember_token column on {m.table} '
                "— add t.rememberToken() to its migration", n)
    token = secrets.token_urlsafe(45)
    mstate(user).attrs["remember_token"] = token
    save(i, user, n)
    return token


def do_logout(i, g, n):
    from barq_framework.orm import mstate
    from barq.web import current_request, req_cookies, s_regenerate, sdata, start_session, cookie_header
    user = resolve_user(i, g, n)
    req = current_request(i)
    if req is not None and g.driver == "session":
        session = start_session(i, req, n)
        sdata(session).pop(session_key(g), None)
        s_regenerate(i, [], n, session)
        if remember_cookie(g) in req_cookies(req):
            req.native.queued.append(cookie_header(i, remember_cookie(g), "", {"maxAge": 0}, n, "Auth.logout"))
    if user is not None and mstate(user).attrs.get("remember_token"):
        cycle_remember_token(i, user, n, "Auth.logout")     # old remember-me cookies stop working
    set_user(i, g, None)
    if user is not None:
        fire(i, "auth.logout", user, n)
    return None


# ---- Guard methods (also the Auth module, on the default guard) -------------

def gm_user(i, g, a, n):
    return resolve_user(i, g, n)


def gm_id(i, g, a, n):
    user = resolve_user(i, g, n)
    return model_key(i, user, n) if user is not None else None


def gm_login(i, g, a, n):
    remember = arg(i, a, 1, ("bool",), "Auth.login", n, False)
    return do_login(i, g, a[0], remember, n, "Auth.login")


def gm_login_by_id(i, g, a, n):
    remember = arg(i, a, 1, ("bool",), "Auth.loginById", n, False)
    user = find_user(i, g, a[0], n)
    if user is None:
        return None
    do_login(i, g, user, remember, n, "Auth.loginById")
    return user


def gm_attempt(i, g, a, n):
    remember = arg(i, a, 1, ("bool",), "Auth.attempt", n, False)
    user = valid_user(i, g, a[0], n, "Auth.attempt")
    if user is None:
        return False
    do_login(i, g, user, remember, n, "Auth.attempt")
    return True


def gm_validate(i, g, a, n):
    return valid_user(i, g, a[0], n, "Auth.validate") is not None


def gm_once(i, g, a, n):
    user = valid_user(i, g, a[0], n, "Auth.once")
    if user is None:
        return False
    set_user(i, g, user)
    return True


def gm_once_by_id(i, g, a, n):
    user = find_user(i, g, a[0], n)
    if user is not None:
        set_user(i, g, user)
    return user


def gm_set_user(i, g, a, n):
    set_user(i, g, need_user(i, g, a[0], n, "Auth.setUser") if a[0] is not None else None)
    return None


def gm_token(i, g, a, n):
    from barq_framework.orm import mstate
    user = resolve_user(i, g, n)
    return token_dict(mstate(user).token) if user is not None and mstate(user).token else None


GUARD_FUNCS = {
    "user": (gm_user, 0, 0),
    "id": (gm_id, 0, 0),
    "check": (lambda i, g, a, n: resolve_user(i, g, n) is not None, 0, 0),
    "guest": (lambda i, g, a, n: resolve_user(i, g, n) is None, 0, 0),
    "login": (gm_login, 1, 2),
    "loginById": (gm_login_by_id, 1, 2),
    "loginUsingId": (gm_login_by_id, 1, 2),
    "attempt": (gm_attempt, 1, 2),
    "validate": (gm_validate, 1, 1),
    "once": (gm_once, 1, 1),
    "onceUsingId": (gm_once_by_id, 1, 1),
    "setUser": (gm_set_user, 1, 1),
    "logout": (lambda i, g, a, n: do_logout(i, g, n), 0, 0),
    "token": (gm_token, 0, 0),
    "name": (lambda i, g, a, n: g.name, 0, 0),
}


def as_method(fn):
    return lambda i, a, n, this: fn(i, this.native, a, n)


def as_auth(fn):
    return lambda i, a, n: fn(i, default_guard(i, n).native, a, n)


def auth_guard(i, a, n):
    name = arg(i, a, 0, ("string",), "Auth.guard", n, None)
    return guard_obj(i, name, n) if name else default_guard(i, n)


def auth_should_use(i, a, n):
    from barq.web import current_request
    name = need(i, a[0], ("string",), "Auth.shouldUse", 1, n)
    guard_config(i, name, n)
    req = current_request(i)
    if req is not None:
        req.native.guard = name
    else:
        from barq.stdlib2 import config_set
        config_set(i, ["auth.default_guard", name], n)
    return None


def req_user(i, a, n, this):
    name = arg(i, a, 0, ("string",), "Request.user", n, None)
    from barq.web import current
    with current(i, this):
        return resolve_user(i, (guard_obj(i, name, n) if name else default_guard(i, n)).native, n)


# ===========================================================================
# API tokens
# ===========================================================================

def token_hash(plain):
    return hashlib.sha256(plain.encode()).hexdigest()


def token_db(i, cls, n):
    from barq_framework.orm import meta, model_db, table_columns
    db = model_db(i, meta(i, cls, n), n)
    if not table_columns(i, db, TOKEN_TABLE, n):
        i.throw("DbException", f'API tokens need the "{TOKEN_TABLE}" table — run "barq auth:install" and '
                '"barq migrate" (or create it: t.id(), t.morphs("tokenable"), t.string("name"), '
                't.string("token", 64).unique(), t.text("abilities").nullable(), t.int("last_used_at").nullable(), '
                't.int("expires_at").nullable(), t.timestamps())', n)
    return db


def token_query(i, db, n):
    from barq.stdlib2 import new_query, qid
    return new_query(i, db, qid(i, TOKEN_TABLE, n, "table"))


def token_dict(row):
    out = dict(row)
    out.pop("token", None)
    try:
        out["abilities"] = json.loads(row.get("abilities") or '["*"]')
    except ValueError:
        out["abilities"] = []
    return out


def need_saved(i, this, n, fname):
    from barq_framework.orm import mstate
    if not mstate(this).exists:
        i.throw("AuthException", f"{fname}(): save the {this.cls.name} first", n)


def m_create_token(i, a, n, this):
    from barq.stdlib2 import db_state, insert_rows
    fname = f"{this.cls.name}.createToken"
    need_saved(i, this, n, fname)
    name = need(i, a[0], ("string",), fname, 1, n)
    abilities = arg(i, a, 1, ("list",), fname, n, ["*"])
    for ab in abilities:
        if not isinstance(ab, str):
            i.throw("TypeException", f"{fname}(): abilities must be strings, got {type_name(ab)}", n)
    expires = arg(i, a, 2, ("int",), fname, n, None)
    db = token_db(i, this.cls, n)
    plain = secrets.token_hex(20)
    now = int(time.time())
    row = {"tokenable_type": this.cls.fqn, "tokenable_id": model_key(i, this, n), "name": name,
           "token": token_hash(plain), "abilities": json.dumps(abilities), "last_used_at": None,
           "expires_at": expires, "created_at": now, "updated_at": now}
    insert_rows(i, token_query(i, db, n), [row], n, fname)
    row["id"] = db_state(i, db, n).last_id
    info = token_dict(row)
    return new_native(i, "NewAccessToken", None, plainTextToken=f"{row['id']}|{plain}", accessToken=info,
                      id=row["id"], name=name, abilities=list(abilities))


def m_tokens(i, a, n, this):
    from barq.stdlib2 import add_where
    fname = f"{this.cls.name}.tokens"
    need_saved(i, this, n, fname)
    q = token_query(i, token_db(i, this.cls, n), n)
    add_where(i, ["tokenable_type", this.cls.fqn], n, q, "AND", fname)
    add_where(i, ["tokenable_id", model_key(i, this, n)], n, q, "AND", fname)
    return q


def m_token_can(i, a, n, this):
    from barq_framework.orm import mstate
    ability = need(i, a[0], ("string",), f"{this.cls.name}.tokenCan", 1, n)
    tok = mstate(this).token
    if tok is None:
        return False
    abilities = token_dict(tok)["abilities"]
    return "*" in abilities or ability in abilities


def m_current_token(i, a, n, this):
    from barq_framework.orm import mstate
    tok = mstate(this).token
    return token_dict(tok) if tok else None


def m_with_token(i, a, n, this):
    """user.withAccessToken(row): mark the user as authenticated by this token (tests)."""
    from barq_framework.orm import mstate
    tok = need(i, a[0], ("dict",), f"{this.cls.name}.withAccessToken", 1, n)
    row = dict(tok)
    if isinstance(row.get("abilities"), list):
        row["abilities"] = json.dumps(row["abilities"])
    mstate(this).token = row
    return this


def bearer(req):
    h = header_lookup(req.fields["headers"], "Authorization") or ""
    m = re.match(r"^\s*Bearer\s+(\S+)\s*$", h, re.I)
    return m.group(1) if m else None


def token_user(i, g, req, n):
    from barq_framework.orm import mstate
    from barq.stdlib2 import add_where, qb_first, QUERY_METHODS
    plain = bearer(req)
    if not plain:
        return None
    cls = user_model(i, g.provider, n)
    db = token_db(i, cls, n)
    q = token_query(i, db, n)
    tid, sep, secret = plain.partition("|")
    if sep and tid.isdigit():
        add_where(i, ["id", int(tid)], n, q, "AND", "auth")
    else:
        secret = plain
        add_where(i, ["token", token_hash(plain)], n, q, "AND", "auth")
    row = qb_first(i, [], n, q)
    if row is None or not hmac.compare_digest(row.get("token") or "", token_hash(secret)):
        return None
    now = int(time.time())
    if row.get("expires_at") is not None and row["expires_at"] <= now:
        return None
    minutes = settings(i).get("token_expiration")
    if isinstance(minutes, int) and row.get("created_at") is not None and row["created_at"] + minutes * 60 <= now:
        return None
    if row.get("tokenable_type") not in (cls.fqn, cls.name):
        return None
    user = find_user(i, g, row["tokenable_id"], n)
    if user is None:
        return None
    upd = token_query(i, db, n)
    add_where(i, ["id", row["id"]], n, upd, "AND", "auth")
    QUERY_METHODS["update"][0](i, [{"last_used_at": now}], n, upd)
    row["last_used_at"] = now
    mstate(user).token = row
    return user


# ===========================================================================
# Gate — abilities and policies
# ===========================================================================

class GateState:
    def __init__(self):
        self.abilities = {}     # name -> function or [Class, "method"]
        self.policies = {}      # model fqn -> policy class
        self.before = []
        self.after = []


def gate(i):
    st = i.__dict__.get("_gate")
    if st is None:
        st = i._gate = GateState()
    return st


def is_callable(v):
    return isinstance(v, (BarqFunction, NativeFunction, BoundMethod))


def check_callback(i, fn, n, fname):
    if is_callable(fn):
        return fn
    if isinstance(fn, list) and len(fn) == 2 and isinstance(fn[0], BarqClass) and isinstance(fn[1], str):
        if fn[0].find_method(fn[1]) is None:
            i.throw("NameException", f"{fname}(): {fn[0].name} has no method {fn[1]}()", n)
        return fn
    i.throw("TypeException", f'{fname}() needs a function or #[Class, "method"], got {type_name(fn)}', n)


def callable_of(i, fn, n):
    from barq.web import resolve_handler
    return resolve_handler(i, fn, n)


def takes_guest(fn):
    """Guests only reach callbacks whose user parameter accepts null:
    typed `?User`, `any`, or untyped."""
    f = fn.func if isinstance(fn, BoundMethod) else fn
    if isinstance(f, BarqFunction) and f.params:
        t = f.params[0].type
        return t is None or t.name == "any" or bool(t.nullable)
    return True


def call_rule(i, fn, args, n):
    from barq_framework.framework import arity
    k = arity(fn)
    if k >= 0:
        args = args[:k]
    return i.call_function(fn, args, n)


def as_result(i, v, what, n):
    if v is None or isinstance(v, bool):
        return v
    i.throw("TypeException", f"{what} must return bool (or null to let the next check decide), got {type_name(v)}", n)


def policy_class_for(i, target, n):
    from barq_framework.orm import model_class
    cls = target if isinstance(target, BarqClass) else target.cls if isinstance(target, BarqObject) else None
    if cls is None or not cls.is_subclass_of(model_class(i)) or cls is model_class(i):
        return None
    st = gate(i)
    c = cls
    while c is not None and c is not model_class(i):
        if c.fqn in st.policies:
            return st.policies[c.fqn]
        c = c.parent
    # App\Models\Post -> App\Policies\PostPolicy
    if "\\Models\\" in cls.fqn or cls.fqn.startswith("Models\\"):
        guess = cls.fqn.replace("Models\\", "Policies\\", 1) + "Policy"
    elif "\\" in cls.fqn:
        guess = cls.fqn.rsplit("\\", 1)[0] + "\\" + cls.name + "Policy"
    else:
        guess = cls.name + "Policy"
    found = i.classes.get(guess)
    if found is None and "\\" in guess:
        try:
            found = i.lookup_fqn(guess, n, None, required=False)
        except BarqThrow:
            found = None
    if isinstance(found, BarqClass):
        st.policies[cls.fqn] = found
        return found
    return None


def spread(args):
    return list(args[0]) if len(args) == 1 and isinstance(args[0], list) else list(args)


# fn(i, user, ability, args, n) -> True / None, asked before everything else
# (the permissions package: super admins and granted permissions)
PRE_CHECKS = []


def raw_check(i, user, ability, args, n):
    """-> True / False / None (nothing decided). AuthorizationException from Gate.deny() propagates."""
    from barq_framework.framework import container_make
    st = gate(i)
    if user is not None:
        for fn in PRE_CHECKS:
            r = fn(i, user, ability, args, n)
            if r is not None:
                return r
    for fn in st.before:
        if user is None and not takes_guest(fn):
            continue
        r = as_result(i, call_rule(i, fn, [user, ability, *args], n), "Gate.before() callbacks", n)
        if r is not None:
            return r
    result = None
    pcls = policy_class_for(i, args[0], n) if args else None
    if pcls is not None:
        policy = container_make(i, pcls, n)
        before = pcls.find_method("before")
        if before is not None:
            fn = BoundMethod(policy, before)
            if user is not None or takes_guest(fn):
                result = as_result(i, call_rule(i, fn, [user, ability], n), f"{pcls.name}.before()", n)
        m = pcls.find_method(ability)
        if result is None and m is not None:
            fn = BoundMethod(policy, m)
            if user is None and not takes_guest(fn):
                result = False
            else:
                rest = args[1:] if isinstance(args[0], BarqClass) else args
                result = as_result(i, call_rule(i, fn, [user, *rest], n), f"{pcls.name}.{ability}()", n)
    if result is None and ability in st.abilities:
        fn = callable_of(i, st.abilities[ability], n)
        if user is None and not takes_guest(fn):
            result = False
        else:
            result = as_result(i, call_rule(i, fn, [user, *args], n), f'the "{ability}" ability', n)
    for fn in st.after:
        if user is None and not takes_guest(fn):
            continue
        r = as_result(i, call_rule(i, fn, [user, ability, result, *args], n), "Gate.after() callbacks", n)
        if result is None and r is not None:
            result = r
    return result


def inspect(i, user, ability, args, n):
    """-> (allowed, message)"""
    need(i, ability, ("string",), "Gate", 1, n)
    try:
        return bool(raw_check(i, user, ability, args, n)), None
    except BarqThrow as t:
        if t.obj.cls.name == "AuthorizationException":
            return False, t.obj.fields.get("message")
        raise


def deny(i, message, n):
    obj = i.make_exception("AuthorizationException", message or "This action is unauthorized.", n)
    obj.fields["status"] = 403
    raise BarqThrow(obj)


def current_user(i, n):
    return resolve_user(i, default_guard(i, n).native, n)


def abilities_arg(i, v, n, fname):
    names = v if isinstance(v, list) else [v]
    for x in names:
        need(i, x, ("string",), fname, 1, n)
    return names


def gate_api(user_of):
    """The checks shared by Gate and Gate.forUser(user)."""
    def allows(i, a, n, *this):
        return inspect(i, user_of(i, n, this), a[0], spread(a[1:]), n)[0]

    def denies(i, a, n, *this):
        return not allows(i, a, n, *this)

    def check(i, a, n, *this):
        return all(inspect(i, user_of(i, n, this), ab, spread(a[1:]), n)[0]
                   for ab in abilities_arg(i, a[0], n, "Gate.check"))

    def any_(i, a, n, *this):
        return any(inspect(i, user_of(i, n, this), ab, spread(a[1:]), n)[0]
                   for ab in abilities_arg(i, a[0], n, "Gate.any"))

    def none(i, a, n, *this):
        return not any_(i, a, n, *this)

    def authorize(i, a, n, *this):
        ok, msg = inspect(i, user_of(i, n, this), a[0], spread(a[1:]), n)
        if not ok:
            deny(i, msg, n)
        return True

    def inspect_(i, a, n, *this):
        ok, msg = inspect(i, user_of(i, n, this), a[0], spread(a[1:]), n)
        return {"allowed": ok, "message": msg}

    return {"allows": (allows, 1, -1), "denies": (denies, 1, -1), "check": (check, 1, -1), "any": (any_, 1, -1),
            "none": (none, 1, -1), "authorize": (authorize, 1, -1), "inspect": (inspect_, 1, -1)}


def g_define(i, a, n):
    name = need(i, a[0], ("string",), "Gate.define", 1, n)
    gate(i).abilities[name] = check_callback(i, a[1], n, "Gate.define")
    return None


def g_policy(i, a, n):
    from barq_framework.orm import need_model_class
    model = need_model_class(i, a[0], n, "Gate.policy")
    if not isinstance(a[1], BarqClass):
        i.throw("TypeException", f"Gate.policy() argument 2 must be a policy class, got {type_name(a[1])}", n)
    gate(i).policies[model.fqn] = a[1]
    return None


def g_hook(attr):
    def fn(i, a, n):
        getattr(gate(i), attr).append(check_callback(i, a[0], n, "Gate." + attr))
        return None
    return fn


def g_get_policy(i, a, n):
    from barq_framework.framework import container_make
    pcls = policy_class_for(i, a[0], n)
    return container_make(i, pcls, n) if pcls is not None else None


def g_for_user(i, a, n):
    from barq_framework.orm import is_model
    if a[0] is not None and not is_model(i, a[0]):
        i.throw("TypeException", f"Gate.forUser() needs a model (or null for a guest), got {type_name(a[0])}", n)
    return new_native(i, "UserGate", a[0])


def g_flush(i, a, n):
    i._gate = GateState()
    return None


GATE = {
    "define": (g_define, 2, 2),
    "policy": (g_policy, 2, 2),
    "before": (g_hook("before"), 1, 1),
    "after": (g_hook("after"), 1, 1),
    "has": (lambda i, a, n: need(i, a[0], ("string",), "Gate.has", 1, n) in gate(i).abilities, 1, 1),
    "abilities": (lambda i, a, n: sorted(gate(i).abilities), 0, 0),
    "getPolicyFor": (g_get_policy, 1, 1),
    "forUser": (g_for_user, 1, 1),
    "deny": (lambda i, a, n: deny(i, arg(i, a, 0, ("string",), "Gate.deny", n, None), n), 0, 1),
    "flush": (g_flush, 0, 0),
}
GATE.update(gate_api(lambda i, n, this: current_user(i, n)))
USER_GATE = gate_api(lambda i, n, this: this[0].native)


def m_can(negate):
    """user.can(ability, ...arguments, team: t) — `team` reaches the permission checks."""
    def fn(i, a, n, this):
        from barq.runtime import split_kwargs
        a, kw = split_kwargs(a)
        if not a:
            i.throw("TypeException", f"{this.cls.name}.{'cannot' if negate else 'can'}() needs an ability", n)
        prev = i.__dict__.get("_perm_team")
        i._perm_team = kw.get("team")
        try:
            ok = inspect(i, this, a[0], spread(a[1:]), n)[0]
        finally:
            i._perm_team = prev
        return not ok if negate else ok
    return fn


# ===========================================================================
# middleware: auth, guest, can
# ===========================================================================

def guard_names(i, extra):
    return [x.strip() for x in extra if x.strip()] or [default_guard_name(i)]


def mw_auth(i, a, n):
    req, nxt, extra = a[0], a[1], a[2:]
    from barq.web import current
    with current(i, req):
        for name in guard_names(i, extra):
            g = guard_obj(i, name, n).native
            if resolve_user(i, g, n) is not None:
                req.native.guard = name             # Auth.user() now means this guard
                return i.call_function(nxt, [req], n)
    obj = i.make_exception("AuthenticationException", "Unauthenticated.", n)
    obj.fields["status"] = 401
    raise BarqThrow(obj)


def mw_guest(i, a, n):
    req, nxt, extra = a[0], a[1], a[2:]
    from barq.web import current
    from barq.stdlib2 import resp_redirect
    with current(i, req):
        for name in guard_names(i, extra):
            if resolve_user(i, guard_obj(i, name, n).native, n) is not None:
                return resp_redirect(i, [settings(i).get("home") or "/"], n)
    return i.call_function(nxt, [req], n)


def handler_params(i, req):
    """{name: class} for the matched handler's class-typed parameters."""
    from barq.web import fn_params, param_class
    route = req.native.route
    if route is None:
        return {}
    h = route.handler
    if isinstance(h, list):
        m = h[0].find_method(h[1])
        params, module = (m.params if isinstance(m, BarqFunction) else None), h[0].module
    else:
        params, module = fn_params(h), getattr(h, "module", None)
    out = {}
    for p in params or []:
        cls = param_class(i, p.type, module)
        if cls is not None:
            out[p.name] = cls
    return out


def can_argument(i, req, name, n):
    from barq_framework.orm import bind_model, model_class
    params = req.native.params
    if name in params:
        cls = handler_params(i, req).get(name)
        if cls is not None and cls.is_subclass_of(model_class(i)):
            return bind_model(i, cls, params[name], n)
        return params[name]
    cls = i.classes.get(name)
    if cls is None and "\\" in name:
        try:
            cls = i.lookup_fqn(name, n, None, required=False)
        except BarqThrow:
            cls = None
    if cls is None:
        for c in i.classes.values():
            if isinstance(c, BarqClass) and c.name == name:
                cls = c
                break
    return cls if isinstance(cls, BarqClass) else name


def mw_can(i, a, n):
    req, nxt, extra = a[0], a[1], a[2:]
    if not extra or not extra[0].strip():
        i.throw("ValueException", 'the "can" middleware needs an ability: "can:update,post"', n)
    from barq.web import current
    with current(i, req):
        args = [can_argument(i, req, x.strip(), n) for x in extra[1:]]
        ok, msg = inspect(i, current_user(i, n), extra[0].strip(), args, n)
        if not ok:
            deny(i, msg, n)
    return i.call_function(nxt, [req], n)


# ===========================================================================
# TestClient additions
# ===========================================================================

def client_acting_as(i, a, n, this):
    from barq_framework.orm import is_model
    if not is_model(i, a[0]):
        i.throw("TypeException", f"TestClient.actingAs() needs a model, got {type_name(a[0])}", n)
    name = arg(i, a, 1, ("string",), "TestClient.actingAs", n, None) or settings(i)["default_guard"]
    guard_config(i, name, n)
    this.native.acting = (name, a[0])
    return this


def client_with_token(i, a, n, this):
    token = need(i, a[0], ("string",), "TestClient.withToken", 1, n)
    this.native.headers["Authorization"] = "Bearer " + token
    return this


# ===========================================================================
# install
# ===========================================================================

def install(i):
    g = i.builtins
    exc = BarqClass("AuthException", "AuthException", None, parent=i.classes["Exception"], native=True)
    i.classes["AuthException"] = exc
    g.declare("AuthException", exc, None, const=True)
    for name in ("AuthenticationException", "AuthorizationException"):
        cls = BarqClass(name, name, None, parent=i.classes["AbortException"], native=True)
        i.classes[name] = cls
        g.declare(name, cls, None, const=True)

    guard_methods = {k: (as_method(fn), lo, hi) for k, (fn, lo, hi) in GUARD_FUNCS.items()}
    native_class(i, "Guard", None, guard_methods)
    table = {k: (as_auth(fn), lo, hi) for k, (fn, lo, hi) in GUARD_FUNCS.items()}
    table.update({"guard": (auth_guard, 0, 1), "shouldUse": (auth_should_use, 1, 1)})
    g.declare("Auth", module("Auth", table), None, const=True)
    g.declare("auth", NativeFunction("auth", auth_guard, 0, 1), None, const=True)

    g.declare("Gate", module("Gate", GATE), None, const=True)
    native_class(i, "UserGate", None, USER_GATE)
    native_class(i, "NewAccessToken", {"plainTextToken": "string", "accessToken": "dict", "id": "int",
                                       "name": "string", "abilities": "list"})

    from barq.web import BUILTIN_MIDDLEWARE, add_natives
    BUILTIN_MIDDLEWARE.update({"auth": NativeFunction("auth", mw_auth, 2, -1),
                               "guest": NativeFunction("guest", mw_guest, 2, -1),
                               "can": NativeFunction("can", mw_can, 2, -1)})
    add_natives(i, "Request", {"user": (req_user, 0, 1)})
    add_natives(i, "TestClient", {"actingAs": (client_acting_as, 1, 2), "withToken": (client_with_token, 1, 1)})

    model = i.classes["Model"]
    for name, (fn, lo, hi) in {"createToken": (m_create_token, 1, 3), "tokens": (m_tokens, 0, 0),
                               "tokenCan": (m_token_can, 1, 1), "currentAccessToken": (m_current_token, 0, 0),
                               "withAccessToken": (m_with_token, 1, 1),
                               "can": (m_can(False), 1, -1), "cannot": (m_can(True), 1, -1)}.items():
        f = NativeFunction(f"Model.{name}", fn, lo, hi)
        f.owner = model
        if name in ("can", "cannot"):
            f.arg_names = ("ability", "*arguments", "team")
        model.methods[name] = f

    from barq.stdlib2 import STDLIB_ALIASES
    STDLIB_ALIASES.update({"Auth\\Auth": "Auth", "Auth\\Gate": "Gate", "Auth\\Guard": "Guard"})
