"""Auth, part 2 (v0.14.0): what the auth:install pages need.

    URL           URL.signedRoute("verification.verify", #{"id": 1}), URL.hasValidSignature(req), URL.to("/x")
    RateLimiter   RateLimiter.hit(key, 60), tooManyAttempts(key, 5), availableIn(key), clear(key)
    Password      Password.sendResetLink(#{"email": e}), Password.reset(#{...}) -> "passwords.reset" etc.
    Verification  user.sendEmailVerificationNotification(), user.hasVerifiedEmail(), user.markEmailAsVerified()
    TwoFactor     TOTP (RFC 6238) secrets and codes, recovery codes, the login challenge
    Middleware    "signed", "throttle:6,1", "verified", "two-factor"

Secrets for signed URLs come from config app.key or APP_KEY (barq key:generate).
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
import urllib.parse

from barq.builtins import need
from barq.runtime import BarqObject, BarqThrow, BoundMethod, NativeFunction, to_display, type_name
from barq.stdlib import arg, module
from barq.stdlib2 import header_lookup, new_native


def now():
    return int(time.time())


def conf(i, key, default=None):
    from barq.stdlib2 import config_lookup
    v = config_lookup(i, key)
    return default if v is None else v


# ===========================================================================
# app key, URLs, signatures
# ===========================================================================

def app_key(i, n):
    import os
    key = conf(i, "app.key") or os.environ.get("APP_KEY")
    if not isinstance(key, str) or not key:
        i.throw("ValueException", 'signed URLs need an app key: run "barq key:generate" '
                '(it writes APP_KEY to .env), or set config app.key', n)
    if key.startswith("base64:"):
        try:
            return base64.b64decode(key[7:])
        except ValueError:
            i.throw("ValueException", "APP_KEY starts with base64: but is not valid base64", n)
    return key.encode()


def base_url(i):
    import os
    url = conf(i, "app.url") or os.environ.get("APP_URL") or "http://localhost:8000"
    return str(url).rstrip("/")


def absolute(i, path):
    if re.match(r"^[a-z][a-z0-9+.-]*://", path, re.I):
        return path
    return base_url(i) + ("" if path.startswith("/") else "/") + path


def signature_of(i, path_and_query, n):
    return hmac.new(app_key(i, n), path_and_query.encode(), hashlib.sha256).hexdigest()


def relative(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.path or "/") + ("?" + parts.query if parts.query else "")


def sign(i, url, minutes, n, fname):
    """Add expires (when minutes is given) and signature to a path or URL."""
    if minutes is not None:
        if type(minutes) is not int or minutes <= 0:
            i.throw("ValueException", f"{fname}(): minutes must be a positive int, got {to_display(minutes, i, True)}", n)
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if any(k in ("signature", "expires") for k, _ in pairs):
        i.throw("ValueException", f'{fname}(): "signature" and "expires" are reserved query parameters', n)
    if minutes is not None:
        pairs.append(("expires", str(now() + minutes * 60)))
    query = urllib.parse.urlencode(pairs)
    rel = (parts.path or "/") + ("?" + query if query else "")
    sig = signature_of(i, rel, n)
    signed = rel + ("&" if query else "?") + "signature=" + sig
    return (parts.scheme + "://" + parts.netloc + signed) if parts.netloc else signed


def valid_signature(i, url, n):
    parts = urllib.parse.urlsplit(url)
    pieces = [p for p in parts.query.split("&") if p] if parts.query else []
    sig, rest = None, []
    for p in pieces:
        if p.startswith("signature="):
            sig = p[len("signature="):]
        else:
            rest.append(p)
    if not sig:
        return False
    rel = (parts.path or "/") + ("?" + "&".join(rest) if rest else "")
    if not hmac.compare_digest(signature_of(i, rel, n), sig):
        return False
    expires = dict(urllib.parse.parse_qsl("&".join(rest))).get("expires")
    if expires is not None:
        return expires.isdigit() and int(expires) > now()
    return True


def request_url(req):
    return relative(req.fields.get("url") or req.fields["path"])


def u_to(i, a, n):
    return absolute(i, need(i, a[0], ("string",), "URL.to", 1, n))


def u_route(i, a, n):
    from barq.web import route_url
    path = route_url(i, [need(i, a[0], ("string",), "URL.route", 1, n), arg(i, a, 1, ("dict",), "URL.route", n, {})], n)
    absolute_ = arg(i, a, 2, ("bool",), "URL.route", n, False)
    return absolute(i, path) if absolute_ else path


def signed_route(i, name, params, minutes, n, fname):
    from barq.web import route_url
    return absolute(i, sign(i, route_url(i, [name, params], n), minutes, n, fname))


def u_signed_route(i, a, n):
    name = need(i, a[0], ("string",), "URL.signedRoute", 1, n)
    params = arg(i, a, 1, ("dict",), "URL.signedRoute", n, {})
    minutes = arg(i, a, 2, ("int",), "URL.signedRoute", n, None)
    return signed_route(i, name, params, minutes, n, "URL.signedRoute")


def u_temporary(i, a, n):
    name = need(i, a[0], ("string",), "URL.temporarySignedRoute", 1, n)
    minutes = need(i, a[1], ("int",), "URL.temporarySignedRoute", 2, n)
    params = arg(i, a, 2, ("dict",), "URL.temporarySignedRoute", n, {})
    return signed_route(i, name, params, minutes, n, "URL.temporarySignedRoute")


def u_sign(i, a, n):
    url = need(i, a[0], ("string",), "URL.sign", 1, n)
    return sign(i, url, arg(i, a, 1, ("int",), "URL.sign", n, None), n, "URL.sign")


def u_has_valid(i, a, n):
    v = a[0]
    if isinstance(v, BarqObject) and v.cls.name == "Request":
        return valid_signature(i, request_url(v), n)
    return valid_signature(i, need(i, v, ("string", "Request"), "URL.hasValidSignature", 1, n), n)


def u_current(i, a, n):
    from barq.web import current_request
    req = current_request(i)
    return absolute(i, request_url(req)) if req is not None else None


def u_previous(i, a, n):
    from barq.web import previous_url
    return previous_url(i, arg(i, a, 0, ("string",), "URL.previous", n, "/"))


def u_intended(i, a, n):
    from barq.web import pull_intended
    return pull_intended(i, arg(i, a, 0, ("string",), "URL.intended", n, "/"))


def u_set_intended(i, a, n):
    from barq.web import INTENDED_KEY, request_session
    url = need(i, a[0], ("string",), "URL.setIntended", 1, n)
    from barq.web import sdata
    sdata(request_session(i, n, "URL.setIntended"))[INTENDED_KEY] = url
    return None


URL = {
    "intended": (u_intended, 0, 1),
    "setIntended": (u_set_intended, 1, 1),
    "to": (u_to, 1, 1),
    "route": (u_route, 1, 3),
    "signedRoute": (u_signed_route, 1, 3),
    "temporarySignedRoute": (u_temporary, 2, 3),
    "sign": (u_sign, 1, 2),
    "hasValidSignature": (u_has_valid, 1, 1),
    "current": (u_current, 0, 0),
    "previous": (u_previous, 0, 1),
}


def mw_signed(i, a, n):
    from barq.web import error_response
    req, nxt = a[0], a[1]
    if not valid_signature(i, request_url(req), n):
        return error_response(i, req, 403, "Invalid signature.", n)
    return i.call_function(nxt, [req], n)


# ===========================================================================
# RateLimiter and the throttle middleware
# ===========================================================================

def limits(i):
    return i.__dict__.setdefault("_limits", {})


def hits(i, key):
    st = limits(i).get(key)
    if st is not None and st[1] <= time.time():
        del limits(i)[key]
        return None
    return st


def rl_hit(i, a, n):
    key = need(i, a[0], ("string",), "RateLimiter.hit", 1, n)
    decay = arg(i, a, 1, ("int",), "RateLimiter.hit", n, 60)
    return hit(i, key, decay)


def hit(i, key, decay):
    st = hits(i, key)
    if st is None:
        st = limits(i)[key] = [0, time.time() + decay]
    st[0] += 1
    return st[0]


def attempts(i, key):
    st = hits(i, key)
    return st[0] if st else 0


def available_in(i, key):
    st = hits(i, key)
    return max(0, int(st[1] - time.time() + 0.999)) if st else 0


def rl_too_many(i, a, n):
    key = need(i, a[0], ("string",), "RateLimiter.tooManyAttempts", 1, n)
    return attempts(i, key) >= need(i, a[1], ("int",), "RateLimiter.tooManyAttempts", 2, n)


def rl_remaining(i, a, n):
    key = need(i, a[0], ("string",), "RateLimiter.remaining", 1, n)
    return max(0, need(i, a[1], ("int",), "RateLimiter.remaining", 2, n) - attempts(i, key))


def rl_attempt(i, a, n):
    key = need(i, a[0], ("string",), "RateLimiter.attempt", 1, n)
    most = need(i, a[1], ("int",), "RateLimiter.attempt", 2, n)
    decay = arg(i, a, 3, ("int",), "RateLimiter.attempt", n, 60)
    if attempts(i, key) >= most:
        return False
    hit(i, key, decay)
    result = i.call_function(a[2], [], n)
    return True if result is None else result


RATE_LIMITER = {
    "hit": (rl_hit, 1, 2),
    "attempts": (lambda i, a, n: attempts(i, need(i, a[0], ("string",), "RateLimiter.attempts", 1, n)), 1, 1),
    "tooManyAttempts": (rl_too_many, 2, 2),
    "remaining": (rl_remaining, 2, 2),
    "availableIn": (lambda i, a, n: available_in(i, need(i, a[0], ("string",), "RateLimiter.availableIn", 1, n)), 1, 1),
    "clear": (lambda i, a, n: limits(i).pop(need(i, a[0], ("string",), "RateLimiter.clear", 1, n), None) and None, 1, 1),
    "attempt": (rl_attempt, 3, 4),
}


def mw_throttle(i, a, n):
    """throttle:max,minutes (default 60,1): per user (or IP when nobody is logged in) and route."""
    from .auth import current_user, model_key
    from barq.web import current, error_response
    req, nxt, extra = a[0], a[1], [x.strip() for x in a[2:]]
    try:
        most = int(extra[0]) if extra and extra[0] else 60
        minutes = int(extra[1]) if len(extra) > 1 and extra[1] else 1
    except ValueError:
        i.throw("ValueException", f'the throttle middleware takes "throttle:maxAttempts,minutes", got '
                f'"throttle:{",".join(extra)}"', n)
    with current(i, req):
        user = current_user(i, n)
        who = f"user:{model_key(i, user, n)}" if user is not None else f"ip:{req.native.ip}"
    route = req.native.route
    key = f"throttle|{who}|{req.fields['method'].upper()}|{route.path if route else req.fields['path']}"
    if attempts(i, key) >= most:
        res = error_response(i, req, 429, "Too Many Attempts.", n)
        res.fields["headers"].update({"Retry-After": str(available_in(i, key)), "X-RateLimit-Limit": str(most),
                                      "X-RateLimit-Remaining": "0"})
        return res
    count = hit(i, key, minutes * 60)
    res = i.call_function(nxt, [req], n)
    if isinstance(res, BarqObject) and res.cls.name == "Response":
        res.fields["headers"].update({"X-RateLimit-Limit": str(most), "X-RateLimit-Remaining": str(max(0, most - count))})
    return res


# ===========================================================================
# mail helpers
# ===========================================================================

def send_mail(i, to, subject, text, html, n, fname):
    from barq.stdlib3 import build_message, deliver

    def build(i2, args, n2):
        st = args[0].native
        st.subject, st.text, st.html = subject, text, html
        return None
    msg = build_message(i, NativeFunction(fname, build, 1, 1), ([to], [], []), n, fname)
    return deliver(i, msg, n)


def call_user_method(i, user, name, args, n):
    """Call a model method so the app's own version (in User) wins over the built-in one."""
    return i.call_function(BoundMethod(user, user.cls.find_method(name)), args, n)


def app_name(i):
    return str(conf(i, "app.name", "Barq"))


def attr(i, user, name):
    from barq_framework.orm import mstate
    return mstate(user).attrs.get(name)


def need_columns(i, user, cols, n, fname, hint):
    from barq_framework.orm import meta, model_db, table_columns
    m = meta(i, user.cls, n)
    have = table_columns(i, model_db(i, m, n), m.table, n)
    missing = [c for c in cols if c not in have]
    if missing:
        i.throw("AuthException", f"{fname}(): the {m.table} table has no {', '.join(missing)} column"
                f"{'s' if len(missing) > 1 else ''} — {hint}", n)


def set_attrs(i, user, values, n):
    from barq_framework.orm import mstate, save
    mstate(user).attrs.update(values)
    save(i, user, n)


# ===========================================================================
# Password — reset links and resets
# ===========================================================================

RESET_TABLE = "password_reset_tokens"
STATUS = {
    "RESET_LINK_SENT": "passwords.sent",
    "PASSWORD_RESET": "passwords.reset",
    "INVALID_USER": "passwords.user",
    "INVALID_TOKEN": "passwords.token",
    "RESET_THROTTLED": "passwords.throttled",
}
MESSAGES = {
    "passwords.sent": "We have emailed your password reset link.",
    "passwords.reset": "Your password has been reset.",
    "passwords.user": "We can't find a user with that email address.",
    "passwords.token": "This password reset token is invalid or has expired.",
    "passwords.throttled": "Please wait before retrying.",
}


def pw_settings(i):
    p = conf(i, "auth.passwords", {})
    p = p if isinstance(p, dict) else {}
    return {"expire": p.get("expire", 60), "throttle": p.get("throttle", 60), "provider": p.get("provider", "users")}


def pw_model(i, n):
    from .auth import user_model
    return user_model(i, pw_settings(i)["provider"], n)


def reset_db(i, cls, n):
    from barq_framework.orm import meta, model_db, table_columns
    db = model_db(i, meta(i, cls, n), n)
    if not table_columns(i, db, RESET_TABLE, n):
        i.throw("DbException", f'password resets need the "{RESET_TABLE}" table — run "barq auth:install" and '
                '"barq migrate" (or create it: t.string("email").primary(), t.string("token"), '
                't.int("created_at").nullable())', n)
    return db


def reset_query(i, db, n):
    from barq.stdlib2 import new_query, qid
    return new_query(i, db, qid(i, RESET_TABLE, n, "table"))


def token_row(i, db, email, n):
    from barq.stdlib2 import add_where, qb_first
    q = reset_query(i, db, n)
    add_where(i, ["email", email], n, q, "AND", "Password")
    return qb_first(i, [], n, q)


def delete_rows(i, db, email, n):
    from barq.stdlib2 import add_where, QUERY_METHODS
    q = reset_query(i, db, n)
    add_where(i, ["email", email], n, q, "AND", "Password")
    QUERY_METHODS["delete"][0](i, [], n, q)


def user_email(i, user, n, fname):
    email = attr(i, user, "email")
    if not isinstance(email, str) or not email:
        i.throw("AuthException", f"{fname}(): the {user.cls.name} has no email", n)
    return email


def create_token(i, user, n):
    from barq.stdlib2 import insert_rows
    db = reset_db(i, user.cls, n)
    email = user_email(i, user, n, "Password.createToken")
    delete_rows(i, db, email, n)
    plain = secrets.token_hex(32)
    insert_rows(i, reset_query(i, db, n), [{"email": email, "token": hashlib.sha256(plain.encode()).hexdigest(),
                                            "created_at": now()}], n, "Password.createToken")
    return plain


def token_valid(i, user, plain, n):
    if not isinstance(plain, str) or not plain:
        return False
    db = reset_db(i, user.cls, n)
    row = token_row(i, db, user_email(i, user, n, "Password.tokenExists"), n)
    if row is None or not hmac.compare_digest(row.get("token") or "", hashlib.sha256(plain.encode()).hexdigest()):
        return False
    expire = pw_settings(i)["expire"]
    return not (expire and (row.get("created_at") or 0) + expire * 60 <= now())


def find_by(i, creds, n, fname):
    from .auth import default_guard, retrieve
    need(i, creds, ("dict",), fname, 1, n)
    look = {k: v for k, v in creds.items() if k not in ("password", "password_confirmation", "token")}
    if not look:
        i.throw("ValueException", f'{fname}() needs a column to find the user by, e.g. #{{"email": e}}', n)
    g = default_guard(i, n).native
    from .auth import user_model
    cls = pw_model(i, n)
    if user_model(i, g.provider, n) is not cls:
        g = type(g)(g.name, g.driver, pw_settings(i)["provider"])
    return retrieve(i, g, dict(look, password=""), n, fname)


def pw_send_reset_link(i, a, n):
    fname = "Password.sendResetLink"
    user = find_by(i, a[0], n, fname)
    if user is None:
        return STATUS["INVALID_USER"]
    db = reset_db(i, user.cls, n)
    row = token_row(i, db, user_email(i, user, n, fname), n)
    throttle = pw_settings(i)["throttle"]
    if row is not None and throttle and (row.get("created_at") or 0) + throttle > now():
        return STATUS["RESET_THROTTLED"]
    token = create_token(i, user, n)
    if len(a) > 1 and a[1] is not None:
        i.call_function(a[1], [user, token], n)
    else:
        call_user_method(i, user, "sendPasswordResetNotification", [token], n)
    return STATUS["RESET_LINK_SENT"]


def pw_reset(i, a, n):
    from .auth import fire
    fname = "Password.reset"
    creds = need(i, a[0], ("dict",), fname, 1, n)
    for k in ("token", "password"):
        if not isinstance(creds.get(k), str):
            i.throw("ValueException", f'{fname}() needs "{k}" (a string) in its first argument', n)
    user = find_by(i, creds, n, fname)
    if user is None:
        return STATUS["INVALID_USER"]
    if not token_valid(i, user, creds["token"], n):
        return STATUS["INVALID_TOKEN"]
    if len(a) > 1 and a[1] is not None:
        i.call_function(a[1], [user, creds["password"]], n)
    else:
        default_reset(i, user, creds["password"], n)
    delete_rows(i, reset_db(i, user.cls, n), user_email(i, user, n, fname), n)
    fire(i, "auth.passwordReset", user, n)
    return STATUS["PASSWORD_RESET"]


def default_reset(i, user, password, n):
    from barq_framework.orm import meta, model_db, table_columns
    from barq.stdlib import hash_password
    values = {"password": hash_password(i, [password], n)}
    m = meta(i, user.cls, n)
    if "remember_token" in table_columns(i, model_db(i, m, n), m.table, n):
        values["remember_token"] = secrets.token_urlsafe(45)      # "remember me" cookies stop working
    set_attrs(i, user, values, n)


def pw_message(i, a, n):
    status = need(i, a[0], ("string",), "Password.message", 1, n)
    return MESSAGES.get(status, status)


def pw_user(i, a, n):
    return find_by(i, a[0], n, "Password.user")


def need_user(i, v, n, fname):
    from barq_framework.orm import is_model
    if not is_model(i, v):
        i.throw("TypeException", f"{fname}() needs a user model, got {type_name(v)}", n)
    return v


PASSWORD = dict(STATUS)
PASSWORD.update({
    "sendResetLink": (pw_send_reset_link, 1, 2),
    "reset": (pw_reset, 1, 2),
    "createToken": (lambda i, a, n: create_token(i, need_user(i, a[0], n, "Password.createToken"), n), 1, 1),
    "tokenExists": (lambda i, a, n: token_valid(i, need_user(i, a[0], n, "Password.tokenExists"),
                                                need(i, a[1], ("string",), "Password.tokenExists", 2, n), n), 2, 2),
    "deleteToken": (lambda i, a, n: delete_rows(i, reset_db(i, need_user(i, a[0], n, "Password.deleteToken").cls, n),
                                                user_email(i, a[0], n, "Password.deleteToken"), n), 1, 1),
    "user": (pw_user, 1, 1),
    "message": (pw_message, 1, 1),
})


def reset_url(i, user, token, n):
    from barq.web import route_url, router
    email = user_email(i, user, n, "sendPasswordResetNotification")
    if "password.reset" in router(i).names:
        return absolute(i, route_url(i, ["password.reset", {"token": token, "email": email}], n))
    return absolute(i, f"/reset-password/{token}?" + urllib.parse.urlencode({"email": email}))


def m_send_reset(i, a, n, this):
    token = need(i, a[0], ("string",), f"{this.cls.name}.sendPasswordResetNotification", 1, n)
    url = reset_url(i, this, token, n)
    minutes = pw_settings(i)["expire"]
    text = (f"You are receiving this email because we received a password reset request for your account.\n\n"
            f"Reset your password: {url}\n\n"
            f"This link expires in {minutes} minutes. If you did not ask for a reset, you can ignore this email.")
    html = (f"<p>You are receiving this email because we received a password reset request for your account.</p>"
            f'<p><a href="{escape(url)}">Reset your password</a></p>'
            f"<p>This link expires in {minutes} minutes. If you did not ask for a reset, you can ignore this email.</p>")
    send_mail(i, user_email(i, this, n, "sendPasswordResetNotification"), f"{app_name(i)}: reset your password",
              text, html, n, "sendPasswordResetNotification")
    return None


def escape(s):
    import html
    return html.escape(s, quote=True)


# ===========================================================================
# email verification
# ===========================================================================

VERIFY_HINT = 'add t.int("email_verified_at").nullable() to the users migration (barq auth:install does)'


def verification_url(i, user, n):
    from .auth import model_key
    from barq.web import router
    if "verification.verify" not in router(i).names:
        i.throw("NameException", 'email verification needs a route named "verification.verify" taking :id and :hash '
                '(barq auth:install writes it to routes/auth.bq)', n)
    email = user_email(i, user, n, "verificationUrl")
    minutes = conf(i, "auth.verification.expire", 60)
    return signed_route(i, "verification.verify", {"id": model_key(i, user, n),
                                                   "hash": hashlib.sha1(email.encode()).hexdigest()},
                        minutes, n, "verificationUrl")


def m_has_verified(i, a, n, this):
    return attr(i, this, "email_verified_at") is not None


def m_mark_verified(i, a, n, this):
    from .auth import fire
    need_columns(i, this, ["email_verified_at"], n, f"{this.cls.name}.markEmailAsVerified", VERIFY_HINT)
    if attr(i, this, "email_verified_at") is not None:
        return False
    set_attrs(i, this, {"email_verified_at": now()}, n)
    fire(i, "auth.verified", this, n)
    return True


def m_send_verification(i, a, n, this):
    url = verification_url(i, this, n)
    text = f"Please confirm your email address by opening this link:\n\n{url}\n\n" \
           "If you did not create an account, no further action is required."
    html = f'<p>Please confirm your email address.</p><p><a href="{escape(url)}">Verify email address</a></p>' \
           "<p>If you did not create an account, no further action is required.</p>"
    send_mail(i, user_email(i, this, n, "sendEmailVerificationNotification"),
              f"{app_name(i)}: verify your email address", text, html, n, "sendEmailVerificationNotification")
    return None


def mw_verified(i, a, n):
    from .auth import current_user
    from barq.web import current, error_response, router, route_url
    from barq.stdlib2 import resp_redirect
    req, nxt = a[0], a[1]
    with current(i, req):
        user = current_user(i, n)
        if user is None:
            obj = i.make_exception("AuthenticationException", "Unauthenticated.", n)
            obj.fields["status"] = 401
            raise BarqThrow(obj)
        verified = call_user_method(i, user, "hasVerifiedEmail", [], n)
    if verified is not True:
        from barq.web import wants_json
        if not wants_json(req) and "verification.notice" in router(i).names:
            return resp_redirect(i, [route_url(i, ["verification.notice"], n)], n)
        return error_response(i, req, 403, "Your email address is not verified.", n)
    return i.call_function(nxt, [req], n)


# ===========================================================================
# TwoFactor — TOTP (RFC 6238), recovery codes, the login challenge
# ===========================================================================

TWO_FACTOR_COLUMNS = ["two_factor_secret", "two_factor_recovery_codes", "two_factor_confirmed_at"]
TWO_FACTOR_HINT = ('add t.text("two_factor_secret").nullable(), t.text("two_factor_recovery_codes").nullable() '
                   'and t.int("two_factor_confirmed_at").nullable() to the users table (barq auth:install does)')
PERIOD = 30
DIGITS = 6
PENDING_KEY = "_2fa_pending"


def tf_settings(i):
    c = conf(i, "auth.2fa", {})
    c = c if isinstance(c, dict) else {}
    return {"enabled": c.get("enabled", True), "required": c.get("required", False),
            "recovery_codes": c.get("recovery_codes", 8), "issuer": c.get("issuer") or app_name(i),
            "window": c.get("window", 1), "max_attempts": c.get("max_attempts", 3)}


def generate_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def secret_bytes(i, secret, n, fname):
    s = re.sub(r"[\s-]", "", secret).upper()
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        i.throw("ValueException", f"{fname}(): the secret is not valid base32", n)


def hotp(key, counter):
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def totp_step(ts):
    return int(ts) // PERIOD


def matching_step(i, secret, code, ts, window, n, fname):
    """The time step the code belongs to (within the window), or None."""
    code = re.sub(r"\s", "", code) if isinstance(code, str) else ""
    if not re.match(r"^\d{6}$", code):
        return None
    key = secret_bytes(i, secret, n, fname)
    step = totp_step(ts)
    for d in sorted(range(-window, window + 1), key=abs):
        if hmac.compare_digest(hotp(key, step + d), code):
            return step + d
    return None


def tf_code(i, a, n):
    secret = need(i, a[0], ("string",), "TwoFactor.code", 1, n)
    ts = arg(i, a, 1, ("int",), "TwoFactor.code", n, None)
    return hotp(secret_bytes(i, secret, n, "TwoFactor.code"), totp_step(now() if ts is None else ts))


def tf_verify_code(i, a, n):
    secret = need(i, a[0], ("string",), "TwoFactor.verifyCode", 1, n)
    code = need(i, a[1], ("string",), "TwoFactor.verifyCode", 2, n)
    ts = arg(i, a, 2, ("int",), "TwoFactor.verifyCode", n, None)
    return matching_step(i, secret, code, now() if ts is None else ts, tf_settings(i)["window"], n,
                         "TwoFactor.verifyCode") is not None


def otpauth_url(issuer, account, secret):
    label = urllib.parse.quote(f"{issuer}:{account}", safe=":")
    return f"otpauth://totp/{label}?" + urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD})


def tf_otpauth(i, a, n):
    account = need(i, a[0], ("string",), "TwoFactor.otpauthUrl", 1, n)
    secret = need(i, a[1], ("string",), "TwoFactor.otpauthUrl", 2, n)
    issuer = arg(i, a, 2, ("string",), "TwoFactor.otpauthUrl", n, None) or tf_settings(i)["issuer"]
    return otpauth_url(issuer, account, secret)


RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def recovery_code():
    pick = [secrets.choice(RECOVERY_ALPHABET) for _ in range(10)]
    return "".join(pick[:5]) + "-" + "".join(pick[5:])


def tf_recovery_codes(i, a, n):
    count = arg(i, a, 0, ("int",), "TwoFactor.recoveryCodes", n, None) or tf_settings(i)["recovery_codes"]
    return [recovery_code() for _ in range(count)]


# ---- user methods ----

def tf_need(i, user, n, fname):
    need_columns(i, user, TWO_FACTOR_COLUMNS, n, fname, TWO_FACTOR_HINT)


def stored_codes(i, user):
    raw = attr(i, user, "two_factor_recovery_codes")
    if isinstance(raw, list):
        return list(raw)
    try:
        v = json.loads(raw) if isinstance(raw, str) and raw else []
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def codes_value(i, user, codes):
    """What to store: a list when the model casts the column to list/json, else JSON text."""
    from barq_framework.orm import meta
    if codes is None:
        return None
    cast = meta(i, user.cls).casts.get("two_factor_recovery_codes")
    return list(codes) if cast in ("list", "json") else json.dumps(codes)


def m_tf_enabled(i, a, n, this):
    return bool(attr(i, this, "two_factor_secret")) and attr(i, this, "two_factor_confirmed_at") is not None


def m_tf_enable(i, a, n, this):
    """Start setup: a new secret, not active until confirmTwoFactor(code)."""
    tf_need(i, this, n, f"{this.cls.name}.enableTwoFactor")
    secret = generate_secret()
    set_attrs(i, this, {"two_factor_secret": secret, "two_factor_confirmed_at": None,
                        "two_factor_recovery_codes": None}, n)
    return secret


def used_steps(i):
    return i.__dict__.setdefault("_2fa_steps", {})


def check_totp(i, user, code, n, fname):
    """A TOTP code for this user, each time step usable once (no replays)."""
    from .auth import model_key
    secret = attr(i, user, "two_factor_secret")
    if not secret:
        return False
    step = matching_step(i, secret, code, now(), tf_settings(i)["window"], n, fname)
    if step is None:
        return False
    who = (user.cls.fqn, model_key(i, user, n), hashlib.sha256(secret.encode()).hexdigest())
    if used_steps(i).get(who, -1) >= step:
        return False
    used_steps(i)[who] = step
    return True


def m_tf_confirm(i, a, n, this):
    from .auth import fire
    fname = f"{this.cls.name}.confirmTwoFactor"
    code = need(i, a[0], ("string",), fname, 1, n)
    tf_need(i, this, n, fname)
    if not attr(i, this, "two_factor_secret"):
        i.throw("AuthException", f"{fname}(): call enableTwoFactor() first", n)
    if not check_totp(i, this, code, n, fname):
        return False
    values = {"two_factor_confirmed_at": now()}
    if not stored_codes(i, this):
        values["two_factor_recovery_codes"] = codes_value(i, this, tf_recovery_codes(i, [], n))
    set_attrs(i, this, values, n)
    fire(i, "auth.twoFactorEnabled", this, n)
    return True


def m_tf_disable(i, a, n, this):
    from .auth import fire
    tf_need(i, this, n, f"{this.cls.name}.disableTwoFactor")
    was = m_tf_enabled(i, a, n, this)
    set_attrs(i, this, {"two_factor_secret": None, "two_factor_confirmed_at": None,
                        "two_factor_recovery_codes": None}, n)
    if was:
        fire(i, "auth.twoFactorDisabled", this, n)
    return None


def m_tf_verify(i, a, n, this):
    fname = f"{this.cls.name}.verifyTwoFactorCode"
    return check_totp(i, this, need(i, a[0], ("string",), fname, 1, n), n, fname)


def m_tf_recovery(i, a, n, this):
    """Use a recovery code: true once per code."""
    fname = f"{this.cls.name}.verifyRecoveryCode"
    code = need(i, a[0], ("string",), fname, 1, n).strip().upper()
    codes = stored_codes(i, this)
    hit_ = next((c for c in codes if isinstance(c, str) and hmac.compare_digest(c.encode(), code.encode())), None)
    if hit_ is None:
        return False
    codes.remove(hit_)
    set_attrs(i, this, {"two_factor_recovery_codes": codes_value(i, this, codes)}, n)
    return True


def m_tf_regenerate(i, a, n, this):
    fname = f"{this.cls.name}.regenerateRecoveryCodes"
    tf_need(i, this, n, fname)
    if not attr(i, this, "two_factor_secret"):
        i.throw("AuthException", f"{fname}(): two-factor authentication is not enabled", n)
    codes = tf_recovery_codes(i, [], n)
    set_attrs(i, this, {"two_factor_recovery_codes": codes_value(i, this, codes)}, n)
    return codes


def m_tf_url(i, a, n, this):
    secret = attr(i, this, "two_factor_secret")
    if not secret:
        return None
    return otpauth_url(tf_settings(i)["issuer"], user_email(i, this, n, "twoFactorQrCodeUrl"), secret)


def m_tf_svg(i, a, n, this):
    from .qr import encode, svg
    url = m_tf_url(i, a, n, this)
    if url is None:
        return None
    size = arg(i, a, 0, ("int",), f"{this.cls.name}.twoFactorQrCodeSvg", n, 192)
    return svg(encode(url), size)


# ---- the login challenge ----

def pending_store(i):
    from barq.web import current_request, sdata, start_session
    req = current_request(i)
    if req is None:
        return i.__dict__.setdefault("_2fa_memory", {})
    return sdata(start_session(i, req, None))


def tf_attempt(i, a, n):
    """-> "login" (logged in), "two-factor" (now ask for a code) or "failed"."""
    from .auth import default_guard, do_login, model_key, valid_user
    fname = "TwoFactor.attempt"
    remember = arg(i, a, 1, ("bool",), fname, n, False)
    g = default_guard(i, n).native
    user = valid_user(i, g, a[0], n, fname)
    if user is None:
        return "failed"
    if call_user_method(i, user, "hasTwoFactorEnabled", [], n) is True:
        pending_store(i)[PENDING_KEY] = {"id": model_key(i, user, n), "remember": remember, "tries": 0,
                                         "guard": g.name}
        return "two-factor"
    do_login(i, g, user, remember, n, fname)
    return "login"


def tf_login(i, a, n):
    """Log in a user already known to be who they say (e.g. after OAuth): the
    2FA challenge first when they have it on. -> "login" or "two-factor"."""
    from .auth import default_guard, do_login, model_key, need_user
    fname = "TwoFactor.login"
    remember = arg(i, a, 1, ("bool",), fname, n, False)
    g = default_guard(i, n).native
    user = need_user(i, g, a[0], n, fname)
    if call_user_method(i, user, "hasTwoFactorEnabled", [], n) is True:
        pending_store(i)[PENDING_KEY] = {"id": model_key(i, user, n), "remember": remember, "tries": 0,
                                         "guard": g.name}
        return "two-factor"
    do_login(i, g, user, remember, n, fname)
    return "login"


def pending_user(i, n):
    from .auth import find_user, guard_obj
    p = pending_store(i).get(PENDING_KEY)
    if not isinstance(p, dict):
        return None, None
    g = guard_obj(i, p["guard"], n).native
    return find_user(i, g, p["id"], n), p


def tf_complete(i, a, n):
    """The code from the authenticator app (or a recovery code) for the pending login."""
    from .auth import do_login, fire, guard_obj
    fname = "TwoFactor.complete"
    code = need(i, a[0], ("string",), fname, 1, n)
    user, p = pending_user(i, n)
    if user is None:
        pending_store(i).pop(PENDING_KEY, None)
        return False
    ok = check_totp(i, user, code, n, fname) or m_tf_recovery(i, [code], n, user)
    store = pending_store(i)
    if ok:
        store.pop(PENDING_KEY, None)
        do_login(i, guard_obj(i, p["guard"], n).native, user, bool(p.get("remember")), n, fname)
        return True
    p["tries"] = p.get("tries", 0) + 1
    fire(i, "auth.twoFactorFailed", user, n)
    if p["tries"] >= tf_settings(i)["max_attempts"]:
        store.pop(PENDING_KEY, None)
        fire(i, "auth.lockout", user, n)
    else:
        store[PENDING_KEY] = p
    return False


def tf_qr(i, a, n):
    from .qr import QR
    return QR["svg"][0](i, a, n)


TWO_FACTOR = {
    "generateSecret": (lambda i, a, n: generate_secret(), 0, 0),
    "code": (tf_code, 1, 2),
    "verifyCode": (tf_verify_code, 2, 3),
    "otpauthUrl": (tf_otpauth, 2, 3),
    "qrCodeSvg": (tf_qr, 1, 2),
    "recoveryCodes": (tf_recovery_codes, 0, 1),
    "attempt": (tf_attempt, 1, 2),
    "login": (tf_login, 1, 2),
    "pending": (lambda i, a, n: pending_user(i, n)[0], 0, 0),
    "attemptsLeft": (lambda i, a, n: max(0, tf_settings(i)["max_attempts"] - (pending_user(i, n)[1] or {}).get("tries", 0))
                     if pending_user(i, n)[0] is not None else 0, 0, 0),
    "complete": (tf_complete, 1, 1),
    "cancel": (lambda i, a, n: pending_store(i).pop(PENDING_KEY, None) and None, 0, 0),
}


def mw_two_factor(i, a, n):
    """When config auth.2fa.required is true, users without 2FA are sent to set it up."""
    from .auth import current_user
    from barq.web import current, error_response, router, route_url, wants_json
    from barq.stdlib2 import resp_redirect
    req, nxt = a[0], a[1]
    if tf_settings(i)["required"]:
        with current(i, req):
            user = current_user(i, n)
            enabled = user is not None and call_user_method(i, user, "hasTwoFactorEnabled", [], n) is True
        if user is not None and not enabled:
            if not wants_json(req) and "two-factor.show" in router(i).names:
                return resp_redirect(i, [route_url(i, ["two-factor.show"], n)], n)
            return error_response(i, req, 403, "Two-factor authentication is required.", n)
    return i.call_function(nxt, [req], n)


# ===========================================================================
# install
# ===========================================================================

MODEL_METHODS = {
    "sendPasswordResetNotification": (m_send_reset, 1, 1),
    "hasVerifiedEmail": (m_has_verified, 0, 0),
    "markEmailAsVerified": (m_mark_verified, 0, 0),
    "sendEmailVerificationNotification": (m_send_verification, 0, 0),
    "verificationUrl": (lambda i, a, n, this: verification_url(i, this, n), 0, 0),
    "hasTwoFactorEnabled": (m_tf_enabled, 0, 0),
    "enableTwoFactor": (m_tf_enable, 0, 0),
    "confirmTwoFactor": (m_tf_confirm, 1, 1),
    "disableTwoFactor": (m_tf_disable, 0, 0),
    "twoFactorSecret": (lambda i, a, n, this: attr(i, this, "two_factor_secret"), 0, 0),
    "twoFactorQrCodeUrl": (m_tf_url, 0, 0),
    "twoFactorQrCodeSvg": (m_tf_svg, 0, 1),
    "verifyTwoFactorCode": (m_tf_verify, 1, 1),
    "recoveryCodes": (lambda i, a, n, this: stored_codes(i, this), 0, 0),
    "verifyRecoveryCode": (m_tf_recovery, 1, 1),
    "regenerateRecoveryCodes": (m_tf_regenerate, 0, 0),
}


def install(i):
    from .qr import QR
    from barq.web import BUILTIN_MIDDLEWARE
    g = i.builtins
    for name, table in (("URL", URL), ("RateLimiter", RATE_LIMITER), ("Password", PASSWORD),
                        ("TwoFactor", TWO_FACTOR), ("Qr", QR)):
        g.declare(name, module(name, table), None, const=True)
    BUILTIN_MIDDLEWARE.update({"signed": NativeFunction("signed", mw_signed, 2, -1),
                               "throttle": NativeFunction("throttle", mw_throttle, 2, -1),
                               "verified": NativeFunction("verified", mw_verified, 2, -1),
                               "two-factor": NativeFunction("two-factor", mw_two_factor, 2, -1)})
    model = i.classes["Model"]
    for name, (fn, lo, hi) in MODEL_METHODS.items():
        f = NativeFunction(f"Model.{name}", fn, lo, hi)
        f.owner = model
        model.methods[name] = f
    from barq.stdlib2 import STDLIB_ALIASES
    STDLIB_ALIASES.update({"Auth\\Password": "Password", "Auth\\TwoFactor": "TwoFactor"})
