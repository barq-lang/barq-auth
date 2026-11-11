"""Auth, part 3 (v0.15.0): devices, social logins and teams.

    Sessions   user.sessions(), Auth.logoutOtherDevices(password), Auth.logoutEveryDevice(),
               Auth.logoutSession(id), session().browser() / .platform() / .ip()
    OAuth      OAuth.driver("google").redirect(), OAuth.driver("google").user() -> OAuthUser,
               GoogleProvider / FacebookProvider / GithubProvider, OAuth.fake("google", #{...})
    Teams      class Team extends TeamModel; team.addMember(user, role: "admin"), team.invite(email),
               Team.acceptInvitation(token), user.teams(), user.currentTeam(), user.switchTeam(team)

OAuth settings live in config auth.oauth.<provider> (client_id, client_secret,
redirect); team settings in auth.teams. The HTTP calls go through the Http
client, so Http.fake() covers them in tests.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse

from barq.builtins import need
from barq.runtime import BarqClass, BarqObject, BarqThrow, NativeFunction, PropInfo, to_display, type_name
from barq.stdlib import arg, module
from barq.stdlib2 import new_native, native_class


def now():
    return int(time.time())


def conf(i, key, default=None):
    from barq.stdlib2 import config_lookup
    v = config_lookup(i, key)
    return default if v is None else v


def opt(a, k, default=None):
    """Argument k, or default when missing or null (named arguments leave gaps as null)."""
    return a[k] if len(a) > k and a[k] is not None else default


def native(name, fn, lo, hi, names=None, owner=None):
    f = NativeFunction(name, fn, lo, hi)
    f.arg_names = names
    f.owner = owner
    return f


def throw(i, cls, message, n, **fields):
    obj = i.make_exception(cls, message, n)
    obj.fields.update(fields)
    raise BarqThrow(obj)


# ===========================================================================
# session management
# ===========================================================================

def public_id(sid):
    """What user.sessions() shows instead of the session id (which works as a login)."""
    return hashlib.sha256(sid.encode()).hexdigest()[:24]


def session_keys_for(i, user, n):
    """The session keys that hold this user's id: _auth_<guard> for each session guard of its model."""
    from .auth import settings, user_model
    keys = []
    for name, g in settings(i)["guards"].items():
        if not isinstance(g, dict) or g.get("driver", "session") != "session":
            continue
        try:
            cls = user_model(i, g.get("provider", "users"), n)
        except BarqThrow:
            continue
        if user.cls.is_subclass_of(cls):
            keys.append("_auth_" + name)
    return keys


def current_session(i):
    from barq.web import current_request
    req = current_request(i)
    return req.native.session if req is not None else None


def user_sessions(i, user, n):
    """[(sid, data, last activity)] for every live session this user is logged in on."""
    from .auth import model_key
    from barq.web import session_settings, store_all
    key = model_key(i, user, n)
    keys = session_keys_for(i, user, n)
    cfg = session_settings(i, n)
    cur = current_session(i)
    skip = {cur.native.id, cur.native.old_id} if cur is not None else set()
    found = []
    for sid, data, last in store_all(i, cfg, key if cfg["driver"] == "database" else None):
        if sid not in skip and any(data.get(k) == key for k in keys):
            found.append((sid, data, last))
    if cur is not None and any(cur.native.data.get(k) == key for k in keys):
        found.append((cur.native.id, cur.native.data, time.time()))
    return found


def session_info(i, sid, data, last):
    from barq.web import parse_agent
    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    agent = meta.get("agent") or ""
    browser, platform, mobile = parse_agent(agent)
    cur = current_session(i)
    return {"id": public_id(sid), "ip": meta.get("ip"), "agent": agent, "browser": browser, "platform": platform,
            "mobile": mobile, "lastActive": int(meta.get("last") or last),
            "current": cur is not None and cur.native.id == sid}


def m_sessions(i, a, n, this):
    from .auth import need_saved
    need_saved(i, this, n, f"{this.cls.name}.sessions")
    rows = [session_info(i, sid, data, last) for sid, data, last in user_sessions(i, this, n)]
    rows.sort(key=lambda r: (not r["current"], -r["lastActive"]))
    return rows


def drop_sessions(i, user, n, keep=None, only=None):
    """Delete the user's stored sessions (not `keep`; only the one shown as `only`). -> how many."""
    from barq.web import session_settings, store_delete
    cfg = session_settings(i, n)
    cur = current_session(i)
    count = 0
    for sid, data, last in user_sessions(i, user, n):
        if sid == keep or (only is not None and public_id(sid) != only):
            continue
        if cur is not None and sid == cur.native.id:
            continue        # the current one: the caller logs it out
        store_delete(i, cfg, sid)
        count += 1
    return count


def logged_in(i, n, fname):
    from .auth import default_guard, resolve_user
    g = default_guard(i, n).native
    user = resolve_user(i, g, n)
    if user is None:
        throw(i, "AuthException", f"{fname}(): nobody is logged in", n)
    return g, user


def recycle_remember(i, g, user, n, fname):
    """New remember-me token: the cookies on other devices stop working. This device keeps one."""
    from .auth import cycle_remember_token, model_key, remember_cookie, settings
    from barq_framework.orm import mstate
    from barq.web import cookie_header, current_request, req_cookies
    if not mstate(user).attrs.get("remember_token"):
        return
    token = cycle_remember_token(i, user, n, fname)
    req = current_request(i)
    if req is not None and remember_cookie(g) in req_cookies(req):
        req.native.queued.append(cookie_header(i, remember_cookie(g), f"{model_key(i, user, n)}|{token}",
                                               {"maxAge": settings(i)["remember_lifetime"], "httpOnly": True,
                                                "sameSite": "Lax"}, n, fname))


def auth_logout_others(i, a, n):
    from .auth import check_password, fire
    fname = "Auth.logoutOtherDevices"
    password = need(i, a[0], ("string",), fname, 1, n)
    g, user = logged_in(i, n, fname)
    if not check_password(i, user, password, n):
        return False
    cur = current_session(i)
    drop_sessions(i, user, n, keep=cur.native.id if cur is not None else None)
    recycle_remember(i, g, user, n, fname)
    fire(i, "auth.otherDeviceLogout", user, n)
    return True


def auth_logout_every(i, a, n):
    from .auth import do_logout
    g, user = logged_in(i, n, "Auth.logoutEveryDevice")
    drop_sessions(i, user, n)
    do_logout(i, g, n)
    return None


def auth_logout_session(i, a, n):
    from .auth import do_logout
    fname = "Auth.logoutSession"
    key = need(i, a[0], ("string",), fname, 1, n)
    g, user = logged_in(i, n, fname)
    cur = current_session(i)
    if cur is not None and public_id(cur.native.id) == key:
        do_logout(i, g, n)
        return True
    return drop_sessions(i, user, n, only=key) > 0


def m_logout_sessions(i, a, n, this):
    """user.logoutSessions(): log this user out everywhere (e.g. from an admin page). -> sessions ended."""
    from .auth import cycle_remember_token, set_user, guard_obj
    from barq_framework.orm import mstate
    fname = f"{this.cls.name}.logoutSessions"
    count = drop_sessions(i, this, n)
    cur = current_session(i)
    from .auth import model_key
    key = model_key(i, this, n)
    if cur is not None:
        for k in session_keys_for(i, this, n):
            if cur.native.data.get(k) == key:
                cur.native.data.pop(k)
                set_user(i, guard_obj(i, k[len("_auth_"):], n).native, None)
                count += 1
    if mstate(this).attrs.get("remember_token"):
        cycle_remember_token(i, this, n, fname)
    return count


# ===========================================================================
# OAuth — social login (authorization code flow)
# ===========================================================================

OAUTH_DRIVERS = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "user_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": ["openid", "email", "profile"], "separator": " ", "pkce": True,
    },
    "facebook": {
        "authorize_url": "https://www.facebook.com/v19.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/v19.0/oauth/access_token",
        "user_url": "https://graph.facebook.com/v19.0/me",
        "fields": "id,name,email,picture.type(large)",
        "scopes": ["email", "public_profile"], "separator": ",", "pkce": False,
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "user_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scopes": ["read:user", "user:email"], "separator": " ", "pkce": False,
    },
}
ENV_NAMES = {"facebook": ("FACEBOOK_APP_ID", "FACEBOOK_APP_SECRET")}
STATE_KEY = "_oauth"


class ProviderState:
    def __init__(self, name, scopes=None, extra=None, params=None, stateless=False, redirect=None):
        self.name = name
        self.scopes = scopes            # replaces the default scopes (setScopes)
        self.extra = extra or []        # added to them (scopes)
        self.params = params or {}      # more query parameters for the authorize URL (with)
        self.stateless = stateless
        self.redirect = redirect

    def copy(self, **changes):
        st = ProviderState(self.name, self.scopes, list(self.extra), dict(self.params), self.stateless, self.redirect)
        for k, v in changes.items():
            setattr(st, k, v)
        return st


def oauth_settings(i, name):
    c = conf(i, "auth.oauth", {})
    c = c.get(name) if isinstance(c, dict) else None
    return c if isinstance(c, dict) else {}


def provider_config(i, name, n, fname):
    import os
    own = oauth_settings(i, name)
    driver = own.get("driver", name)
    base = OAUTH_DRIVERS.get(driver)
    if base is None:
        if not all(own.get(k) for k in ("authorize_url", "token_url", "user_url")):
            known = ", ".join(sorted(set(OAUTH_DRIVERS) | set(conf(i, "auth.oauth", {}) or {})))
            throw(i, "OAuthException", f'{fname}(): unknown OAuth provider "{name}" (built in: google, facebook, '
                  f'github; configured: {known}). A custom one needs authorize_url, token_url and user_url '
                  f'in config auth.oauth.{name}', n)
        base = {"scopes": [], "separator": " ", "pkce": False}
    c = dict(base)
    c.update({k: v for k, v in own.items() if v is not None})
    c["driver"] = driver if driver in OAUTH_DRIVERS else "custom"
    env_id, env_secret = ENV_NAMES.get(name, (f"{name.upper()}_CLIENT_ID", f"{name.upper()}_CLIENT_SECRET"))
    c.setdefault("client_id", os.environ.get(env_id))
    c.setdefault("client_secret", os.environ.get(env_secret))
    c.setdefault("redirect", f"/auth/{name}/callback")
    return c


def oauth_enabled(i, name):
    try:
        c = provider_config(i, name, None, "OAuth.enabled")
    except BarqThrow:
        return False
    return bool(c.get("client_id")) and bool(c.get("client_secret")) and c.get("enabled", True) is not False


def fakes(i):
    return i.__dict__.setdefault("_oauth_fakes", {})


def redirect_uri(i, st, c):
    from .auth2 import absolute
    return absolute(i, st.redirect or c["redirect"])


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def authorize_url(i, st, n, fname):
    from .auth2 import pending_store
    c = provider_config(i, st.name, n, fname)
    if st.name in fakes(i):
        # faked: straight back to the callback, so a TestClient can follow it
        uri = redirect_uri(i, st, c)
        return uri + ("&" if "?" in uri else "?") + "code=fake&state=fake"
    if not c.get("client_id"):
        env_id = ENV_NAMES.get(st.name, (f"{st.name.upper()}_CLIENT_ID",))[0]
        throw(i, "OAuthException", f'{fname}(): no client id for "{st.name}" — set {env_id} in .env '
              f'(or config auth.oauth.{st.name}.client_id)', n)
    scopes = list(st.scopes if st.scopes is not None else c.get("scopes") or [])
    scopes += [s for s in st.extra if s not in scopes]
    params = {"client_id": c["client_id"], "redirect_uri": redirect_uri(i, st, c), "response_type": "code"}
    if scopes:
        params["scope"] = c.get("separator", " ").join(scopes)
    saved = {"provider": st.name}
    if not st.stateless:
        saved["state"] = params["state"] = secrets.token_urlsafe(32)
    if c.get("pkce"):
        verifier = secrets.token_urlsafe(48)
        saved["verifier"] = verifier
        params["code_challenge"] = b64url(hashlib.sha256(verifier.encode()).digest())
        params["code_challenge_method"] = "S256"
    params.update({k: to_display(v) for k, v in st.params.items()})
    if not st.stateless or c.get("pkce"):
        pending_store(i)[STATE_KEY] = saved
    return c["authorize_url"] + ("&" if "?" in c["authorize_url"] else "?") + urllib.parse.urlencode(params)


def p_redirect(i, a, n, this):
    from barq.stdlib2 import resp_redirect
    return resp_redirect(i, [authorize_url(i, this.native, n, "OAuth.redirect")], n)


def p_url(i, a, n, this):
    return authorize_url(i, this.native, n, "OAuth.url")


def body_json(res):
    try:
        v = json.loads(res.fields.get("body") or "")
    except ValueError:
        return None
    return v


def http(i, method, url, data, opts, n, fname):
    from barq.stdlib2 import http_send
    return http_send(i, method, url, data, opts, n, fname)


def exchange_code(i, st, c, code, verifier, n, fname):
    fields = {"client_id": c.get("client_id") or "", "client_secret": c.get("client_secret") or "", "code": code,
              "redirect_uri": redirect_uri(i, st, c), "grant_type": "authorization_code"}
    if verifier:
        fields["code_verifier"] = verifier
    headers = {"Accept": "application/json"}
    if c["driver"] == "facebook":
        res = http(i, "GET", c["token_url"], None, {"query": fields, "headers": headers}, n, fname)
    else:
        res = http(i, "POST", c["token_url"], fields, {"form": True, "headers": headers}, n, fname)
    data = body_json(res)
    if not isinstance(data, dict) and "=" in (res.fields.get("body") or ""):
        data = dict(urllib.parse.parse_qsl(res.fields["body"]))       # old-style form answers
    if res.fields["status"] >= 400 or not isinstance(data, dict) or "error" in data or not data.get("access_token"):
        why = None
        if isinstance(data, dict):
            err = data.get("error")
            why = data.get("error_description") or (err.get("message") if isinstance(err, dict) else err)
        throw(i, "OAuthException", f"{st.name} did not accept the login code: {why or 'HTTP ' + str(res.fields['status'])}",
              n, error=str(data.get("error") if isinstance(data, dict) and isinstance(data.get("error"), str)
                           else "token_error"))
    return data


def api_get(i, st, url, token, n, fname, query=None, accept="application/json"):
    opts = {"headers": {"Accept": accept, "Authorization": "Bearer " + token}}
    if query:
        opts["query"] = query
    res = http(i, "GET", url, None, opts, n, fname)
    data = body_json(res)
    if res.fields["status"] >= 400 or data is None:
        why = None
        if isinstance(data, dict):
            err = data.get("error")
            why = err.get("message") if isinstance(err, dict) else data.get("error_description") or err or data.get("message")
        throw(i, "OAuthException", f"{st.name} did not return the user: {why or 'HTTP ' + str(res.fields['status'])}",
              n, error="user_error")
    return data


def fetch_user(i, st, c, tok, n, fname):
    token = tok["access_token"]
    driver = c["driver"]
    if driver == "facebook":
        proof = hmac.new((c.get("client_secret") or "").encode(), token.encode(), hashlib.sha256).hexdigest()
        raw = api_get(i, st, c["user_url"], token, n, fname,
                      {"fields": c.get("fields") or OAUTH_DRIVERS["facebook"]["fields"], "access_token": token,
                       "appsecret_proof": proof})
        pic = raw.get("picture")
        avatar = pic.get("data", {}).get("url") if isinstance(pic, dict) else None
        info = {"id": raw.get("id"), "name": raw.get("name"), "email": raw.get("email"), "avatar": avatar,
                "nickname": None, "emailVerified": False}     # Facebook does not say whether it checked the address
    elif driver == "github":
        raw = api_get(i, st, c["user_url"], token, n, fname, accept="application/vnd.github+json")
        email, verified = raw.get("email"), False
        try:
            emails = api_get(i, st, c.get("emails_url") or OAUTH_DRIVERS["github"]["emails_url"], token, n, fname,
                             accept="application/vnd.github+json")
        except BarqThrow:
            emails = []
        if isinstance(emails, list):
            best = next((e for e in emails if isinstance(e, dict) and e.get("primary") and e.get("verified")), None)
            if best is not None:
                email, verified = best.get("email"), True
            else:
                verified = any(isinstance(e, dict) and e.get("email") == email and e.get("verified") for e in emails)
        info = {"id": raw.get("id"), "name": raw.get("name") or raw.get("login"), "email": email,
                "avatar": raw.get("avatar_url"), "nickname": raw.get("login"), "emailVerified": verified}
    else:
        raw = api_get(i, st, c["user_url"], token, n, fname)
        if not isinstance(raw, dict):
            throw(i, "OAuthException", f"{st.name} returned {type_name(raw)} for the user, not an object", n,
                  error="user_error")
        info = {"id": raw.get("sub", raw.get("id")), "name": raw.get("name"), "email": raw.get("email"),
                "avatar": raw.get("picture", raw.get("avatar_url", raw.get("avatar"))),
                "nickname": raw.get("nickname", raw.get("preferred_username", raw.get("login"))),
                "emailVerified": raw.get("email_verified") in (True, "true")}
        mapper = c.get("map")
        if mapper is not None:
            mapped = i.call_function(mapper, [dict(raw)], n)
            if not isinstance(mapped, dict):
                throw(i, "OAuthException", f'config auth.oauth.{st.name}.map must return a dict, got {type_name(mapped)}', n)
            info.update(mapped)
    if info.get("id") is None:
        throw(i, "OAuthException", f"{st.name} returned a user without an id", n, error="user_error")
    scope = tok.get("scope")
    scopes = scope.replace(",", " ").split() if isinstance(scope, str) else []
    return oauth_user(i, st.name, info, raw, tok, scopes)


def oauth_user(i, provider, info, raw, tok, scopes):
    expires = tok.get("expires_in")
    return new_native(i, "OAuthUser", None, id=str(info.get("id")), name=info.get("name"), email=info.get("email"),
                      nickname=info.get("nickname"), avatar=info.get("avatar"),
                      emailVerified=bool(info.get("emailVerified")), token=tok.get("access_token"),
                      refreshToken=tok.get("refresh_token"),
                      expiresIn=int(expires) if isinstance(expires, (int, str)) and str(expires).isdigit() else None,
                      scopes=scopes, provider=provider, raw=raw)


def p_user(i, a, n, this):
    from .auth2 import pending_store
    from barq.web import current_request
    fname = "OAuth.user"
    st = this.native
    if st.name in fakes(i):
        info = dict(fakes(i)[st.name])
        return oauth_user(i, st.name, info, dict(info), {"access_token": info.pop("token", "fake-token")}, [])
    c = provider_config(i, st.name, n, fname)
    req = current_request(i)
    if req is None:
        throw(i, "OAuthException", f"{fname}() reads the callback request: call it in the route that "
              f"{c['redirect']} goes to (or use userFromToken(token))", n)
    q = req.native.query or {}
    if q.get("error"):
        throw(i, "OAuthException", f"{st.name}: {q.get('error_description') or q['error']}", n, error=str(q["error"]))
    saved = pending_store(i).pop(STATE_KEY, None)
    verifier = None
    if not st.stateless:
        sent = q.get("state")
        if not isinstance(saved, dict) or saved.get("provider") != st.name or not isinstance(sent, str) \
                or not hmac.compare_digest(str(saved.get("state", "")).encode(), sent.encode()):
            throw(i, "OAuthException", f"{st.name}: the login state does not match — start again from the login page "
                  "(the link was used twice, or opened in another browser)", n, error="invalid_state")
    if isinstance(saved, dict) and saved.get("provider") == st.name:
        verifier = saved.get("verifier")
    code = q.get("code")
    if not isinstance(code, str) or not code:
        throw(i, "OAuthException", f"{st.name}: the callback has no ?code=", n, error="missing_code")
    tok = exchange_code(i, st, c, code, verifier, n, fname)
    return fetch_user(i, st, c, tok, n, fname)


def p_user_from_token(i, a, n, this):
    fname = "OAuth.userFromToken"
    token = need(i, a[0], ("string",), fname, 1, n)
    st = this.native
    if st.name in fakes(i):
        return p_user(i, [], n, this)
    return fetch_user(i, st, provider_config(i, st.name, n, fname), {"access_token": token}, n, fname)


def builder(change):
    def fn(i, a, n, this):
        return new_native(i, "OAuthProvider", change(i, a, n, this.native))
    return fn


def need_strings(i, v, n, fname):
    need(i, v, ("list",), fname, 1, n)
    for s in v:
        need(i, s, ("string",), fname, 1, n)
    return list(v)


PROVIDER_METHODS = {
    "redirect": (p_redirect, 0, 0),
    "url": (p_url, 0, 0),
    "user": (p_user, 0, 0),
    "userFromToken": (p_user_from_token, 1, 1),
    "scopes": (builder(lambda i, a, n, st: st.copy(extra=st.extra + need_strings(i, a[0], n, "OAuth.scopes"))), 1, 1),
    "setScopes": (builder(lambda i, a, n, st: st.copy(scopes=need_strings(i, a[0], n, "OAuth.setScopes"), extra=[])), 1, 1),
    "with": (builder(lambda i, a, n, st: st.copy(params=dict(st.params, **need(i, a[0], ("dict",), "OAuth.with", 1, n)))), 1, 1),
    "stateless": (builder(lambda i, a, n, st: st.copy(stateless=True)), 0, 0),
    "redirectUrl": (builder(lambda i, a, n, st: st.copy(redirect=need(i, a[0], ("string",), "OAuth.redirectUrl", 1, n))), 1, 1),
    "name": (lambda i, a, n, this: this.native.name, 0, 0),
}


def o_driver(i, a, n):
    name = need(i, a[0], ("string",), "OAuth.driver", 1, n)
    provider_config(i, name, n, "OAuth.driver")
    return new_native(i, "OAuthProvider", ProviderState(name))


def o_fake(i, a, n):
    name = need(i, a[0], ("string",), "OAuth.fake", 1, n)
    user = arg(i, a, 1, ("dict",), "OAuth.fake", n, None)
    if user is None:
        fakes(i).pop(name, None)
        return None
    if user.get("id") is None:
        throw(i, "ValueException", 'OAuth.fake(): the fake user needs an "id"', n)
    fakes(i)[name] = dict({"name": None, "email": None, "avatar": None, "nickname": None, "emailVerified": True}, **user)
    return None


def o_providers(i, a, n):
    names = set(OAUTH_DRIVERS) | set(conf(i, "auth.oauth", {}) or {})
    return [x for x in sorted(names) if oauth_enabled(i, x) or x in fakes(i)]


OAUTH = {
    "driver": (o_driver, 1, 1),
    "enabled": (lambda i, a, n: oauth_enabled(i, need(i, a[0], ("string",), "OAuth.enabled", 1, n))
                or a[0] in fakes(i), 1, 1),
    "providers": (o_providers, 0, 0),
    "fake": (o_fake, 1, 2),
    "restore": (lambda i, a, n: fakes(i).clear(), 0, 0),
}


# ===========================================================================
# Teams
# ===========================================================================

TEAM_DEFAULTS = {"enabled": True, "model": "App\\Models\\Team", "provider": "users", "roles": ["admin", "member"],
                 "default_role": "member", "invitation_expire": 10080}
MEMBERS = "team_members"
INVITES = "team_invitations"
TEAM_TABLE_HINTS = {
    MEMBERS: 't.id(), t.int("team_id"), t.int("user_id"), t.string("role").nullable(), t.timestamps(), '
             't.unique(#["team_id", "user_id"])',
    INVITES: 't.id(), t.int("team_id"), t.string("email"), t.string("role").nullable(), t.string("token", 64).unique(), '
             't.int("accepted_at").nullable(), t.int("expires_at").nullable(), t.timestamps()',
}


def team_settings(i):
    c = conf(i, "auth.teams", {})
    out = dict(TEAM_DEFAULTS)
    if isinstance(c, dict):
        out.update({k: v for k, v in c.items() if v is not None})
    return out


def team_base(i):
    return i.classes["TeamModel"]


def team_model(i, n, fname):
    model = team_settings(i)["model"]
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
    if not isinstance(cls, BarqClass) or not cls.is_subclass_of(team_base(i)) or cls is team_base(i):
        throw(i, "AuthException", f"{fname}(): the team model {to_display(model, i, True)} was not found — create "
              "app/Models/Team.bq with 'class Team extends TeamModel' (barq auth:install does), or set config "
              "auth.teams.model", n)
    return cls


def members_model(i, n):
    from .auth import user_model
    return user_model(i, team_settings(i)["provider"], n)


def need_team(i, v, n, fname):
    from barq_framework.orm import mstate
    if not (isinstance(v, BarqObject) and v.cls.is_subclass_of(team_base(i))):
        throw(i, "TypeException", f"{fname}() needs a team, got {type_name(v)}", n)
    if not mstate(v).exists:
        throw(i, "AuthException", f"{fname}(): save the team first", n)
    return v


def need_member_user(i, v, n, fname):
    from barq_framework.orm import is_model, mstate
    if not is_model(i, v) or v.cls.is_subclass_of(team_base(i)):
        throw(i, "TypeException", f"{fname}() needs a user, got {type_name(v)}", n)
    if not mstate(v).exists:
        throw(i, "AuthException", f"{fname}(): save the user first", n)
    return v


def check_role(i, role, n, fname):
    roles = team_settings(i)["roles"]
    need(i, role, ("string",), fname, 2, n)
    if role == "owner":
        throw(i, "ValueException", f'{fname}(): "owner" is not a member role — a team has one owner (its user_id); '
              "use team.transferOwnership(user)", n)
    if role not in roles:
        throw(i, "ValueException", f'{fname}(): unknown team role "{role}" (roles: {", ".join(roles)} — '
              "set config auth.teams.roles)", n)
    return role


def key_of(i, model, n):
    from .auth import model_key
    return model_key(i, model, n)


def owner_id(i, team):
    from barq_framework.orm import mstate
    return mstate(team).attrs.get("user_id")


def team_db(i, cls, n):
    from barq_framework.orm import meta, model_db
    return model_db(i, meta(i, cls, n), n)


def table_query(i, cls, table, n):
    from barq_framework.orm import table_columns
    from barq.stdlib2 import new_query, qid
    db = team_db(i, cls, n)
    if not table_columns(i, db, table, n):
        throw(i, "DbException", f'teams need the "{table}" table — run "barq auth:install" and "barq migrate" '
              f"(or create it: {TEAM_TABLE_HINTS[table]})", n)
    return new_query(i, db, qid(i, table, n, "table"))


def where(i, q, col, value, n):
    from barq.stdlib2 import add_where
    add_where(i, [col, value], n, q, "AND", "Team")
    return q


def q_get(i, q, n):
    from barq.stdlib2 import qb_get
    return qb_get(i, [], n, q)


def q_first(i, q, n):
    from barq.stdlib2 import qb_first
    return qb_first(i, [], n, q)


def q_run(i, name, q, args, n):
    from barq.stdlib2 import QUERY_METHODS
    return QUERY_METHODS[name][0](i, args, n, q)


def member_rows(i, team, n, user_id=None):
    q = where(i, table_query(i, team.cls, MEMBERS, n), "team_id", key_of(i, team, n), n)
    if user_id is not None:
        where(i, q, "user_id", user_id, n)
    q_run(i, "orderBy", q, ["id"], n)
    return q_get(i, q, n)


def models_by_ids(i, cls, ids, n):
    from barq_framework.orm import meta, mq, mq_get, new_mq
    from barq.stdlib2 import where_in
    if not ids:
        return []
    q = new_mq(i, cls, n)
    where_in(False)(i, [f"{meta(i, cls, n).table}.{meta(i, cls, n).pk}", list(ids)], n, mq(q).q)
    found = {key_of(i, m, n): m for m in mq_get(i, [], n, q)}
    return [found[k] for k in ids if k in found]


def role_of(i, team, user, n):
    uid = key_of(i, user, n)
    if owner_id(i, team) == uid:
        return "owner"
    rows = member_rows(i, team, n, uid)
    return (rows[0].get("role") or team_settings(i)["default_role"]) if rows else None


def team_event(i, name, team, user, role, n):
    from .auth import fire
    fire(i, name, {"team": team, "user": user, "role": role}, n)


# ---- team methods -----------------------------------------------------------

def t_owner(i, a, n, this):
    from barq_framework.orm import mq_find, new_mq
    oid = owner_id(i, this)
    return mq_find(i, [oid], n, new_mq(i, members_model(i, n), n)) if oid is not None else None


def t_members(i, a, n, this):
    """Everyone on the team: the owner first, then members in the order they joined."""
    need_team(i, this, n, "Team.members")
    ids = [owner_id(i, this)] if owner_id(i, this) is not None else []
    ids += [r["user_id"] for r in member_rows(i, this, n) if r["user_id"] not in ids]
    return models_by_ids(i, members_model(i, n), ids, n)


def t_members_with_role(i, a, n, this):
    fname = "Team.membersWithRole"
    role = need(i, a[0], ("string",), fname, 1, n)
    need_team(i, this, n, fname)
    if role == "owner":
        owner = t_owner(i, [], n, this)
        return [owner] if owner is not None else []
    default = team_settings(i)["default_role"]
    ids = [r["user_id"] for r in member_rows(i, this, n) if (r.get("role") or default) == role
           and r["user_id"] != owner_id(i, this)]
    return models_by_ids(i, members_model(i, n), ids, n)


def t_has_member(i, a, n, this):
    fname = "Team.hasMember"
    need_team(i, this, n, fname)
    from barq_framework.orm import is_model, mstate
    if not is_model(i, a[0]) or not mstate(a[0]).exists:
        return False
    return role_of(i, this, a[0], n) is not None


def t_role_of(i, a, n, this):
    fname = "Team.roleOf"
    need_team(i, this, n, fname)
    return role_of(i, this, need_member_user(i, a[0], n, fname), n)


def t_add_member(i, a, n, this):
    from barq.stdlib2 import insert_rows
    fname = "Team.addMember"
    need_team(i, this, n, fname)
    user = need_member_user(i, a[0], n, fname)
    role = check_role(i, opt(a, 1, team_settings(i)["default_role"]), n, fname)
    current = role_of(i, this, user, n)
    if current == "owner":
        throw(i, "ValueException", f"{fname}(): that user owns this team already", n)
    if current is not None:
        throw(i, "ValueException", f"{fname}(): that user is on this team already (role: {current}) — "
              "use team.updateMemberRole(user, role)", n)
    t = now()
    insert_rows(i, table_query(i, this.cls, MEMBERS, n), [{"team_id": key_of(i, this, n), "user_id": key_of(i, user, n),
                                                          "role": role, "created_at": t, "updated_at": t}], n, fname)
    team_event(i, "teams.memberAdded", this, user, role, n)
    return None


def clear_current_team(i, user, team, n):
    from barq_framework.orm import meta, model_db, mstate, save, table_columns
    m = meta(i, user.cls, n)
    if "current_team_id" in table_columns(i, model_db(i, m, n), m.table, n) \
            and mstate(user).attrs.get("current_team_id") == key_of(i, team, n):
        mstate(user).attrs["current_team_id"] = None
        save(i, user, n)


def t_remove_member(i, a, n, this):
    fname = "Team.removeMember"
    need_team(i, this, n, fname)
    user = need_member_user(i, a[0], n, fname)
    if owner_id(i, this) == key_of(i, user, n):
        throw(i, "ValueException", f"{fname}(): the owner cannot leave their team — transferOwnership(user) "
              "first, or delete the team with purge()", n)
    q = where(i, where(i, table_query(i, this.cls, MEMBERS, n), "team_id", key_of(i, this, n), n),
              "user_id", key_of(i, user, n), n)
    removed = q_run(i, "delete", q, [], n)
    if not removed:
        return False
    clear_current_team(i, user, this, n)
    team_event(i, "teams.memberRemoved", this, user, None, n)
    return True


def t_update_role(i, a, n, this):
    fname = "Team.updateMemberRole"
    need_team(i, this, n, fname)
    user = need_member_user(i, a[0], n, fname)
    role = check_role(i, a[1], n, fname)
    current = role_of(i, this, user, n)
    if current == "owner":
        throw(i, "ValueException", f"{fname}(): the owner's role cannot change — use transferOwnership(user)", n)
    if current is None:
        throw(i, "ValueException", f"{fname}(): that user is not on this team — use team.addMember(user, role)", n)
    q = where(i, where(i, table_query(i, this.cls, MEMBERS, n), "team_id", key_of(i, this, n), n),
              "user_id", key_of(i, user, n), n)
    q_run(i, "update", q, [{"role": role, "updated_at": now()}], n)
    team_event(i, "teams.memberRoleUpdated", this, user, role, n)
    return None


def t_transfer(i, a, n, this):
    """The new owner must be a member; the old owner stays on as admin (or the first role)."""
    from barq_framework.orm import mstate, save
    fname = "Team.transferOwnership"
    need_team(i, this, n, fname)
    user = need_member_user(i, a[0], n, fname)
    current = role_of(i, this, user, n)
    if current == "owner":
        return None
    if current is None:
        throw(i, "ValueException", f"{fname}(): add the user to the team first", n)
    old = t_owner(i, [], n, this)
    roles = team_settings(i)["roles"]
    keep_role = "admin" if "admin" in roles else roles[0]
    q = where(i, where(i, table_query(i, this.cls, MEMBERS, n), "team_id", key_of(i, this, n), n),
              "user_id", key_of(i, user, n), n)
    q_run(i, "delete", q, [], n)
    mstate(this).attrs["user_id"] = key_of(i, user, n)
    save(i, this, n)
    if old is not None:
        t_add_member(i, [old, keep_role], n, this)
    team_event(i, "teams.ownershipTransferred", this, user, "owner", n)
    return None


# ---- invitations ----

def token_hash(plain):
    return hashlib.sha256(plain.encode()).hexdigest()


def invite_dict(row):
    out = {k: v for k, v in row.items() if k != "token"}
    return out


def pending_invites(i, team, n, email=None):
    q = where(i, table_query(i, team.cls, INVITES, n), "team_id", key_of(i, team, n), n)
    q_run(i, "whereNull", q, ["accepted_at"], n)
    if email is not None:
        where(i, q, "email", email, n)
    q_run(i, "orderBy", q, ["id"], n)
    t = now()
    return [r for r in q_get(i, q, n) if r.get("expires_at") is None or r["expires_at"] > t]


def find_by_email(i, email, n):
    from barq_framework.orm import meta, mq, mq_first, new_mq
    from barq.stdlib2 import add_where
    cls = members_model(i, n)
    q = new_mq(i, cls, n)
    add_where(i, [f"{meta(i, cls, n).table}.email", email], n, mq(q).q, "AND", "Team")
    return mq_first(i, [], n, q)


def t_invite(i, a, n, this):
    from .auth2 import absolute, app_name, escape, send_mail
    from barq.stdlib2 import db_state, insert_rows
    from barq.web import route_url, router
    fname = "Team.invite"
    need_team(i, this, n, fname)
    email = need(i, a[0], ("string",), fname, 1, n).strip()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        throw(i, "ValueException", f'{fname}(): "{email}" is not an email address', n)
    role = check_role(i, opt(a, 1, team_settings(i)["default_role"]), n, fname)
    send = opt(a, 2, True)
    existing = find_by_email(i, email, n)
    if existing is not None and role_of(i, this, existing, n) is not None:
        throw(i, "ValueException", f"{fname}(): {email} is on this team already", n)
    old = where(i, where(i, table_query(i, this.cls, INVITES, n), "team_id", key_of(i, this, n), n), "email", email, n)
    q_run(i, "whereNull", old, ["accepted_at"], n)
    q_run(i, "delete", old, [], n)
    plain = secrets.token_hex(20)
    t = now()
    minutes = team_settings(i)["invitation_expire"]
    row = {"team_id": key_of(i, this, n), "email": email, "role": role, "token": token_hash(plain), "accepted_at": None,
           "expires_at": t + minutes * 60 if minutes else None, "created_at": t, "updated_at": t}
    insert_rows(i, table_query(i, this.cls, INVITES, n), [row], n, fname)
    row["id"] = db_state(i, team_db(i, this.cls, n), n).last_id
    url = None
    if "team-invitations.accept" in router(i).names:
        url = absolute(i, route_url(i, ["team-invitations.accept", {"token": plain}], n))
    out = dict(invite_dict(row), token=plain, url=url)
    from barq_framework.orm import mstate
    team_name = to_display(mstate(this).attrs.get("name") or "a team")
    if send and url is not None:
        text = (f"You have been invited to join the {team_name} team on {app_name(i)}.\n\n"
                f"Accept the invitation: {url}\n\n"
                "If you do not have an account yet, create one with this email address first. "
                "If you did not expect this invitation, you can ignore this email.")
        html = (f"<p>You have been invited to join the <strong>{escape(team_name)}</strong> team on "
                f"{escape(app_name(i))}.</p><p><a href=\"{escape(url)}\">Accept the invitation</a></p>"
                "<p>If you do not have an account yet, create one with this email address first.</p>")
        send_mail(i, email, f"{app_name(i)}: join the {team_name} team", text, html, n, fname)
    team_event(i, "teams.invited", this, existing, role, n)
    return out


def t_invitations(i, a, n, this):
    need_team(i, this, n, "Team.invitations")
    return [invite_dict(r) for r in pending_invites(i, this, n)]


def t_cancel_invitation(i, a, n, this):
    fname = "Team.cancelInvitation"
    need_team(i, this, n, fname)
    v = a[0]
    q = where(i, table_query(i, this.cls, INVITES, n), "team_id", key_of(i, this, n), n)
    if type(v) is int:
        where(i, q, "id", v, n)
    else:
        where(i, q, "email", need(i, v, ("string", "int"), fname, 1, n), n)
    q_run(i, "whereNull", q, ["accepted_at"], n)
    return bool(q_run(i, "delete", q, [], n))


def invitation_row(i, cls, token, n, team=None):
    q = where(i, table_query(i, cls, INVITES, n), "token", token_hash(token), n)
    if team is not None:
        where(i, q, "team_id", key_of(i, team, n), n)
    q_run(i, "whereNull", q, ["accepted_at"], n)
    row = q_first(i, q, n)
    if row is None or (row.get("expires_at") is not None and row["expires_at"] <= now()):
        return None
    return row


def accept(i, cls, token, user, n, fname, team=None):
    """-> True when the user joined (or was on the team already)."""
    from .auth import current_user
    from barq_framework.orm import mq_find, mstate, new_mq
    need(i, token, ("string",), fname, 1, n)
    if user is None:
        user = current_user(i, n)
        if user is None:
            throw(i, "AuthException", f"{fname}(): log in first (or pass the user)", n)
    need_member_user(i, user, n, fname)
    row = invitation_row(i, cls, token, n, team)
    if row is None:
        return False
    email = mstate(user).attrs.get("email")
    if not isinstance(email, str) or email.strip().lower() != str(row["email"]).strip().lower():
        return False        # the invitation is for someone else's address
    if team is None:
        team = mq_find(i, [row["team_id"]], n, new_mq(i, cls, n))
        if team is None:
            return False
    if role_of(i, team, user, n) is None:
        t_add_member(i, [user, row.get("role") or team_settings(i)["default_role"]], n, team)
    q = where(i, table_query(i, cls, INVITES, n), "id", row["id"], n)
    q_run(i, "update", q, [{"accepted_at": now(), "updated_at": now()}], n)
    team_event(i, "teams.invitationAccepted", team, user, row.get("role"), n)
    return True


def t_accept(i, a, n, this):
    need_team(i, this, n, "Team.acceptInvitation")
    return accept(i, this.cls, a[0], opt(a, 1), n, "Team.acceptInvitation", this)


def s_accept(i, a, n, cls):
    return accept(i, team_static_cls(i, cls, n, "acceptInvitation"), a[0], opt(a, 1), n, "Team.acceptInvitation")


def team_static_cls(i, cls, n, name):
    if cls is team_base(i):
        return team_model(i, n, f"TeamModel.{name}")
    return cls


def s_find_invitation(i, a, n, cls):
    from barq_framework.orm import mq_find, new_mq
    fname = "Team.findInvitation"
    cls = team_static_cls(i, cls, n, "findInvitation")
    row = invitation_row(i, cls, need(i, a[0], ("string",), fname, 1, n), n)
    if row is None:
        return None
    return dict(invite_dict(row), team=mq_find(i, [row["team_id"]], n, new_mq(i, cls, n)))


def t_purge(i, a, n, this):
    """Delete the team, its memberships and invitations; users who had it as current team get none."""
    from .auth2 import call_user_method
    from barq_framework.orm import meta, model_db, table_columns
    from barq.stdlib2 import new_query, qid
    fname = "Team.purge"
    need_team(i, this, n, fname)
    tid = key_of(i, this, n)
    q_run(i, "delete", where(i, table_query(i, this.cls, MEMBERS, n), "team_id", tid, n), [], n)
    q_run(i, "delete", where(i, table_query(i, this.cls, INVITES, n), "team_id", tid, n), [], n)
    ucls = members_model(i, n)
    m = meta(i, ucls, n)
    db = model_db(i, m, n)
    if "current_team_id" in table_columns(i, db, m.table, n):
        q = where(i, new_query(i, db, qid(i, m.table, n, "table")), "current_team_id", tid, n)
        q_run(i, "update", q, [{"current_team_id": None}], n)
    call_user_method(i, this, "delete", [], n)
    return None


TEAM_METHODS = {
    "owner": (t_owner, 0, 0, None),
    "members": (t_members, 0, 0, None),
    "users": (t_members, 0, 0, None),
    "membersWithRole": (t_members_with_role, 1, 1, ("role",)),
    "hasMember": (t_has_member, 1, 1, ("user",)),
    "hasUser": (t_has_member, 1, 1, ("user",)),
    "roleOf": (t_role_of, 1, 1, ("user",)),
    "addMember": (t_add_member, 1, 2, ("user", "role")),
    "removeMember": (t_remove_member, 1, 1, ("user",)),
    "updateMemberRole": (t_update_role, 2, 2, ("user", "role")),
    "transferOwnership": (t_transfer, 1, 1, ("user",)),
    "invite": (t_invite, 1, 3, ("email", "role", "send")),
    "invitations": (t_invitations, 0, 0, None),
    "cancelInvitation": (t_cancel_invitation, 1, 1, ("invitation",)),
    "acceptInvitation": (t_accept, 1, 2, ("token", "user")),
    "purge": (t_purge, 0, 0, None),
}
TEAM_STATICS = {
    "acceptInvitation": (s_accept, 1, 2, ("token", "user")),
    "findInvitation": (s_find_invitation, 1, 1, ("token",)),
}


# ---- user methods -----------------------------------------------------------

def user_teams(i, user, n, owned_only=False):
    from barq_framework.orm import meta, mq, mq_get, new_mq
    from barq.stdlib2 import add_where, where_in
    fname = f"{user.cls.name}.teams"
    from .auth import need_saved
    need_saved(i, user, n, fname)
    cls = team_model(i, n, fname)
    uid = key_of(i, user, n)
    m = meta(i, cls, n)
    q = new_mq(i, cls, n)
    add_where(i, [f"{m.table}.user_id", uid], n, mq(q).q, "AND", fname)
    teams = mq_get(i, [], n, q)
    if not owned_only:
        mq_ = where(i, table_query(i, cls, MEMBERS, n), "user_id", uid, n)
        ids = [r["team_id"] for r in q_get(i, mq_, n)]
        if ids:
            q2 = new_mq(i, cls, n)
            where_in(False)(i, [f"{m.table}.{m.pk}", ids], n, mq(q2).q)
            have = {key_of(i, t, n) for t in teams}
            teams += [t for t in mq_get(i, [], n, q2) if key_of(i, t, n) not in have]
    teams.sort(key=lambda t: key_of(i, t, n))
    return teams


def has_current_column(i, user, n):
    from barq_framework.orm import meta, model_db, table_columns
    m = meta(i, user.cls, n)
    return "current_team_id" in table_columns(i, model_db(i, m, n), m.table, n)


def u_current_team(i, a, n, this):
    from barq_framework.orm import mq_find, mstate, new_mq, save
    fname = f"{this.cls.name}.currentTeam"
    column = has_current_column(i, this, n)
    cid = mstate(this).attrs.get("current_team_id") if column else None
    if cid is not None:
        team = mq_find(i, [cid], n, new_mq(i, team_model(i, n, fname), n))
        if team is not None and role_of(i, team, this, n) is not None:
            return team
    teams = user_teams(i, this, n)
    if not teams:
        return None
    if column:
        mstate(this).attrs["current_team_id"] = key_of(i, teams[0], n)
        save(i, this, n)
    return teams[0]


def u_switch_team(i, a, n, this):
    from barq_framework.orm import mstate, save
    fname = f"{this.cls.name}.switchTeam"
    team = need_team(i, a[0], n, fname)
    if role_of(i, team, this, n) is None:
        return False
    if not has_current_column(i, this, n):
        throw(i, "AuthException", f"{fname}(): the users table has no current_team_id column — add "
              't.int("current_team_id").nullable() (barq auth:install does)', n)
    mstate(this).attrs["current_team_id"] = key_of(i, team, n)
    save(i, this, n)
    team_event(i, "teams.switched", team, this, None, n)
    return True


def u_belongs(i, a, n, this):
    from barq_framework.orm import mstate
    v = a[0]
    if not (isinstance(v, BarqObject) and v.cls.is_subclass_of(team_base(i))) or not mstate(v).exists:
        return False
    return role_of(i, v, this, n) is not None


def u_owns(i, a, n, this):
    from barq_framework.orm import mstate
    v = a[0]
    if not (isinstance(v, BarqObject) and v.cls.is_subclass_of(team_base(i))) or not mstate(v).exists:
        return False
    return owner_id(i, v) == key_of(i, this, n)


def u_team_role(i, a, n, this):
    fname = f"{this.cls.name}.teamRole"
    return role_of(i, need_team(i, a[0], n, fname), this, n)


def u_has_team_role(i, a, n, this):
    """The owner has every role; members have the one they were given."""
    fname = f"{this.cls.name}.hasTeamRole"
    team = need_team(i, a[0], n, fname)
    roles = a[1] if isinstance(a[1], list) else [need(i, a[1], ("string",), fname, 2, n)]
    role = role_of(i, team, this, n)
    return role == "owner" or (role is not None and role in roles)


USER_METHODS = {
    "teams": (lambda i, a, n, this: user_teams(i, this, n), 0, 0, None),
    "allTeams": (lambda i, a, n, this: user_teams(i, this, n), 0, 0, None),
    "ownedTeams": (lambda i, a, n, this: user_teams(i, this, n, owned_only=True), 0, 0, None),
    "currentTeam": (u_current_team, 0, 0, None),
    "switchTeam": (u_switch_team, 1, 1, ("team",)),
    "belongsToTeam": (u_belongs, 1, 1, ("team",)),
    "ownsTeam": (u_owns, 1, 1, ("team",)),
    "teamRole": (u_team_role, 1, 1, ("team",)),
    "hasTeamRole": (u_has_team_role, 2, 2, ("team", "role")),
    "sessions": (m_sessions, 0, 0, None),
    "logoutSessions": (m_logout_sessions, 0, 0, None),
}


# ===========================================================================
# install
# ===========================================================================

def install(i):
    from barq.stdlib2 import STDLIB_ALIASES
    g = i.builtins
    exc = BarqClass("OAuthException", "OAuthException", None, parent=i.classes["Exception"], native=True)
    exc.props["error"] = PropInfo("error", None, "public", None, exc)
    i.classes["OAuthException"] = exc
    g.declare("OAuthException", exc, None, const=True)

    # Auth: session management
    auth = g.vars["Auth"][0]
    for name, fn, lo, hi, names in (("logoutOtherDevices", auth_logout_others, 1, 1, ("password",)),
                                    ("logoutEveryDevice", auth_logout_every, 0, 0, None),
                                    ("logoutSession", auth_logout_session, 1, 1, ("id",))):
        auth.members[name] = native(f"Auth.{name}", fn, lo, hi, names)

    # OAuth
    native_class(i, "OAuthProvider", None, PROVIDER_METHODS)
    native_class(i, "OAuthUser", {"id": "string", "name": None, "email": None, "nickname": None, "avatar": None,
                                  "emailVerified": "bool", "token": None, "refreshToken": None, "expiresIn": None,
                                  "scopes": "list", "provider": "string", "raw": None})
    g.declare("OAuth", module("OAuth", OAUTH), None, const=True)
    for name in OAUTH_DRIVERS:
        g.declare(name.capitalize() + "Provider", new_native(i, "OAuthProvider", ProviderState(name)), None, const=True)

    # Teams: TeamModel is the base of the app's Team model
    model = i.classes["Model"]
    team = BarqClass("TeamModel", "TeamModel", None, parent=model, native=True)
    team.is_abstract = True
    for name, (fn, lo, hi, names) in TEAM_METHODS.items():
        team.methods[name] = native(f"Team.{name}", fn, lo, hi, names, team)
    for name, (fn, lo, hi, names) in TEAM_STATICS.items():
        f = native(f"Team.{name}", fn, lo, hi, names)
        f.late_static = True
        team.statics[name] = PropInfo(name, None, "public", None, team, is_static=True, const=True)
        team.static_values[name] = f
    i.classes["TeamModel"] = team
    g.declare("TeamModel", team, None, const=True)
    for name, (fn, lo, hi, names) in USER_METHODS.items():
        model.methods[name] = native(f"Model.{name}", fn, lo, hi, names, model)

    STDLIB_ALIASES.update({"Auth\\OAuth": "OAuth", "Auth\\OAuth\\GoogleProvider": "GoogleProvider",
                           "Auth\\OAuth\\FacebookProvider": "FacebookProvider",
                           "Auth\\OAuth\\GithubProvider": "GithubProvider", "Auth\\TeamModel": "TeamModel",
                           "Auth\\OAuthUser": "OAuthUser"})
