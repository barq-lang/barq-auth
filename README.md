# barq-auth

Authentication for Barq: session and API-token guards, the Gate and policies, signed URLs and rate limits, password resets, email verification, two-factor login (TOTP + QR codes), social login with OAuth (Google, Facebook, GitHub, custom), teams with invitations, and logged-in devices — plus `barq auth:install`, which writes the pages, controllers, migrations and config into your app.

Part of [Barq (برق)](https://github.com/barq-lang/barq). Needs [barq-framework](https://github.com/barq-lang/barq-framework).

## Install

```bash
git clone https://github.com/barq-lang/barq
git clone https://github.com/barq-lang/barq-framework
git clone https://github.com/barq-lang/barq-auth
barq/bin/barq packages        # lists barq-auth
```

With barq 0.21 or later you can instead run `barq install barq-lang/barq-auth` in a project: it goes into the project's `vendor/` and loads from there.

The `barq` command loads packages cloned next to the `barq` checkout (or listed in `BARQ_PATH`); see [Repositories and packages](https://github.com/barq-lang/barq#repositories-and-packages).

## Tests

```bash
cd barq-auth && python3 tests/test_auth.py    # both engines; finds ../barq (or set BARQ_HOME)
```

The design notes (guards, config shape, every page) are in [docs/barq-auth.md](docs/barq-auth.md).

## Authentication (v0.11.0)

```barq
if Auth.attempt(#{"email": req.input("email"), "password": req.input("password")}, remember)
    return Response.redirect("/dashboard")
Auth.user()            // the User, or null       Auth.id(), Auth.check(), Auth.guest()
Auth.login(user)       // Auth.login(user, true) also sets a "remember me" cookie
Auth.loginById(42)     // returns the user, or null
Auth.logout()
Auth.validate(creds)   // check a password without logging in
Auth.once(creds)       // log in for this request only (no session)
auth().user()          // auth() is the default guard; auth("api") another one
req.user()             // the same, from a Request
```

- Passwords are checked with `Hash.verify()` against the model's `password` column. Store `Hash.password(plain)` there; a plain-text password gives an `AuthException`, so the mistake can't go unnoticed.
- `attempt()` finds the user by every key except `password` (usually `email`).
- **Guards.** `"web"` keeps the user id in the session. Logging in makes a new session id, which stops session fixation. `"api"` reads `Authorization: Bearer <token>`.
- The user model comes from `config/auth.bq` (`providers.users.model`, default `'App\Models\User'`). `Config.set("auth.providers.users.model", User)` also works.
- **Remember me** needs a `remember_token` column (`t.rememberToken()`). The cookie is `remember_web`. Logging out changes the token, so old cookies stop working.
- **Events:** `auth.login`, `auth.logout`, `auth.failed`. They work with `Event.listen("auth.*", ...)` and `Event.fake()`.
- Outside a request (scripts, tests, `barq test`), the guards keep the user in memory, so `Auth.login(user)` then `Gate.allows(...)` just works.

**Middleware.** These are built in. `Route.alias()` with the same name replaces one.

| Middleware | What it does |
|------------|--------------|
| `"auth"` | Guests get a 401 JSON response, or a redirect to the route named `login` (or config `auth.login`) |
| `"auth:api"`, `"auth:web,api"` | Same, for those guards. The first guard that has a user becomes the default for the request, so `Auth.user()` works in the handler |
| `"guest"` | Logged-in users are redirected to config `auth.home` (default `/`) |
| `"can:update,post"` | Runs `Gate.authorize("update", post)`. `post` is the route parameter, loaded as a model when the handler takes `Post post`. `"can:create,Post"` passes the class |

## API tokens (Sanctum-style)

```barq
NewAccessToken t = user.createToken("cli", #["posts:read"])   // abilities default to #["*"]
print(t.plainTextToken)        // "3|9f2c…" — show it once; only a SHA-256 hash is stored
user.tokens().count()          // a QueryBuilder on personal_access_tokens
user.tokens().where("name", "cli").delete()
user.tokenCan("posts:read")    // when the request came in with a token
user.currentAccessToken()      // that token's row (without the hash), or null
```

`barq auth:install` creates `config/auth.bq` and the `personal_access_tokens` migration. New Blueprint helpers: `t.morphs("tokenable")` (a `_type` and an `_id` column, indexed) and `t.rememberToken()`. Tokens can expire: pass `createToken(name, abilities, expiresAt)`, or set config `auth.token_expiration` (minutes). Each use updates `last_used_at`.

## Authorization: Gate and policies

```barq
Gate.define("see-dashboard", kr(User u): bool => u.isAdmin)
Gate.allows("see-dashboard")              // for the logged-in user; guests are denied
Gate.denies("edit", post)
Gate.authorize("update", post)            // throws AuthorizationException (a 403 in a request)
Gate.check(#["a", "b"], post)             // all of them; Gate.any(), Gate.none()
Gate.inspect("delete", post)              // #{"allowed": false, "message": "Locked posts cannot be deleted."}
Gate.forUser(other).allows("update", post)
user.can("update", post)                  // user.cannot(...)
Gate.before(kr(User u, string ability): any => u.isSuperAdmin ? true : null)
```

- **Policies.** `App\Models\Post` automatically uses `App\Policies\PostPolicy`. You can also register one with `Gate.policy(Post, PostPolicy)`.
- A policy method gets `(user, post)`. For class-level checks like `user.can("create", Post)` it gets just `(user)`.
- An optional `before(user, ability)` method in the policy runs first. Returning `null` lets the normal check decide.
- **Guests.** A guest is denied without calling the function, unless the function's user parameter accepts null: `?User` (or `any`). Then it is called with `null`: `Gate.define("read-news", kr(?User u): bool => true)`.
- Checks must return `bool`, or `null` from `before`/`after` to let the next check decide.
- **Messages.** Inside a check, `Gate.deny("message")` refuses with that message.
- `barq make:policy PostPolicy --model Post` writes a stub with `viewAny/view/create/update/delete`.

## Auth, part 2: the auth pages (v0.14.0)

New files: `barq_auth/auth2.py` (`URL`, `RateLimiter`, `Password`, email verification, `TwoFactor`), `barq_auth/qr.py` (`Qr`), `barq_auth/scaffold.py` (what `auth:install` writes). The form helpers it uses (`csrf`, `back()`, `old()`, `errors`) are in the language ([barq#forms](https://github.com/barq-lang/barq#forms-v0140)). Tests: [tests/cases/auth2.bq](tests/cases/auth2.bq), and `AuthScaffold`, which runs `auth:install` in an empty project and drives the generated pages end to end ([tests/auth_scaffold/](tests/auth_scaffold/)).

### `barq auth:install`

```bash
barq auth:install     # routes/auth.bq, app/Controllers/Auth/*, views/auth/*, migrations, config/auth.bq, APP_KEY
barq migrate
barq serve            # /register, /login, /forgot-password, /settings/2fa, /dashboard
```

| Pages | Routes |
|-------|--------|
| Register, log in (remember me, 5 tries a minute per email + IP), log out | `/register`, `/login`, `POST /logout` |
| Forgotten password | `/forgot-password`, `/reset-password/:token` (`password.reset`) |
| Email verification | `/verify-email` (`verification.notice`), `/verify-email/:id/:hash` (`verification.verify`, signed), `POST /email/verification-notification` |
| Two-factor login | `/2fa` |
| Two-factor settings: QR code, confirm, recovery codes, turn off | `/settings/2fa` (`two-factor.show`) |
| A dashboard behind `auth` + `verified` | `/dashboard` |

- Every file is ordinary app code. Running the command again keeps files that exist.
- A project that already has a users migration gets an `add_auth_columns_to_users_table` migration. It adds only the missing columns: `password`, `email_verified_at`, `remember_token`, `two_factor_*`.
- `barq serve`, `route:list` and now `barq test` load `routes/auth.bq` before `routes/web.bq`. So a `TestClient` in a project test reaches the app's routes.
- Emails go through `Mail`, so they print to stderr until a mailer is set. To change an email, define `sendPasswordResetNotification(string token)` or `sendEmailVerificationNotification()` in `User`: the app's method wins.
- `barq key:generate` writes a random `APP_KEY` to `.env` (`--show` prints one, `--force` replaces it).

### Signed URLs and rate limits

```barq
URL.signedRoute("unsubscribe", #{"id": 3})                  // https://app.test/unsubscribe/3?signature=…
URL.temporarySignedRoute("unsubscribe", 30, #{"id": 3})     // adds expires=
URL.sign("/download/report.pdf", 10)    URL.hasValidSignature(urlOrRequest)
URL.to("/a")   URL.route("name", params, true)   URL.current()   URL.previous()
Route.get("/unsubscribe/:id", fn).name("unsubscribe").middleware("signed")     // 403 "Invalid signature."

RateLimiter.hit(key, 60)   attempts(key)   tooManyAttempts(key, 5)   remaining(key, 5)   availableIn(key)   clear(key)
RateLimiter.attempt(key, 5, fn)                             // runs fn unless the limit is reached
Route.post("/login", fn).middleware("throttle:5,1")         // 5 a minute per user (or IP); 429 + Retry-After
```

Signatures are HMAC-SHA256 of the path and query, keyed with config `app.key` or `APP_KEY`. Absolute URLs use config `app.url` / `APP_URL` (default `http://localhost:8000`). Rate limits are kept in memory, which suits one `barq serve` process.

### Password resets

```barq
string status = Password.sendResetLink(#{"email": email})      // or pass kr(User u, string token) to send it yourself
Password.reset(#{"email": e, "token": t, "password": p})          // or pass kr(User u, string password) to save it yourself
Password.message(status)                                           // "We have emailed your password reset link."
Password.createToken(user)   Password.tokenExists(user, token)   Password.deleteToken(user)
```

- **Statuses:** `Password.RESET_LINK_SENT`, `PASSWORD_RESET`, `INVALID_USER`, `INVALID_TOKEN`, `RESET_THROTTLED` (`"passwords.sent"` etc.).
- **Tokens** are 64 hex characters. Only their SHA-256 is stored, in `password_reset_tokens`. They last config `auth.passwords.expire` minutes (60), and one address gets at most one email per `auth.passwords.throttle` seconds (60).
- **A reset** stores `Hash.password()`, changes `remember_token` so "remember me" cookies stop working, deletes the token and fires `auth.passwordReset`.

### Email verification

`user.hasVerifiedEmail()`, `user.markEmailAsVerified()` (fires `auth.verified`), `user.sendEmailVerificationNotification()`, `user.verificationUrl()`.

The link is a signed URL to the route named `verification.verify` with `:id` and `:hash` (SHA-1 of the email). It expires after config `auth.verification.expire` minutes (60). The `"verified"` middleware sends unverified users to the `verification.notice` route; JSON requests get a 403.

### Two-factor authentication (TOTP)

```barq
string secret = user.enableTwoFactor()     // setup starts; not active yet
user.twoFactorQrCodeSvg()                  // <svg> for the authenticator app; twoFactorQrCodeUrl() is the otpauth:// URL
user.confirmTwoFactor(code)                // true: on, and 8 recovery codes made
user.hasTwoFactorEnabled()   user.verifyTwoFactorCode(code)   user.disableTwoFactor()
user.recoveryCodes()   user.verifyRecoveryCode("ABCDE-FGH23")   user.regenerateRecoveryCodes()

string result = TwoFactor.attempt(#{"email": e, "password": p}, remember)    // "login", "two-factor", "failed"
TwoFactor.pending()          // the user waiting for a code, or null
TwoFactor.complete(code)     // an app code or a recovery code: logs the user in
TwoFactor.attemptsLeft()   TwoFactor.cancel()
TwoFactor.generateSecret()   TwoFactor.code(secret, ts?)   TwoFactor.verifyCode(secret, code, ts?)   TwoFactor.otpauthUrl(account, secret, issuer?)
```

- **Codes** follow RFC 6238: SHA-1, 6 digits, 30 seconds, so Google Authenticator, Authy, 1Password and Microsoft Authenticator all work.
- **Time drift.** Codes from the step before or after are accepted (config `auth.2fa.window`).
- **No replays.** A code works once.
- **Lockout.** After `auth.2fa.max_attempts` (3) wrong codes, the login has to start again.
- **Recovery codes** are single-use `XXXXX-XXXXX` codes (config `auth.2fa.recovery_codes`, default 8). Case doesn't matter.
- **Columns:** `two_factor_secret`, `two_factor_recovery_codes` (JSON text) and `two_factor_confirmed_at`.
- **`"two-factor"` middleware.** When config `auth.2fa.required` is true, it sends users without 2FA to the `two-factor.show` route.
- **Events:** `auth.twoFactorEnabled`, `auth.twoFactorDisabled`, `auth.twoFactorFailed`, `auth.lockout`.
- `Auth.attempt()` itself does not ask for a code. Use `TwoFactor.attempt()` in login code, as the generated `LoginController` does.

### QR codes

`Qr.svg(text, #{"size": 240, "margin": 4, "color": "#111", "background": "#fff"})` returns an `<svg>` string; put it in a view with `{!...!}`. `Qr.matrix(text)` returns rows of booleans.

It uses byte mode and error correction level M, for up to 213 bytes. Matrices match a reference encoder (segno) for every version and mask, and a decoder (zxing) reads them.

## Auth, part 3: social login, teams, devices (v0.15.0)

New file: `barq_auth/auth3.py`. The language gained device info on sessions, a `database` session driver, intended URLs and `Http.fake()` for it. Tests: [tests/cases/auth3.bq](tests/cases/auth3.bq), and the `AuthScaffold` flow now also logs in with Google, runs a team invitation and logs out another device ([tests/auth_scaffold/](tests/auth_scaffold/)).

### New pages from `barq auth:install`

| Pages | Routes |
|-------|--------|
| "Continue with Google / Facebook / GitHub" on the login page (only providers with an id and secret in `.env`) | `/auth/:provider` (`oauth.redirect`), `/auth/:provider/callback` |
| Teams: list and switch, create, manage (rename, members and roles, invitations, delete) | `/teams`, `/teams/create`, `/teams/:team` (`can:view,team`), `PUT /current-team` |
| Accepting an invitation (guests log in first, then come back) | `/team-invitations/:token` (`team-invitations.accept`) |
| Devices: where you are logged in, log one out, log out everywhere else (asks for the password) | `/settings/sessions` (`sessions.index`) |

New files: `OAuthController`, `SessionController`, `TeamController`, `TeamMemberController`, `TeamInvitationController`, `app/Models/Team.bq`, `app/Policies/TeamPolicy.bq`, `views/auth/sessions.bq`, `views/auth/teams/*`, and migrations for `teams`, `team_members`, `team_invitations` and `sessions`. The users table gets `avatar`, `google_id`, `facebook_id`, `github_id` and `current_team_id`. A project set up by v0.14 gets an `add_social_and_team_columns_to_users_table` migration instead. It keeps its old `routes/auth.bq`, and the command says how to get the new routes.

Login, registration and the 2FA page now finish with `intended(home)`, so people land on the page they first asked for.

### Intended URLs

```barq
Route.get("/billing", fn).middleware("auth")   // a guest is sent to the login route; /billing is remembered
return intended("/dashboard")                  // after logging in: back to /billing, else /dashboard
URL.intended("/dashboard")                     // the same URL as a string (and forgets it)
URL.setIntended("/teams/3")                    // remember a page yourself; session().intendedUrl() reads it
```

Only GET requests from a browser are remembered (JSON requests get a 401 as before), and only paths on this site are followed, so it can't become an open redirect.

### Devices (session management)

```barq
user.sessions()                    // #[#{"id", "ip", "agent", "browser", "platform", "mobile", "lastActive", "current"}]
Auth.logoutOtherDevices(password)  // false when the password is wrong
Auth.logoutSession(id)             // one device, by the id from sessions()
Auth.logoutEveryDevice()           // this one too
user.logoutSessions()              // from an admin page or a script: how many sessions ended
session().ip()   session().browser()   session().platform()   session().isMobile()   session().lastActivity()
```

- Each session records the IP address, User-Agent and last activity of its latest request. `browser()` and `platform()` read the User-Agent ("Chrome", "Safari", "Firefox", "Edge"…; "Windows", "macOS", "iOS", "Android", "Linux"…).
- The `id` in `sessions()` is a hash of the session id. The real id would work as a login, so it is never shown.
- Logging out other devices deletes their sessions and changes `remember_token`, so their "remember me" cookies stop working too. This device keeps a fresh cookie. It fires `auth.otherDeviceLogout`.
- All three session drivers work. `memory` and `file` read every session to find a user's. The new **`database`** driver (`Session.config(#{"driver": "database"})`, or config `session.driver`) keeps them in a `sessions` table with a `user_id` column, which is the better choice with many users. Options: `table` (`"sessions"`) and `connection`.

### Social login (OAuth 2)

```barq
return OAuth.driver("google").redirect()          // in /auth/google — or GoogleProvider.redirect()
OAuthUser u = OAuth.driver("google").user()        // in the callback route
u.id   u.name   u.email   u.emailVerified   u.avatar   u.nickname   u.token   u.refreshToken   u.expiresIn   u.scopes   u.raw

GoogleProvider.scopes(#["https://www.googleapis.com/auth/calendar"]).with(#{"prompt": "consent"}).redirect()
GithubProvider.setScopes(#["read:user"]).redirectUrl("/connect/github/callback").redirect()
FacebookProvider.stateless().user()   FacebookProvider.userFromToken(token)   GoogleProvider.url()
OAuth.enabled("google")   OAuth.providers()   // providers with an id and secret
```

```barq
// config/auth.bq
"oauth": #{
    "google": #{"client_id": Env.get("GOOGLE_CLIENT_ID"), "client_secret": Env.get("GOOGLE_CLIENT_SECRET"), "redirect": "/auth/google/callback"},
    "acme": #{   // any other OAuth 2 provider
        "client_id": "...", "client_secret": "...",
        "authorize_url": "https://id.acme.test/authorize", "token_url": "https://id.acme.test/token",
        "user_url": "https://id.acme.test/me", "scopes": #["profile"],
        "map": kr(dict<string, any> raw): dict<string, any> => #{"id": raw["uid"], "name": raw["full_name"]}
    }
}
```

- **Built in:** `google` (OpenID Connect user info, with PKCE), `facebook` (Graph API v19.0, with `appsecret_proof`; `emailVerified` is always false because Facebook doesn't report it) and `github` (the verified primary email comes from `/user/emails`).
- **The flow:** `redirect()` saves a random `state` in the session, and for Google a PKCE verifier. `user()` checks the state (a wrong or reused one throws `OAuthException` with `error` `"invalid_state"`), swaps the code for a token and fetches the user. A refusal on the provider's page (`?error=access_denied`) throws with that `error`.
- **Where values come from:** config `auth.oauth.<name>`, else `.env` (`GOOGLE_CLIENT_ID`, `FACEBOOK_APP_ID`, `GITHUB_CLIENT_ID`… and the matching secrets). The redirect URL is made absolute with `APP_URL`; register exactly that URL with the provider.
- **The generated `OAuthController`** finds the user by `<provider>_id`, then by email. It links an existing account only when the provider says the email is verified, so nobody can take over an account by adding its address to a social profile. Otherwise it creates a user with a random password. Users with 2FA on still get the code page (`TwoFactor.login(user)`).
- **Tests:** `OAuth.fake("google", #{"id": "1", "email": "a@x.test"})` makes `redirect()` go straight to the callback and `user()` return that user. `OAuth.restore()` undoes it. To test the real flow, fake the provider's URLs with `Http.fake()`.

### Teams

```barq
class Team extends TeamModel                       // app/Models/Team.bq
    protected list<string> fillable = #["name", "user_id"]

Team team = Team.create(#{"name": "Acme", "user_id": auth().id()})    // user_id is the owner
team.addMember(user, role: "admin")    team.updateMemberRole(user, "member")    team.removeMember(user)
team.members()   team.membersWithRole("admin")   team.owner()   team.hasMember(user)   team.roleOf(user)
team.transferOwnership(user)           // the old owner stays on as admin
team.purge()                           // the team, its members and invitations

dict<string, any> invite = team.invite("bob@x.test", role: "member")   // emails a link; send: false to skip
team.invitations()   team.cancelInvitation("bob@x.test")
Team.findInvitation(token)             // #{"email", "role", "team", ...} or null
Team.acceptInvitation(token)           // for Auth.user(), or pass the user

user.teams()   user.ownedTeams()   user.currentTeam()   user.switchTeam(team)
user.belongsToTeam(team)   user.ownsTeam(team)   user.teamRole(team)   user.hasTeamRole(team, "admin")
```

- **Roles:** the owner is the team's `user_id`. The other roles come from config `auth.teams.roles` (`#["admin", "member"]`, default role `"member"`). `"owner"` can't be given with `addMember()`; use `transferOwnership()`. `hasTeamRole()` is always true for the owner, and also takes a list of roles.
- **`members()`** lists the owner first, then the others in the order they joined.
- **`currentTeam()`** reads `users.current_team_id`. When that is empty or the user has left that team, it picks the first team and saves it.
- **Invitations:** the token is 40 hex characters, and only its SHA-256 is stored. It works for config `auth.teams.invitation_expire` minutes (7 days). Inviting the same address again replaces the old invitation. Only a user whose email matches the invitation can accept it. The email is sent only when a route named `team-invitations.accept` exists (the generated one does). `invite()` returns the link either way.
- **Permissions** are an ordinary policy: the generated `TeamPolicy` has `view`, `update`, `delete`, `addMember`, `updateMember` and `removeMember`, used by `can:` middleware and `user.can()` in the views.
- **Events:** `teams.memberAdded`, `teams.memberRemoved`, `teams.memberRoleUpdated`, `teams.ownershipTransferred`, `teams.invited`, `teams.invitationAccepted`, `teams.switched`. Each gets `#{"team", "user", "role"}`.
- **Tables:** `teams` (id, user_id, name), `team_members` (team_id, user_id, role), `team_invitations` (team_id, email, role, token, accepted_at, expires_at).

## License

MIT — see [LICENSE](LICENSE).
