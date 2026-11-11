"""The files `barq auth:install` writes (v0.14.0, v0.15.0): routes, controllers,
views, migrations and config for registration, login, password reset, email
verification, two-factor authentication, social login (OAuth), teams and the
list of logged-in devices. They are ordinary app code — edit
them freely; running the command again keeps files that already exist.
"""

AUTH_CONFIG = '''// Authentication settings (see docs/packages/barq-auth.md)
dict<string, any> auth = #{
    "default_guard": "web",
    "guards": #{
        "web": #{"driver": "session", "provider": "users"},
        "api": #{"driver": "token", "provider": "users"}
    },
    "providers": #{
        "users": #{"driver": "orm", "model": 'App\\Models\\User'}
    },
    "home": "/dashboard",           // where logging in (and the "guest" middleware) sends users
    "remember_lifetime": 2592000,   // "remember me" cookie, seconds (30 days)
    "token_expiration": null,       // API tokens expire after this many minutes (null: never)

    "passwords": #{
        "expire": 60,               // minutes a reset link works
        "throttle": 60              // seconds between reset emails to one address
    },
    "verification": #{
        "enabled": true,            // send a verification email when someone registers
        "expire": 60                // minutes a verification link works
    },
    "2fa": #{
        "required": false,          // true: the "two-factor" middleware sends users to set it up
        "recovery_codes": 8,
        "window": 1,                // also accept codes 30 seconds early or late
        "max_attempts": 3           // wrong codes before the login has to start again
    },

    // Social login: a provider shows up on the login page once its id and secret are set in .env.
    "oauth": #{
        "google": #{
            "client_id": Env.get("GOOGLE_CLIENT_ID"),
            "client_secret": Env.get("GOOGLE_CLIENT_SECRET"),
            "redirect": "/auth/google/callback"
        },
        "facebook": #{
            "client_id": Env.get("FACEBOOK_APP_ID"),
            "client_secret": Env.get("FACEBOOK_APP_SECRET"),
            "redirect": "/auth/facebook/callback"
        },
        "github": #{
            "client_id": Env.get("GITHUB_CLIENT_ID"),
            "client_secret": Env.get("GITHUB_CLIENT_SECRET"),
            "redirect": "/auth/github/callback"
        }
    },

    "teams": #{
        "model": 'App\\Models\\Team',
        "roles": #["admin", "member"],  // the owner is the team's user_id and can do everything
        "default_role": "member",
        "invitation_expire": 10080      // minutes an invitation link works (7 days)
    }
}
'''

ROUTES = '''// Authentication routes, written by barq auth:install. Edit freely.
// barq serve loads this file before routes/web.bq.
use App\\Controllers\\Auth\\LoginController
use App\\Controllers\\Auth\\RegisterController
use App\\Controllers\\Auth\\LogoutController
use App\\Controllers\\Auth\\ForgotPasswordController
use App\\Controllers\\Auth\\ResetPasswordController
use App\\Controllers\\Auth\\VerifyEmailController
use App\\Controllers\\Auth\\TwoFactorController
use App\\Controllers\\Auth\\OAuthController
use App\\Controllers\\Auth\\SessionController
use App\\Controllers\\Auth\\TeamController
use App\\Controllers\\Auth\\TeamMemberController
use App\\Controllers\\Auth\\TeamInvitationController

Route.group(#{"middleware": #["csrf"]}, karo(): void
    Route.group(#{"middleware": #["guest"]}, karo(): void
        Route.get("/register", #[RegisterController, "show"]).name("register")
        Route.post("/register", #[RegisterController, "store"]).middleware("throttle:10,1")
        Route.get("/login", #[LoginController, "show"]).name("login")
        Route.post("/login", #[LoginController, "store"])
        Route.get("/forgot-password", #[ForgotPasswordController, "show"]).name("password.request")
        Route.post("/forgot-password", #[ForgotPasswordController, "store"]).middleware("throttle:6,1").name("password.email")
        Route.get("/reset-password/:token", #[ResetPasswordController, "show"]).name("password.reset")
        Route.post("/reset-password", #[ResetPasswordController, "store"]).name("password.update")
        Route.get("/2fa", #[TwoFactorController, "challenge"]).name("two-factor.login")
        Route.post("/2fa", #[TwoFactorController, "verify"]).middleware("throttle:10,1")
        Route.get("/auth/:provider", #[OAuthController, "redirect"]).name("oauth.redirect")
        Route.get("/auth/:provider/callback", #[OAuthController, "callback"]).middleware("throttle:10,1").name("oauth.callback")
    )

    Route.group(#{"middleware": #["auth"]}, karo(): void
        Route.post("/logout", #[LogoutController, "store"]).name("logout")
        Route.get("/verify-email", #[VerifyEmailController, "notice"]).name("verification.notice")
        Route.get("/verify-email/:id/:hash", #[VerifyEmailController, "verify"]).middleware(#["signed", "throttle:6,1"]).name("verification.verify")
        Route.post("/email/verification-notification", #[VerifyEmailController, "resend"]).middleware("throttle:6,1").name("verification.send")
        Route.get("/settings/2fa", #[TwoFactorController, "show"]).name("two-factor.show")
        Route.post("/settings/2fa/enable", #[TwoFactorController, "enable"])
        Route.post("/settings/2fa/confirm", #[TwoFactorController, "confirm"])
        Route.delete("/settings/2fa", #[TwoFactorController, "disable"])
        Route.post("/settings/2fa/codes", #[TwoFactorController, "regenerateCodes"])
        Route.get("/settings/sessions", #[SessionController, "index"]).name("sessions.index")
        Route.delete("/settings/sessions", #[SessionController, "destroyOthers"])
        Route.delete("/settings/sessions/:id", #[SessionController, "destroy"])

        Route.get("/teams", #[TeamController, "index"]).name("teams.index")
        Route.get("/teams/create", #[TeamController, "create"]).name("teams.create")
        Route.post("/teams", #[TeamController, "store"])
        Route.put("/current-team", #[TeamController, "switchTeam"]).name("current-team.update")
        Route.get("/teams/:team", #[TeamController, "show"]).middleware("can:view,team").name("teams.show")
        Route.put("/teams/:team", #[TeamController, "update"]).middleware("can:update,team")
        Route.delete("/teams/:team", #[TeamController, "destroy"]).middleware("can:delete,team")
        Route.post("/teams/:team/members", #[TeamMemberController, "store"]).middleware(#["can:addMember,team", "throttle:20,1"])
        Route.put("/teams/:team/members/:user", #[TeamMemberController, "update"]).middleware("can:updateMember,team")
        Route.delete("/teams/:team/members/:user", #[TeamMemberController, "destroy"]).middleware("can:view,team")
        Route.delete("/teams/:team/invitations/:invitation", #[TeamInvitationController, "cancel"]).middleware("can:addMember,team")
        Route.get("/team-invitations/:token", #[TeamInvitationController, "accept"]).name("team-invitations.accept")
        Route.get("/dashboard", kr(): Response => view("dashboard")).middleware("verified").name("dashboard")
    )
)
'''

HOME = 'to_str(Config.get("auth.home", "/dashboard"))'

LOGIN = '''namespace App\\Controllers\\Auth

class LoginController

    #[Public]
    #[any]
    karo show()
        return view("auth.login")

    #[Public]
    #[any]
    karo store(Request request)
        dict<string, any> data = request.validate(#{"email": "required|email", "password": "required|string"})
        string key = "login|" + str_lower(data["email"]) + "|" + to_str(request.ip())
        if RateLimiter.tooManyAttempts(key, 5)
            int seconds = RateLimiter.availableIn(key)
            return back().withErrors(#{"email": "Too many login attempts. Try again in {seconds} seconds."}).withInput()
        bool remember = request.input("remember") != null
        string result = TwoFactor.attempt(#{"email": data["email"], "password": data["password"]}, remember)
        if result == "failed"
            RateLimiter.hit(key, 60)
            return back().withErrors(#{"email": "These credentials do not match our records."}).withInput()
        RateLimiter.clear(key)
        if result == "two-factor"
            return redirect("/2fa")
        return intended(HOME)
'''.replace("HOME", HOME)

REGISTER = '''namespace App\\Controllers\\Auth

use App\\Models\\User

class RegisterController

    #[Public]
    #[any]
    karo show()
        return view("auth.register")

    #[Public]
    #[any]
    karo store(Request request)
        dict<string, any> data = request.validate(#{
            "name": "required|string|max:255",
            "email": "required|email|max:255|unique:users,email",
            "password": "required|string|min:8|confirmed"
        })
        User user = new User(#{"name": data["name"], "email": data["email"]})
        user.password = Hash.password(data["password"])     // set directly: password stays out of fillable
        user.save()
        event("auth.registered", user)
        if Config.get("auth.verification.enabled", true) == true
            user.sendEmailVerificationNotification()
        Auth.login(user)
        return intended(HOME)
'''.replace("HOME", HOME)

LOGOUT = '''namespace App\\Controllers\\Auth

class LogoutController

    #[Public]
    #[any]
    karo store(Request request)
        Auth.logout()
        request.session().invalidate()
        return redirect("/")
'''

FORGOT = '''namespace App\\Controllers\\Auth

class ForgotPasswordController

    #[Public]
    #[any]
    karo show()
        return view("auth.forgot-password")

    #[Public]
    #[any]
    karo store(Request request)
        dict<string, any> data = request.validate(#{"email": "required|email"})
        string status = Password.sendResetLink(#{"email": data["email"]})
        if status == Password.RESET_LINK_SENT
            return back().with("status", Password.message(status))
        return back().withErrors(#{"email": Password.message(status)}).withInput()
'''

RESET = '''namespace App\\Controllers\\Auth

class ResetPasswordController

    #[Public]
    #[any]
    karo show(Request request, string token)
        return view("auth.reset-password", #{"token": token, "email": request.query("email") ?? ""})

    #[Public]
    #[any]
    karo store(Request request)
        dict<string, any> data = request.validate(#{
            "token": "required|string",
            "email": "required|email",
            "password": "required|string|min:8|confirmed"
        })
        string status = Password.reset(#{"email": data["email"], "token": data["token"], "password": data["password"]})
        if status == Password.PASSWORD_RESET
            return redirect("/login").with("status", Password.message(status))
        return back().withErrors(#{"email": Password.message(status)}).withInput()
'''

VERIFY = '''namespace App\\Controllers\\Auth

use App\\Models\\User

class VerifyEmailController

    #[Public]
    #[any]
    karo notice()
        User user = Auth.user()
        if user.hasVerifiedEmail()
            return redirect(HOME)
        return view("auth.verify-email")

    #[Public]
    #[any]
    karo verify(int id, string hash)
        User user = Auth.user()
        if user.id != id or not Hash.equals(Hash.sha1(user.email), hash)
            Http.abort(403, "This verification link is for another account.")
        user.markEmailAsVerified()
        return redirect(HOME + "?verified=1")

    #[Public]
    #[any]
    karo resend()
        User user = Auth.user()
        if user.hasVerifiedEmail()
            return redirect(HOME)
        user.sendEmailVerificationNotification()
        return back().with("status", "A new verification link has been sent to your email address.")
'''.replace("HOME", HOME)

TWO_FACTOR = '''namespace App\\Controllers\\Auth

use App\\Models\\User

class TwoFactorController

    // ---- the login challenge (after email + password were right) ----

    #[Public]
    #[any]
    karo challenge()
        if TwoFactor.pending() == null
            return redirect("/login")
        return view("auth.two-factor-challenge")

    #[Public]
    #[any]
    karo verify(Request request)
        if TwoFactor.pending() == null
            return redirect("/login").withErrors(#{"email": "Please log in again."})
        if TwoFactor.complete(to_str(request.input("code") ?? ""))
            return intended(HOME)
        if TwoFactor.pending() == null
            return redirect("/login").withErrors(#{"email": "Too many invalid codes. Please log in again."})
        return back().withErrors(#{"code": "That code is not valid."})

    // ---- settings ----

    #[Public]
    #[any]
    karo show()
        User user = Auth.user()
        bool enabled = user.hasTwoFactorEnabled()
        bool settingUp = not enabled and user.twoFactorSecret() != null
        return view("auth.two-factor", #{"user": user, "enabled": enabled, "settingUp": settingUp})

    #[Public]
    #[any]
    karo enable()
        User user = Auth.user()
        user.enableTwoFactor()
        return redirect("/settings/2fa")

    #[Public]
    #[any]
    karo confirm(Request request)
        dict<string, any> data = request.validate(#{"code": "required|digits:6"})
        User user = Auth.user()
        if user.confirmTwoFactor(to_str(data["code"]))
            return redirect("/settings/2fa").with("status", "Two-factor authentication is on. Save your recovery codes somewhere safe.")
        return back().withErrors(#{"code": "That code is not valid. Check the time on your phone and try again."})

    #[Public]
    #[any]
    karo disable(Request request)
        dict<string, any> data = request.validate(#{"password": "required|string"})
        User user = Auth.user()
        if not Auth.validate(#{"email": user.email, "password": data["password"]})
            return back().withErrors(#{"password": "The password is incorrect."})
        user.disableTwoFactor()
        return redirect("/settings/2fa").with("status", "Two-factor authentication is off.")

    #[Public]
    #[any]
    karo regenerateCodes()
        User user = Auth.user()
        user.regenerateRecoveryCodes()
        return redirect("/settings/2fa").with("status", "New recovery codes are ready. The old ones no longer work.")
'''.replace("HOME", HOME)

OAUTH = '''namespace App\\Controllers\\Auth

use App\\Models\\User

// Social login. A user is found by <provider>_id, then by a verified email; otherwise one is created.
class OAuthController

    #[Public]
    #[any]
    karo redirect(string provider)
        if not OAuth.enabled(provider)
            Http.abort(404)
        return OAuth.driver(provider).redirect()

    #[Public]
    #[any]
    karo callback(string provider)
        if not OAuth.enabled(provider)
            Http.abort(404)
        string label = provider == "github" ? "GitHub" : str_title(provider)
        OAuthUser social = null
        try
            social = OAuth.driver(provider).user()
        except OAuthException as e
            return redirect("/login").withErrors(#{"email": "Logging in with {label} did not work. Please try again."})
        string column = provider + "_id"
        User user = User.where(column, social.id).first()
        if user == null
            if social.email == null
                return redirect("/login").withErrors(#{"email": "{label} did not share your email address. Create an account with your email instead."})
            user = User.where("email", social.email).first()
            if user != null and not social.emailVerified
                return redirect("/login").withErrors(#{"email": "An account with this email already exists. Log in with your password."})
            if user == null
                user = new User(#{"name": social.name ?? social.nickname ?? social.email, "email": social.email})
                user.password = Hash.password(Crypto.token(32))     // a random password: they can reset it later
            user.setAttribute(column, social.id)
        if social.emailVerified and user.email_verified_at == null
            user.email_verified_at = Date.now()
        if social.avatar != null
            user.avatar = social.avatar
        user.save()
        if TwoFactor.login(user) == "two-factor"
            return redirect("/2fa")
        return intended(HOME)
'''.replace("HOME", HOME)

SESSIONS = '''namespace App\\Controllers\\Auth

// The devices a user is logged in on, and logging them out.
class SessionController

    #[Public]
    #[any]
    karo index()
        list<dict<string, any>> sessions = #[]
        for s in Auth.user().sessions()
            sessions.push(dict_merge(s, #{"ago": this.ago(s["lastActive"])}))
        return view("auth.sessions", #{"sessions": sessions})

    #[Public]
    #[any]
    karo destroyOthers(Request request)
        dict<string, any> data = request.validate(#{"password": "required|string"})
        if not Auth.logoutOtherDevices(data["password"])
            return back().withErrors(#{"password": "The password is incorrect."})
        return back().with("status", "You are logged out on your other devices.")

    #[Public]
    #[any]
    karo destroy(string id)
        Auth.logoutSession(id)
        return back().with("status", "That device has been logged out.")

    #[Private]
    #[string]
    karo ago(int when)
        int seconds = Date.now() - when
        if seconds < 60
            return "active now"
        if seconds < 3600
            return "{seconds / 60} minutes ago"
        if seconds < 86400
            return "{seconds / 3600} hours ago"
        return "{seconds / 86400} days ago"
'''

TEAMS = '''namespace App\\Controllers\\Auth

use App\\Models\\Team
use App\\Models\\User

class TeamController

    #[Public]
    #[any]
    karo index()
        User user = Auth.user()
        return view("auth.teams.index", #{"teams": user.teams(), "current": user.currentTeam()})

    #[Public]
    #[any]
    karo create()
        return view("auth.teams.create")

    #[Public]
    #[any]
    karo store(Request request)
        dict<string, any> data = request.validate(#{"name": "required|string|max:255"})
        User user = Auth.user()
        Team team = Team.create(#{"name": data["name"], "user_id": user.id})
        user.switchTeam(team)
        return redirect("/teams/{team.id}").with("status", "Team created. Invite people to join it below.")

    #[Public]
    #[any]
    karo show(Team team)
        User user = Auth.user()
        return view("auth.teams.manage", #{
            "team": team, "user": user, "members": team.members(), "invitations": team.invitations(),
            "roles": Config.get("auth.teams.roles", #["admin", "member"])
        })

    #[Public]
    #[any]
    karo update(Request request, Team team)
        dict<string, any> data = request.validate(#{"name": "required|string|max:255"})
        team.name = data["name"]
        team.save()
        return back().with("status", "Team name saved.")

    #[Public]
    #[any]
    karo destroy(Team team)
        team.purge()
        return redirect("/teams").with("status", "Team deleted.")

    #[Public]
    #[any]
    karo switchTeam(Request request)
        Team team = Team.findOrFail(to_int(request.input("team_id")))
        if not Auth.user().switchTeam(team)
            Http.abort(403)
        return back()
'''

TEAM_MEMBERS = '''namespace App\\Controllers\\Auth

use App\\Models\\Team
use App\\Models\\User

class TeamMemberController

    // Invite someone by email (they join when they open the link and log in with that address).
    #[Public]
    #[any]
    karo store(Request request, Team team)
        list<string> roles = Config.get("auth.teams.roles", #["admin", "member"])
        dict<string, any> data = request.validate(#{"email": "required|email", "role": "required|in:" + roles.join(",")})
        User existing = User.where("email", data["email"]).first()
        if existing != null and team.hasMember(existing)
            return back().withErrors(#{"email": "That person is on this team already."}).withInput()
        team.invite(data["email"], role: data["role"])
        string email = data["email"]
        return back().with("status", "Invitation sent to {email}.")

    #[Public]
    #[any]
    karo update(Request request, Team team, User user)
        list<string> roles = Config.get("auth.teams.roles", #["admin", "member"])
        dict<string, any> data = request.validate(#{"role": "required|in:" + roles.join(",")})
        string current = team.roleOf(user) ?? ""
        if current == "" or current == "owner"
            return back().withErrors(#{"team": "That role cannot be changed."})
        team.updateMemberRole(user, data["role"])
        return back().with("status", "{user.name} is now {data["role"]}.")

    // Remove someone (owners and admins), or leave the team yourself.
    #[Public]
    #[any]
    karo destroy(Team team, User user)
        User me = Auth.user()
        bool leaving = me.id == user.id
        if not leaving
            Gate.authorize("removeMember", team)
        if team.roleOf(user) == "owner"
            return back().withErrors(#{"team": "The owner cannot leave the team. Delete the team instead."})
        team.removeMember(user)
        if leaving
            return redirect("/teams").with("status", "You left {team.name}.")
        return back().with("status", "{user.name} was removed from the team.")
'''

TEAM_INVITATIONS = '''namespace App\\Controllers\\Auth

use App\\Models\\Team

class TeamInvitationController

    // The link in the invitation email. Guests log in first and come back here.
    #[Public]
    #[any]
    karo accept(string token)
        dict<string, any> invitation = Team.findInvitation(token)
        if invitation == null
            return redirect("/teams").withErrors(#{"team": "This invitation is not valid any more. Ask for a new one."})
        Team team = invitation["team"]
        string email = invitation["email"]
        if not Team.acceptInvitation(token)
            return redirect("/teams").withErrors(#{"team": "This invitation was sent to {email}. Log in with that address to accept it."})
        Auth.user().switchTeam(team)
        return redirect("/teams/{team.id}").with("status", "Welcome to {team.name}!")

    #[Public]
    #[any]
    karo cancel(Team team, int invitation)
        team.cancelInvitation(invitation)
        return back().with("status", "Invitation cancelled.")
'''

TEAM_MODEL = '''namespace App\\Models

// TeamModel gives teams their members, roles and invitations (docs/packages/barq-auth.md, section 7).
class Team extends TeamModel

    protected list<string> fillable = #["name", "user_id"]
'''

TEAM_POLICY = '''namespace App\\Policies

use App\\Models\\Team
use App\\Models\\User

// Who may do what with a team. The owner has every role, so hasTeamRole(team, "admin") is true for them.
class TeamPolicy

    #[Public]
    #[bool]
    karo view(User user, Team team)
        return user.belongsToTeam(team)

    #[Public]
    #[bool]
    karo update(User user, Team team)
        return user.hasTeamRole(team, "admin")

    #[Public]
    #[bool]
    karo delete(User user, Team team)
        return user.ownsTeam(team)

    #[Public]
    #[bool]
    karo addMember(User user, Team team)
        return user.hasTeamRole(team, "admin")

    #[Public]
    #[bool]
    karo updateMember(User user, Team team)
        return user.hasTeamRole(team, "admin")

    #[Public]
    #[bool]
    karo removeMember(User user, Team team)
        return user.hasTeamRole(team, "admin")
'''

# ---------------------------------------------------------------------------
# views
# ---------------------------------------------------------------------------

LAYOUT = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><yield name="title">Welcome</yield> · {Config.get("app.name", "Barq")}</title>
    <style>
        :root {
            --green: #15803D; --blue: #4F46E5; --ink: #0f172a; --muted: #64748b;
            --line: #e2e8f0; --bg: #f8fafc; --card: #ffffff; --danger: #b91c1c; --ok-bg: #ecfdf5;
        }
        @media (prefers-color-scheme: dark) {
            :root { --ink: #e2e8f0; --muted: #94a3b8; --line: #334155; --bg: #0b1120; --card: #111827;
                    --danger: #f87171; --ok-bg: #052e1a; }
        }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px 16px;
               background: var(--bg); color: var(--ink);
               font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
        .card { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--line);
                border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px rgba(15, 23, 42, .06); }
        .brand { font: 700 22px/1 Sora, Inter, sans-serif; margin: 0 0 24px; background: linear-gradient(90deg, var(--green), var(--blue));
                 -webkit-background-clip: text; background-clip: text; color: transparent; }
        h1 { font: 600 20px/1.3 Sora, Inter, sans-serif; margin: 0 0 8px; }
        p { margin: 0 0 16px; color: var(--muted); }
        label { display: block; font-weight: 500; margin: 16px 0 6px; }
        input[type=text], input[type=email], input[type=password] {
            width: 100%; padding: 10px 12px; border: 1px solid var(--line); border-radius: 10px;
            background: transparent; color: inherit; font: inherit; }
        input:focus { outline: 2px solid var(--blue); outline-offset: 1px; }
        .check { display: flex; gap: 8px; align-items: center; margin-top: 16px; font-weight: 400; }
        button, .button { display: inline-block; width: 100%; margin-top: 24px; padding: 11px 16px; border: 0;
                 border-radius: 10px; font: 600 15px/1.2 Inter, sans-serif; color: #fff; cursor: pointer; text-align: center;
                 background: linear-gradient(90deg, var(--green), var(--blue)); text-decoration: none; }
        button.secondary { background: transparent; color: var(--ink); border: 1px solid var(--line); }
        button.danger { background: var(--danger); }
        .error { color: var(--danger); font-size: 13px; margin: 6px 0 0; }
        .status { background: var(--ok-bg); color: var(--green); border-radius: 10px; padding: 10px 12px; margin-bottom: 16px; }
        .links { display: flex; justify-content: space-between; margin-top: 20px; font-size: 14px; }
        a { color: var(--blue); }
        .qr { display: grid; place-items: center; background: #fff; border-radius: 12px; padding: 12px; margin: 16px 0; }
        code, .codes { font-family: "JetBrains Mono", ui-monospace, monospace; }
        .codes { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; padding: 12px; border: 1px dashed var(--line);
                 border-radius: 10px; margin: 12px 0; }
        select { width: 100%; padding: 9px 10px; border: 1px solid var(--line); border-radius: 10px;
                 background: transparent; color: inherit; font: inherit; }
        h2 { font: 600 16px/1.3 Sora, Inter, sans-serif; margin: 28px 0 8px; }
        .divider { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13px; margin: 24px 0 0; }
        .divider::before, .divider::after { content: ""; flex: 1; border-top: 1px solid var(--line); }
        .button.secondary { background: transparent; color: var(--ink); border: 1px solid var(--line); margin-top: 12px; }
        .list { list-style: none; margin: 8px 0 0; padding: 0; border: 1px solid var(--line); border-radius: 12px; }
        .list li { display: flex; gap: 12px; align-items: center; justify-content: space-between; padding: 12px 14px;
                   border-top: 1px solid var(--line); flex-wrap: wrap; }
        .list li:first-child { border-top: 0; }
        .list small { display: block; color: var(--muted); }
        .list form { margin: 0; display: flex; gap: 8px; align-items: center; }
        .list button, .list select { width: auto; margin: 0; padding: 6px 10px; font-size: 13px; }
        .badge { font-size: 12px; padding: 2px 8px; border-radius: 99px; border: 1px solid var(--line); color: var(--muted); }
    </style>
</head>
<body>
    <main class="card">
        <div class="brand">{Config.get("app.name", "Barq")}</div>
        <if condition="{session("status") != null}"><div class="status">{session("status")}</div></if>
        <if condition="{errors.has("team")}"><p class="error">{errors.first("team")}</p></if>
<yield name="content" />
    </main>
</body>
</html>
'''


def field(name, label, kind, extra=""):
    value = f' value="{{old("{name}", "")}}"' if kind not in ("password",) else ""
    return f'''        <label for="{name}">{label}</label>
        <input id="{name}" name="{name}" type="{kind}"{value}{extra}>
        <if condition="{{errors.has("{name}")}}"><p class="error">{{errors.first("{name}")}}</p></if>
'''


LOGIN_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Log in</section>
<section name="content">
    <h1>Log in</h1>
    <p>Welcome back.</p>
    <form method="POST" action="/login">
        {!csrf_field()!}
''' + field("email", "Email", "email", " required autofocus autocomplete=\"username\"") + \
    field("password", "Password", "password", " required autocomplete=\"current-password\"") + '''        <label class="check"><input type="checkbox" name="remember" value="1"> Remember me</label>
        <button type="submit">Log in</button>
    </form>
    <if condition="{OAuth.providers().len() > 0}">
    <div class="divider">or</div>
    <each provider in {OAuth.providers()}>
    <a class="button secondary" href="/auth/{provider}">Continue with {provider == "github" ? "GitHub" : str_title(provider)}</a>
    </each>
    </if>
    <div class="links"><a href="/forgot-password">Forgot your password?</a><a href="/register">Create an account</a></div>
</section>
'''

REGISTER_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Create an account</section>
<section name="content">
    <h1>Create an account</h1>
    <form method="POST" action="/register">
        {!csrf_field()!}
''' + field("name", "Name", "text", " required autofocus autocomplete=\"name\"") + \
    field("email", "Email", "email", " required autocomplete=\"username\"") + \
    field("password", "Password", "password", " required autocomplete=\"new-password\"") + \
    field("password_confirmation", "Confirm password", "password", " required autocomplete=\"new-password\"") + '''        <button type="submit">Create account</button>
    </form>
    <div class="links"><span></span><a href="/login">Already registered? Log in</a></div>
</section>
'''

FORGOT_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Forgot password</section>
<section name="content">
    <h1>Forgot your password?</h1>
    <p>Enter your email and we will send you a link to choose a new one.</p>
    <form method="POST" action="/forgot-password">
        {!csrf_field()!}
''' + field("email", "Email", "email", " required autofocus") + '''        <button type="submit">Email reset link</button>
    </form>
    <div class="links"><a href="/login">Back to log in</a></div>
</section>
'''

RESET_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Reset password</section>
<section name="content">
    <h1>Choose a new password</h1>
    <form method="POST" action="/reset-password">
        {!csrf_field()!}
        <input type="hidden" name="token" value="{token}">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" value="{old("email", email)}" required autocomplete="username">
        <if condition="{errors.has("email")}"><p class="error">{errors.first("email")}</p></if>
''' + field("password", "New password", "password", " required autofocus autocomplete=\"new-password\"") + \
    field("password_confirmation", "Confirm password", "password", " required autocomplete=\"new-password\"") + '''        <button type="submit">Reset password</button>
    </form>
</section>
'''

VERIFY_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Verify your email</section>
<section name="content">
    <h1>Check your inbox</h1>
    <p>We sent a link to <strong>{auth().user().email}</strong>. Open it to verify your email address.</p>
    <form method="POST" action="/email/verification-notification">
        {!csrf_field()!}
        <button type="submit">Send the link again</button>
    </form>
    <form method="POST" action="/logout">
        {!csrf_field()!}
        <button type="submit" class="secondary">Log out</button>
    </form>
</section>
'''

CHALLENGE_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Two-factor authentication</section>
<section name="content">
    <h1>Enter your code</h1>
    <p>Open your authenticator app and enter the 6-digit code. Lost your phone? Enter one of your recovery codes instead.</p>
    <form method="POST" action="/2fa">
        {!csrf_field()!}
''' + field("code", "Code", "text", " required autofocus inputmode=\"numeric\" autocomplete=\"one-time-code\"") + \
    '''        <p class="error">{TwoFactor.attemptsLeft()} attempt(s) left.</p>
        <button type="submit">Verify</button>
    </form>
    <div class="links"><a href="/login">Start over</a></div>
</section>
'''

TWO_FACTOR_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Two-factor authentication</section>
<section name="content">
    <h1>Two-factor authentication</h1>
    <if condition="{enabled}">
    <p>Two-factor authentication is <strong>on</strong>. Keep these recovery codes somewhere safe. Each one works once.</p>
    <div class="codes"><each code in {user.recoveryCodes()}><span>{code}</span></each></div>
    <form method="POST" action="/settings/2fa/codes">
        {!csrf_field()!}
        <button type="submit" class="secondary">Make new recovery codes</button>
    </form>
    <form method="POST" action="/settings/2fa">
        {!csrf_field()!}
        {!method_field("DELETE")!}
''' + field("password", "Password (to turn it off)", "password", " required autocomplete=\"current-password\"") + '''        <button type="submit" class="danger">Turn off</button>
    </form>
    <elseif condition="{settingUp}">
    <p>Scan this QR code with an authenticator app (Google Authenticator, Authy, 1Password…), then enter the code it shows.</p>
    <div class="qr">{!user.twoFactorQrCodeSvg(192)!}</div>
    <p>Can't scan it? Enter this key: <code>{user.twoFactorSecret()}</code></p>
    <form method="POST" action="/settings/2fa/confirm">
        {!csrf_field()!}
''' + field("code", "Code", "text", " required autofocus inputmode=\"numeric\" autocomplete=\"one-time-code\"") + '''        <button type="submit">Confirm</button>
    </form>
    <else>
    <p>Add a second step to logging in: a code from an app on your phone.</p>
    <form method="POST" action="/settings/2fa/enable">
        {!csrf_field()!}
        <button type="submit">Turn on</button>
    </form>
    </if>
    <div class="links"><a href="/dashboard">Back to the dashboard</a></div>
</section>
'''

DASHBOARD_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Dashboard</section>
<section name="content">
    <h1>Hello, {auth().user().name}</h1>
    <p>You are logged in.</p>
    <if condition="{auth().user().currentTeam() != null}"><p>Current team: <strong>{auth().user().currentTeam().name}</strong></p></if>
    <a class="button" href="/teams">Teams</a>
    <a class="button secondary" href="/settings/2fa">Two-factor authentication</a>
    <a class="button secondary" href="/settings/sessions">Devices</a>
    <form method="POST" action="/logout">
        {!csrf_field()!}
        <button type="submit" class="secondary">Log out</button>
    </form>
</section>
'''

SESSIONS_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Devices</section>
<section name="content">
    <h1>Where you are logged in</h1>
    <p>If you do not recognise a device, log it out and change your password.</p>
    <ul class="list">
    <each s in {sessions}>
        <li>
            <span>{s["browser"]} on {s["platform"]}<if condition="{s["mobile"]}"> (phone)</if>
                <small>{s["ip"] ?? "unknown address"} · <if condition="{s["current"]}">this device<else>{s["ago"]}</if></small></span>
            <if condition="{not s["current"]}">
            <form method="POST" action="/settings/sessions/{s["id"]}">
                {!csrf_field()!}
                {!method_field("DELETE")!}
                <button type="submit" class="secondary">Log out</button>
            </form>
            </if>
        </li>
    </each>
    </ul>
    <if condition="{sessions.len() > 1}">
    <h2>Log out everywhere else</h2>
    <form method="POST" action="/settings/sessions">
        {!csrf_field()!}
        {!method_field("DELETE")!}
''' + field("password", "Your password", "password", " required autocomplete=\"current-password\"") + '''        <button type="submit" class="danger">Log out other devices</button>
    </form>
    </if>
    <div class="links"><a href="/dashboard">Back to the dashboard</a></div>
</section>
'''

TEAMS_INDEX_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Teams</section>
<section name="content">
    <h1>Your teams</h1>
    <if condition="{teams.len() == 0}">
    <p>You are not on a team yet. Create one, or ask someone to invite you.</p>
    <else>
    <ul class="list">
    <each team in {teams}>
        <li>
            <span><a href="/teams/{team.id}">{team.name}</a>
                <small>{auth().user().teamRole(team)}</small></span>
            <if condition="{current != null and current.id == team.id}">
            <span class="badge">current</span>
            <else>
            <form method="POST" action="/current-team">
                {!csrf_field()!}
                {!method_field("PUT")!}
                <input type="hidden" name="team_id" value="{team.id}">
                <button type="submit" class="secondary">Switch</button>
            </form>
            </if>
        </li>
    </each>
    </ul>
    </if>
    <a class="button" href="/teams/create">Create a team</a>
    <div class="links"><a href="/dashboard">Back to the dashboard</a></div>
</section>
'''

TEAMS_CREATE_VIEW = '''<extends layout="layouts.auth" />
<section name="title">Create a team</section>
<section name="content">
    <h1>Create a team</h1>
    <p>You will own the team and can invite people to it.</p>
    <form method="POST" action="/teams">
        {!csrf_field()!}
''' + field("name", "Team name", "text", " required autofocus") + '''        <button type="submit">Create team</button>
    </form>
    <div class="links"><a href="/teams">Back to your teams</a></div>
</section>
'''

TEAMS_MANAGE_VIEW = '''<extends layout="layouts.auth" />
<section name="title">{team.name}</section>
<section name="content">
    <h1>{team.name}</h1>
    <p>Owned by {team.owner().name}. You are {user.teamRole(team)}.</p>

    <if condition="{user.can("update", team)}">
    <form method="POST" action="/teams/{team.id}">
        {!csrf_field()!}
        {!method_field("PUT")!}
        <label for="name">Team name</label>
        <input id="name" name="name" type="text" value="{old("name", team.name)}" required>
        <if condition="{errors.has("name")}"><p class="error">{errors.first("name")}</p></if>
        <button type="submit" class="secondary">Save name</button>
    </form>
    </if>

    <h2>Members</h2>
    <ul class="list">
    <each member in {members}>
        <li>
            <span>{member.name}<small>{member.email} · {team.roleOf(member)}</small></span>
            <if condition="{team.roleOf(member) != "owner" and user.can("updateMember", team)}">
            <form method="POST" action="/teams/{team.id}/members/{member.id}">
                {!csrf_field()!}
                {!method_field("PUT")!}
                <select name="role" aria-label="Role">
                <each role in {roles}><option value="{role}" {!team.roleOf(member) == role ? "selected" : ""!}>{role}</option></each>
                </select>
                <button type="submit" class="secondary">Save</button>
            </form>
            </if>
            <if condition="{team.roleOf(member) != "owner" and (member.id == user.id or user.can("removeMember", team))}">
            <form method="POST" action="/teams/{team.id}/members/{member.id}">
                {!csrf_field()!}
                {!method_field("DELETE")!}
                <button type="submit" class="secondary">{member.id == user.id ? "Leave" : "Remove"}</button>
            </form>
            </if>
        </li>
    </each>
    </ul>

    <if condition="{user.can("addMember", team)}">
    <h2>Invite someone</h2>
    <form method="POST" action="/teams/{team.id}/members">
        {!csrf_field()!}
''' + field("email", "Email", "email", " required") + '''        <label for="role">Role</label>
        <select id="role" name="role">
        <each role in {roles}><option value="{role}">{role}</option></each>
        </select>
        <if condition="{errors.has("role")}"><p class="error">{errors.first("role")}</p></if>
        <button type="submit">Send invitation</button>
    </form>
    <if condition="{invitations.len() > 0}">
    <h2>Waiting for an answer</h2>
    <ul class="list">
    <each invitation in {invitations}>
        <li>
            <span>{invitation["email"]}<small>{invitation["role"]}</small></span>
            <form method="POST" action="/teams/{team.id}/invitations/{invitation["id"]}">
                {!csrf_field()!}
                {!method_field("DELETE")!}
                <button type="submit" class="secondary">Cancel</button>
            </form>
        </li>
    </each>
    </ul>
    </if>
    </if>

    <if condition="{user.can("delete", team)}">
    <h2>Delete the team</h2>
    <p>Everyone loses access. This cannot be undone.</p>
    <form method="POST" action="/teams/{team.id}">
        {!csrf_field()!}
        {!method_field("DELETE")!}
        <button type="submit" class="danger">Delete team</button>
    </form>
    </if>
    <div class="links"><a href="/teams">Back to your teams</a></div>
</section>
'''

# ---------------------------------------------------------------------------
# models and migrations
# ---------------------------------------------------------------------------

USER_MODEL = '''namespace App\\Models

class User extends Model

    protected list<string> fillable = #["name", "email"]
    protected list<string> hidden = #["password", "remember_token", "two_factor_secret", "two_factor_recovery_codes"]
'''

USERS_MIGRATION = '''namespace Database\\Migrations

class CreateUsersTable extends Migration

    #[Public]
    #[void]
    karo up(Schema schema)
        schema.create("users", karo(Blueprint table): void
            table.id()
            table.string("name")
            table.string("email").unique()
            table.int("email_verified_at").nullable()
            table.string("password")
            table.text("two_factor_secret").nullable()
            table.text("two_factor_recovery_codes").nullable()
            table.int("two_factor_confirmed_at").nullable()
            table.string("avatar").nullable()
            table.string("google_id").nullable().index()
            table.string("facebook_id").nullable().index()
            table.string("github_id").nullable().index()
            table.int("current_team_id").nullable()
            table.rememberToken()
            table.timestamps()
        )

    #[Public]
    #[void]
    karo down(Schema schema)
        schema.dropIfExists("users")
'''

# For a project that already has a users table: add only what is missing.
AUTH_COLUMNS = [
    ("password", 'table.string("password").nullable()'),
    ("email_verified_at", 'table.int("email_verified_at").nullable()'),
    ("remember_token", 'table.rememberToken()'),
    ("two_factor_secret", 'table.text("two_factor_secret").nullable()'),
    ("two_factor_recovery_codes", 'table.text("two_factor_recovery_codes").nullable()'),
    ("two_factor_confirmed_at", 'table.int("two_factor_confirmed_at").nullable()'),
]
# Added in v0.15.0 (social login and teams).
SOCIAL_COLUMNS = [
    ("avatar", 'table.string("avatar").nullable()'),
    ("google_id", 'table.string("google_id").nullable().index()'),
    ("facebook_id", 'table.string("facebook_id").nullable().index()'),
    ("github_id", 'table.string("github_id").nullable().index()'),
    ("current_team_id", 'table.int("current_team_id").nullable()'),
]


def add_columns_migration(columns=None, cls="AddAuthColumnsToUsersTable",
                          about="Adds the columns barq auth needs to an existing users table (only the missing ones)."):
    columns = AUTH_COLUMNS + SOCIAL_COLUMNS if columns is None else columns
    ups, downs = [], []
    for col, code in columns:
        ups.append(f'''        if not schema.hasColumn("users", "{col}")
            schema.table("users", karo(Blueprint table): void
                {code}
            )''')
    for col, _ in [c for c in columns if c[0] != "password"]:
        downs.append(f'''        if schema.hasColumn("users", "{col}")
            schema.table("users", karo(Blueprint table): void
                table.dropColumn("{col}")
            )''')
    return '''namespace Database\\Migrations

// ABOUT
class CLS extends Migration
'''.replace("ABOUT", about).replace("CLS", cls) + '''
    #[Public]
    #[void]
    karo up(Schema schema)
''' + "\n".join(ups) + '''

    #[Public]
    #[void]
    karo down(Schema schema)
''' + "\n".join(downs) + "\n"


RESETS_MIGRATION = '''namespace Database\\Migrations

class CreatePasswordResetTokensTable extends Migration

    #[Public]
    #[void]
    karo up(Schema schema)
        schema.create("password_reset_tokens", karo(Blueprint table): void
            table.string("email").primary()
            table.string("token")
            table.int("created_at").nullable()
        )

    #[Public]
    #[void]
    karo down(Schema schema)
        schema.dropIfExists("password_reset_tokens")
'''

TOKENS_MIGRATION = '''namespace Database\\Migrations

class CreatePersonalAccessTokensTable extends Migration

    #[Public]
    #[void]
    karo up(Schema schema)
        schema.create("personal_access_tokens", karo(Blueprint table): void
            table.id()
            table.morphs("tokenable")
            table.string("name")
            table.string("token", 64).unique()
            table.text("abilities").nullable()
            table.int("last_used_at").nullable()
            table.int("expires_at").nullable()
            table.timestamps()
        )

    #[Public]
    #[void]
    karo down(Schema schema)
        schema.dropIfExists("personal_access_tokens")
'''

def create_table(cls, table, body):
    lines = "\n".join("            " + x for x in body)
    return f'''namespace Database\\Migrations

class {cls} extends Migration

    #[Public]
    #[void]
    karo up(Schema schema)
        schema.create("{table}", karo(Blueprint table): void
{lines}
        )

    #[Public]
    #[void]
    karo down(Schema schema)
        schema.dropIfExists("{table}")
'''


TEAMS_MIGRATION = create_table("CreateTeamsTable", "teams", [
    'table.id()', 'table.int("user_id").index()', 'table.string("name")', 'table.timestamps()'])
TEAM_MEMBERS_MIGRATION = create_table("CreateTeamMembersTable", "team_members", [
    'table.id()', 'table.int("team_id").index()', 'table.int("user_id").index()', 'table.string("role").nullable()',
    'table.timestamps()', 'table.unique(#["team_id", "user_id"])'])
TEAM_INVITATIONS_MIGRATION = create_table("CreateTeamInvitationsTable", "team_invitations", [
    'table.id()', 'table.int("team_id").index()', 'table.string("email")', 'table.string("role").nullable()',
    'table.string("token", 64).unique()', 'table.int("accepted_at").nullable()', 'table.int("expires_at").nullable()',
    'table.timestamps()'])
# Only used with config session.driver = "database"; harmless otherwise.
SESSIONS_MIGRATION = create_table("CreateSessionsTable", "sessions", [
    'table.string("id").primary()', 'table.int("user_id").nullable().index()', 'table.string("ip_address", 45).nullable()',
    'table.text("user_agent").nullable()', 'table.text("payload")', 'table.int("last_activity").index()'])

CONTROLLERS = {
    "LoginController": LOGIN,
    "RegisterController": REGISTER,
    "LogoutController": LOGOUT,
    "ForgotPasswordController": FORGOT,
    "ResetPasswordController": RESET,
    "VerifyEmailController": VERIFY,
    "TwoFactorController": TWO_FACTOR,
    "OAuthController": OAUTH,
    "SessionController": SESSIONS,
    "TeamController": TEAMS,
    "TeamMemberController": TEAM_MEMBERS,
    "TeamInvitationController": TEAM_INVITATIONS,
}

VIEWS = {
    "layouts/auth.bq": LAYOUT,
    "auth/login.bq": LOGIN_VIEW,
    "auth/register.bq": REGISTER_VIEW,
    "auth/forgot-password.bq": FORGOT_VIEW,
    "auth/reset-password.bq": RESET_VIEW,
    "auth/verify-email.bq": VERIFY_VIEW,
    "auth/two-factor-challenge.bq": CHALLENGE_VIEW,
    "auth/two-factor.bq": TWO_FACTOR_VIEW,
    "auth/sessions.bq": SESSIONS_VIEW,
    "auth/teams/index.bq": TEAMS_INDEX_VIEW,
    "auth/teams/create.bq": TEAMS_CREATE_VIEW,
    "auth/teams/manage.bq": TEAMS_MANAGE_VIEW,
    "dashboard.bq": DASHBOARD_VIEW,
}

# app files other than controllers: path -> contents
APP_FILES = {
    "Models/Team.bq": TEAM_MODEL,
    "Policies/TeamPolicy.bq": TEAM_POLICY,
}

# migration name suffix -> (contents, does an existing file with this suffix count as "already there")
MIGRATIONS = [
    ("create_password_reset_tokens_table", RESETS_MIGRATION),
    ("create_personal_access_tokens_table", TOKENS_MIGRATION),
    ("create_teams_table", TEAMS_MIGRATION),
    ("create_team_members_table", TEAM_MEMBERS_MIGRATION),
    ("create_team_invitations_table", TEAM_INVITATIONS_MIGRATION),
    ("create_sessions_table", SESSIONS_MIGRATION),
]
