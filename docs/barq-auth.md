# Package — Barq Auth

> The official authentication package for the Barq framework.  
> Equivalent to **Laravel Breeze + Jetstream** in one package.

> **Status (v0.15.0-alpha):** everything on this page is built (in the barq-auth package): guards (session + token), `Auth.attempt/login/logout/once`, remember-me, API tokens, the `auth` / `guest` / `can:` / `verified` / `signed` / `throttle:` / `csrf` / `two-factor` middleware, password resets, email verification, two-factor authentication with QR codes and recovery codes, **social login** (Google, Facebook and GitHub, plus any OAuth 2 provider), **teams** with roles and email invitations, **session management** (`user.sessions()`, `Auth.logoutOtherDevices()`), and the page you asked for before logging in (`intended()`). `barq auth:install` writes the controllers, views, `routes/auth.bq`, migrations and config. Differences from this page: the helpers are on every `Model` and the team model extends `TeamModel`, instead of `use HasTeams` / `use HasTwoFactor` traits; social login is `OAuth.driver("google")` (or `GoogleProvider`) with one `/auth/:provider` route pair; 2FA login goes through `TwoFactor.attempt()`; recovery codes are listed on the `/settings/2fa` page; `team.members()` includes the owner; and only a user with the invited email can accept an invitation. The `Route::get(...)` and `"Controller@method"` forms below are from the early design. Today's syntax is `Route.get(...)` with `#[Controller, "method"]`. See [README.md](../README.md#auth-part-3-social-login-teams-devices-v0150).

---

## Overview

Barq Auth provides complete authentication scaffolding out of the box:

| Feature | Included |
|---------|---------|
| Registration & Login | ✅ |
| Email Verification | ✅ |
| Password Reset | ✅ |
| Remember Me | ✅ |
| Google OAuth | ✅ |
| Facebook OAuth | ✅ |
| Two-Factor Authentication (TOTP) | ✅ |
| Recovery Codes | ✅ |
| Teams | ✅ |
| API Tokens (Sanctum-style) | ✅ |
| Session Management | ✅ |

---

## Installation

```bash
barq install barq/auth

# Run the scaffolding command — generates routes, controllers, views, migrations
barq auth:install

# Apply database migrations
barq migrate
```

---

## Generated File Structure

```
app/
├── Controllers/
│   └── Auth/
│       ├── LoginController.bq
│       ├── RegisterController.bq
│       ├── LogoutController.bq
│       ├── ForgotPasswordController.bq
│       ├── ResetPasswordController.bq
│       ├── VerifyEmailController.bq
│       ├── TwoFactorController.bq
│       └── OAuthController.bq
├── Models/
│   ├── User.bq              (modified — adds 2FA + team fields)
│   ├── Team.bq
│   └── PersonalAccessToken.bq
views/
└── auth/
    ├── login.bq
    ├── register.bq
    ├── verify-email.bq
    ├── forgot-password.bq
    ├── reset-password.bq
    ├── two-factor.bq
    └── teams/
        ├── index.bq
        ├── create.bq
        └── manage.bq
database/
└── migrations/
    ├── 001_create_users_table.bq
    ├── 002_add_2fa_to_users.bq
    ├── 003_create_teams_table.bq
    ├── 004_create_team_members_table.bq
    └── 005_create_personal_access_tokens_table.bq
config/
└── auth.bq
```

---

## Configuration

```barq
// config/auth.bq
return #{
    "default_guard": "web",

    "guards": #{
        "web": #{
            "driver":   "session",
            "provider": "users"
        },
        "api": #{
            "driver":   "token",
            "provider": "users"
        }
    },

    "providers": #{
        "users": #{
            "driver": "orm",
            "model":  "App\\Models\\User"
        }
    },

    "passwords": #{
        "expire": 60,           // minutes before reset link expires
        "throttle": 60          // seconds between reset emails
    },

    "oauth": #{
        "google": #{
            "client_id":     Env.get("GOOGLE_CLIENT_ID"),
            "client_secret": Env.get("GOOGLE_CLIENT_SECRET"),
            "redirect":      "/auth/google/callback"
        },
        "facebook": #{
            "client_id":     Env.get("FACEBOOK_APP_ID"),
            "client_secret": Env.get("FACEBOOK_APP_SECRET"),
            "redirect":      "/auth/facebook/callback"
        }
    },

    "2fa": #{
        "enabled":        true,
        "required":       false,          // require all users to set up 2FA?
        "recovery_codes": 8               // number of recovery codes to generate
    },

    "teams": #{
        "enabled":        true,
        "default_role":   "member"
    }
}
```

---

## 1. Registration & Login

Generated routes:

```barq
// Auto-registered by barq/auth
Route::get("/register",         "Auth\RegisterController@show")
Route::post("/register",        "Auth\RegisterController@store")
Route::get("/login",            "Auth\LoginController@show")
Route::post("/login",           "Auth\LoginController@store")
Route::post("/logout",          "Auth\LogoutController@store")
```

User model after install:

```barq
namespace App\Models

use Barq\Auth\Authenticatable
use Barq\Auth\HasApiTokens
use Barq\Auth\HasTeams
use Barq\Auth\HasTwoFactor

class User extends Model
    use Authenticatable
    use HasApiTokens
    use HasTeams
    use HasTwoFactor

    list<string> fillable = #[
        "name", "email", "password"
    ]

    list<string> hidden = #[
        "password", "remember_token",
        "two_factor_secret", "two_factor_recovery_codes"
    ]

    list<string> casts = #{
        "email_verified_at": "datetime",
        "two_factor_confirmed_at": "datetime"
    }
```

---

## 2. Email Verification

```barq
// Routes
Route::get("/verify-email",             "Auth\VerifyEmailController@notice")
Route::get("/verify-email/{id}/{hash}", "Auth\VerifyEmailController@verify")
    .middleware("signed")
Route::post("/email/verification-notification",
    "Auth\VerifyEmailController@resend")
    .middleware("throttle:6,1")

// Protect routes requiring verified email
Route::get("/dashboard", "DashboardController@index")
    .middleware(#["auth", "verified"])
```

---

## 3. Password Reset

```barq
// Routes
Route::get("/forgot-password",          "Auth\ForgotPasswordController@show")
Route::post("/forgot-password",         "Auth\ForgotPasswordController@store")
Route::get("/reset-password/{token}",   "Auth\ResetPasswordController@show")
Route::post("/reset-password",          "Auth\ResetPasswordController@store")
```

---

## 4. Google OAuth

```barq
// Routes (auto-registered)
Route::get("/auth/google",          "Auth\OAuthController@redirectGoogle")
Route::get("/auth/google/callback", "Auth\OAuthController@handleGoogle")
```

Underlying controller logic:

```barq
namespace App\Controllers\Auth

use Barq\Auth\OAuth\GoogleProvider

class OAuthController

    #[Public]
    #[void]
    karo redirectGoogle()
        return GoogleProvider.redirect()

    #[Public]
    #[void]
    karo handleGoogle(Request request)
        oauthUser = GoogleProvider.user()

        user = User.firstOrCreate(
            #{"email": oauthUser.email},
            #{
                "name":              oauthUser.name,
                "google_id":         oauthUser.id,
                "avatar":            oauthUser.avatar,
                "email_verified_at": Date.now()
            }
        )

        Auth.login(user)
        return redirect("/dashboard")
```

**`.env` variables needed:**
```
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

**Google Cloud Console setup:**
- Create OAuth 2.0 credentials
- Add `http://localhost:8000/auth/google/callback` as authorized redirect URI

---

## 5. Facebook OAuth

```barq
// Routes (auto-registered)
Route::get("/auth/facebook",          "Auth\OAuthController@redirectFacebook")
Route::get("/auth/facebook/callback", "Auth\OAuthController@handleFacebook")
```

**`.env` variables needed:**
```
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
```

**Facebook Developer Console setup:**
- Create a Facebook App
- Enable "Facebook Login" product
- Add `http://localhost:8000/auth/facebook/callback` as valid OAuth redirect URI

---

## 6. Two-Factor Authentication (TOTP)

Barq Auth implements **TOTP** (Time-based One-Time Password) — compatible with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any TOTP-compatible app

### Setup flow for the user:

1. User visits `/settings/2fa`
2. App generates a TOTP secret
3. App shows a QR code — user scans with Authenticator app
4. User enters the 6-digit code to confirm setup
5. App shows 8 recovery codes — user saves them

### Login flow with 2FA enabled:

1. User enters email + password → valid credentials
2. If 2FA enabled → redirect to `/2fa` challenge page
3. User enters 6-digit code from their app
4. If valid → session created, redirect to dashboard
5. If invalid → error shown, 3 attempts max then lockout

### Recovery codes:

Each user gets 8 single-use recovery codes. If they lose their phone:
1. Enter recovery code instead of TOTP code
2. That code is consumed (cannot be used again)
3. User regenerates new codes from settings

```barq
// Routes
Route::get("/settings/2fa",         "Auth\TwoFactorController@show")
Route::post("/settings/2fa/enable", "Auth\TwoFactorController@enable")
Route::post("/settings/2fa/confirm","Auth\TwoFactorController@confirm")
Route::delete("/settings/2fa",      "Auth\TwoFactorController@disable")
Route::get("/settings/2fa/codes",   "Auth\TwoFactorController@recoveryCodes")
Route::post("/settings/2fa/codes",  "Auth\TwoFactorController@regenerateCodes")

Route::get("/2fa",                  "Auth\TwoFactorController@challenge")
Route::post("/2fa",                 "Auth\TwoFactorController@verify")
```

```barq
// Check in code
user.hasTwoFactorEnabled()           → true/false
user.twoFactorQrCodeUrl()            → URL for QR code image
user.twoFactorSecret()               → base32 secret
user.recoveryCodes()                 → list of active codes

// Verify a code
user.verifyTwoFactorCode("123456")   → true/false
user.verifyRecoveryCode("ABCD-EFGH") → true/false (also consumes it)
```

---

## 7. Teams

Teams allow users to collaborate under a shared workspace with role-based access.

### Team roles:

| Role | Permissions |
|------|------------|
| `owner` | Full control — rename, delete team, manage all members |
| `admin` | Invite/remove members, change roles (except owner) |
| `member` | Access team resources, no admin actions |

### Usage:

```barq
// Create a team
team = Team.create(#{
    "name":    "Acme Corp",
    "user_id": auth().id()           // creator = owner
})

// Invite a member
team.invite("bob@example.com", role: "member")

// Accept invitation (from email link)
team.acceptInvitation(token)

// Add existing user directly
team.addMember(user, role: "admin")

// Remove a member
team.removeMember(user)

// Change a member's role
team.updateMemberRole(user, "admin")

// Get team members
team.members()                       → list of User
team.membersWithRole("admin")        → list of User
team.owner()                         → User

// User's teams
user.teams()                         → list of Team
user.ownedTeams()                    → list of Team (where user = owner)
user.currentTeam()                   → Team (last active team)
user.switchTeam(team)                // change active team
user.belongsToTeam(team)             → true/false
user.teamRole(team)                  → "owner" / "admin" / "member"
user.hasTeamRole(team, "admin")      → true/false

// In controllers — scope queries to current team
posts = Post.where("team_id", auth().user().currentTeam().id).get()
```

### Database tables created:

```
teams
  id, name, user_id (owner), created_at, updated_at

team_members
  id, team_id, user_id, role, created_at

team_invitations
  id, team_id, email, role, token, accepted_at, expires_at
```

---

## 8. API Tokens

```barq
// Generate a token (shown once to the user)
token = user.createToken("My App Token")
plainTextToken = token.plainTextToken   // show this to the user ONCE

// Generate a token with abilities
token = user.createToken(
    "Read-only Token",
    abilities: #["read:posts", "read:profile"]
)

// Delete a token
user.tokens().where("id", tokenId).delete()

// Delete all tokens
user.tokens().delete()

// In API controller — check ability
Route::get("/api/posts", "Api\PostController@index")
    .middleware("auth:api")

class PostController
    #[Public]
    karo index(Request request)
        // Check the token's ability
        if (not request.user().tokenCan("read:posts"))
            return abort(403, "Token cannot read posts")

        return Post.all()
```

**Usage in API requests:**
```
Authorization: Bearer 1|abc123def456...
```

---

## 9. Session Management

```barq
// View all active sessions
user.sessions()                      → list of active sessions

// Get current session info
session().id()
session().ip()
session().browser()

// Logout from all other devices
Auth.logoutOtherDevices("current-password")

// Logout everywhere (all sessions)
Auth.logoutEveryDevice()
```

---

## 10. Using Auth in Controllers & Templates

```barq
// In any controller
Auth.user()                          // authenticated User or null
Auth.check()                         // is logged in?
Auth.id()                            // user ID or null

// Protect a route with middleware
Route::get("/profile", "ProfileController@show")
    .middleware("auth")

// API route protection
Route::get("/api/me", "Api\UserController@me")
    .middleware("auth:api")
```

```html
<!-- In templates -->
<if condition="auth().check()">
    <span>Hello, {auth().user().name}</span>
    <a href="/logout">Logout</a>
<else>
    <a href="/login">Login</a>
    <a href="/register">Register</a>
</else>
</if>

<!-- Show only for specific role (requires barq/permissions) -->
<if condition="auth().user().hasRole('admin')">
    <a href="/admin">Admin Panel</a>
</if>
```

---

*Back to: [Step 15 — Multi-lingual Support](https://github.com/barq-lang/barq/blob/main/docs/step-15-multilingual.md)*
*Next package: [Barq Permissions →](https://github.com/barq-lang/barq-permissions/blob/main/docs/barq-permissions.md)*
