"""barq-auth — authentication for Barq (برق): session and token guards, the
Gate and policies, password resets, email verification, two-factor login,
signed URLs, rate limits, social login (OAuth), teams and device sessions,
plus `barq auth:install`, which writes the pages, controllers and migrations.

Needs barq-framework.
"""

NAME = "barq-auth"
__version__ = "0.20.0-alpha"
REQUIRES = ["barq_framework"]

USAGE = """
Auth commands (barq-auth):
  barq auth:install              Add login, registration, password reset, email verification,
                                 two-factor, social login, teams and device pages
                                 (controllers, views, routes/auth.bq, migrations,
                                 config/auth.bq, APP_KEY)
"""


def cmd_auth_install(cmd, args):
    from .commands import cmd_auth_install as run
    return run(args)


def register(hooks):
    from . import auth, auth2, auth3
    hooks.INSTALLERS.extend([auth.install, auth2.install, auth3.install])
    hooks.login_url = auth.login_url
    hooks.add_command("auth:install", cmd_auth_install)
    hooks.USAGE.append(USAGE)
