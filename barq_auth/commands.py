"""barq auth:install — writes the auth pages, controllers, migrations and config."""

import os

from barq.project import all_text_has, any_text_has, cmd_key_generate, env_value, write_new
from barq_framework.commands import MIGRATIONS, migration_stamp


def cmd_auth_install(args):
    """Write the auth scaffolding. Files that already exist are kept, so it is safe to run again."""
    from . import scaffold as sc
    files = [(os.path.join("config", "auth.bq"), sc.AUTH_CONFIG), (os.path.join("routes", "auth.bq"), sc.ROUTES)]
    files += [(os.path.join("app", "Controllers", "Auth", f"{name}.bq"), text) for name, text in sc.CONTROLLERS.items()]
    files += [(os.path.join("views", *rel.split("/")), text) for rel, text in sc.VIEWS.items()]
    files += [(os.path.join("app", *rel.split("/")), text) for rel, text in sc.APP_FILES.items()]
    model = os.path.join("app", "Models", "User.bq")
    had_model = os.path.exists(model)
    files.append((model, sc.USER_MODEL))
    base = os.path.join("app", "Controllers", "Controller.bq")   # the auth controllers extend it
    if not os.path.exists(base) and write_new(base, sc.BASE_CONTROLLER):
        return 1
    for path, text in files:
        if os.path.exists(path):
            print(f"Kept {path} (already there)")
        elif write_new(path, text):
            return 1
    existing = os.listdir(MIGRATIONS) if os.path.isdir(MIGRATIONS) else []

    def has(suffix):
        return any(f.endswith(f"_{suffix}.bq") for f in existing)
    migrations = list(sc.MIGRATIONS)
    users = [f for f in existing if f.endswith("_create_users_table.bq")]
    if not users:
        migrations.insert(0, ("create_users_table", sc.USERS_MIGRATION))
    elif not has("add_auth_columns_to_users_table") and not all_text_has(MIGRATIONS, users, "two_factor_secret"):
        migrations.insert(0, ("add_auth_columns_to_users_table", sc.add_columns_migration()))
    else:
        # installed by an older barq: add the social login and team columns
        mine = users + [f for f in existing if f.endswith("_add_auth_columns_to_users_table.bq")]
        if not has("add_social_and_team_columns_to_users_table") and not any_text_has(MIGRATIONS, mine, "current_team_id"):
            migrations.insert(0, ("add_social_and_team_columns_to_users_table", sc.add_columns_migration(
                sc.SOCIAL_COLUMNS, "AddSocialAndTeamColumnsToUsersTable",
                "Adds the social login and team columns to the users table (only the missing ones).")))
    for suffix, text in migrations:
        if has(suffix):
            print(f"Kept the {suffix} migration (already there)")
        elif write_new(os.path.join(MIGRATIONS, f"{migration_stamp()}_{suffix}.bq"), text):
            return 1
        existing = os.listdir(MIGRATIONS)
    if not env_value("APP_KEY"):
        cmd_key_generate([])
    print("\nNext:\n  - run: barq migrate\n  - run: barq serve, then open http://127.0.0.1:8000/register")
    routes = os.path.join("routes", "auth.bq")
    if not all_text_has("routes", ["auth.bq"], "OAuthController"):
        print(f"  - {routes} is from an older barq: it has no routes for social login, teams and devices. "
              "Rename it and run barq auth:install again to get the new one, then copy back your changes")
    if had_model and not all_text_has(os.path.dirname(model), [os.path.basename(model)], "two_factor_secret"):
        print('  - in app/Models/User.bq, hide the secrets: protected list<string> hidden = #["password", '
              '"remember_token", "two_factor_secret", "two_factor_recovery_codes"]')
    print("  - emails go to the log (stderr) until you set MAIL_MAILER and MAIL_HOST in .env")
    print("  - social login: set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET (or FACEBOOK_APP_ID, GITHUB_CLIENT_ID...) in .env;"
          " the redirect URL to register is APP_URL + /auth/<provider>/callback")
    return 0
