"""barq-auth test suite: guards, Gate, auth pages, 2FA, OAuth, teams, devices.

Run from this folder (needs a barq checkout next to this one, or BARQ_HOME):

    python3 tests/test_auth.py
"""

import glob
import http.cookiejar
import json
import signal
import socket
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.environ.get("BARQ_HOME") or os.path.join(os.path.dirname(ROOT), "barq")
if not os.path.isdir(os.path.join(CORE, "barq")):
    sys.exit(f"cannot find the barq checkout at {CORE} — clone https://github.com/barq-lang/barq next to "
             "this repo or set BARQ_HOME")
sys.path.insert(0, CORE)

from barq import devtest  # noqa: E402
from barq.devtest import ENGINES, barq_env, fetch, free_port, run_barq, run_both, wait_for_port  # noqa: E402,F401

devtest.PACKAGES = "barq_auth"
devtest.PATHS = [ROOT] + [os.path.join(os.path.dirname(ROOT), d) for d in ['barq-framework']]


class GoldenOutput(unittest.TestCase):
    """tests/cases/NAME.bq must print exactly tests/cases/NAME.out, on both engines."""


devtest.add_golden_tests(GoldenOutput, os.path.join(HERE, "cases"))


class AuthScaffold(unittest.TestCase):
    """barq auth:install in an empty project, then the generated pages driven end to end
    (register, verify email, 2FA setup and login, password reset) by tests/auth_scaffold/."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="barq-auth-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def barq(self, *args):
        proc = subprocess.run([sys.executable, "-m", "barq", *args], capture_output=True, text=True,
                              env=barq_env(), timeout=120, cwd=self.dir)
        return proc.returncode, proc.stdout, proc.stderr

    def test_generated_pages(self):
        code, out, err = self.barq("auth:install")
        self.assertEqual(code, 0, err)
        for rel in ("routes/auth.bq", "app/Controllers/Auth/TwoFactorController.bq", "views/auth/login.bq",
                    "views/layouts/auth.bq", "app/Models/User.bq", "config/auth.bq"):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, rel)), rel)
        with open(os.path.join(self.dir, ".env")) as f:
            self.assertRegex(f.read(), r"APP_KEY=base64:[A-Za-z0-9+/=]{44}")
        code, out, _ = self.barq("auth:install")
        self.assertIn("Kept routes/auth.bq", out)
        self.assertNotIn("Created", out)
        self.assertEqual(self.barq("compile", "app", "config", "database", "routes")[0], 0)
        code, out, err = self.barq("fmt", "--check", ".")                  # written the way barq fmt writes
        self.assertEqual(code, 0, out + err)
        os.makedirs(os.path.join(self.dir, "tests"))
        shutil.copy(os.path.join(HERE, "auth_scaffold", "auth_flow_test.bq"), os.path.join(self.dir, "tests"))
        with open(os.path.join(HERE, "auth_scaffold", "expected.out")) as f:
            expected = f.read()
        for engine in ENGINES:
            with self.subTest(engine=engine):
                self.assertEqual(self.barq("migrate:fresh", *(["--interp"] if engine == "tree" else []))[0], 0)
                code, out, err = self.barq("test", *(["--interp"] if engine == "tree" else []))
                self.assertEqual(code, 0, out + err)
                lines = out.splitlines()
                self.assertEqual("\n".join(lines[1:-1]) + "\n", expected)
        code, out, err = self.barq("route:list")
        self.assertIn("verification.verify", out)


class AuthInProject(unittest.TestCase):
    """auth:install, make:policy, storage:link and the scheduler in tests/project."""

    def setUp(self):
        self.dir = os.path.join(tempfile.mkdtemp(prefix="barq-app-"), "app")
        shutil.copytree(os.path.join(HERE, "project"), self.dir)

    def tearDown(self):
        shutil.rmtree(os.path.dirname(self.dir), ignore_errors=True)

    def barq(self, *args, engine="vm"):
        extra = ["--interp"] if engine == "tree" else []
        if args[0].endswith(".bq"):
            args = ("run",) + tuple(extra) + args
            extra = []
        proc = subprocess.run([sys.executable, "-m", "barq", *args, *extra], capture_output=True, text=True,
                              env=barq_env(), timeout=60, cwd=self.dir)
        return proc.returncode, proc.stdout, proc.stderr

    def fresh_db(self, engine="vm"):
        shutil.rmtree(os.path.join(self.dir, "storage"), ignore_errors=True)
        code, _, err = self.barq("migrate", engine=engine)
        self.assertEqual(code, 0, err)
        code, out, err = self.barq("db:seed", engine=engine)
        self.assertEqual(code, 0, err)
        return out

    def test_auth_storage_schedule(self):
        """auth:install, make:policy, storage:link and schedule:run|list in a real project."""
        code, out, err = self.barq("auth:install")
        self.assertEqual(code, 0, err)
        self.assertIn("Created config/auth.bq", out)
        self.assertIn("Kept config/auth.bq", self.barq("auth:install")[1])     # safe to run twice
        migrations = os.listdir(os.path.join(self.dir, "database", "migrations"))
        self.assertTrue(any(f.endswith("_add_auth_columns_to_users_table.bq") for f in migrations))   # users existed
        for args in (("make:policy", "UserPolicy"), ("make:policy", "Admin/PostPolicy", "--model", "Post")):
            self.assertEqual(self.barq(*args)[0], 0)
        self.assertEqual(self.barq("compile", "app", "config", "database")[0], 0)
        self.assertEqual(self.barq("storage:link")[0], 0)
        self.assertEqual(os.readlink(os.path.join(self.dir, "public", "storage")),
                         os.path.join("..", "storage", "app", "public"))
        with open(os.path.join(self.dir, "routes", "console.bq"), "w") as f:
            f.write('Schedule.call(kr(): bool => Storage.append("ticks.log", "tick")).everyMinute().name("tick")\n'
                    'Schedule.call(kr(): void => print("never")).yearly().name("new year")\n')
        with open(os.path.join(self.dir, "tokens.bq"), "w") as f:
            f.write('use App\\Models\\User\n'
                    'User u = User.create(#{"name": "Tok", "email": "tok@x.pk"})\n'
                    'NewAccessToken t = u.createToken("cli", #["read"])\n'
                    'TestClient c = new TestClient().withToken(t.plainTextToken)\n'
                    'Route.get("/me", kr(): string => Auth.user().name + " " + to_str(Auth.user().tokenCan("read")))'
                    '.middleware("auth:api")\n'
                    'print(c.get("/me").body, Storage.get("ticks.log"))\n')
        for engine in ENGINES:
            with self.subTest(engine=engine):
                self.fresh_db(engine)
                for _ in range(2):
                    code, out, err = self.barq("schedule:run", engine=engine)
                    self.assertEqual(code, 0, err)
                    self.assertIn("Running [tick]", out)
                    self.assertNotIn("new year", out)
                code, out, err = self.barq("schedule:list", engine=engine)
                self.assertEqual(code, 0, err)
                self.assertIn("* * * * *  tick", out)
                self.assertIn("0 0 1 1 *  new year  next: ", out)
                code, out, err = self.barq("tokens.bq", engine=engine)
                self.assertEqual((code, out), (0, "Tok true tick\ntick\n"), err)
                os.remove(os.path.join(self.dir, "storage", "app", "ticks.log"))


class NewWithAuth(unittest.TestCase):
    """barq new --auth: the framework's files plus auth:install, which owns the User model and users table."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="barq-new-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_new_with_auth(self):
        code, out, err = devtest.barq_cli("new", "site", "--auth", cwd=self.dir, timeout=120)
        self.assertEqual(code, 0, err)
        app = os.path.join(self.dir, "site")
        self.assertNotIn("Kept", out)
        with open(os.path.join(app, "app", "Models", "User.bq")) as f:
            self.assertIn("two_factor_secret", f.read())
        self.assertEqual(len(glob.glob(os.path.join(app, "database", "migrations", "*_users_table.bq"))), 1)
        with open(os.path.join(app, ".env")) as f:
            self.assertEqual(f.read().count("APP_KEY="), 1)
        self.assertEqual(devtest.barq_cli("check", ".", cwd=app)[0], 0)
        code, out, err = devtest.barq_cli("migrate:fresh", "--seed", cwd=app, timeout=120)
        self.assertEqual(code, 0, out + err)
        code, out, err = devtest.barq_cli("test", cwd=app, timeout=120)
        self.assertEqual(code, 0, out + err)
        code, out, _ = devtest.barq_cli("route:list", cwd=app)
        self.assertIn("login", out)
        self.assertIn("home", out)


if __name__ == "__main__":
    unittest.main()
