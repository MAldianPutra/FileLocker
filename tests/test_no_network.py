"""Evidence that FileLocker cannot use the network.

1. Static: no application module imports networking/web/process-launching modules
   (except netguard.py, which imports `socket` to disable it, and selftest.py,
   which imports it to prove it is disabled).
2. Runtime: after netguard.install(), sockets, connections and DNS lookups fail,
   including through high-level libraries such as urllib.
3. Import audit: loading the whole application does not load SSL/HTTP clients.
4. The built-in self-test passes when run from source.

Run:  python tests/test_no_network.py
"""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_MODULES = sorted(p for p in ROOT.glob("*.py"))

FORBIDDEN = {
    "socket", "_socket", "ssl", "_ssl", "http", "urllib", "requests", "httpx", "aiohttp",
    "urllib3", "ftplib", "smtplib", "poplib", "imaplib", "nntplib", "telnetlib", "xmlrpc",
    "socketserver", "asyncio", "websocket", "websockets", "webbrowser", "subprocess",
    "multiprocessing", "email",
}
ALLOWED = {
    "netguard.py": {"socket", "_socket"},  # imports socket in order to disable it
    "selftest.py": {"socket"},              # imports socket to prove it is disabled
}

APP_IMPORTS = ("import gui, main, processor, zip_processor, office_crypto, pdf_crypto, "
               "scanner, logger, netguard, version, selftest")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "import_module":
            if node.args and isinstance(node.args[0], ast.Constant):
                found.add(str(node.args[0].value).split(".")[0])
    return found


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True,
                          text=True, timeout=120)


class TestStaticImports(unittest.TestCase):
    def test_app_modules_found(self):
        names = {p.name for p in APP_MODULES}
        self.assertTrue({"main.py", "gui.py", "processor.py", "netguard.py"} <= names, names)

    def test_no_network_imports(self):
        problems = []
        for path in APP_MODULES:
            bad = (_imports(path) & FORBIDDEN) - ALLOWED.get(path.name, set())
            if bad:
                problems.append(f"{path.name}: {sorted(bad)}")
        self.assertEqual(problems, [], "networking modules imported by application code")


class TestRuntimeGuard(unittest.TestCase):
    def test_guard_blocks_everything(self):
        code = r"""
import netguard; netguard.install()
import socket, _socket, urllib.request, urllib.error
checks = {
  "socket.socket": lambda: socket.socket(),
  "_socket.socket": lambda: _socket.socket(),
  "create_connection": lambda: socket.create_connection(("127.0.0.1", 9), timeout=1),
  "getaddrinfo": lambda: socket.getaddrinfo("example.com", 443),
  "gethostbyname": lambda: socket.gethostbyname("example.com"),
  "socketpair": lambda: socket.socketpair(),
}
for name, fn in checks.items():
    try:
        fn()
        print("NOT BLOCKED", name)
    except netguard.NetworkBlockedError:
        print("blocked", name)
try:
    urllib.request.urlopen("http://127.0.0.1:9/", timeout=1)
    print("NOT BLOCKED urlopen")
except urllib.error.URLError as e:
    print("blocked urlopen" if isinstance(e.reason, netguard.NetworkBlockedError) else f"NOT BLOCKED urlopen {e.reason!r}")
"""
        r = _run(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.split("\n")
        self.assertEqual([l for l in lines if l.startswith("NOT BLOCKED")], [], r.stdout)
        self.assertEqual(sum(l.startswith("blocked") for l in lines), 7, r.stdout)

    def test_main_installs_guard_before_anything_else(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        first_imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        names = [a.name for n in first_imports for a in getattr(n, "names", [])]
        # Only os/sys may come before netguard; netguard.install() must be called at module level.
        self.assertEqual(names[:3], ["os", "sys", "netguard"], names)
        calls = [n for n in tree.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                 and ast.unparse(n.value) == "netguard.install()"]
        self.assertEqual(len(calls), 1)


class TestImportAudit(unittest.TestCase):
    def test_app_does_not_load_web_or_ssl(self):
        code = (APP_IMPORTS + "\nimport sys\n"
                "bad = sorted(m for m in sys.modules if m in {'ssl','_ssl','http.client','urllib.request',"
                "'ftplib','smtplib','xmlrpc.client','socketserver','webbrowser','asyncio','subprocess'})\n"
                "print('LOADED:', bad)")
        r = _run(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("LOADED: []", r.stdout)


class TestSelftestFromSource(unittest.TestCase):
    def test_selftest_passes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "report.txt"
            r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--selftest", str(report)],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
            text = report.read_text(encoding="utf-8")
            self.assertEqual(r.returncode, 0, text + r.stderr)
            self.assertIn("RESULT: PASS", text)
            self.assertIn("PASS  Network kill switch", text)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
