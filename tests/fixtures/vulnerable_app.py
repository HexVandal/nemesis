"""A deliberately vulnerable HTTP application used as a test target.

This is a *test fixture*, not a tool. It exists so the scanner's detection
logic can be tested against known-vulnerable behaviour: every handler here
reproduces a specific CWE, and the comments say which.

Run it with::

    python -m tests.fixtures.vulnerable_app 8899
"""

from __future__ import annotations

import http.server
import sys
import urllib.parse

HOST = "127.0.0.1"
PORT = 8899

PAGES = {
    "/": """<!DOCTYPE html>
<html><head><title>Vulnerable Test App</title></head>
<body>
<h1>Widget Store</h1>
<nav><a href="/products">Products</a> <a href="/search">Search</a>
<a href="/admin">Admin</a> <a href="/admin/">Admin files</a> <a href="/docs">Docs</a>
<a href="/echo?msg=hello">Echo</a> <a href="/redirect?next=/home">Redirect</a>
<a href="/download?file=report.pdf">Download</a> <a href="/cookie">Cookie</a>
<a href="/graphql">GraphQL</a></nav>
<form action="/search" method="GET">
  <input type="text" name="q" placeholder="search">
  <input type="hidden" name="page" value="1">
  <input type="submit" value="Go">
</form>
<form action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
</body></html>""",
    "/products": """<html><body><h1>Products</h1>
<a href="/product?id=1">Widget</a> <a href="/product?id=2">Gadget</a>
<a href="/product?id=3">Doohickey</a>
</body></html>""",
    "/docs": """<html><body><h1>Docs</h1><p>Nothing secret here.</p>
<a href="/download?file=report.pdf">download</a></body></html>""",
}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *args):  # silence
        pass

    # -- helpers ---------------------------------------------------------
    def _send(self, body: str, status: int = 200, content_type: str = "text/html",
              extra_headers: dict | None = None, raw: bool = False):
        if isinstance(body, bytes):
            payload = body
        else:
            payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # Deliberately missing HSTS, CSP, X-Content-Type-Options, Referrer-Policy
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def handle_one_request(self):
        """Survive a client that hangs up mid-response.

        A scanner closes connections it does not need - a request
        smuggling probe does it deliberately. The fixture is a test
        target, not a production server, so it prints nothing and
        carries on.
        """
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _params(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        raw = parsed.query
        if self.command == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))

    # -- routing ---------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        params = self._params()

        if path in PAGES:
            self._send(PAGES[path])

        elif path == "/search":
            # CWE-89: the query is concatenated into SQL and the DB error leaks.
            q = params.get("q", "")
            if "'" in q:
                self._send(
                    "<html><body><h1>Error</h1><p>You have an error in your SQL "
                    "syntax near &#39;" + q.replace("'", "") + "&#39;</p>"
                    "<pre>Warning: mysql_fetch_array(): supplied argument is not a "
                    "valid MySQL result resource in /var/www/html/search.php on line 42</pre>"
                    "</body></html>",
                    status=500,
                )
            else:
                self._send(f"<html><body><h1>Results for {q}</h1></body></html>")

        elif path == "/echo":
            # CWE-79: the parameter is reflected into HTML with no encoding.
            q = params.get("msg", "")
            self._send(f"<html><body><h1>Message</h1><p>{q}</p></body></html>")

        elif path == "/download":
            # CWE-22: the file name is used to build a path.
            name = params.get("file", "")
            if ".." in name or name.startswith("/etc/"):
                try:
                    with open("/etc/passwd", "rb") as handle:
                        self._send(handle.read(), raw=True, content_type="text/plain")
                except OSError:
                    self._send("not found", status=404)
            else:
                self._send(f"file {name} not found", status=404)

        elif path == "/redirect":
            # CWE-601: unvalidated redirect target.
            target = params.get("next", "/")
            self._send("", status=302, extra_headers={"Location": target})

        elif path == "/admin":
            # CWE-209: a stack trace is rendered into the page.
            self._send(
                "<html><body><h1>Internal Server Error</h1>"
                "<pre>Traceback (most recent call last):\n"
                '  File "/var/www/html/admin/index.py", line 88, in handler\n'
                "    user = current_user\n"
                "KeyError: 'session_id'\n"
                "During handling of the above exception, another exception occurred:\n"
                "ValueError: invalid configuration at /opt/app/settings.py</pre>"
                "</body></html>",
                status=500,
            )

        elif path == "/product":
            # CWE-639: the object is returned without an ownership check.
            product_id = params.get("id", "1")
            self._send(
                f"<html><body><h1>Product {product_id}</h1>"
                f"<p>Owner: user{product_id}@internal-corp.local</p>"
                f"<p>Cost: 19.99</p></body></html>"
            )

        elif path == "/cookie":
            # CWE-614: cookie without Secure / HttpOnly / SameSite.
            self._send(
                "<html><body>ok</body></html>",
                extra_headers={"Set-Cookie": "sessionid=abc123def456; Path=/"},
            )

        elif path == "/redirect-to":
            self._send("", status=302, extra_headers={"Location": "/"})

        elif path == "/.git/HEAD":
            self._send("ref: refs/heads/main\n")

        elif path == "/.env":
            self._send(
                "DEBUG=True\nDATABASE_URL=postgres://admin:hunter2@db.internal:5432/app\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                content_type="text/plain",
            )

        elif path == "/admin/":
            self._send(
                "<html><body><h1>Index of /admin</h1><pre>"
                "  <a href=\"../\">../</a>\n  <a href=\"config.php\">config.php</a>\n"
                "  <a href=\"backup.sql\">backup.sql</a>\n"
                "</pre></body></html>"
            )

        elif path == "/graphql":
            self._send(
                '{"data":{"__schema":{"types":[{"name":"User"},{"name":"Secret"}]}}}',
                content_type="application/json",
            )

        else:
            self._send("<html><body><h1>404 Not Found</h1></body></html>", status=404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        params = self._params()

        if path == "/login":
            # CWE-79: the username is reflected unescaped after a failed login.
            username = params.get("username", "")
            self._send(
                f"<html><body><p>Invalid username or password for {username}</p>"
                "<form action='/login' method='POST'>"
                "<input name='username'><input type='password' name='password'>"
                "</form></body></html>"
            )
        else:
            self._send("<html><body><h1>404 Not Found</h1></body></html>", status=404)


def serve(port: int = PORT) -> None:
    # Threaded: a scanner that desynchronises a connection on purpose
    # must not be able to block every other request.
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    with http.server.ThreadingHTTPServer((HOST, port), Handler) as httpd:
        print(f"vulnerable test app on http://{HOST}:{port}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else PORT)
