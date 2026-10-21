"""A shop with three deliberately tamperable price surfaces.

* ``/product?price=``  - the price arrives in the query string
* ``/cart``            - hidden ``price`` and ``qty`` inputs, POSTed
* ``/api/pay``         - a JSON-only gateway; form encoding is rejected
* ``/safe``            - a control: the price is fixed server-side

Nothing here is vulnerable by accident. Each route exists to be the
positive or the negative case of one specific assertion.
"""

from __future__ import annotations

import http.server
import json
import urllib.parse

INDEX = b"""<html><body>
<h1>Shop</h1>
<a href="/product?id=1&price=100.00">Widget</a>
<form method="post" action="/cart">
  <input type="hidden" name="price" value="100.00">
  <input type="hidden" name="qty" value="1">
  <button>Add to cart</button>
</form>
<form method="post" action="/api/pay">
  <input type="hidden" name="amount" value="100.00">
  <button>Pay</button>
</form>
<a href="/safe?price=100.00">Fixed-price item</a>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    """Serves the shop. Silent on the console so test output stays readable."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, body: bytes, content_type: str = "text/html") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/product":
            try:
                price = float(query.get("price", ["100"])[0])
            except ValueError:
                price = 100.0
            body = f"<html><body><h1>Widget</h1><p>Price: ${price:.2f}</p></body></html>"
            self._send(body.encode())
            return

        if parsed.path == "/safe":
            # The parameter is ignored entirely: the price is authoritative.
            self._send(b"<html><body><p>Price: $100.00</p></body></html>")
            return

        self._send(INDEX)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode() if length else ""
        parsed = urllib.parse.urlparse(self.path)
        is_json = self.headers.get("Content-Type", "").startswith("application/json")

        if is_json:
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data = {}
        else:
            data = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

        if parsed.path == "/api/pay":
            if not is_json:
                self._send(json.dumps({"error": "json required"}).encode(), "application/json")
                return
            try:
                amount = float(data.get("amount", 100))
            except (TypeError, ValueError):
                amount = 100.0
            self._send(json.dumps({"status": "ok", "total": amount}).encode(), "application/json")
            return

        try:
            price = float(data.get("price", 100))
            qty = float(data.get("qty", 1))
        except (TypeError, ValueError):
            price, qty = 100.0, 1.0
        body = f"<html><body>Cart total: ${price * qty:.2f}</body></html>"
        self._send(body.encode())
