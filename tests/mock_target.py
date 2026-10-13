#!/usr/bin/env python3
"""Target web application mockup sederhana untuk pengujian integrasi DAST di CI/CD."""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif self.path == "/api/items":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"items": [{"id": 1, "name": "sample_item"}]}')
        elif self.path == "/about":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>About Us</h1><p>Mock target application.</p></body></html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><body><h1>Home</h1><a href="/about">About</a> <a href="/api/items">Items</a></body></html>'
            )

    def log_message(self, format: str, *args: object) -> None:
        # Menjaga log konsol tetap bersih selama CI scan
        pass


def run() -> None:
    server = HTTPServer(("127.0.0.1", PORT), TargetHandler)
    print(f"Mock target app running at http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
