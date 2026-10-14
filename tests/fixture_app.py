import http.server
import json
import threading
from typing import ClassVar


class FixtureState:
    destructive_called: bool = False
    destructive_hits: list[str] = []

    @classmethod
    def reset(cls):
        cls.destructive_called = False
        cls.destructive_hits = []


class VulnerableFixtureHandler(http.server.BaseHTTPRequestHandler):
    """
    Server pengujian lokal terkontrol yang menyediakan rute dengan:
    - Missing security headers (X-Frame-Options, CSP, X-Content-Type-Options)
    - Tautan crawlable (/about, /api/public, /login)
    - Endpoint terlindungi autentikasi (/admin/secret)
    - Simulasi proteksi Vercel (/vercel-demo)
    - Redirect ke luar scope (/external-redirect)
    - Endpoint kontrol destruktif (/delete-account, /reset-db)
    """

    server_version = "FixtureApp/1.0"

    def log_message(self, format, *args):
        # Mute logging default agar output test bersih
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        # 1. Endpoint kontrol destruktif
        if path in ("/delete-account", "/reset-db", "/destroy-data"):
            FixtureState.destructive_called = True
            FixtureState.destructive_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "DESTRUCTIVE_ACTION_TRIGGERED"}')
            return

        # 2. Redirect ke luar scope
        if path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "https://out-of-scope.example.com/unauthorized")
            self.end_headers()
            return

        # 3. Rute terlindungi HTTP Auth
        if path.startswith("/admin"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Admin Access"')
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized admin area"}')
            return

        # 4. Simulasi Vercel Deployment Protection
        if path == "/vercel-demo":
            # Periksa apakah request mengirim bypass secret yang benar
            bypass = self.headers.get("x-vercel-protection-bypass")
            if bypass == "valid-vercel-secret-key":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Vercel Bypass Success</h1></body></html>")
                return

            self.send_response(401)
            self.send_header("x-vercel-challenge", "true")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Vercel Deployment Protection Authentication Required</body></html>")
            return

        # 5. Endpoint API Publik
        if path == "/api/public":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "items": ["data1", "data2"]}')
            return

        # 6. Halaman About
        if path == "/about":
            self.send_response(200)
            # Sengaja TIDAK mengirimkan security headers (X-Frame-Options, CSP, X-Content-Type-Options)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>About Us</h1><p>Halaman pengujian tanpa security headers.</p></body></html>"
            )
            return

        # 7. Halaman Login
        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b'<html><body><form action="/login" method="POST">'
                b'<input name="username" type="text">'
                b'<input name="password" type="password">'
                b'<button type="submit">Login</button>'
                b"</form></body></html>"
            )
            return

        # 8. Halaman Utama (Index dengan crawlable links)
        self.send_response(200)
        # Sengaja tidak ada X-Frame-Options atau CSP
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = (
            "<!DOCTYPE html><html><head><title>DAST Test Fixture</title></head><body>"
            "<h1>Selamat datang di DAST Fixture App</h1>"
            "<ul>"
            '<li><a href="/about">About Page</a></li>'
            '<li><a href="/api/public">Public API</a></li>'
            '<li><a href="/login">Login Area</a></li>'
            '<li><a href="/admin/secret">Protected Admin Area</a></li>'
            '<li><a href="/vercel-demo">Vercel Demo</a></li>'
            '<li><a href="/external-redirect">External Redirect</a></li>'
            '<li><a href="/delete-account">Delete Account (Destructive Control)</a></li>'
            "</ul>"
            "</body></html>"
        )
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        # Menerima form login dummy
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message": "POST received"}')


class FixtureServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server = http.server.ThreadingHTTPServer((host, port), VulnerableFixtureHandler)
        self.host = host
        self.port = self.server.server_port
        self.base_url = f"http://{host}:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        FixtureState.reset()
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
