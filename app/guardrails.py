import fnmatch
import ipaddress
import re
import socket
from urllib.parse import urlparse

from .config import settings

# Jaringan terlarang (SSRF & Cloud Metadata Protection)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),       # IPv4 Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-local
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("ff00::/8"),             # IPv6 Multicast
    ipaddress.ip_network("0.0.0.0/8"),            # Broadcast / Current network
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
]

METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
}

DANGEROUS_WILDCARDS = {
    "*", "*.*", "*.com", "*.org", "*.net", "*.edu", "*.gov",
    "*.io", "*.app", "*.dev", "*.co", "*.xyz", "*.info",
}


class TargetNotAllowed(Exception):
    pass


def _is_ip_in_blocked_networks(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Memeriksa apakah IP termasuk link-local, cloud metadata, atau multicast terlarang."""
    if ip in METADATA_IPS or ip.is_link_local:
        return True
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def is_host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    """
    Pencocokan allowlist ketat dengan proteksi wildcard TLD luas:
    - Menolak wildcard berbahaya seperti '*', '*.com', '*.app'
    - Memvalidasi domain wildcard dan memastikan isolasi scope domain
    """
    host_clean = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        p_clean = pattern.strip().rstrip(".").lower()
        if not p_clean:
            continue
        # Tolak wildcard berbahaya atau terlalu luas (misal '*', '*.com')
        if p_clean in DANGEROUS_WILDCARDS:
            continue
        # Jika mengandung '*', pastikan memiliki setidaknya 2 segmen non-wildcard (mis. *.vercel.app)
        if "*" in p_clean:
            parts = p_clean.split(".")
            non_wildcards = [part for part in parts if "*" not in part]
            if len(non_wildcards) < 2:
                continue

            # Validasi batas domain agar tidak mencocokkan across domain boundary
            # Contoh: design-log-*.vercel.app tidak boleh cocok dengan other.vercel.app atau design-log.evil.com
            star_idx = p_clean.find("*")
            prefix = p_clean[:star_idx]
            suffix = p_clean[star_idx + 1:]

            if prefix and not host_clean.startswith(prefix):
                continue
            if suffix and not host_clean.endswith(suffix):
                continue

            # Subdomain dalam wildcard tidak boleh mengandung titik tambahan jika pola adalah 1 level
            mid = host_clean[len(prefix): len(host_clean) - len(suffix)] if suffix else host_clean[len(prefix):]
            if "." in mid:
                continue

            if fnmatch.fnmatch(host_clean, p_clean):
                return True
        else:
            if host_clean == p_clean:
                return True

    return False


def assert_target_allowed(url: str) -> None:
    """Gerbang keamanan: dipanggil SEBELUM scan apa pun dimulai."""
    if settings.environment not in ("local", "staging"):
        raise TargetNotAllowed("ENVIRONMENT harus 'local' atau 'staging'.")

    # Mencegah URL ambigu atau bypass whitespace
    if not url or any(c in url for c in (" ", "\t", "\r", "\n")):
        raise TargetNotAllowed("URL tidak valid.")

    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetNotAllowed("URL tidak valid.")

    # Tolak userinfo (misal http://user:pass@host) untuk mencegah URL parser confusion
    if p.username or p.password or "@" in (p.netloc.split(":")[0]):
        raise TargetNotAllowed("URL mengandung userinfo atau format ambigu yang dilarang.")

    # Validasi port
    try:
        port = p.port
    except ValueError:
        raise TargetNotAllowed("Port URL di luar rentang valid.")

    if port is not None and not (1 <= port <= 65535):
        raise TargetNotAllowed("Port URL di luar rentang valid.")

    hostname = p.hostname.rstrip(".").lower()
    if not is_host_allowed(hostname, settings.allowed_hosts):
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak ada di allowlist.")

    # Validasi DNS & SSRF protection
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise TargetNotAllowed(f"Gagal me-resolve host '{p.hostname}': {e}")

    if not addr_info:
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak menghasilkan alamat IP.")

    for info in addr_info:
        ip = ipaddress.ip_address(info[4][0])

        # 1. Selalu blokir Cloud Metadata IP & Link-Local (SSRF protection)
        if _is_ip_in_blocked_networks(ip):
            raise TargetNotAllowed(f"Host '{p.hostname}' resolve ke alamat link-local/cloud metadata ({ip}).")

        # 2. Selalu blokir Multicast dan Reserved (kecuali loopback sah)
        if ip.is_multicast or (ip.is_reserved and not ip.is_loopback):
            raise TargetNotAllowed(f"Host '{p.hostname}' resolve ke IP reserved/multicast ({ip}).")

        # 3. Mode REQUIRE_PRIVATE_IP: hanya izinkan IP private dan loopback
        if settings.require_private_ip:
            if not (ip.is_private or ip.is_loopback):
                raise TargetNotAllowed(f"{p.hostname} resolve ke IP publik ({ip}).")

        # 4. Mode REQUIRE_PRIVATE_IP=False (misal Vercel Preview): cegah DNS Rebinding
        # Jika hostname adalah domain publik eksternal (bukan localhost/internal), jangan izinkan resolve ke private/loopback
        else:
            is_local_host = (
                hostname in ("localhost", "127.0.0.1")
                or hostname.endswith(".local")
                or hostname.endswith(".internal")
            )
            if not is_local_host and (ip.is_private or ip.is_loopback):
                raise TargetNotAllowed(
                    f"Potensi DNS Rebinding/SSRF: host eksternal '{p.hostname}' me-resolve ke IP privat/loopback ({ip})."
                )


def build_zap_scope_regex(target_url: str) -> str:
    """
    Membuat regex konteks ZAP yang strictly anchored.
    Mencegah http://example.com mencocokkan http://example.com.attacker.com.
    """
    p = urlparse(target_url)
    scheme = re.escape(p.scheme)
    hostname = re.escape(p.hostname.lower() if p.hostname else "")
    port_part = f":{p.port}" if p.port else r"(?::\d+)?"
    path_prefix = re.escape(p.path.rstrip("/")) if p.path and p.path != "/" else ""

    return f"^{scheme}://{hostname}{port_part}{path_prefix}(?:/.*)?$"


def is_url_in_scope(redirect_url: str, original_target: str) -> bool:
    """Memeriksa apakah redirect URL masih dalam host/port yang diotorisasi."""
    orig = urlparse(original_target)
    redir = urlparse(redirect_url)

    if redir.scheme not in ("http", "https"):
        return False

    if orig.scheme != redir.scheme:
        return False

    orig_host = (orig.hostname or "").lower()
    redir_host = (redir.hostname or "").lower()
    if orig_host != redir_host:
        return False

    orig_port = orig.port or (443 if orig.scheme == "https" else 80)
    redir_port = redir.port or (443 if redir.scheme == "https" else 80)
    return orig_port == redir_port
