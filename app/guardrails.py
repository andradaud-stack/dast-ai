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

            star_idx = p_clean.find("*")
            prefix = p_clean[:star_idx]
            suffix = p_clean[star_idx + 1:]

            if prefix and not host_clean.startswith(prefix):
                continue
            if suffix and not host_clean.endswith(suffix):
                continue

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

    if not url or any(c in url for c in (" ", "\t", "\r", "\n")):
        raise TargetNotAllowed("URL tidak valid.")

    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetNotAllowed("URL tidak valid.")

    if p.username or p.password or "@" in (p.netloc.split(":")[0]):
        raise TargetNotAllowed("URL mengandung userinfo atau format ambigu yang dilarang.")

    try:
        port = p.port
    except ValueError:
        raise TargetNotAllowed("Port URL di luar rentang valid.")

    if port is not None and not (1 <= port <= 65535):
        raise TargetNotAllowed("Port URL di luar rentang valid.")

    hostname = p.hostname.rstrip(".").lower()
    if not is_host_allowed(hostname, settings.allowed_hosts):
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak ada di allowlist.")

    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise TargetNotAllowed(f"Gagal me-resolve host '{p.hostname}': {e}")

    if not addr_info:
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak menghasilkan alamat IP.")

    for info in addr_info:
        ip = ipaddress.ip_address(info[4][0])

        if _is_ip_in_blocked_networks(ip):
            raise TargetNotAllowed(f"Host '{p.hostname}' resolve ke alamat link-local/cloud metadata ({ip}).")

        if ip.is_multicast or (ip.is_reserved and not ip.is_loopback):
            raise TargetNotAllowed(f"Host '{p.hostname}' resolve ke IP reserved/multicast ({ip}).")

        if settings.require_private_ip:
            if not (ip.is_private or ip.is_loopback):
                raise TargetNotAllowed(f"{p.hostname} resolve ke IP publik ({ip}).")
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
    Satu fungsi acuan scope builder yang strictly anchored.
    Digunakan secara konsisten untuk:
    - Context inclusion ZAP
    - ZAP Replacer header URL isolation
    - Validasi URL hasil crawling (spider & core)
    - Validasi redirect dan URL target lanjutan.
    """
    p = urlparse(target_url)
    scheme = p.scheme.lower()
    hostname = (p.hostname or "").lower()

    if p.port:
        port_regex = f":{p.port}"
    else:
        default_port = 443 if scheme == "https" else 80
        # Diizinkan tanpa port atau dengan default port eksplisit (:80 atau :443)
        port_regex = f"(?::{default_port})?"

    escaped_scheme = re.escape(scheme)
    escaped_host = re.escape(hostname)

    return f"^{escaped_scheme}://{escaped_host}{port_regex}(?:/.*)?$"


def is_url_in_scope(url: str, target_url: str) -> bool:
    """
    Memeriksa apakah URL target/redirect/crawler berada dalam scope yang diotorisasi.
    Menggunakan regex berjangkar yang sama persis dengan aturan konteks ZAP.
    """
    if not url or not isinstance(url, str):
        return False
    url_clean = url.strip()
    regex_str = build_zap_scope_regex(target_url)
    return bool(re.match(regex_str, url_clean))
