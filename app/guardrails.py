import fnmatch
import ipaddress
import socket
from urllib.parse import urlparse

from .config import settings


class TargetNotAllowed(Exception):
    pass


DANGEROUS_WILDCARDS = {
    "*", "*.*", "*.com", "*.org", "*.net", "*.edu", "*.gov",
    "*.io", "*.app", "*.dev", "*.co", "*.xyz", "*.info",
}


def is_host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
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

        if host_clean == p_clean or fnmatch.fnmatch(host_clean, p_clean):
            return True
    return False


METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
}


def assert_target_allowed(url: str) -> None:
    """Gerbang keamanan: dipanggil SEBELUM scan apa pun dimulai."""
    if settings.environment not in ("local", "staging"):
        raise TargetNotAllowed("ENVIRONMENT harus 'local' atau 'staging'.")

    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetNotAllowed("URL tidak valid.")

    hostname = p.hostname.rstrip(".").lower()
    if not is_host_allowed(hostname, settings.allowed_hosts):
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak ada di allowlist.")

    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise TargetNotAllowed(f"Gagal me-resolve host '{p.hostname}': {e}")

    for info in addr_info:
        ip = ipaddress.ip_address(info[4][0])

        # 1. Selalu blokir Cloud Metadata IP & Link-Local (SSRF protection)
        if ip in METADATA_IPS or ip.is_link_local:
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
            is_local_host = hostname in ("localhost", "127.0.0.1") or hostname.endswith(".local") or hostname.endswith(".internal")
            if not is_local_host and (ip.is_private or ip.is_loopback):
                raise TargetNotAllowed(
                    f"Potensi DNS Rebinding/SSRF: host eksternal '{p.hostname}' me-resolve ke IP privat/loopback ({ip})."
                )

