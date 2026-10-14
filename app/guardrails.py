import fnmatch
import ipaddress
import socket
from urllib.parse import urlparse

from .config import settings


class TargetNotAllowed(Exception):
    pass


def is_host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host_lower = hostname.lower()
    for pattern in allowed_hosts:
        p_clean = pattern.strip().lower()
        if not p_clean or p_clean == "*":
            # Menolak wildcard tunggal '*' untuk mencegah pembukaan scope tanpa batas
            continue
        if host_lower == p_clean or fnmatch.fnmatch(host_lower, p_clean):
            return True
    return False


def assert_target_allowed(url: str) -> None:
    """Gerbang keamanan: dipanggil SEBELUM scan apa pun dimulai."""
    if settings.environment not in ("local", "staging"):
        raise TargetNotAllowed("ENVIRONMENT harus 'local' atau 'staging'.")

    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetNotAllowed("URL tidak valid.")
    if not is_host_allowed(p.hostname, settings.allowed_hosts):
        raise TargetNotAllowed(f"Host '{p.hostname}' tidak ada di allowlist.")

    if settings.require_private_ip:
        try:
            addr_info = socket.getaddrinfo(p.hostname, None)
        except socket.gaierror as e:
            raise TargetNotAllowed(f"Gagal me-resolve host '{p.hostname}': {e}")
        for info in addr_info:
            ip = ipaddress.ip_address(info[4][0])
            if not (ip.is_private or ip.is_loopback):
                raise TargetNotAllowed(f"{p.hostname} resolve ke IP publik ({ip}).")
