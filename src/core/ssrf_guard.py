"""
AgentShield SSRF & Network Egress Guard
Protects against Server-Side Request Forgery by blocking loopback, RFC-1918 private subnets,
cloud instance metadata endpoints (169.254.169.254 / fd00:ec2::254), hex/octal/decimal IP encodings,
and IPv4-mapped IPv6 evasions.
"""

import ipaddress
import socket
import re
from urllib.parse import urlparse
from typing import Tuple, List

# Standard Denied Networks (IPv4 & IPv6)
DENIED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # Cloud Provider Instance Metadata (AWS, Azure, GCP, DigitalOcean, Oracle)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"), # AWS IMDSv6
    # RFC 1918 Private IPv4 Networks
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Carrier Grade NAT & Special Use
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"), # Reserved
]

LOCAL_DOMAIN_SUFFIXES = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
)

class SSRFSecurityViolation(Exception):
    """Raised when an outbound URL violates SSRF security egress policy."""
    pass

class SSRFGuard:
    @staticmethod
    def parse_candidate_ip(host_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Attempts to parse raw IP, decimal, hex, or octal IP representations."""
        host_clean = host_str.strip("[]").strip()
        
        # 1. Standard IP string parse
        try:
            return ipaddress.ip_address(host_clean)
        except ValueError:
            pass

        # 2. Hex notation (e.g., 0x7f000001)
        if host_clean.lower().startswith("0x"):
            try:
                num = int(host_clean, 16)
                return ipaddress.ip_address(num)
            except ValueError:
                pass

        # 3. Decimal integer notation (e.g., 2130706433)
        if host_clean.isdigit():
            try:
                num = int(host_clean, 10)
                return ipaddress.ip_address(num)
            except ValueError:
                pass

        # 4. Octal or mixed dotted notation (e.g., 0177.0.0.1)
        parts = host_clean.split(".")
        if len(parts) == 4:
            try:
                nums = []
                for p in parts:
                    if p.startswith("0x") or p.startswith("0X"):
                        nums.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1:
                        nums.append(int(p, 8))
                    else:
                        nums.append(int(p, 10))
                packed_ip = ".".join(str(n) for n in nums)
                return ipaddress.ip_address(packed_ip)
            except (ValueError, OverflowError):
                pass

        return None

    @classmethod
    def is_safe_ip(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> Tuple[bool, str]:
        """Evaluates whether an IP address belongs to an authorized public range."""
        try:
            if isinstance(ip_obj, str):
                parsed = cls.parse_candidate_ip(ip_obj)
                if parsed is None:
                    return False, f"Invalid IP address format: {ip_obj}"
                ip = parsed
            else:
                ip = ip_obj

            # If IPv6 mapped IPv4 address (e.g. ::ffff:127.0.0.1), check embedded IPv4
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                return cls.is_safe_ip(ip.ipv4_mapped)

            for net in DENIED_NETWORKS:
                if ip.version == net.version and ip in net:
                    return False, f"Target IP {ip} falls within forbidden range {net}."
            
            return True, "IP is safe and public."
        except Exception as e:
            return False, f"Error evaluating IP {ip_obj}: {str(e)}"

    @classmethod
    def is_safe_url(cls, url: str) -> Tuple[bool, str]:
        """
        Parses a URL, resolves its hostname to IP addresses,
        and checks all resolved IPs against forbidden subnets.
        """
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string."

        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported URL scheme: {parsed.scheme}. Only HTTP/HTTPS allowed."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL lacks a valid hostname."

        lower_host = hostname.lower()

        # Check local domain names immediately
        if lower_host == "localhost" or any(lower_host.endswith(sfx) for sfx in LOCAL_DOMAIN_SUFFIXES):
            return False, f"Hostname '{hostname}' matches local or internal domain policy."

        # Check IP literal (standard, hex, octal, decimal, IPv6)
        direct_ip = cls.parse_candidate_ip(hostname)
        if direct_ip is not None:
            return cls.is_safe_ip(direct_ip)

        # Resolve DNS hostnames
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                return False, f"DNS resolution failed for host: {hostname}"

            for family, _, _, _, sockaddr in addr_info:
                ip_resolved = sockaddr[0]
                safe, reason = cls.is_safe_ip(ip_resolved)
                if not safe:
                    return False, f"DNS for {hostname} resolved to forbidden IP {ip_resolved} ({reason})"

            return True, f"Hostname {hostname} resolved to valid public IP(s)."
        except socket.gaierror as e:
            return False, f"DNS resolution error for {hostname}: {e}"

    @classmethod
    def assert_safe_url(cls, url: str) -> None:
        """Raises SSRFSecurityViolation if the URL fails SSRF safety checks."""
        safe, reason = cls.is_safe_url(url)
        if not safe:
            raise SSRFSecurityViolation(f"SSRF Violation: {reason}")
