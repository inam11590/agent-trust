"""SSRF Protection and Endpoint URL Validator for AgentTrust Gateway (Step 21).

Protects against:
- Loopback connections (127.0.0.0/8, ::1)
- Private network probes (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Cloud metadata service access (169.254.169.254, metadata.google.internal)
- IPv4-mapped IPv6 bypasses (::ffff:127.0.0.1)
- Non-HTTP(S) schemes (file://, gopher://, ftp://)
- DNS rebinding attacks via IP pre-resolution and verification
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse


class SSRFValidationError(ValueError):
    """Raised when an endpoint URL violates SSRF safety rules."""

    def __init__(self, message: str, code: str = "SSRF_BLOCKED"):
        super().__init__(message)
        self.code = code
        self.message = message


BLOCKED_DOMAINS: Set[str] = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "localhost",
}

# Explicitly prohibited IPv4 networks
PROHIBITED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation / TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation / TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation / TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
]

# Explicitly prohibited IPv6 networks
PROHIBITED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


def is_ip_prohibited(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """
    Check whether an IP address falls into a private, loopback, link-local,
    reserved, or prohibited range.
    """
    # Check if IPv6 is IPv4-mapped (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, "IP address is a loopback address."
    if ip.is_private:
        return True, "IP address is a private network address."
    if ip.is_link_local:
        return True, "IP address is a link-local address."
    if ip.is_multicast:
        return True, "IP address is a multicast address."
    if ip.is_reserved:
        return True, "IP address is reserved."
    if ip.is_unspecified:
        return True, "IP address is unspecified."

    if isinstance(ip, ipaddress.IPv4Address):
        for net in PROHIBITED_IPV4_NETWORKS:
            if ip in net:
                return True, f"IP address {ip} falls into prohibited network {net}."
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in PROHIBITED_IPV6_NETWORKS:
            if ip in net:
                return True, f"IPv6 address {ip} falls into prohibited network {net}."

    return False, None


def resolve_and_validate_endpoint_url(
    url: str,
    allow_private_ips: bool = False,
    enforce_https: bool = True,
) -> Tuple[str, List[str]]:
    """
    Validate an endpoint URL against SSRF vulnerabilities.
    
    Args:
        url: The endpoint URL to validate.
        allow_private_ips: Only allowed in sandbox/testing environments.
        enforce_https: If True, scheme must be https.
        
    Returns:
        (canonical_url, list_of_resolved_ip_strings)
        
    Raises:
        SSRFValidationError: If URL violates any security constraint.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Endpoint URL must be a non-empty string.", code="INVALID_URL")

    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise SSRFValidationError(f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.", code="INVALID_SCHEME")

    if enforce_https and scheme != "https":
        raise SSRFValidationError("Endpoint URL must use HTTPS in production environments.", code="HTTPS_REQUIRED")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Endpoint URL must include a valid hostname.", code="MISSING_HOSTNAME")

    hostname_lower = hostname.lower().strip(".")

    # Reject blocked domain names
    if hostname_lower in BLOCKED_DOMAINS or hostname_lower.endswith(".internal"):
        if not allow_private_ips:
            raise SSRFValidationError(f"Access to domain '{hostname}' is prohibited by SSRF policy.", code="BLOCKED_DOMAIN")

    # If hostname is a literal IP address
    try:
        literal_ip = ipaddress.ip_address(hostname_lower)
        if not allow_private_ips:
            prohibited, reason = is_ip_prohibited(literal_ip)
            if prohibited:
                raise SSRFValidationError(f"Prohibited IP address '{literal_ip}': {reason}", code="PROHIBITED_IP")
        return url.strip(), [str(literal_ip)]
    except (ipaddress.AddressValueError, ValueError) as exc:
        if isinstance(exc, SSRFValidationError):
            raise
        # Not an IP literal, proceed to DNS resolution
        pass

    # Resolve host to IP addresses
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname_lower, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Failed to resolve hostname '{hostname}': {exc}", code="DNS_RESOLUTION_FAILED") from exc

    resolved_ips: List[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not allow_private_ips:
                prohibited, reason = is_ip_prohibited(ip_obj)
                if prohibited:
                    raise SSRFValidationError(
                        f"Resolved IP '{ip_str}' for hostname '{hostname}' is prohibited: {reason}",
                        code="PROHIBITED_IP",
                    )
            resolved_ips.append(str(ip_obj))
        except ValueError:
            continue

    if not resolved_ips:
        raise SSRFValidationError(f"Hostname '{hostname}' did not resolve to any valid IP addresses.", code="DNS_RESOLUTION_FAILED")

    return url.strip(), resolved_ips
