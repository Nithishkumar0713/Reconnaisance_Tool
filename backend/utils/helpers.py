"""
Input validation and DNS resolution helpers.
This file checks if user input is a valid domain/IP, and resolves
domain names to IP addresses using multiple DNS methods as fallbacks.
"""

import asyncio
import ipaddress
import re
import socket
import dns.resolver
import dns.exception

from utils.concurrency import PRIORITY_DNS_SEMAPHORE

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_input(target: str) -> dict:
    """
    Checks if the user's input is a valid IP address or domain name.
    Returns a dict like {"valid": True, "type": "domain"} or {"valid": False, "error": "..."}
    """
    if not target:
        return {"valid": False, "error": "Target cannot be empty"}

    target = re.sub(r"^https?://", "", target)
    target = target.rstrip("/")

    try:
        ipaddress.ip_address(target)
        return {"valid": True, "type": "ip"}
    except ValueError:
        pass

    segments = target.split(".")
    if len(segments) >= 2 and all(seg.isdigit() for seg in segments):
        if len(segments) != 4:
            return {
                "valid": False,
                "error": f"'{target}' is not a valid IP address — expected 4 dot-separated numbers, got {len(segments)}.",
            }
        bad_octet = next((seg for seg in segments if int(seg) > 255), None)
        if bad_octet:
            return {
                "valid": False,
                "error": f"'{target}' is not a valid IP address — '{bad_octet}' is out of range (must be 0-255).",
            }
        return {"valid": False, "error": f"'{target}' is not a valid IP address."}

    if DOMAIN_REGEX.match(target):
        return {"valid": True, "type": "domain"}

    return {"valid": False, "error": f"'{target}' is not a valid IP or domain"}


async def _resolve_with_nslookup(target: str, is_ip: bool = False) -> str | None:
    """
    Uses the command-line 'nslookup' tool as a fallback DNS resolver.
    This is useful when Python's DNS libraries fail but the OS can still resolve.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "nslookup", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return None

        output = stdout.decode("utf-8", errors="ignore")

        if is_ip:
            for line in output.splitlines():
                if "name:" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) >= 2:
                        return parts[1].strip()
        else:
            lines = output.splitlines()
            answer_started = False
            for line in lines:
                line_lower = line.lower()
                if "name:" in line_lower:
                    answer_started = True
                    continue
                if answer_started:
                    if "address:" in line_lower:
                        parts = line.split(":", 1)
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val and not val.startswith("::") and not val.startswith("127."):
                                return val
                    elif "addresses:" in line_lower:
                        parts = line.split(":", 1)
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            tokens = val.split()
                            return tokens[0] if tokens else None
    except Exception:
        pass
    return None


async def resolve_target(target: str) -> dict:
    """
    Resolves a domain to its IP address using multiple methods as fallbacks:
      1. Python's dnspython library (default DNS)
      2. Google (8.8.8.8) and Cloudflare (1.1.1.1) public DNS
      3. OS-level socket resolution
    
    Returns a dict with the IP, whether it's a domain, and hostname info.
    If ALL methods fail, returns IP as None (scan continues for domain-only checks).
    """
    target = re.sub(r"^https?://", "", target).rstrip("/")

    try:
        ipaddress.ip_address(target)
        return {"ip": target, "is_domain": False, "hostname": None}
    except ValueError:
        pass

    loop = asyncio.get_event_loop()

    def _resolve_dns():
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0
        
        try:
            answers = resolver.resolve(target, "A")
            if answers:
                return str(answers[0])
        except Exception:
            pass

        try:
            answers = resolver.resolve(target, "AAAA")
            if answers:
                return str(answers[0])
        except Exception:
            pass

        try:
            fallback = dns.resolver.Resolver(configure=False)
            fallback.nameservers = ["8.8.8.8", "1.1.1.1"]
            fallback.timeout = 4.0
            fallback.lifetime = 4.0
            answers = fallback.resolve(target, "A")
            if answers:
                return str(answers[0])
        except Exception:
            pass

        try:
            fallback = dns.resolver.Resolver(configure=False)
            fallback.nameservers = ["8.8.8.8", "1.1.1.1"]
            fallback.timeout = 4.0
            fallback.lifetime = 4.0
            answers = fallback.resolve(target, "AAAA")
            if answers:
                return str(answers[0])
        except Exception:
            pass

        try:
            return socket.gethostbyname(target)
        except Exception:
            pass

        return None

    # Gated by the small, high-priority DNS concurrency pool (see
    # PRIORITY_DNS_SEMAPHORE), never the large bulk pool — a failure here
    # is the single highest-blast-radius failure mode in the whole scan
    # (every IP-dependent module inherits "no IP"), so it should never be
    # queued behind an unrelated flood of subdomain-resolution traffic.
    async with PRIORITY_DNS_SEMAPHORE:
        resolved_ip = await loop.run_in_executor(None, _resolve_dns)

    return {
        "ip": resolved_ip,
        "is_domain": True,
        "hostname": target,
        "primary_resolver_ip": resolved_ip,
        "nslookup_resolver_ip": None,
    }


def classify_non_public_ip(ip_str: str) -> str | None:
    """
    Returns a short reason string ("loopback address", "link-local address",
    "private/internal address") if ip_str is a non-globally-routable IP —
    RFC 1918 private space, loopback, link-local/APIPA (including the
    169.254.169.254 cloud metadata endpoint), or Carrier-Grade NAT. Returns
    None if it's a genuinely public IP, or if ip_str isn't a valid IP at all
    (callers should validate that separately via is_valid_input).

    Shared by module_batch.py (multi-target checks) and main.py (single-target
    checks) so both paths reject the same ranges the same way, for modules
    where a private IP is either meaningless or a real SSRF-style risk.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if ip_obj.is_global:
        return None
    if ip_obj.is_loopback:
        return "loopback address"
    if ip_obj.is_link_local:
        return "link-local address"
    return "private/internal address"


def clean_domain(target: str) -> str:
    """Removes http/https prefix and trailing slashes, converts to lowercase."""
    return re.sub(r"^https?://", "", target).rstrip("/").lower()


def get_safe_ssl_context():
    """
    Creates an SSL context that skips certificate verification.
    Used when scanning sites with self-signed or invalid certs —
    we still want to connect and inspect, not get blocked by SSL errors.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_relaxed_ssl_context():
    """
    Like get_safe_ssl_context(), but also lowers OpenSSL's own security
    level (SECLEVEL) so the handshake itself doesn't get refused on legacy
    servers — e.g. a 1024-bit DH key, which modern OpenSSL (SECLEVEL 1+)
    rejects outright with DH_KEY_TOO_SMALL before any certificate is even
    considered. Verified directly against a real target (pramani.cdac.in):
    Python's default ssl context refuses the handshake, while curl on this
    machine (Windows Schannel backend, not OpenSSL) connects fine — proving
    the site is genuinely reachable, just not to a strict-by-default OpenSSL
    client. `openssl s_client -cipher "ALL:@SECLEVEL=0"` reproduces that same
    tolerant behavior manually and confirms the 1024-bit DH key as the cause.
    Intended only as an explicit, narrowly-scoped fallback after a strict
    attempt fails for this reason — never the first attempt — so the
    resulting security gap gets reported, not silently hidden.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx

