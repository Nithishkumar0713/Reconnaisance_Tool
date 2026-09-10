"""
Timeout settings and error handling utilities.
Every scanner module has a max time limit — if it takes too long, it's stopped.
This prevents one slow module from blocking the entire scan.
"""

import asyncio
import socket
import ssl as ssl_mod
from typing import Any, Coroutine

TIMEOUTS = {
    "dns": 60,
    "whois": 45,
    "ssl": 45,
    "geo_ip": 30,
    "http_headers": 45,
    # Bumped 45->90: web_tech's aiohttp phase (<=30s) is now followed by a
    # headless-browser pass reading JS-runtime version signals
    # (_JS_DETECTION_TIMEOUT=25s, raised from 15s after a real 5-concurrent-
    # deep-scan burst measured real page loads taking longer than that under
    # genuine DNS/CPU contention from the scan's own other modules) plus a
    # second catalog-match pass (_CATALOG_MATCH_HARD_TIMEOUT=12s) — see
    # modules/web_tech.py. 90s comfortably covers that worst-case sequential
    # total with margin, and is still far under the modules that actually
    # dominate a deep/detailed scan's wall time (subdomains,
    # port_scan_detailed, virustotal below).
    "web_tech": 90,
    "subdomains": 360,
    # Bumped 30->45 alongside shodan below: both are a single external
    # HTTP call with their own internal concurrency cap (Semaphore(5) here,
    # Semaphore(3) for shodan) rather than VirusTotal's strict proactive
    # pacing, so they were never queue-starved the way VT was, but still
    # produced genuine timeouts under real concurrent load even with a
    # retry. 45s matches the budget already given to comparable
    # single-external-call modules (ssl, http_headers, web_tech,
    # cloud_provider) rather than singling these two out as tighter.
    "abuseipdb": 45,
    # reputation.py proactively paces VirusTotal calls to a real 16s minimum
    # spacing, process-wide (see _vt_wait_for_slot) — under concurrent load
    # a call can spend real time simply queued for its turn before the
    # actual request even starts, and that wait counts against this same
    # timeout. 120s comfortably covers the worst realistic case for this
    # app's concurrency ceilings.
    "virustotal": 120,
    "shodan": 45,
    "email_harvester": 30,
    "cloud_provider": 45,
    "waf_detect": 60,
    "cms_fingerprint": 60,
    "email_gather": 180,
    "http_availability": 45,

    "port_scan_fast": 120,
    "port_scan_detailed": 300,
    "port_scan_full": 900,
    "directories": 180,
    "reverse_dns": 30,

    "port_probe": 3.0,
    "banner_grab": 4.0,
    "http_request": 30,
    "dns_query": 20,
}


class ScanError:
    """
    Standard error code constants used across all modules.
    Instead of random error strings, we use these consistent codes
    so the frontend can show appropriate icons and messages.
    """
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    FIREWALL_FILTERED = "firewall_filtered"
    SERVER_DISCONNECTED = "server_disconnected"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    SSL_HANDSHAKE_FAILED = "ssl_handshake_failed"
    API_KEY_MISSING = "api_key_missing"
    API_RATE_LIMITED = "api_rate_limited"
    API_UNREACHABLE = "api_unreachable"
    NOT_FOUND = "not_found"
    UNAUTHORIZED = "unauthorized"
    INVALID_RESPONSE = "invalid_response"
    UNKNOWN_ERROR = "unknown_error"
    INVALID_TARGET = "invalid_target"


def error_response(code: str, message: str, **details) -> dict:
    """Creates a standardized error dict that the frontend knows how to display."""
    return {"status": "error", "error_code": code, "error_message": message, **details}


def skip_response(reason: str, **details) -> dict:
    """Creates a 'skipped' response — used when a module is intentionally not run."""
    return {"status": "skipped", "reason": reason, **details}


async def with_timeout(coro: Coroutine, timeout_seconds: float, module_name: str) -> Any:
    """
    Runs an async function with a time limit.
    If it finishes in time, return the result.
    If it times out or crashes, return a clean error dict instead of crashing.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return error_response(
            ScanError.TIMEOUT,
            f"{module_name} did not respond within {timeout_seconds}s.",
            module=module_name,
            timeout_seconds=timeout_seconds,
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return error_response(
            ScanError.UNKNOWN_ERROR,
            f"{module_name} failed: {type(e).__name__}: {str(e)[:200]}",
            module=module_name,
            exception_type=type(e).__name__,
        )


def classify_socket_error(exc: BaseException) -> tuple[str, str]:
    """
    Takes a network error and classifies it into one of our standard error codes.
    This helps the frontend show the right message (e.g. "firewall blocked" vs "host down").
    """
    name = type(exc).__name__
    msg = str(exc).lower()
    if isinstance(exc, asyncio.TimeoutError) or "timeout" in msg or "timed out" in msg:
        return (ScanError.FIREWALL_FILTERED, "No response — blocked by a firewall, or the host/network is unreachable from here.")
    if isinstance(exc, ConnectionRefusedError) or "refused" in msg:
        return (ScanError.CONNECTION_REFUSED, "Connection refused (nothing listening)")
    if isinstance(exc, ssl_mod.SSLError):
        return (ScanError.SSL_HANDSHAKE_FAILED, f"SSL/TLS handshake failed: {str(exc)[:120]}")
    if (
        isinstance(exc, socket.gaierror)
        or "name or service not known" in msg
        or "nodename nor servname" in msg
        or "domain name not found" in msg
    ):
        return (ScanError.DNS_RESOLUTION_FAILED, "DNS resolution failed")
    if isinstance(exc, OSError):
        if "network is unreachable" in msg:
            return (ScanError.API_UNREACHABLE, "Network unreachable")
        if "host is down" in msg or "no route to host" in msg:
            return (ScanError.API_UNREACHABLE, "Host unreachable / no route")
        if "connection reset" in msg:
            return (ScanError.FIREWALL_FILTERED, "Connection reset (possibly rate-limited)")
    return (ScanError.UNKNOWN_ERROR, f"{name}: {str(exc)[:150]}")


def classify_http_status(status: int, url: str = "") -> dict | None:
    """
    Checks HTTP status codes from API responses and returns appropriate error dicts.
    Returns None for success codes (200-399), error dict for failures.
    """
    if 200 <= status < 400:
        return None
    if status == 401:
        return error_response(ScanError.UNAUTHORIZED, "API returned 401 Unauthorized", http_status=status)
    if status == 403:
        return error_response(ScanError.UNAUTHORIZED, "API returned 403 Forbidden", http_status=status)
    if status == 404:
        return error_response(ScanError.NOT_FOUND, "Target not found in the remote database", http_status=status)
    if status == 429:
        return error_response(ScanError.API_RATE_LIMITED, "Rate limited by remote API", http_status=status)
    if 500 <= status < 600:
        return error_response(ScanError.API_UNREACHABLE, f"Remote service returned {status}", http_status=status)
    return error_response(ScanError.INVALID_RESPONSE, f"Unexpected HTTP status {status}", http_status=status)
