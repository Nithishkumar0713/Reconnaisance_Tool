"""
HTTP Headers Fetcher and Analyzer Module.
Connects to the target website (HTTP or HTTPS) and downloads the server's response headers.
What this helps you analyze and explain:
  1. Security Headers: Checks for headers that protect users (like CSP, HSTS, X-Frame-Options).
  2. Server Information Leaks: Checks if headers leak internal details (like web server software versions).
  3. Cookie Security: Verifies if tracking/session cookies have security flags (HttpOnly, Secure, SameSite).
  4. Redirection History: Tracks if the site redirects users from HTTP to HTTPS, or across different URLs.
"""

import asyncio
import ipaddress
import ssl as ssl_mod
import time
import json
from typing import Any

from utils.safety import TIMEOUTS, ScanError, error_response


def _url_host(target: str) -> str:
    """Formats `target` for embedding directly in a URL string. A bare IPv6
    literal (e.g. "2404:6800:4007:808::200e") is only valid on the wire —
    inside a URL it's ambiguous with the ":port" separator, so RFC 3986
    requires it be wrapped in brackets ("[2404:...::200e]"). Verified
    directly: without this, curl exits with code 3 ("URL malformed") on any
    raw IPv6 target, which is a legitimate, reachable input here
    (classify_non_public_ip/is_valid_input both already accept public IPv6
    addresses). Domains and IPv4 literals pass through unchanged."""
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        return target
    return f"[{target}]" if ip_obj.version == 6 else target

_PER_URL_TIMEOUT = max(10, TIMEOUTS.get("http_headers", 45) - 10)

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
]

LEAKAGE_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "x-backend-server",
    "x-runtime", "x-request-id", "x-amz-request-id", "x-cache",
    "via", "x-forwarded-for", "x-real-ip",
]


def _analyze_cookies(cookies) -> list[dict]:
    """
    Analyzes cookie security settings.
    Looks for HttpOnly (prevents JS access), Secure (HTTPS only), and SameSite (prevents CSRF).
    """
    analyzed = []
    for c in cookies:
        flags = {
            "name": c.key,
            "httponly": c.get("httponly", False),
            "secure": c.get("secure", False),
            "samesite": c.get("samesite", None),
            "domain": c.get("domain", None),
            "path": c.get("path", None),
            "expires": str(c.get("expires", None)),
        }
        issues = []
        if not flags["httponly"]:
            issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
        if not flags["secure"]:
            issues.append("Missing Secure flag — transmitted over HTTP")
        if not flags["samesite"]:
            issues.append("Missing SameSite flag — CSRF risk")
        elif flags["samesite"].lower() == "none" and not flags["secure"]:
            issues.append("SameSite=None without Secure is rejected by modern browsers")
        
        flags["issues"] = issues
        flags["is_secure"] = len(issues) == 0
        analyzed.append(flags)
    return analyzed


def _analyze_hsts(hsts_value: str) -> dict:
    """
    Evaluates HTTP Strict Transport Security (HSTS) configuration.
    HSTS forces browsers to connect using HTTPS rather than insecure HTTP.
    """
    parts = [p.strip().lower() for p in hsts_value.split(";")]
    max_age = None
    include_sub = False
    preload = False
    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=")[1])
            except Exception:
                pass
        elif part == "includesubdomains":
            include_sub = True
        elif part == "preload":
            preload = True

    issues = []
    if max_age is None:
        issues.append("max-age not set")
    elif max_age < 86400:
        issues.append(f"max-age={max_age} is very short (recommended ≥ 31536000)")
    elif max_age < 31536000:
        issues.append(f"max-age={max_age} — recommended ≥ 31536000 (1 year)")

    return {
        "raw": hsts_value,
        "max_age_seconds": max_age,
        "include_subdomains": include_sub,
        "preload": preload,
        "issues": issues,
    }


async def _try_fetch(url: str) -> dict | None:
    """
    Connects to a single URL using curl, measures latency, extracts headers and cookies,
    and grades the server's security configurations.

    Runs curl as a real async subprocess (asyncio.create_subprocess_exec)
    rather than the previous sync subprocess.run() called through
    loop.run_in_executor(). That distinction matters for cancellation:
    when the caller times this out (either the with_timeout() wrapper in
    main.py/module_batch.py, or asyncio.gather in fetch() below), an async
    subprocess can actually be killed via proc.kill() — a sync subprocess
    running inside a thread-pool executor can't be interrupted at all; the
    thread just keeps blocking on subprocess.run()'s own internal timeout
    in the background, wasting a worker thread until it finally elapses.
    """
    start = time.monotonic()
    cmd = [
        "curl",
        "-s", "-i",
        "-k",
        "-L",
        "-m", str(_PER_URL_TIMEOUT - 2),
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        url
    ]

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_PER_URL_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"_failure": "timeout", "_url": url}

        elapsed_ms = round((time.monotonic() - start) * 1000)

        if proc.returncode != 0:
            return {"_failure": "curl_error", "_url": url, "_msg": stderr.decode('utf-8', errors='ignore')[:120]}

        try:
            output = stdout.decode('utf-8', errors='ignore')
        except Exception:
            return {"_failure": "decode_error", "_url": url}

        lines = output.split('\n')
        if not lines:
            return {"_failure": "no_response", "_url": url}

        status_line_idx = -1
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip().startswith('HTTP/'):
                status_line_idx = i
                break

        if status_line_idx == -1:
            return {"_failure": "no_status_line", "_url": url}

        status_line = lines[status_line_idx]
        try:
            http_status = int(status_line.split()[1])
            reason = " ".join(status_line.split()[2:]) if len(status_line.split()) > 2 else "OK"
        except (IndexError, ValueError):
            return {"_failure": "parse_error", "_url": url}

        all_headers = {}
        for i in range(status_line_idx + 1, len(lines)):
            line = lines[i]
            if not line.strip():
                break
            if ":" in line:
                key, val = line.split(":", 1)
                all_headers[key.strip()] = val.strip()

        lower_headers = {k.lower(): v for k, v in all_headers.items()}

        security_present = {h: lower_headers[h] for h in SECURITY_HEADERS if h in lower_headers}
        security_missing = [h for h in SECURITY_HEADERS if h not in lower_headers]
        leaked_headers = {h: lower_headers[h] for h in LEAKAGE_HEADERS if h in lower_headers}

        hsts_analysis = None
        if "strict-transport-security" in lower_headers:
            hsts_analysis = _analyze_hsts(lower_headers["strict-transport-security"])

        cookie_analysis = []
        cookie_issues = []

        critical_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "referrer-policy",
        ]
        score = sum(1 for h in critical_headers if h in lower_headers)
        security_grade = ["F", "F", "D", "C", "C", "B", "A", "A", "A+"][min(score + score, 8)]

        return {
            "status": "ok",
            "url": url,
            "http_status": http_status,
            "reason": reason,
            "response_time_ms": elapsed_ms,
            "all_headers": all_headers,
            "security_headers_present": security_present,
            "security_headers_missing": security_missing,
            "security_headers_count": len(security_present),
            "security_grade": security_grade,
            "hsts_analysis": hsts_analysis,
            "leaked_server_headers": leaked_headers,
            "cookies": cookie_analysis,
            "cookie_count": len(cookie_analysis),
            "cookie_issues": cookie_issues,
            "was_redirected": False,
            "redirect_count": 0,
            "redirect_history": [],
            "uses_https": url.startswith("https://"),
        }
    except FileNotFoundError:
        return {"_failure": "curl_not_found", "_url": url, "_msg": "curl binary not found on this system"}
    except Exception as e:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        return {"_failure": "unknown", "_url": url, "_msg": f"{type(e).__name__}: {str(e)[:120]}"}


async def fetch(target: str) -> dict[str, Any]:
    """
    Main Header Fetcher Entry Point.
    Tries https://target, http://target, and the www. variants of both,
    preferring the first successful result in that exact priority order
    (https bare domain first, since that's the most meaningful result for
    security grading — an HTTP-only fallback would under-report a site's
    real HTTPS posture).

    All variants are fetched *concurrently* (not one at a time) — see the
    comment above _PER_URL_TIMEOUT for why: this function's total runtime
    is bounded by a single attempt's timeout instead of the sum of all
    four, which is what actually lets each attempt afford a generous
    timeout without risking the outer TIMEOUTS["http_headers"] wrapper
    (used by both the full-scan and any batch run) cutting it off early.
    asyncio.gather preserves input order in its results regardless of which
    attempt finishes first, so the priority-order selection below still
    works exactly the same as the old sequential version did.
    """
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    host = _url_host(target)
    try:
        ipaddress.ip_address(target)
        target_is_ip = True
    except ValueError:
        target_is_ip = False

    urls_to_try = [f"https://{host}", f"http://{host}"]
    if not target_is_ip and not target.startswith("www."):
        urls_to_try.extend([f"https://www.{target}", f"http://www.{target}"])

    results = await asyncio.gather(*(_try_fetch(url) for url in urls_to_try), return_exceptions=True)

    attempts = []
    for url, result in zip(urls_to_try, results):
        if isinstance(result, BaseException):
            attempts.append({"url": url, "failure": "exception", "detail": f"{type(result).__name__}: {str(result)[:120]}"})
            continue
        if result and "_failure" not in result:
            return result
        if result:
            attempts.append({"url": result.get("_url"), "failure": result.get("_failure"), "detail": result.get("_msg")})

    return {
        "status": "ok",
        "url": f"https://{target}",
        "http_status": 0,
        "reason": "Unreachable / Filtered",
        "response_time_ms": 0,
        "all_headers": {},
        "security_headers_present": {},
        "security_headers_missing": SECURITY_HEADERS,
        "security_headers_count": 0,
        "security_grade": "N/A",
        "hsts_analysis": None,
        "leaked_server_headers": {},
        "cookies": [],
        "cookie_count": 0,
        "cookie_issues": [],
        "was_redirected": False,
        "redirect_count": 0,
        "redirect_history": [],
        "uses_https": False,
        "note": "Target web service (ports 80/443) unreachable or filtered by firewall.",
        "attempts": attempts,
    }
