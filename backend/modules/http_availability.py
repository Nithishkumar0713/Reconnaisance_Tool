"""
HTTP/HTTPS Accessibility Module.
Independently tests whether a target is reachable on port 80 (HTTP) and port
443 (HTTPS) — not "try one, fall back to the other" like http_headers.py
does, but genuinely checks both and reports both separately, since a real
browser hitting a bare domain makes that exact same choice and either port
can be misconfigured independently of the other.

For each port: status code, response time, and whether it redirects (and to
where — this is what confirms a proper HTTP-to-HTTPS redirect is actually in
place, not just assumed).

HTTP version is reported for port 443 using a direct TLS ALPN probe — the
same mechanism a real browser uses to decide HTTP/2 vs HTTP/1.1 during the
TLS handshake, before any HTTP request is even sent. This is a deliberate
choice: neither Git's nor Windows' bundled curl.exe has HTTP/2 compiled
in, and aiohttp's own client only ever speaks HTTP/1.1 on the wire, so
relying on either would misreport "HTTP/1.1" even for servers that fully
support HTTP/2.
"""

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlencode

import aiohttp

from utils.helpers import get_safe_ssl_context, get_relaxed_ssl_context
from utils.safety import TIMEOUTS, ScanError, classify_socket_error

MAX_REDIRECT_HOPS = 8

_WAF_CHALLENGE_URL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"_event_attackname=",
    r"_event_threatcategory=",
    r"cdn-cgi/challenge-platform",
    r"__cf_chl_",
    r"/_incapsula_resource",
    r"distil_r_captcha",
    r"/perimeterx/",
    r"px-captcha",
    r"waf[-_]?block",
    r"access[-_]?denied",
    r"url[-_]?access[-_]?violation",
]]

_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_META_HTTP_EQUIV_REFRESH_RE = re.compile(r"""http-equiv\s*=\s*["']?refresh["']?""", re.IGNORECASE)
_META_CONTENT_URL_RE = re.compile(
    r"""content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*['"]?([^'">\s]+)""",
    re.IGNORECASE,
)


def _find_meta_refresh_url(html: str) -> str | None:
    for tag in _META_TAG_RE.findall(html):
        if _META_HTTP_EQUIV_REFRESH_RE.search(tag):
            m = _META_CONTENT_URL_RE.search(tag)
            if m:
                return m.group(1)
    return None


_BODY_ONLOAD_ATTR_RE = re.compile(r"""<body\b[^>]*\bonload\s*=\s*(["'])(.*?)\1""", re.IGNORECASE)
_WINDOW_LOAD_HANDLER_RE = re.compile(
    r"""(?:window\.onload\s*=\s*function\s*\([^)]*\)\s*\{|addEventListener\(\s*['"](?:load|DOMContentLoaded)['"]\s*,\s*function\s*\([^)]*\)\s*\{)([\s\S]{0,800}?)\}""",
    re.IGNORECASE,
)
_BARE_FUNC_CALL_RE = re.compile(r"""^\s*([A-Za-z_$][\w$]*)\s*\(\s*\)\s*;?\s*$""")
_SUBMIT_CALL_RE = re.compile(r"""\.submit\s*\(\s*\)""", re.IGNORECASE)
_SUBMIT_TARGET_REF_RE = re.compile(r"""['"]?([\w-]+)['"]?\s*\)?\s*\.submit\s*\(\s*\)""", re.IGNORECASE)
_FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_TAG_ATTR_RE_TMPL = r"""\b{attr}\s*=\s*(["'])(.*?)\1"""
_FORM_ACTION_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="action"), re.IGNORECASE)
_FORM_METHOD_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="method"), re.IGNORECASE)
_FORM_ID_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="id"), re.IGNORECASE)
_FORM_NAME_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="name"), re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="name"), re.IGNORECASE)
_INPUT_VALUE_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="value"), re.IGNORECASE)
_INPUT_TYPE_RE = re.compile(_TAG_ATTR_RE_TMPL.format(attr="type"), re.IGNORECASE)


def _extract_page_load_js(html: str) -> str | None:
    """Returns the JS that runs automatically at page-load, if any is
    detectable — resolving a bare function-name call (e.g.
    `onload="redirect()"`) to that function's own body when it's defined
    elsewhere in the page. Returns None if no page-load trigger is found."""
    m = _BODY_ONLOAD_ATTR_RE.search(html)
    js = m.group(2) if m else None
    if js is None:
        m = _WINDOW_LOAD_HANDLER_RE.search(html)
        js = m.group(1) if m else None
    if js is None:
        return None

    call_match = _BARE_FUNC_CALL_RE.match(js.strip())
    if call_match:
        func_name = re.escape(call_match.group(1))
        func_re = re.compile(r"""function\s+""" + func_name + r"""\s*\([^)]*\)\s*\{([\s\S]{0,1000}?)\}""", re.IGNORECASE)
        func_match = func_re.search(html)
        if func_match:
            return func_match.group(1)
    return js


def _find_autosubmit_form(html: str) -> dict[str, Any] | None:
    """Detects a static <form> that page-load JS auto-submits (see the long
    comment above _BODY_ONLOAD_ATTR_RE). Returns
    {"action": str, "method": "get"|"post", "fields": {name: value}} if a
    form can be confidently identified, else None."""
    trigger_js = _extract_page_load_js(html)
    if not trigger_js or not _SUBMIT_CALL_RE.search(trigger_js):
        return None

    form_tags = list(_FORM_TAG_RE.finditer(html))
    candidates = []
    for fm in form_tags:
        tag = fm.group(0)
        action_m = _FORM_ACTION_RE.search(tag)
        if action_m and action_m.group(2).strip():
            candidates.append((fm, tag, action_m.group(2).strip()))
    if not candidates:
        return None

    target_form_tag = target_action = None
    ref_match = _SUBMIT_TARGET_REF_RE.search(trigger_js)
    ref_name = ref_match.group(1) if ref_match else None
    if ref_name:
        for fm, tag, action in candidates:
            id_m = _FORM_ID_RE.search(tag)
            name_m = _FORM_NAME_RE.search(tag)
            if (id_m and id_m.group(2) == ref_name) or (name_m and name_m.group(2) == ref_name):
                target_form_tag, target_action = fm, action
                break

    if target_form_tag is None:
        if len(candidates) != 1:
            return None
        target_form_tag, _, target_action = candidates[0]

    method_m = _FORM_METHOD_RE.search(target_form_tag.group(0))
    method = (method_m.group(2).strip().lower() if method_m else "get") or "get"
    if method not in ("get", "post"):
        method = "get"

    form_start = target_form_tag.end()
    close_idx = html.lower().find("</form>", form_start)
    form_body = html[form_start:close_idx if close_idx != -1 else form_start + 4000]
    fields: dict[str, str] = {}
    for inp in _INPUT_TAG_RE.findall(form_body):
        type_m = _INPUT_TYPE_RE.search(inp)
        input_type = (type_m.group(2).strip().lower() if type_m else "text")
        if input_type in ("submit", "button", "reset", "image", "file"):
            continue
        name_m = _INPUT_NAME_RE.search(inp)
        if not name_m:
            continue
        value_m = _INPUT_VALUE_RE.search(inp)
        fields[name_m.group(2)] = value_m.group(2) if value_m else ""

    return {"action": target_action, "method": method, "fields": fields}


_WAF_BLOCK_BODY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"attention required!\s*\|\s*cloudflare",
    r"sorry, you have been blocked",
    r"cf-error-details",
    r"<title>\s*access denied\s*</title>",
    r"the requested url was rejected",
    r"<title>\s*request rejected\s*</title>",
    r"incapsula incident id",
    r"<title>\s*error:\s*the request could not be satisfied\s*</title>",
    r"reference #[0-9a-f.]+",
]]


def _looks_like_waf_block_body(body: str) -> bool:
    return any(p.search(body) for p in _WAF_BLOCK_BODY_PATTERNS)


def _looks_like_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _url_host(target: str) -> str:
    """Formats `target` for embedding directly in a URL string. A bare IPv6
    literal (e.g. "2404:6800:4007:808::200e") is only valid on the wire —
    inside a URL it's ambiguous with the ":port" separator, so RFC 3986
    requires it be wrapped in brackets ("[2404:...::200e]"). Without this,
    yarl/aiohttp raises "Invalid URL: port can't be converted to integer"
    on any raw IPv6 target, which is a legitimate, reachable input here
    (classify_non_public_ip and is_valid_input both already accept public
    IPv6 addresses). Domains and IPv4 literals pass through unchanged."""
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        return target
    return f"[{target}]" if ip_obj.version == 6 else target


def _looks_like_waf_challenge(url: str) -> bool:
    return any(p.search(url) for p in _WAF_CHALLENGE_URL_PATTERNS)


def _parse_hsts(header_value: str | None) -> dict[str, Any] | None:
    """Parses a Strict-Transport-Security header into its directives. Per
    RFC 6797, this header is only spec-meaningful when received over a
    genuine HTTPS connection — a browser is supposed to ignore it entirely
    if seen over plain HTTP — so the caller should only capture this from
    the HTTPS check, not the HTTP one. This is what explains a real browser
    showing https:// for a domain even when its HTTP-level redirect chain
    (as measured by a plain client with no cached browser trust) never
    leaves plaintext: once any browser has received this header over a
    valid HTTPS connection to the domain (or a covering parent domain, if
    includeSubDomains is set), or if the domain is on the browser's built-in
    preload list (which the `preload` directive requests), it silently
    upgrades every future request before ever hitting the network — a
    protection plain HTTP clients and first-ever visits don't get."""
    if not header_value:
        return None
    max_age = None
    include_subdomains = False
    preload = False
    for part in (p.strip() for p in header_value.split(";")):
        low = part.lower()
        if low.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif low == "includesubdomains":
            include_subdomains = True
        elif low == "preload":
            preload = True
    return {
        "raw": header_value,
        "max_age_seconds": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
    }


def _classify_port_state(result: dict[str, Any]) -> str:
    """Maps a port result onto the same open/closed/filtered vocabulary
    port_scanner.py already uses, so the two modules read consistently."""
    if result.get("accessible"):
        return "open"
    code = result.get("error_code")
    if code == ScanError.CONNECTION_REFUSED:
        return "closed"
    if code == ScanError.FIREWALL_FILTERED:
        return "filtered"
    if code == ScanError.SSL_HANDSHAKE_FAILED:
        return "open"
    if code == ScanError.TIMEOUT:
        return "open"
    if code == ScanError.SERVER_DISCONNECTED:
        return "open"
    return "unknown"


def _probe_alpn(host: str, port: int, timeout: float) -> str | None:
    """Opens a raw TLS connection and reads back which protocol the server
    selected via ALPN. This is the actual mechanism a browser relies on to
    pick HTTP/2 vs HTTP/1.1 — independent of whatever protocol our own HTTP
    client speaks on the wire. Returns None on any failure (caller already
    has a separate, real HTTPS accessibility result from the aiohttp check;
    this is purely a version-capability signal, not the accessibility check
    itself)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol()
    except Exception:
        return None


def _waf_redirect_block_result(
    port: int, resp: aiohttp.ClientResponse, hops: list[dict[str, Any]], abs_location: str, start: float
) -> dict[str, Any]:
    """Shared result shape for all three "the next hop leads into a WAF/bot
    challenge" cases (HTTP 3xx Location, meta-refresh, and auto-submit-form
    action all funnel through here) — the server responded, but the thing it
    pointed at next is a known challenge/block pattern, so it's reported
    distinctly rather than followed."""
    elapsed_ms = round((time.monotonic() - start) * 1000)
    return {
        "port": port,
        "accessible": True,
        "status_code": hops[0]["status"] if hops else resp.status,
        "http_version": f"HTTP/{resp.version.major}.{resp.version.minor}",
        "response_time_ms": elapsed_ms,
        "redirect_count": len(hops) + 1,
        "redirects_to": hops[0]["location"] if hops else abs_location,
        "final_url": None,
        "final_status_code": None,
        "redirects_to_https": False,
        "blocked_by_waf": True,
        "waf_note": (
            "The server responded, but redirected into what looks like a "
            "WAF/bot-protection challenge page rather than real content — "
            "this is likely blocking automated requests specifically, not a "
            "sign the site itself is down. A real browser can usually pass "
            "this kind of challenge; a simple HTTP request cannot."
        ),
    }


async def _check_port(target: str, port: int, use_ssl: bool, use_relaxed_tls: bool = False) -> dict[str, Any]:
    scheme = "https" if use_ssl else "http"
    start_url = f"{scheme}://{_url_host(target)}/"
    timeout = aiohttp.ClientTimeout(total=TIMEOUTS.get("http_availability", 45), connect=8, sock_read=15)
    start = time.monotonic()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            current_url = start_url
            hops: list[dict[str, Any]] = []
            pending_post_data: dict[str, str] | None = None
            hsts_seen: str | None = None
            for _ in range(MAX_REDIRECT_HOPS + 1):
                is_https_hop = current_url.startswith("https://")
                if is_https_hop:
                    ssl_ctx = get_relaxed_ssl_context() if use_relaxed_tls else get_safe_ssl_context()
                else:
                    ssl_ctx = None
                if pending_post_data is not None:
                    post_data, pending_post_data = pending_post_data, None
                    req_ctx = session.post(current_url, data=post_data, ssl=ssl_ctx, allow_redirects=False, headers=headers)
                else:
                    req_ctx = session.get(current_url, ssl=ssl_ctx, allow_redirects=False, headers=headers)
                async with req_ctx as resp:
                    if is_https_hop and not hsts_seen:
                        hsts_seen = resp.headers.get("Strict-Transport-Security")
                    if 300 <= resp.status < 400 and resp.headers.get("Location"):
                        location = resp.headers.get("Location")
                        abs_location = str(resp.url.join(aiohttp.client.URL(location)))
                        if _looks_like_waf_challenge(abs_location):
                            return _waf_redirect_block_result(port, resp, hops, abs_location, start)
                        hops.append({"status": resp.status, "location": abs_location})
                        current_url = abs_location
                        continue

                    content_type = resp.headers.get("Content-Type", "")
                    if "html" in content_type.lower() or not content_type:
                        body_sample = (await resp.content.read(4096)).decode("utf-8", errors="ignore")

                        meta_url = _find_meta_refresh_url(body_sample)
                        if meta_url:
                            location = meta_url.strip().strip("'\"")
                            abs_location = str(resp.url.join(aiohttp.client.URL(location)))
                            if _looks_like_waf_challenge(abs_location):
                                return _waf_redirect_block_result(port, resp, hops, abs_location, start)
                            hops.append({"status": resp.status, "location": abs_location, "via": "meta_refresh"})
                            current_url = abs_location
                            continue

                        autosubmit = _find_autosubmit_form(body_sample)
                        if autosubmit:
                            abs_action = str(resp.url.join(aiohttp.client.URL(autosubmit["action"])))
                            if _looks_like_waf_challenge(abs_action):
                                return _waf_redirect_block_result(port, resp, hops, abs_action, start)
                            if autosubmit["method"] == "post":
                                pending_post_data = autosubmit["fields"]
                                hops.append({"status": resp.status, "location": abs_action, "via": "autosubmit_form"})
                                current_url = abs_action
                            else:
                                qs = urlencode(autosubmit["fields"]) if autosubmit["fields"] else ""
                                get_url = abs_action + (("&" if "?" in abs_action else "?") + qs if qs else "")
                                hops.append({"status": resp.status, "location": get_url, "via": "autosubmit_form"})
                                current_url = get_url
                            continue

                        if _looks_like_waf_block_body(body_sample):
                            elapsed_ms = round((time.monotonic() - start) * 1000)
                            return {
                                "port": port,
                                "accessible": True,
                                "status_code": hops[0]["status"] if hops else resp.status,
                                "http_version": f"HTTP/{resp.version.major}.{resp.version.minor}",
                                "response_time_ms": elapsed_ms,
                                "redirect_count": len(hops),
                                "redirects_to": hops[0]["location"] if hops else None,
                                "final_url": current_url,
                                "final_status_code": resp.status,
                                "redirects_to_https": current_url.startswith("https://"),
                                "blocked_by_waf": True,
                                "waf_note": (
                                    "The response itself is a WAF/bot-protection block page (detected "
                                    "via its content), not the site's real page — likely blocking this "
                                    "automated request specifically, not a sign the site itself is down. "
                                    "This can be intermittent: the same request may succeed on a retry. "
                                    "A real browser can usually get through; a simple HTTP request often can't."
                                ),
                                "hsts": _parse_hsts(hsts_seen),
                            }

                    elapsed_ms = round((time.monotonic() - start) * 1000)
                    return {
                        "port": port,
                        "accessible": True,
                        "status_code": hops[0]["status"] if hops else resp.status,
                        "http_version": f"HTTP/{resp.version.major}.{resp.version.minor}",
                        "response_time_ms": elapsed_ms,
                        "redirect_count": len(hops),
                        "redirects_to": hops[0]["location"] if hops else None,
                        "final_url": current_url,
                        "final_status_code": resp.status,
                        "redirects_to_https": current_url.startswith("https://"),
                        "hsts": _parse_hsts(hsts_seen),
                    }

            elapsed_ms = round((time.monotonic() - start) * 1000)
            return {
                "port": port,
                "accessible": True,
                "status_code": hops[0]["status"] if hops else None,
                "http_version": None,
                "response_time_ms": elapsed_ms,
                "redirect_count": len(hops),
                "redirects_to": hops[0]["location"] if hops else None,
                "final_url": None,
                "final_status_code": None,
                "redirects_to_https": False,
                "hsts": _parse_hsts(hsts_seen),
                "note": f"Redirect chain exceeded {MAX_REDIRECT_HOPS} hops without resolving.",
            }
    except aiohttp.ConnectionTimeoutError:
        return {
            "port": port,
            "accessible": False,
            "error_code": ScanError.FIREWALL_FILTERED,
            "error_message": f"No response on port {port} — blocked by a firewall, or the host/network is unreachable from here.",
        }
    except asyncio.TimeoutError:
        return {
            "port": port,
            "accessible": False,
            "error_code": ScanError.TIMEOUT,
            "error_message": f"Port {port} accepted the connection, but no HTTP response arrived in time — the service is likely overloaded, misconfigured, or hung, rather than the port being blocked.",
        }
    except aiohttp.ServerDisconnectedError:
        return {
            "port": port,
            "accessible": False,
            "error_code": ScanError.SERVER_DISCONNECTED,
            "error_message": (
                f"Port {port} accepted the connection, but the server closed it immediately "
                f"without sending any response — likely not actually running "
                f"{'HTTPS' if use_ssl else 'HTTP'} on this port."
            ),
        }
    except Exception as e:
        code, msg = classify_socket_error(e)
        return {"port": port, "accessible": False, "error_code": code, "error_message": msg}


_RETRY_WORTHY_ERROR_CODES = {ScanError.FIREWALL_FILTERED, ScanError.SERVER_DISCONNECTED}


async def _check_port_verified(target: str, port: int, use_ssl: bool) -> dict[str, Any]:
    """Wraps _check_port with a single retry for genuinely ambiguous,
    single-attempt-only outcomes: the error codes in
    _RETRY_WORTHY_ERROR_CODES, plus a WAF/bot-protection block. Some
    Cloudflare-fronted targets flip between blocked and accessible across
    back-to-back identical requests since bot-scoring is probabilistic,
    not a hard yes/no, so a single blocked attempt doesn't reliably mean
    the site is really unreachable. Mirrors the same retry-on-ambiguous-
    result strategy port_scanner.py uses."""
    result = await _check_port(target, port, use_ssl)

    if use_ssl and result.get("error_code") == ScanError.SSL_HANDSHAKE_FAILED:
        strict_error_message = result.get("error_message") or ""
        ssl_reason_match = re.search(r"\[SSL:[^\]]*\]", strict_error_message)
        ssl_reason = ssl_reason_match.group(0).strip() if ssl_reason_match else strict_error_message
        relaxed_result = await _check_port(target, port, use_ssl, use_relaxed_tls=True)
        if relaxed_result.get("accessible"):
            relaxed_result["weak_tls_downgrade"] = True
            relaxed_result["weak_tls_note"] = (
                "A standards-compliant TLS client refuses this connection "
                f"({ssl_reason}) — but a more permissive client (matching what curl / "
                "this system's own TLS library accepts) can still connect, and got the response shown "
                "here. The server's TLS configuration doesn't meet modern security standards, even "
                "though some clients — including most browsers, which fall back gracefully — will "
                "still connect successfully."
            )
            relaxed_result["verified"] = True
            return relaxed_result

    first_error_code = result.get("error_code")
    first_blocked = bool(result.get("blocked_by_waf"))
    if first_error_code not in _RETRY_WORTHY_ERROR_CODES and not first_blocked:
        result["verified"] = True
        return result

    retry_result = await _check_port(target, port, use_ssl)
    retry_result["verified"] = True
    retry_blocked = bool(retry_result.get("blocked_by_waf"))

    if first_blocked and retry_blocked:
        retry_result["waf_note"] = retry_result.get("waf_note", "").rstrip(".") + " (confirmed blocked on a second attempt too — not just a one-off)."
    elif first_blocked and not retry_blocked:
        retry_result["note"] = "The first attempt was blocked by an apparent WAF/bot-protection check, but a second attempt got through — this kind of blocking is often probabilistic rather than a hard, persistent block."
    elif retry_result.get("error_code") == first_error_code and first_error_code is not None:
        retry_result["error_message"] = retry_result["error_message"].rstrip(".") + " (confirmed on a second attempt)."
    else:
        retry_result["note"] = "The first attempt showed no usable response, but a second attempt got a different result — the first was likely a transient blip rather than a persistent condition."
    return retry_result


async def check(target: str) -> dict[str, Any]:
    """Main entry point — tests port 80 and 443 concurrently and independently,
    plus an ALPN probe on 443 for real HTTP/2 capability, then combines
    everything into one plain-English accessibility verdict."""
    loop = asyncio.get_event_loop()
    alpn_timeout = min(TIMEOUTS.get("http_availability", 45), 8.0)

    http_result, https_result, alpn_protocol = await asyncio.gather(
        _check_port_verified(target, 80, use_ssl=False),
        _check_port_verified(target, 443, use_ssl=True),
        loop.run_in_executor(None, _probe_alpn, target, 443, alpn_timeout),
    )

    http_result["port_state"] = _classify_port_state(http_result)
    https_result["port_state"] = _classify_port_state(https_result)

    if https_result.get("accessible"):
        https_result["http2_supported"] = alpn_protocol == "h2"
        if https_result["http2_supported"]:
            https_result["http_version"] = "HTTP/2"

    if https_result.get("blocked_by_waf") or http_result.get("blocked_by_waf"):
        overall = "blocked_by_waf"
        blocked_ports = [p["port"] for p in (http_result, https_result) if p.get("blocked_by_waf")]
        summary = f"Port(s) {', '.join(str(p) for p in blocked_ports)} responded but redirected into an apparent WAF/bot-protection challenge — likely blocking this automated request specifically, not a sign the site itself is down."
    elif https_result.get("accessible") and http_result.get("redirects_to_https"):
        overall = "https_ok"
        summary = "Accessible via HTTPS, and HTTP correctly redirects to it."
    elif https_result.get("accessible") and http_result.get("accessible"):
        overall = "no_forced_https"
        if https_result.get("hsts"):
            summary = (
                "HTTP does not redirect to HTTPS, but the server does send an HSTS header — most "
                "browsers that have already trusted this domain over HTTPS (or that have it on their "
                "built-in preload list) will auto-upgrade and never show this gap. It still leaves "
                "plaintext access open to non-browser clients and to any client's very first-ever "
                "connection, before that trust exists."
            )
        else:
            summary = "Both HTTP and HTTPS respond, but HTTP does not redirect to HTTPS — plaintext access remains available."
    elif https_result.get("accessible"):
        overall = "https_ok"
        summary = "Accessible via HTTPS. HTTP (port 80) did not respond."
    elif http_result.get("accessible"):
        overall = "http_only"
        summary = "Accessible via HTTP only — HTTPS (port 443) did not respond or failed."
    else:
        overall = "not_accessible"
        summary = "Not accessible on either port 80 or port 443."

    result = {
        "status": "ok",
        "target": target,
        "overall": overall,
        "summary": summary,
        "http": http_result,
        "https": https_result,
    }

    if _looks_like_ip(target):
        result["checked_via_raw_ip"] = True
        result["ip_sni_note"] = (
            "Checked via raw IP address, not a domain. If this IP hosts multiple sites "
            "(CDN, load balancer, shared hosting), the response shown may belong to a "
            "different site than expected — HTTP relies on the domain name (Host header/SNI) "
            "to pick the right site, which a raw IP can't provide."
        )

    return result
