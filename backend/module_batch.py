"""
module_batch.py — Runs a single diagnostic module (e.g. AbuseIPDB) across
multiple targets at once (up to 20), for the "Single Check" pages.

This is intentionally isolated from batch_scanner.py and scan_config.py:
it never sets is_batch=True, never touches the full-scan aggressive/reputation
gating logic, and does not share any code path with the full-scan /scan or
/scan/batch endpoints. Changes here cannot affect full-scan behavior.
"""

import asyncio
import ipaddress
import re
from typing import Any

from modules import dns_recon, geo_ip, http_availability, http_headers, reputation, shodan_intel, ssl_check, web_tech, whois_lookup
from utils.helpers import classify_non_public_ip, is_valid_input, resolve_target
from utils.safety import ScanError, TIMEOUTS, error_response, with_timeout

MAX_MODULE_BATCH_TARGETS = 20
BATCH_CONCURRENCY = 4

WHOIS_BATCH_DELAY_SECONDS = 2.0

# VirusTotal isn't listed here — reputation.py now paces its own calls with
# a process-wide rate limiter (_vt_wait_for_slot), so every caller gets
# correct spacing automatically, including this one running several targets
# "concurrently." A caller-side delay on top of that would just double-pace
# it for no benefit.
_SEQUENTIAL_MODULE_DELAYS = {
    "whois": WHOIS_BATCH_DELAY_SECONDS,
}

_RANGE_SHORT_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})$")
_RANGE_FULL_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)

SUPPORTED_BATCH_MODULES = {"abuseipdb", "virustotal", "geo_ip", "whois", "ssl_certificate", "dns_records", "shodan_intel", "http_availability", "http_headers", "web_technologies", "reverse_dns"}


def _looks_like_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


_PUBLIC_IP_ONLY_MODULES = {"abuseipdb", "virustotal", "ssl_certificate", "dns_records", "shodan_intel", "http_availability", "http_headers", "web_technologies", "reverse_dns"}

_IP_ONLY_MODULES = {"reverse_dns"}


def _pre_validate_target(target: str, module: str) -> dict[str, Any] | None:
    """
    Cheap, instant format checks (CIDR rejection + IP/domain shape +
    private-IP rejection where relevant) that never touch the network.
    Returns an error result dict if `target` is invalid, or None if it's OK
    to actually check. Split out from _check_single_target so callers (like
    the VirusTotal sequential runner) can skip the rate-limit pacing
    entirely for targets that were never going to hit the API anyway.
    """
    target = target.strip()

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            return {
                "target": target,
                "results": {
                    module: error_response(
                        ScanError.INVALID_TARGET,
                        f"'{target}' is a CIDR range ({network.num_addresses} addresses) — "
                        f"subnet scanning isn't supported here. Enter individual IPs or domains instead."
                    )
                },
            }
        except ValueError:
            pass

    validation = is_valid_input(target)
    if not validation["valid"]:
        return {
            "target": target,
            "results": {
                module: error_response(ScanError.INVALID_TARGET, validation["error"])
            },
        }

    if module in _PUBLIC_IP_ONLY_MODULES:
        reason = classify_non_public_ip(target)
        if reason:
            return {
                "target": target,
                "results": {
                    module: error_response(
                        ScanError.INVALID_TARGET,
                        f"'{target}' is a {reason}, not a public IP — this check only applies to "
                        f"public internet targets."
                    )
                },
            }

    if module == "whois" and _looks_like_ip(target):
        return {
            "target": target,
            "results": {
                module: error_response(
                    ScanError.INVALID_TARGET,
                    f"'{target}' is an IP address — WHOIS lookups require a domain name."
                )
            },
        }

    if module in _IP_ONLY_MODULES and not _looks_like_ip(target):
        return {
            "target": target,
            "results": {
                module: error_response(
                    ScanError.INVALID_TARGET,
                    f"'{target}' is a domain — reverse DNS requires an IP address."
                )
            },
        }

    return None


async def _check_single_target(
    target: str,
    module: str,
    abuseipdb_api_key: str | None,
    virustotal_api_key: str | None = None,
) -> dict[str, Any]:
    """
    Validates and checks exactly one target. Never raises — always returns a
    result dict, so one bad/mistyped target can never take the batch down.
    """
    target = target.strip()

    pre_check_error = _pre_validate_target(target, module)
    if pre_check_error is not None:
        return pre_check_error

    try:
        if module == "abuseipdb":
            result = await with_timeout(
                reputation.check_abuseipdb(target, abuseipdb_api_key),
                TIMEOUTS.get("abuseipdb", 30),
                "AbuseIPDB",
            )
        elif module == "virustotal":
            result = await with_timeout(
                reputation.check_virustotal(target, not _looks_like_ip(target), virustotal_api_key),
                TIMEOUTS.get("virustotal", 30),
                "VirusTotal",
            )
        elif module == "geo_ip":
            ip_to_check = target
            if not _looks_like_ip(target):
                try:
                    resolved = await resolve_target(target)
                    ip_to_check = resolved.get("ip")
                except ValueError as e:
                    ip_to_check = None
                if not ip_to_check:
                    result = error_response(
                        ScanError.DNS_RESOLUTION_FAILED,
                        f"'{target}' could not be resolved to an IP address."
                    )
                    ip_to_check = None
            if ip_to_check:
                result = await with_timeout(
                    geo_ip.lookup(ip_to_check),
                    TIMEOUTS.get("geo_ip", 30),
                    "GeoIP",
                )
        elif module == "whois":
            result = await with_timeout(
                whois_lookup.lookup(target),
                TIMEOUTS.get("whois", 45),
                "WHOIS",
            )
        elif module == "ssl_certificate":
            result = await with_timeout(
                ssl_check.get_certificate(target),
                TIMEOUTS.get("ssl", 45),
                "SSL Certificate",
            )
            if isinstance(result, dict) and _looks_like_ip(target):
                result["checked_via_raw_ip"] = True
                result["ip_sni_note"] = (
                    "Checked via raw IP address, not a domain. If this IP hosts multiple "
                    "sites (CDN, load balancer, shared hosting), the certificate shown may "
                    "belong to a different site than expected — TLS relies on the domain "
                    "name (SNI) to pick the right certificate, which a raw IP can't provide."
                )
        elif module == "dns_records":
            if _looks_like_ip(target):
                rdns_result = await with_timeout(
                    dns_recon.reverse_dns(target),
                    TIMEOUTS.get("reverse_dns", 30),
                    "Reverse DNS",
                )
                hostname = rdns_result.get("hostname") if isinstance(rdns_result, dict) else None
                if not hostname:
                    result = error_response(
                        ScanError.DNS_RESOLUTION_FAILED,
                        f"'{target}' has no reverse DNS (PTR) record, so there's no hostname to "
                        f"look up DNS records for. Try the Reverse DNS check instead, or enter a "
                        f"domain name directly."
                    )
                else:
                    result = await with_timeout(
                        dns_recon.get_all_records(hostname),
                        TIMEOUTS.get("dns", 60),
                        "DNS Records",
                    )
                    if isinstance(result, dict) and result.get("status") == "ok":
                        result["resolved_via_ptr"] = hostname
                        result["ptr_note"] = (
                            f"'{target}' has no DNS records of its own — these are the records "
                            f"for '{hostname}', the hostname its reverse DNS (PTR) record points to."
                        )
            else:
                result = await with_timeout(
                    dns_recon.get_all_records(target),
                    TIMEOUTS.get("dns", 60),
                    "DNS Records",
                )
        elif module == "shodan_intel":
            ip_to_check = target
            if not _looks_like_ip(target):
                try:
                    resolved = await resolve_target(target)
                    ip_to_check = resolved.get("ip")
                except ValueError:
                    ip_to_check = None
                if not ip_to_check:
                    result = error_response(
                        ScanError.DNS_RESOLUTION_FAILED,
                        f"'{target}' could not be resolved to an IP address."
                    )
                    ip_to_check = None
            if ip_to_check:
                result = await with_timeout(
                    shodan_intel.lookup(ip_to_check),
                    TIMEOUTS.get("shodan", 30),
                    "Shodan Intel",
                )
        elif module == "http_availability":
            result = await with_timeout(
                http_availability.check(target),
                TIMEOUTS.get("http_availability", 45),
                "HTTP Availability",
            )
        elif module == "http_headers":
            result = await with_timeout(
                http_headers.fetch(target),
                TIMEOUTS.get("http_headers", 45),
                "HTTP Headers",
            )
        elif module == "web_technologies":
            result = await with_timeout(
                web_tech.detect(target),
                TIMEOUTS.get("web_tech", 45),
                "Web Technologies",
            )
        elif module == "reverse_dns":
            result = await with_timeout(
                dns_recon.reverse_dns(target),
                TIMEOUTS.get("reverse_dns", 30),
                "Reverse DNS",
            )
        else:
            result = error_response(
                ScanError.INVALID_TARGET, f"Module '{module}' is not supported for batch checks."
            )
    except Exception as e:
        result = error_response(
            ScanError.UNKNOWN_ERROR, f"Unexpected error: {type(e).__name__}: {str(e)[:150]}"
        )

    return {"target": target, "results": {module: result}}


def _expand_ip_range(raw: str, max_targets: int = MAX_MODULE_BATCH_TARGETS) -> list[str] | None:
    """
    If `raw` matches the short ("110.0.0.1-20") or full
    ("110.0.0.46-110.0.0.65") range syntax, returns the expanded list of
    individual IPs. Returns None if `raw` doesn't look like a range at all
    (the caller should then treat it as a normal single IP/domain).

    Raises ValueError with a clear message if it LOOKS like a range but is
    malformed, backwards (start > end), or expands past `max_targets` —
    this is checked per-range so "110.0.0.1-30" fails immediately with a
    specific reason, not a generic "too many targets" message. `max_targets`
    defaults to MAX_MODULE_BATCH_TARGETS (this function's original, only
    caller); the full-scan-batch feature passes its own, lower cap.
    """
    raw = raw.strip()

    m = _RANGE_SHORT_RE.match(raw)
    if m:
        prefix, start_s, end_s = m.groups()
        start, end = int(start_s), int(end_s)
        base_ip = f"{prefix}.{start}"
        try:
            ipaddress.ip_address(base_ip)
            ipaddress.ip_address(f"{prefix}.{end}")
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid IP range.")
        if start > end:
            raise ValueError(f"'{raw}' is backwards — the start of a range must come before the end.")
        count = end - start + 1
        if count > max_targets:
            raise ValueError(
                f"'{raw}' covers {count} addresses ({prefix}.{start}–{prefix}.{end}) — "
                f"maximum is {max_targets} per batch check."
            )
        return [f"{prefix}.{i}" for i in range(start, end + 1)]

    m = _RANGE_FULL_RE.match(raw)
    if m:
        start_ip_s, end_ip_s = m.groups()
        try:
            start_ip = ipaddress.IPv4Address(start_ip_s)
            end_ip = ipaddress.IPv4Address(end_ip_s)
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid IP range.")
        start_int, end_int = int(start_ip), int(end_ip)
        if start_int > end_int:
            raise ValueError(f"'{raw}' is backwards — the start of a range must come before the end.")
        count = end_int - start_int + 1
        if count > max_targets:
            raise ValueError(
                f"'{raw}' covers {count} addresses ({start_ip_s}–{end_ip_s}) — "
                f"maximum is {max_targets} per batch check."
            )
        return [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]

    return None


def normalize_targets(raw_targets: list[str], max_targets: int = MAX_MODULE_BATCH_TARGETS) -> list[str]:
    """
    Expands any range shorthand (e.g. "110.0.0.1-20") into individual IPs,
    trims, drops empties, and dedupes (case-insensitive) while preserving
    order. Raises ValueError if a single range is malformed or too large —
    the aggregate cap (`max_targets`) is enforced separately by the caller,
    after expansion, so a mix of ranges + individual targets is still
    caught. Defaults to MAX_MODULE_BATCH_TARGETS for this module's own
    single-module-batch callers; the full-scan-batch feature passes its own
    lower cap.
    """
    seen: set[str] = set()
    cleaned: list[str] = []
    for raw in raw_targets:
        t = (raw or "").strip()
        if not t:
            continue

        expanded = _expand_ip_range(t, max_targets)
        candidates = expanded if expanded is not None else [t]

        for c in candidates:
            key = c.lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(c)
    return cleaned


async def run_module_batch(
    targets: list[str],
    module: str,
    abuseipdb_api_key: str | None = None,
    virustotal_api_key: str | None = None,
) -> list[dict[str, Any]]:
    """
    Runs `module` against every target in `targets`. Execution strategy
    depends on the module's real rate limits:

    - abuseipdb, geo_ip, ssl_certificate, dns_records, shodan_intel,
      http_availability, http_headers, web_technologies, reverse_dns,
      virustotal: no caller-side pacing needed here — runs BATCH_CONCURRENCY
      (4) at a time. virustotal is safe to run this way because reputation.py
      itself now paces every call to a real 16s minimum spacing, process-wide
      — it doesn't matter how many "concurrent" callers there are, the actual
      requests still queue correctly.
    - whois: each check starts no sooner than the module's configured delay
      (_SEQUENTIAL_MODULE_DELAYS) after the previous one *started* (not after
      it finished) — a start-to-start interval, so a 20-target batch takes
      ~delay * 19 seconds, not delay * 20.

    Every target — valid or not — gets a result entry, so the caller can
    render a card per target and never has to guess what happened.
    """
    if module in _SEQUENTIAL_MODULE_DELAYS:
        delay = _SEQUENTIAL_MODULE_DELAYS[module]
        results: list[dict[str, Any]] = []
        loop = asyncio.get_event_loop()
        last_start: float | None = None

        for t in targets:
            pre_check_error = _pre_validate_target(t, module)
            if pre_check_error is not None:
                results.append(pre_check_error)
                continue

            if last_start is not None:
                elapsed = loop.time() - last_start
                remaining = delay - elapsed
                if remaining > 0:
                    await asyncio.sleep(remaining)
            last_start = loop.time()
            results.append(await _check_single_target(t, module, abuseipdb_api_key, virustotal_api_key))

        return results

    semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)

    async def _bounded(t: str) -> dict[str, Any]:
        async with semaphore:
            return await _check_single_target(t, module, abuseipdb_api_key, virustotal_api_key)

    return await asyncio.gather(*[_bounded(t) for t in targets])
