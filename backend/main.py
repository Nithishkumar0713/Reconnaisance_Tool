
import asyncio
import aiohttp
import warnings

import aiohttp.resolver
aiohttp.resolver.DefaultResolver = aiohttp.resolver.ThreadedResolver

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import time
from datetime import datetime
from typing import Any, Callable, Coroutine
import os
import sys

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator
from concurrent.futures import ThreadPoolExecutor

import json
from database import engine, Base, get_db
from sqlalchemy.orm import Session
import models
from auth_router import router as auth_router

from utils.scan_config import (
    should_include_aggressive_modules,
    should_include_reputation_checks,
    validate_scan_mode,
)
import logging
logger = logging.getLogger(__name__)
from auth import get_current_user
from models import User, ScanHistory, LoginHistory, BatchScan, SubdomainScan, FullScanBatch, FullScanBatchTarget

from modules import (
    dns_recon,
    whois_lookup,
    ssl_check,
    port_scanner,
    subdomain_finder,
    web_tech,
    http_headers,
    geo_ip,
    reputation,
    directory_enum,
    cloud_provider,
    waf_detect,
    cms_fingerprint,
    email_gather,
    shodan_intel,
    http_availability,
)
from utils.helpers import classify_non_public_ip, is_valid_input, resolve_target
from utils.safety import TIMEOUTS, ScanError, error_response, with_timeout, skip_response
import module_batch


def refresh_windows_path():
    """
    On Windows, sometimes new programs installed don't show up in PATH
    until you restart. This function reads the latest PATH from Windows
    registry so tools like nslookup and whois can be found.
    """
    if sys.platform != 'win32':
        return
    try:
        import winreg
        try:
            user_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment")
            user_path, _ = winreg.QueryValueEx(user_key, "Path")
            winreg.CloseKey(user_key)
        except Exception:
            user_path = ""
            
        try:
            system_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, 
                r"System\CurrentControlSet\Control\Session Manager\Environment"
            )
            system_path, _ = winreg.QueryValueEx(system_key, "Path")
            winreg.CloseKey(system_key)
        except Exception:
            system_path = ""
            
        raw_paths = (system_path + ";" + user_path).split(";")
        unique_paths = []
        for p in raw_paths:
            p = p.strip()
            if p and p not in unique_paths:
                unique_paths.append(p)
                
        os.environ['PATH'] = ";".join(unique_paths)
    except Exception as e:
        print(f"Failed to refresh Windows registry PATH: {e}")


refresh_windows_path()

try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

import multiprocessing
cpu_count = multiprocessing.cpu_count()
optimal_workers = min(600, max(300, cpu_count * 25))
loop.set_default_executor(ThreadPoolExecutor(max_workers=optimal_workers))
print(f"[INIT] Thread pool configured: {optimal_workers} workers (CPU cores: {cpu_count})")

app = FastAPI(
    title="Recon Scanner API",
    description="Passive + Active reconnaissance for IPs and domains",
    version="1.1.0",
)


@app.on_event("startup")
async def _warm_up_caches():
    """
    web_tech.py lazily builds its ~7,200-technology, ~20,000-pattern regex
    catalog on first use, cached at module level after that. Fine for a
    single request — but verified directly: right after a fresh restart, a
    batch scan whose first wave runs web_technologies for several targets
    concurrently can have multiple threads race to build that same cold
    cache at once, and that much simultaneous CPU-bound regex compilation
    is enough GIL contention to make even a trivial /health request briefly
    unresponsive (observed directly: one wave-1 request took 20+ seconds
    where it's normally under 0.2s; no repeat for the rest of that batch,
    or in any wave of a second batch run right after). Building the
    catalog once here, at startup — before any request can trigger a
    concurrent race for it — avoids that entirely.
    """
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, web_tech._load_catalog)
    print("[INIT] Web technology catalog pre-loaded")

running_batch_tasks: dict[int, "asyncio.Task"] = {}
running_full_scan_batch_tasks: dict[int, "asyncio.Task"] = {}

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
Base.metadata.create_all(bind=engine)

app.include_router(auth_router)



ALLOWED_MODULES = {
    "dns_records", "whois", "ssl_certificate", "geo_ip", "http_headers",
    "web_technologies", "abuseipdb", "virustotal", "port_scan",
    "subdomains", "directories", "reverse_dns", "cloud_provider",
    "waf_detect", "cms_fingerprint", "email_gather",
    "standalone_port_scanner", "port_scanner", "shodan_intel",
    "http_availability",
}
ALLOWED_PORT_RANGES = {"top100", "1-1024", "1-65535", "fast", "detailed", "full"}
ALLOWED_MODES = {"fast", "standard", "deep", "detailed"}


class ScanRequest(BaseModel):
    """What the frontend sends when scanning a single target."""
    target: str
    mode: str = "fast"
    include_reputation: bool = True
    module: str | None = None
    port_range: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ALLOWED_MODES:
            raise ValueError(f"Invalid mode '{v}'. Must be one of: {ALLOWED_MODES}")
        return v

    @field_validator("module")
    @classmethod
    def validate_module(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ALLOWED_MODULES:
            raise ValueError(f"Unknown module '{v}'.")
        return v

    @field_validator("port_range")
    @classmethod
    def validate_port_range(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ALLOWED_PORT_RANGES:
            raise ValueError(f"Invalid port_range '{v}'. Must be one of: {ALLOWED_PORT_RANGES}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty.")
        if len(v) > 253:
            raise ValueError("Target is too long.")
        import re
        v = re.sub(r"^https?://", "", v).rstrip("/").lower()
        return v

    @field_validator("abuseipdb_api_key", "virustotal_api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import re
        if not re.match(r'^[A-Za-z0-9\-_]{1,128}$', v):
            raise ValueError("Invalid API key format.")
        return v

class VerifyKeyRequest(BaseModel):
    """What the frontend sends to verify an API key."""
    service: str
    api_key: str

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"abuseipdb", "virustotal"}:
            raise ValueError("Service must be 'abuseipdb' or 'virustotal'.")
        return v

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("API key cannot be empty.")
        return v

class BatchScanRequest(BaseModel):
    """What the frontend sends when scanning multiple targets at once."""
    targets: list[str]
    mode: str = "fast"
    include_reputation: bool = True
    parallel: bool = True
    module: str | None = None
    port_range: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ALLOWED_MODES:
            raise ValueError(f"Invalid mode '{v}'.")
        return v

    @field_validator("module")
    @classmethod
    def validate_module(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ALLOWED_MODULES:
            raise ValueError(f"Unknown module '{v}'.")
        return v

    @field_validator("port_range")
    @classmethod
    def validate_port_range(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in ALLOWED_PORT_RANGES:
            raise ValueError(f"Invalid port_range '{v}'.")
        return v


class ModuleBatchRequest(BaseModel):
    """
    What the frontend sends for a "Single Check" page's multi-target mode
    (e.g. running just AbuseIPDB against up to 20 IPs/domains at once).

    Deliberately separate from BatchScanRequest — this never runs a full
    scan and never sets is_batch, so it can't be affected by (or affect)
    the full-scan aggressive/reputation gating in scan_config.py.
    """
    targets: list[str]
    module: str
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("module")
    @classmethod
    def validate_module(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in module_batch.SUPPORTED_BATCH_MODULES:
            raise ValueError(
                f"Module '{v}' is not supported for batch checks. "
                f"Supported: {sorted(module_batch.SUPPORTED_BATCH_MODULES)}"
            )
        return v

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        cleaned = module_batch.normalize_targets(v)
        if not cleaned:
            raise ValueError("At least one non-empty target is required.")
        if len(cleaned) > module_batch.MAX_MODULE_BATCH_TARGETS:
            raise ValueError(
                f"Too many targets: {len(cleaned)}. "
                f"Maximum is {module_batch.MAX_MODULE_BATCH_TARGETS} per batch check."
            )
        return cleaned



@app.get("/")
async def root():
    """Homepage endpoint — just returns basic info about the API."""
    return {
        "service": "Recon Scanner API",
        "version": "1.1.0",
        "status": "online",
        "endpoints": {
            "/scan": "POST - Scan a single target",
            "/scan/batch": "POST - Scan multiple targets",
            "/health": "GET - Health check",
        },
    }


@app.get("/health")
async def health():
    """Simple health check — if this responds, the server is running."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


def sanitize_surrogates(val: Any) -> Any:
    """
    Cleans up invalid unicode characters that would crash JSON serialization.
    Some WHOIS/DNS responses contain broken characters — this removes them.
    """
    if isinstance(val, str):
        return "".join(c for c in val if not (0xD800 <= ord(c) <= 0xDFFF))
    elif isinstance(val, dict):
        return {sanitize_surrogates(k): sanitize_surrogates(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_surrogates(x) for x in val]
    return val


async def _safe_module(coro: Coroutine, timeout_key: str, module_name: str, extra_timeout: float = 0) -> Any:
    """
    Runs a scanner module with a timeout limit.
    If the module crashes or takes too long, it returns an error dict
    instead of crashing the whole scan.

    extra_timeout (default 0, so every existing call site is unaffected)
    exists for the one case where a module's own *internal* timeout is set
    to the exact same value as this outer one: port_scan.py was fixed to
    gracefully return whatever real port data it had collected when its
    own internal deadline hit, instead of discarding everything — but that
    fix only works if the internal logic actually gets to run its
    return-partial-results path before this outer wrapper gives up too.
    With both set to an identical timeout, it's a race with no guaranteed
    winner. Verified directly: a 10-target Deep batch at concurrency 5
    produced 5 hard "Port scan did not respond within 120s" failures where
    the scan had almost certainly already computed a real partial result
    that this outer timeout was cancelling before it could be returned.
    """
    timeout = TIMEOUTS.get(timeout_key, 30) + extra_timeout
    return await with_timeout(coro, timeout, module_name)


# Error codes worth retrying for the curated fast-module set in run_scan()'s
# task dict — genuinely ambiguous, "couldn't get a clean signal" outcomes,
# not confirmed facts. Started as TIMEOUT-only; widened after directly
# observing (a 10-target concurrent Deep batch, before vs. after
# comparison) that two of the three still-failing cases weren't outer
# with_timeout() timeouts at all: geo_ip completed within its own budget
# but had all 4 of its own internal providers fail at once
# (API_UNREACHABLE), and ssl_certificate hit a one-off DNS resolution
# failure (DNS_RESOLUTION_FAILED) — both are exactly as transient as an
# outright timeout, just surfaced through a different code path.
#
# INVALID_RESPONSE added after a real case: abuseipdb.py's catch-all
# "none of our attempts returned usable data" branch (not a specific
# unauthorized/rate-limited/timeout signal — genuinely just "didn't work,
# unclear why") produced this code for discord.com in a live batch, and
# was NOT retried under the old set. Verified directly seconds later: the
# exact same IP, queried fresh, returned a completely normal, valid
# AbuseIPDB response — proving that specific failure was transient, not
# AbuseIPDB genuinely rejecting the IP as invalid/private despite what its
# message text says. Every current use of INVALID_RESPONSE across the
# retried modules (reputation.py's AbuseIPDB/VirusTotal branches) is this
# same kind of "couldn't parse/get a clean result" catch-all rather than a
# deterministic fact, so it belongs in this set for the same reason as the
# other three.
_MODULE_RETRY_WORTHY_ERROR_CODES = {
    ScanError.TIMEOUT,
    ScanError.API_UNREACHABLE,
    ScanError.DNS_RESOLUTION_FAILED,
    ScanError.INVALID_RESPONSE,
}


async def _safe_module_with_retry(
    coro_factory: Callable[[], Coroutine],
    timeout_key: str,
    module_name: str,
    retry_delays: tuple[float, ...] = (2.0,),
) -> Any:
    """
    Like _safe_module, but retries — with a *fresh* call each time, not a
    resumed coroutine (a timed-out coroutine can't be safely re-awaited) —
    when the most recent attempt comes back with an ambiguous,
    plausibly-transient result (see _MODULE_RETRY_WORTHY_ERROR_CODES), plus
    one further targeted case: whois_lookup.py returns status "not_found"
    both for a genuinely unregistered domain *and* for its own underlying
    WHOIS query silently coming back empty (its "if not w or not
    w.domain_name" branch) — these are indistinguishable from here, but
    verified directly: github.com, wikipedia.org, and apache.org (all
    obviously registered) each returned "not_found" once under concurrent
    batch load, then succeeded normally on a bare retry — so for whois
    specifically, "not_found" is treated as ambiguous too rather than
    trusted as fact.

    `retry_delays` controls how many attempts follow the first, and how
    long to wait before each: default is one retry after 2s (matches the
    original design). Modules cheap enough that a couple of extra fresh
    attempts cost little are given (2.0, 5.0) — two retries, backing off
    further the second time — because a single 2s-later retry sometimes
    still lands in the same contention window (observed directly: a
    10-target concurrent Deep batch where geo_ip failed on both the first
    attempt *and* the first retry for two targets, on a run that also
    included a domain with pathological wildcard-DNS-driven resource
    contention). A longer second gap gives real contention more room to
    clear before trying again.

    Deliberately a *new*, separate function from _safe_module rather than
    a parameter on it — _safe_module is also used by the single-check
    dispatch further down in this file, which this retry behavior should
    not affect. Only used here, in run_scan()'s own task dict.

    Includes abuseipdb, virustotal, and http_availability as of this
    round — an earlier version of this docstring assumed those three
    already had enough internal resilience (their own per-request/429
    retry logic) to not need this. Verified directly that assumption was
    wrong: their internal retries only cover a slow-but-responding
    request (e.g. a 429), not the whole call hanging until the *outer*
    with_timeout() budget expires under real concurrent batch load — which
    is exactly what was observed for several targets in a 10-target Deep
    batch. An outer retry after a fresh delay is a different, additive
    layer, not a redundant one. virustotal keeps only a single retry
    (default retry_delays) since each attempt already costs ~16s of
    proactive rate-limit pacing — doubling that further has a worse
    cost/benefit ratio than for the other, cheaper modules.

    Still deliberately NOT applied to the long-running aggressive modules
    (subdomains, directories, email_gather) or to port_scan — doubling
    those risks exceeding the full-scan-batch orchestrator's own
    per-target ceiling, and port_scan now returns its real partial results
    on its own internal timeout (see port_scanner.py) rather than needing
    a whole-scan redo.
    """
    result = await _safe_module(coro_factory(), timeout_key, module_name)
    original_note = None
    for delay in retry_delays:
        should_retry = isinstance(result, dict) and (
            result.get("error_code") in _MODULE_RETRY_WORTHY_ERROR_CODES
            or (timeout_key == "whois" and result.get("status") == "not_found")
        )
        if not should_retry:
            break
        if original_note is None:
            original_note = result.get("error_message") or f"status: {result.get('status')}"
        # A delay before retrying, not an instant retry — verified directly
        # against a real failure (slack.com's WHOIS returning "not_found"
        # twice in a row during a real batch run, then succeeding 3/3 times
        # when tested standalone moments later): an immediate retry can
        # land in the exact same contention window that caused the first
        # failure (this module is one of several concurrent targets' many
        # modules all competing at once), so it doesn't actually improve
        # the odds. A pause lets that contention move past its peak.
        await asyncio.sleep(delay)
        result = await _safe_module(coro_factory(), timeout_key, module_name)
    if original_note is not None and isinstance(result, dict):
        result["retried"] = True
        result["first_attempt_note"] = (
            f"First attempt didn't get a clean result ({original_note[:150]}) — "
            f"this is the result of a later, fresh attempt."
        )
    return result


async def run_scan(
    target: str,
    mode: str,
    include_reputation: bool,
    module: str | None = None,
    port_range: str | None = None,
    abuseipdb_api_key: str | None = None,
    virustotal_api_key: str | None = None,
    is_batch: bool = False,
) -> dict:
    """
    THE MAIN SCAN FUNCTION — orchestrates all reconnaissance modules.

    Behavior depends purely on scan mode (is_batch no longer changes which
    modules run — see should_include_aggressive_modules/should_include_reputation_checks
    in utils/scan_config.py):
    - Fast/Standard: Skip aggressive + reputation modules (safe, fast, no blocking)
    - Deep/Detailed: Run ALL modules including aggressive + reputation, whether
      this is a solo scan or one target inside a batch. Batch safety comes from
      the batch's own concurrency cap plus each module's internal rate limiter
      (VirusTotal/AbuseIPDB pacing and email_gather's concurrency cap live in
      the modules themselves, so they protect every caller automatically).

    Args:
        target: Domain or IP to scan
        mode: Scan mode (fast, standard, deep, detailed)
        include_reputation: Whether to include VirusTotal/AbuseIPDB checks
        module: If set, run ONLY this module (ignores mode)
        port_range: Port range for port scanner
        abuseipdb_api_key: API key for AbuseIPDB
        virustotal_api_key: API key for VirusTotal
        is_batch: True if this scan is part of a batch (subdomain-batch or
            full-scan-batch) — used for timeout scaling and logging only

    Returns:
        dict with scan results

    Module Behavior:
    - Passive modules (DNS, WHOIS, SSL, GeoIP, headers, tech): Always run
    - Aggressive/slow modules (port_scan, directories, waf_detect, subdomains,
      cloud_provider): Only if mode="deep"/"detailed" —
      subdomains and cloud_provider moved here because subdomains alone
      routinely takes 40-50s (15+ OSINT sources + CLI tools + wordlist
      brute-force + permutation discovery), which was making every Standard
      scan pay that cost even though nothing else in Standard needs it.
    - Reputation checks (AbuseIPDB, VirusTotal): Only if mode="deep"/"detailed"
    """
    start_time = time.time()
    target = target.strip().lower()

    validation = is_valid_input(target)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail=validation["error"])

    try:
        resolved = await resolve_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if module is None and resolved.get("is_domain") and not resolved.get("ip"):
        # A failure right here cascades far worse than any individual
        # module's own failure: every IP-dependent module below
        # (geo_ip, ssl, shodan, abuseipdb, port_scan, reverse_dns,
        # cloud_provider — 7 modules) inherits "no IP" and has nothing
        # left to retry against. Verified directly (a 10-target Deep
        # batch): resolve_target() — which already tries dnspython,
        # Google/Cloudflare DNS, and socket.gethostbyname sequentially —
        # still failed outright, once, for a definitely-registered,
        # definitely-resolvable domain (salesforce.com), taking out 7
        # otherwise-healthy modules in one shot on a run with heavy
        # concurrent DNS load from other targets. One retry here, after
        # a short delay, is far higher-leverage than retrying each of
        # those 7 modules individually after they've already inherited
        # "no IP". Scoped to module is None (full scans, solo or
        # batched) — never affects single-module-check timing/behavior.
        await asyncio.sleep(2.0)
        try:
            resolved = await resolve_target(target)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    ip_address = resolved["ip"]
    is_domain = resolved["is_domain"]

    resolved_domain = None
    if is_domain:
        resolved_domain = target
    elif ip_address:
        try:
            rdns_result = await _safe_module(dns_recon.reverse_dns(ip_address), "reverse_dns", "Reverse DNS")
            if isinstance(rdns_result, dict) and rdns_result.get("status") == "ok":
                resolved_domain = rdns_result.get("hostname")
        except Exception:
            pass

    chosen_range = str(port_range or mode).strip().lower()
    if chosen_range in ("1-65535", "full", "65535", "all"):
        port_scan_key = "port_scan_full"
    elif chosen_range in ("1-1024", "1000", "detailed"):
        port_scan_key = "port_scan_detailed"
    else:
        port_scan_key = "port_scan_fast"

    ip_resolution_error = error_response(
        ScanError.DNS_RESOLUTION_FAILED,
        f"Domain '{target}' could not be resolved to an IP address. IP-dependent check skipped."
    )

    # Three retries (2s, 5s, then 10s) for the cheap, single-external-call
    # modules — verified directly that even two retries can still both
    # land badly: a live batch had shodan_intel and whois both exhaust
    # this budget on discord.com and still fail, then work perfectly on a
    # fresh call moments later — proving the failures were real but
    # short-lived, just outlasting a 2s+5s retry window. A third attempt
    # with a longer final backoff gives a genuinely brief blip more room
    # to clear without meaningfully risking the per-target time budget:
    # worst case this adds ~17s to a single module's own timeout, on a
    # target whose overall Deep-mode budget is 240s, and it only fires at
    # all when a module is already failing.
    _CHEAP_RETRY_DELAYS = (2.0, 5.0, 10.0)

    tasks: dict[str, Any] = {
        "geo_ip": _safe_module_with_retry(lambda: geo_ip.lookup(ip_address), "geo_ip", "GeoIP", retry_delays=_CHEAP_RETRY_DELAYS) if ip_address else asyncio.sleep(0, result=ip_resolution_error),
        "http_headers": _safe_module(http_headers.fetch(target), "http_headers", "HTTP headers"),
        "ssl_certificate": _safe_module_with_retry(lambda: ssl_check.get_certificate(target), "ssl", "SSL check", retry_delays=_CHEAP_RETRY_DELAYS),
        "web_technologies": _safe_module(web_tech.detect(target), "web_tech", "Web tech detection"),
        "http_availability": _safe_module_with_retry(lambda: http_availability.check(target), "http_availability", "HTTP Availability"),
        "shodan_intel": _safe_module_with_retry(lambda: shodan_intel.lookup(ip_address), "shodan", "Shodan Intel", retry_delays=_CHEAP_RETRY_DELAYS) if ip_address else asyncio.sleep(0, result=ip_resolution_error),

        "waf_detect": _safe_module(waf_detect.detect(target), "waf_detect", "WAF Detection"),
        "cms_fingerprint": _safe_module(cms_fingerprint.detect(target), "cms_fingerprint", "CMS Fingerprinting"),
    }

    if resolved_domain:
        tasks["dns_records"] = _safe_module_with_retry(lambda: dns_recon.get_all_records(resolved_domain), "dns", "DNS records", retry_delays=_CHEAP_RETRY_DELAYS)
        tasks["whois"] = _safe_module_with_retry(lambda: whois_lookup.lookup(resolved_domain), "whois", "WHOIS", retry_delays=_CHEAP_RETRY_DELAYS)
    else:
        tasks["dns_records"] = asyncio.sleep(0, result=skip_response("Target is an IP and could not be reverse-resolved to a domain, no DNS records to fetch"))
        tasks["whois"] = asyncio.sleep(0, result=skip_response("Target is an IP and could not be reverse-resolved to a domain, no WHOIS to fetch"))

    include_aggressive = should_include_aggressive_modules(mode, is_batch)
    include_reputation = should_include_reputation_checks(mode, is_batch, include_reputation)

    logger.info(f"Scan config: mode={mode}, is_batch={is_batch}, include_aggressive={include_aggressive}, include_reputation={include_reputation}")

    if include_reputation:
        logger.debug("Including reputation checks (AbuseIPDB, VirusTotal)")
        tasks["abuseipdb"] = _safe_module_with_retry(lambda: reputation.check_abuseipdb(ip_address, abuseipdb_api_key), "abuseipdb", "AbuseIPDB", retry_delays=_CHEAP_RETRY_DELAYS) if ip_address else asyncio.sleep(0, result=ip_resolution_error)
        # Single retry only (default retry_delays) — each VirusTotal attempt
        # already costs ~16s of proactive rate-limit pacing, so a second
        # retry's cost/benefit is worse than for the other cheap modules.
        tasks["virustotal"] = _safe_module_with_retry(lambda: reputation.check_virustotal(target if is_domain else ip_address, is_domain, virustotal_api_key), "virustotal", "VirusTotal")
    else:
        logger.debug("Skipping reputation checks (AbuseIPDB, VirusTotal) for safety/speed")
        if str(mode).lower() in ["standard", "fast"]:
            reason = f"Reputation checks only run in deep/detailed mode (this scan is {mode})"
        else:
            reason = "Reputation checks not enabled for this scan mode"
        tasks["abuseipdb"] = asyncio.sleep(0, result=skip_response(reason))
        tasks["virustotal"] = asyncio.sleep(0, result=skip_response(reason))

    if include_aggressive:
        logger.debug("Including aggressive modules (port_scan, directories, waf_detect, subdomains, cloud_provider)")
        tasks["port_scan"] = _safe_module(port_scanner.scan(ip_address, mode=port_range or mode, target=target, timing_template="T3_FULLSCAN"), port_scan_key, "Port scan", extra_timeout=20) if ip_address else asyncio.sleep(0, result=ip_resolution_error)
        tasks["directories"] = _safe_module(directory_enum.enumerate(target), "directories", "Directory enum")
        tasks["reverse_dns"] = _safe_module_with_retry(lambda: dns_recon.reverse_dns(ip_address), "reverse_dns", "Reverse DNS", retry_delays=_CHEAP_RETRY_DELAYS) if ip_address else asyncio.sleep(0, result=ip_resolution_error)
        tasks["email_gather"] = _safe_module(email_gather.gather(resolved_domain or target), "email_gather", "Email Gather") if resolved_domain else asyncio.sleep(0, result=skip_response("Email gathering requires a domain name, not a raw IP"))
        tasks["subdomains"] = _safe_module(subdomain_finder.find(resolved_domain, is_single_module=False, scan_mode=mode), "subdomains", "Subdomains") if resolved_domain else asyncio.sleep(0, result=skip_response("Target is an IP and could not be reverse-resolved to a domain, no subdomains to enumerate"))
        tasks["cloud_provider"] = _safe_module_with_retry(lambda: cloud_provider.detect(ip_address), "cloud_provider", "Cloud Provider", retry_delays=_CHEAP_RETRY_DELAYS) if ip_address else asyncio.sleep(0, result=ip_resolution_error)
    else:
        logger.debug("Skipping aggressive modules (port_scan, directories, subdomains, cloud_provider) for safety/speed")
        if str(mode).lower() in ["standard", "fast"]:
            reason = f"Aggressive modules only run in deep/detailed mode (this scan is {mode})"
        else:
            reason = "Aggressive modules not enabled for this scan mode"
        tasks["port_scan"] = asyncio.sleep(0, result=skip_response(reason))
        tasks["directories"] = asyncio.sleep(0, result=skip_response(reason))
        tasks["reverse_dns"] = asyncio.sleep(0, result=skip_response("Reverse DNS only runs in detailed mode"))
        tasks["email_gather"] = asyncio.sleep(0, result=skip_response("Email gathering only runs in detailed mode"))
        tasks["subdomains"] = asyncio.sleep(0, result=skip_response("Subdomain enumeration only runs in deep/detailed mode"))
        tasks["cloud_provider"] = asyncio.sleep(0, result=skip_response("Cloud provider detection only runs in deep/detailed mode"))

    if module:
        if module in ("standalone_port_scanner", "port_scanner", "port_scan"):
            chosen_range = port_range or "top100"
            max_timeout = 360 if str(chosen_range).lower() in ("1-65535", "full", "65535") else 120
            tasks = {
                module: with_timeout(
                    port_scanner.scan(ip_address, mode=chosen_range, target=target),
                    max_timeout,
                    "Port scan"
                ) if ip_address else asyncio.sleep(0, result=ip_resolution_error)
            }
        elif module == "directories":
            tasks = {"directories": _safe_module(directory_enum.enumerate(target), "directories", "Directory enum")}
        elif module == "reverse_dns":
            if is_domain:
                raise HTTPException(status_code=400, detail=f"'{target}' is a domain — reverse DNS requires an IP address.")
            reason = classify_non_public_ip(ip_address)
            if reason:
                raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"reverse_dns": _safe_module(dns_recon.reverse_dns(ip_address), "reverse_dns", "Reverse DNS")}
        elif module == "abuseipdb":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"abuseipdb": _safe_module(reputation.check_abuseipdb(ip_address, abuseipdb_api_key), "abuseipdb", "AbuseIPDB") if ip_address else asyncio.sleep(0, result=ip_resolution_error)}
        elif module == "virustotal":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"virustotal": _safe_module(
                reputation.check_virustotal(target if is_domain else ip_address, is_domain, virustotal_api_key),
                "virustotal", "VirusTotal"
            )}
        elif module == "dns_records":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            if not resolved_domain:
                raise HTTPException(status_code=400, detail="Cannot fetch DNS records: target is an IP and could not be resolved to a domain.")
            tasks = {"dns_records": _safe_module(dns_recon.get_all_records(resolved_domain), "dns", "DNS records")}
        elif module == "ssl_certificate":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"ssl_certificate": _safe_module(ssl_check.get_certificate(target), "ssl", "SSL check")}
        elif module == "shodan_intel":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"shodan_intel": _safe_module(shodan_intel.lookup(ip_address), "shodan", "Shodan Intel") if ip_address else asyncio.sleep(0, result=ip_resolution_error)}
        elif module == "whois":
            if not resolved_domain:
                raise HTTPException(status_code=400, detail="Cannot fetch WHOIS details: target is an IP and could not be resolved to a domain.")
            tasks = {"whois": _safe_module(whois_lookup.lookup(resolved_domain), "whois", "WHOIS")}
        elif module == "subdomains":
            if not resolved_domain:
                raise HTTPException(status_code=400, detail="Cannot run subdomain enumeration: target is an IP and could not be resolved to a domain.")
            tasks = {"subdomains": with_timeout(subdomain_finder.find(resolved_domain, is_single_module=True), TIMEOUTS["subdomains"], "Subdomains")}
        elif module == "cloud_provider":
            tasks = {"cloud_provider": _safe_module(cloud_provider.detect(ip_address), "cloud_provider", "Cloud Provider") if ip_address else asyncio.sleep(0, result=ip_resolution_error)}
        elif module == "waf_detect":
            tasks = {"waf_detect": _safe_module(waf_detect.detect(target), "waf_detect", "WAF Detection")}
        elif module == "cms_fingerprint":
            tasks = {"cms_fingerprint": _safe_module(cms_fingerprint.detect(target), "cms_fingerprint", "CMS Fingerprinting")}
        elif module == "http_availability":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"http_availability": _safe_module(http_availability.check(target), "http_availability", "HTTP Availability")}
        elif module == "http_headers":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"http_headers": _safe_module(http_headers.fetch(target), "http_headers", "HTTP headers")}
        elif module == "web_technologies":
            if not is_domain:
                reason = classify_non_public_ip(ip_address)
                if reason:
                    raise HTTPException(status_code=400, detail=f"'{target}' is a {reason}, not a public IP — this check only applies to public internet targets.")
            tasks = {"web_technologies": _safe_module(web_tech.detect(target), "web_tech", "Web tech detection")}
        elif module == "email_gather":
            if not is_domain:
                raise HTTPException(status_code=400, detail=f"'{target}' is an IP address — email harvesting requires a domain name.")
            tasks = {"email_gather": _safe_module(email_gather.gather(resolved_domain), "email_gather", "Email Gather")}
        elif module in tasks:
            tasks = {module: tasks[module]}
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scan module: {module}")

    all_keys = list(tasks.keys())
    all_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    output = {}
    for key, result in zip(all_keys, all_results):
        if isinstance(result, Exception):
            output[key] = error_response(
                ScanError.UNKNOWN_ERROR,
                f"Module '{key}' raised unhandled exception: {type(result).__name__}: {str(result)[:150]}",
                module=key,
            )
        else:
            output[key] = result

    summary = {"ok": [], "skipped": [], "error": [], "partial": []}
    for key, res in output.items():
        if not isinstance(res, dict):
            summary["ok"].append(key)
            continue
        s = res.get("status")
        if s == "error":
            summary["error"].append({
                "module": key,
                "code": res.get("error_code"),
                "message": res.get("error_message"),
            })
        elif s == "skipped":
            summary["skipped"].append({"module": key, "reason": res.get("reason")})
        elif s == "partial":
            summary["partial"].append({"module": key, "note": res.get("note") or res.get("error_message")})
        else:
            summary["ok"].append(key)

    duration = round(time.time() - start_time, 2)

    return sanitize_surrogates({
        "target": target,
        "resolved_ip": ip_address,
        "is_domain": is_domain,
        "scan_mode": mode,
        "scan_duration_seconds": duration,
        "scanned_at": datetime.utcnow().isoformat(),
        "module_summary": summary,
        "results": output,
    })


@app.post("/verify-key")
async def verify_api_key(
    request: VerifyKeyRequest,
    current_user: User = Depends(get_current_user)
):
    """Verifies whether a provided AbuseIPDB or VirusTotal API key is valid."""
    service = request.service
    key = request.api_key.strip()

    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if service == "abuseipdb":
                url = "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1"
                headers = {"Key": key, "Accept": "application/json"}
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return {"valid": True, "service": "abuseipdb", "message": "AbuseIPDB API key is valid and working!"}
                    elif resp.status in (401, 403):
                        return {"valid": False, "service": "abuseipdb", "message": "Invalid AbuseIPDB API key (Unauthorized)."}
                    else:
                        return {"valid": False, "service": "abuseipdb", "message": f"Verification returned HTTP {resp.status}."}

            elif service == "virustotal":
                url = "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"
                headers = {"x-apikey": key, "Accept": "application/json"}
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return {"valid": True, "service": "virustotal", "message": "VirusTotal API key is valid and working!"}
                    elif resp.status in (401, 403):
                        return {"valid": False, "service": "virustotal", "message": "Invalid VirusTotal API key (Unauthorized)."}
                    else:
                        return {"valid": False, "service": "virustotal", "message": f"Verification returned HTTP {resp.status}."}

    except Exception as e:
        return {"valid": False, "service": service, "message": f"Verification error: {str(e)[:100]}"}


@app.post("/scan")
async def scan_target(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """API endpoint to scan a single target. Requires a valid JWT Bearer token."""
    try:
        res = await run_scan(
            request.target,
            request.mode,
            request.include_reputation,
            request.module,
            request.port_range,
            request.abuseipdb_api_key,
            request.virustotal_api_key
        )

        try:
            scan_entry = ScanHistory(
                user_id=current_user.id,
                target=request.target,
                mode=request.mode,
                module=request.module,
                result_json=json.dumps(res)
            )
            db.add(scan_entry)
            db.commit()
            db.refresh(scan_entry)
            res["scan_id"] = scan_entry.id
        except Exception as db_err:
            print(f"Failed to persist scan history in DB: {db_err}")

        return res
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fatal scan error: {type(e).__name__}: {str(e)[:200]}")


@app.post("/scan/module-batch")
async def scan_module_batch(
    request: ModuleBatchRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Runs a single module (currently just AbuseIPDB) against up to 20 targets
    at once, at most 4 concurrently. Completely isolated from run_scan() and
    batch_scanner.py — does not touch full-scan behavior in any way.

    Response shape matches what the frontend's existing batch-results
    rendering already expects: {"results": [...], "batch_size": N}.
    """
    try:
        results = await module_batch.run_module_batch(
            targets=request.targets,
            module=request.module,
            abuseipdb_api_key=request.abuseipdb_api_key,
            virustotal_api_key=request.virustotal_api_key,
        )
        return {"results": results, "batch_size": len(request.targets), "module": request.module}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fatal module batch error: {type(e).__name__}: {str(e)[:200]}")



def _format_timestamp(dt):
    if not dt:
        return None
    iso = dt.isoformat()
    if not iso.endswith("Z") and "+" not in iso and "-" not in iso[10:]:
        iso += "Z"
    return iso


@app.get("/history/scans")
def get_scan_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetch scan history records for the currently authenticated user, including batch scan info."""
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.timestamp.desc())
        .limit(50)
        .all()
    )
    results = []
    for r in records:
        try:
            parsed_data = json.loads(r.result_json)
        except Exception:
            parsed_data = None

        batch_info = None
        if r.batch_scan:
            batch_info = {
                "batch_id": r.batch_scan.id,
                "status": r.batch_scan.status,
                "total_subdomains": r.batch_scan.total_subdomains,
                "completed_scans": r.batch_scan.completed_scans,
                "failed_scans": r.batch_scan.failed_scans,
                "started_at": _format_timestamp(r.batch_scan.started_at),
                "completed_at": _format_timestamp(r.batch_scan.completed_at)
            }

        results.append({
            "id": r.id,
            "target": r.target,
            "mode": r.mode,
            "module": r.module,
            "timestamp": _format_timestamp(r.timestamp),
            "data": parsed_data,
            "batch": batch_info
        })
    return results


@app.delete("/history/scans/{scan_id}")
def delete_scan_history_item(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a specific scan history item for the current user."""
    item = (
        db.query(ScanHistory)
        .filter(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Scan history item not found.")
    db.delete(item)
    db.commit()
    return {"message": "Scan history item deleted."}


@app.delete("/history/scans")
def clear_all_scan_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Clear all scan history items for the current user."""
    db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).delete()
    db.commit()
    return {"message": "All scan history cleared."}


@app.get("/history/logins")
def get_login_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetch login history audit records for the currently authenticated user."""
    records = (
        db.query(LoginHistory)
        .filter(LoginHistory.user_id == current_user.id)
        .order_by(LoginHistory.timestamp.desc())
        .limit(30)
        .all()
    )
    results = []
    for r in records:
        results.append({
            "id": r.id,
            "timestamp": _format_timestamp(r.timestamp),
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "session_type": r.session_type or "Web Session"
        })
    return results


@app.post("/scan/batch")
async def batch_scan(request: BatchScanRequest, _: User = Depends(get_current_user)):
    """API endpoint to scan multiple targets at once. Requires a valid JWT Bearer token."""
    cleaned_targets = [t.strip() for t in request.targets if t.strip()]
    if not cleaned_targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    if len(cleaned_targets) > 20:
        raise HTTPException(status_code=400, detail="Maximum only 20 allowed at once per scan")
    request.targets = cleaned_targets

    start_time = time.time()

    async def safe_scan(t):
        """Wrapper that catches errors per-target so one failure doesn't kill the batch."""
        try:
            return await run_scan(
                t,
                request.mode,
                request.include_reputation,
                request.module,
                request.port_range,
                request.abuseipdb_api_key,
                request.virustotal_api_key
            )


        except HTTPException as e:
            return {"target": t, "error": e.detail, "http_status": e.status_code}
        except Exception as e:
            return {"target": t, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    if request.parallel:
        results = await asyncio.gather(*[safe_scan(t) for t in request.targets])
    else:
        results = []
        for t in request.targets:
            results.append(await safe_scan(t))

    total_duration = round(time.time() - start_time, 2)

    return sanitize_surrogates({
        "batch_size": len(request.targets),
        "parallel": request.parallel,
        "total_duration_seconds": total_duration,
        "results": results,
    })



class FullScanBatchRequest(BaseModel):
    """Request to start a full Standard/Deep scan across up to
    MAX_FULL_SCAN_BATCH_TARGETS user-typed targets. Deliberately separate
    from BatchScanRequest (the
    unused synchronous /scan/batch) and from SubdomainBatchRequest (which
    batches subdomains discovered by one prior scan, always is_batch=True) —
    this always runs each target as a genuinely full, unmodified Standard or
    Deep scan (is_batch=False internally); safety comes from the
    concurrency cap and the modules' own rate limiters instead."""
    targets: list[str]
    mode: str = "fast"
    include_reputation: bool = True
    max_concurrent: int | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ALLOWED_MODES:
            raise ValueError(f"Invalid mode '{v}'. Must be one of: {ALLOWED_MODES}")
        return v

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        # Local import: full_scan_batch.py imports run_scan from this module
        # at its own top level, so importing it back at main.py's module
        # level here would be circular.
        from full_scan_batch import MAX_FULL_SCAN_BATCH_TARGETS

        cleaned = module_batch.normalize_targets(v, max_targets=MAX_FULL_SCAN_BATCH_TARGETS)
        if not cleaned:
            raise ValueError("At least one non-empty target is required.")
        if len(cleaned) > MAX_FULL_SCAN_BATCH_TARGETS:
            raise ValueError(
                f"Too many targets: {len(cleaned)}. "
                f"Maximum is {MAX_FULL_SCAN_BATCH_TARGETS} per batch scan."
            )
        return cleaned


class SubdomainBatchRequest(BaseModel):
    """Request to start batch scanning of discovered subdomains."""
    parent_scan_id: int
    subdomains: list[str]
    mode: str = "detailed"
    max_concurrent: int = 10
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v.lower() not in {"fast", "detailed"}:
            raise ValueError("mode must be 'fast' or 'detailed'")
        return v.lower()

    @field_validator("max_concurrent")
    @classmethod
    def validate_concurrent(cls, v: int) -> int:
        if not 1 <= v <= 10:
            raise ValueError("max_concurrent must be between 1 and 10")
        return v

    @model_validator(mode="after")
    def clamp_concurrent_for_detailed(self) -> "SubdomainBatchRequest":
        # Detailed mode now runs the full aggressive module set per subdomain
        # (port_scan, directory enum, subdomain CLI tools, email harvesting) —
        # each concurrent target can spawn OS subprocesses and hit rate-limited
        # APIs. Same ceiling full_scan_batch.py uses for its own deep/detailed
        # concurrency (MAX_CONCURRENCY["detailed"] = 5), for the same reason.
        if self.mode == "detailed" and self.max_concurrent > 5:
            self.max_concurrent = 5
        return self


@app.post("/scan/start-subdomain-batch")
async def start_subdomain_batch(
    request: SubdomainBatchRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """
    Start batch scanning of discovered subdomains (optimized for 64GB RAM systems).
    - Deduplicates subdomains automatically
    - Limits to max_concurrent parallel scans (default 10, configurable 1-10)
    - Respects VirusTotal rate limiting (16 sec between requests)
    - Retry logic with exponential backoff (3 attempts per subdomain)
    - Robust database session management prevents connection pool exhaustion
    - No timeouts, hangs, or bottlenecks
    """
    from batch_scanner import start_batch_scan

    if not request.subdomains:
        raise HTTPException(status_code=400, detail="No subdomains provided")

    parent_scan = db.query(ScanHistory).filter(ScanHistory.id == request.parent_scan_id).first()
    if not parent_scan:
        raise HTTPException(status_code=404, detail="Parent scan not found")

    batch = BatchScan(
        parent_scan_id=request.parent_scan_id,
        status="pending",
        total_subdomains=len(set(request.subdomains))
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)

    task = asyncio.create_task(
        start_batch_scan(
            batch_scan_id=batch.id,
            subdomains=request.subdomains,
            mode=request.mode,
            max_concurrent=request.max_concurrent,
            abuseipdb_api_key=request.abuseipdb_api_key,
            virustotal_api_key=request.virustotal_api_key
        )
    )
    running_batch_tasks[batch.id] = task
    task.add_done_callback(lambda t, bid=batch.id: running_batch_tasks.pop(bid, None))

    return {
        "batch_id": batch.id,
        "status": "started",
        "unique_subdomains": len(set(request.subdomains)),
        "message": f"Batch scan started for {len(set(request.subdomains))} unique subdomains"
    }


@app.post("/scan/batch-cancel/{batch_id}")
async def cancel_subdomain_batch(
    batch_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """
    Cancel a running batch subdomain scan.
    Stops the asyncio task immediately (any in-flight subdomain scans are
    abandoned) and marks the batch + still-pending/running subdomains as
    'cancelled' so the UI reflects the stopped state.
    """
    batch = db.query(BatchScan).filter(BatchScan.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    task = running_batch_tasks.get(batch_id)
    if task and not task.done():
        task.cancel()

    batch.status = "cancelled"
    batch.completed_at = datetime.utcnow()
    db.commit()

    db.query(SubdomainScan).filter(
        SubdomainScan.batch_scan_id == batch_id,
        SubdomainScan.status.in_(["pending", "running"])
    ).update({"status": "cancelled"}, synchronize_session=False)
    db.commit()

    return {"batch_id": batch_id, "status": "cancelled", "message": "Batch scan cancelled"}


@app.get("/scan/batch-progress/{batch_id}")
async def get_batch_progress(
    batch_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get real-time progress of a running batch scan."""
    batch = db.query(BatchScan).filter(BatchScan.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    sub_scans = db.query(SubdomainScan).filter(
        SubdomainScan.batch_scan_id == batch_id
    ).all()

    status_counts = {}
    for sub in sub_scans:
        status = sub.status
        status_counts[status] = status_counts.get(status, 0) + 1

    live_completed = status_counts.get("completed", 0)
    live_failed = status_counts.get("failed", 0) + status_counts.get("timeout", 0)
    processed = live_completed + live_failed

    return {
        "batch_id": batch_id,
        "status": batch.status,
        "total": batch.total_subdomains,
        "completed": live_completed,
        "failed": live_failed,
        "status_breakdown": status_counts,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "progress_percent": int((processed / batch.total_subdomains * 100) if batch.total_subdomains else 0),
        "subdomains": [
            {
                "subdomain": s.subdomain,
                "status": s.status,
                "resolved_ips": s.resolved_ips,
                "error": s.error_message
            }
            for s in sub_scans
        ]
    }


@app.get("/scan/batch-results/{batch_id}")
async def get_batch_results(
    batch_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get final results of a completed batch scan."""
    batch = db.query(BatchScan).filter(BatchScan.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    sub_scans = db.query(SubdomainScan).filter(
        SubdomainScan.batch_scan_id == batch_id
    ).all()

    results = []
    for sub in sub_scans:
        result = {
            "subdomain": sub.subdomain,
            "status": sub.status,
            "resolved_ips": json.loads(sub.resolved_ips) if sub.resolved_ips else [],
            "error": sub.error_message,
            "started_at": sub.started_at,
            "completed_at": sub.completed_at
        }
        if sub.result_json:
            result["scan_result"] = json.loads(sub.result_json)
        results.append(result)

    return sanitize_surrogates({
        "batch_id": batch_id,
        "status": batch.status,
        "total_subdomains": batch.total_subdomains,
        "completed_scans": batch.completed_scans,
        "failed_scans": batch.failed_scans,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "results": results
    })


@app.post("/scan/full-batch")
async def start_full_scan_batch_endpoint(
    request: FullScanBatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a full Standard/Deep scan across up to 20 user-typed targets.
    Returns immediately with a batch_id — poll /scan/full-batch-progress/{id}
    for live status, since a 20-target Deep batch can realistically take
    several minutes (each target runs every module a single Deep scan would,
    plus VirusTotal's own ~16s-per-request pacing across the whole batch)."""
    from full_scan_batch import start_full_scan_batch

    batch = FullScanBatch(
        user_id=current_user.id,
        mode=request.mode,
        include_reputation=request.include_reputation,
        status="pending",
        total_targets=len(request.targets),
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)

    task = asyncio.create_task(
        start_full_scan_batch(
            batch_id=batch.id,
            targets=request.targets,
            mode=request.mode,
            user_id=current_user.id,
            include_reputation=request.include_reputation,
            max_concurrent=request.max_concurrent,
            abuseipdb_api_key=request.abuseipdb_api_key,
            virustotal_api_key=request.virustotal_api_key,
        )
    )
    running_full_scan_batch_tasks[batch.id] = task
    task.add_done_callback(lambda t, bid=batch.id: running_full_scan_batch_tasks.pop(bid, None))

    return {
        "batch_id": batch.id,
        "status": "started",
        "total_targets": len(request.targets),
        "mode": request.mode,
        "message": f"Full scan batch started for {len(request.targets)} target(s)",
    }


@app.post("/scan/full-batch-cancel/{batch_id}")
async def cancel_full_scan_batch(
    batch_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel a running full-scan batch. Stops the asyncio task immediately
    (any in-flight target scan is abandoned) and marks the batch + still
    pending/running targets as 'cancelled'."""
    batch = db.query(FullScanBatch).filter(
        FullScanBatch.id == batch_id, FullScanBatch.user_id == current_user.id
    ).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    task = running_full_scan_batch_tasks.get(batch_id)
    if task and not task.done():
        task.cancel()

    batch.status = "cancelled"
    batch.completed_at = datetime.utcnow()
    db.commit()

    db.query(FullScanBatchTarget).filter(
        FullScanBatchTarget.batch_id == batch_id,
        FullScanBatchTarget.status.in_(["pending", "running"])
    ).update({"status": "cancelled"}, synchronize_session=False)
    db.commit()

    return {"batch_id": batch_id, "status": "cancelled", "message": "Full scan batch cancelled"}


@app.get("/scan/full-batch-progress/{batch_id}")
async def get_full_scan_batch_progress(
    batch_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get real-time progress of a running full-scan batch."""
    batch = db.query(FullScanBatch).filter(
        FullScanBatch.id == batch_id, FullScanBatch.user_id == current_user.id
    ).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    target_rows = db.query(FullScanBatchTarget).filter(
        FullScanBatchTarget.batch_id == batch_id
    ).all()

    status_counts = {}
    for row in target_rows:
        status_counts[row.status] = status_counts.get(row.status, 0) + 1

    live_completed = status_counts.get("completed", 0)
    live_failed = status_counts.get("failed", 0) + status_counts.get("timeout", 0)
    processed = live_completed + live_failed

    return {
        "batch_id": batch_id,
        "status": batch.status,
        "mode": batch.mode,
        "total": batch.total_targets,
        "completed": live_completed,
        "failed": live_failed,
        "status_breakdown": status_counts,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "progress_percent": int((processed / batch.total_targets * 100) if batch.total_targets else 0),
        "targets": [
            {"target": row.target, "status": row.status, "error": row.error_message}
            for row in target_rows
        ]
    }


@app.get("/scan/full-batch-results/{batch_id}")
async def get_full_scan_batch_results(
    batch_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get final results of a completed full-scan batch."""
    batch = db.query(FullScanBatch).filter(
        FullScanBatch.id == batch_id, FullScanBatch.user_id == current_user.id
    ).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch scan not found")

    target_rows = db.query(FullScanBatchTarget).filter(
        FullScanBatchTarget.batch_id == batch_id
    ).all()

    results = []
    for row in target_rows:
        result = {
            "target": row.target,
            "status": row.status,
            "error": row.error_message,
            "started_at": row.started_at,
            "completed_at": row.completed_at,
        }
        if row.result_json:
            result["scan_result"] = json.loads(row.result_json)
        results.append(result)

    return sanitize_surrogates({
        "batch_id": batch_id,
        "status": batch.status,
        "mode": batch.mode,
        "total_targets": batch.total_targets,
        "completed_scans": batch.completed_scans,
        "failed_scans": batch.failed_scans,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "results": results
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

