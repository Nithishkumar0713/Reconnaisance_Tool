"""
Web Technology Fingerprinting & Version Extraction Module.
Inspects HTTP response headers, cookies, meta tags, script sources, and page
content against a large technology signature catalog (backend/data/wappalyzer/
— see NOTICE in that folder for where this data comes from) to pinpoint
thousands of possible technologies along with version numbers, confidence
levels, and detection evidence.

About 46% of the catalog's ~7,200 technologies only carry a version/presence
signal on a live JS runtime property (e.g. `React.version`, `jQuery.fn.jquery`)
rather than anything visible in a static HTTP response — a plain aiohttp GET
can never see those. When a headless-browser pass is available (see
`_gather_js_properties`), this module renders the page once with Playwright
and reads those properties directly out of the live `window` object, merging
the result back into the same catalog-matching pipeline used for
headers/cookies/html/meta/scriptSrc.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import ssl as ssl_mod
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from utils.helpers import get_relaxed_ssl_context, get_safe_ssl_context
from utils.safety import TIMEOUTS, ScanError, error_response

logger = logging.getLogger(__name__)


def _url_host(target: str) -> str:
    """Formats `target` for embedding directly in a URL string. A bare IPv6
    literal (e.g. "2404:6800:4007:808::200e") is only valid on the wire —
    inside a URL it's ambiguous with the ":port" separator, so RFC 3986
    requires it be wrapped in brackets ("[2404:...::200e]"). Without this,
    yarl/aiohttp raises "Invalid URL: port can't be converted to integer"
    on any raw IPv6 target, which is a legitimate, reachable input here
    (classify_non_public_ip/is_valid_input both already accept public
    IPv6 addresses). Domains and IPv4 literals pass through unchanged."""
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        return target
    return f"[{target}]" if ip_obj.version == 6 else target



_HERE = os.path.dirname(os.path.abspath(__file__))
_CATALOG_DIR = os.path.join(os.path.dirname(_HERE), "data", "wappalyzer")
_CATALOG_RULES_DIR = os.path.join(_CATALOG_DIR, "technologies")
_CATALOG_CATEGORIES_PATH = os.path.join(_CATALOG_DIR, "categories.json")

_CATALOG_MATCH_BUDGET_SECONDS = 6.0
_CATALOG_MATCH_CHECK_EVERY = 200


class _RulePattern:
    __slots__ = ("regex", "version_template", "confidence")

    def __init__(self, regex: "re.Pattern[str] | None", version_template: str, confidence: int):
        self.regex = regex
        self.version_template = version_template
        self.confidence = confidence


def _parse_rule_pattern(raw: str) -> _RulePattern:
    """Catalog pattern format: "regex\\;version:\\1\\;confidence:50". A
    pattern that fails to compile under Python's `re` (a handful use regex
    features this catalog's own authoring tool supports but Python
    doesn't) becomes a pattern with regex=None rather than being dropped —
    for header/cookie/meta checks this is treated as "field is present" on
    its own (see _rule_field_hit), matching how the catalog is meant to
    degrade; for html/url/script checks (which scan a whole page rather
    than a single known field) an uncompilable pattern just never matches,
    since "matches everything" would be far too noisy there."""
    parts = raw.split("\\;")
    pattern = parts[0]
    version_template = ""
    confidence = 100
    for part in parts[1:]:
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        if key == "version":
            version_template = val
        elif key == "confidence":
            try:
                confidence = int(val)
            except ValueError:
                confidence = 100
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        regex = None
    return _RulePattern(regex, version_template, confidence)


def _parse_rule_pattern_list(raw: Any) -> list[_RulePattern]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    return [_parse_rule_pattern(str(item)) for item in items]


def _extract_rule_version(match: "re.Match[str] | None", version_template: str) -> str:
    if not version_template or not match:
        return ""

    def repl(m: "re.Match[str]") -> str:
        try:
            return match.group(int(m.group(1))) or ""
        except (IndexError, re.error):
            return ""

    try:
        return re.sub(r"\\(\d)", repl, version_template).strip()
    except re.error:
        return ""


def _compile_catalog_entry(name: str, entry: dict[str, Any], categories: dict[str, str]) -> dict[str, Any]:
    cat_ids = entry.get("cats") or []
    cat_names = [categories.get(str(c), str(c)) for c in cat_ids]

    implies_raw = entry.get("implies")
    implies: list[tuple[str, int]] = []
    if implies_raw:
        for item in (implies_raw if isinstance(implies_raw, list) else [implies_raw]):
            parts = str(item).split("\\;")
            implied_name = parts[0]
            confidence = 100
            for part in parts[1:]:
                if part.startswith("confidence:"):
                    try:
                        confidence = int(part.split(":", 1)[1])
                    except ValueError:
                        confidence = 100
            implies.append((implied_name, confidence))

    return {
        "name": name,
        "categories": cat_names,
        "description": entry.get("description", ""),
        "implies": implies,
        "url": _parse_rule_pattern_list(entry.get("url")),
        "headers": {k.lower(): _parse_rule_pattern_list(v) for k, v in (entry.get("headers") or {}).items()},
        "cookies": {k.lower(): _parse_rule_pattern_list(v) for k, v in (entry.get("cookies") or {}).items()},
        "html": _parse_rule_pattern_list(entry.get("html")),
        "meta": {k.lower(): _parse_rule_pattern_list(v) for k, v in (entry.get("meta") or {}).items()},
        "scriptSrc": _parse_rule_pattern_list(entry.get("scriptSrc")),
        # Property paths are case-sensitive JS identifiers (e.g.
        # "React.version", "$.fn.jquery") — unlike headers/cookies/meta,
        # never lowercase these.
        "js": {k: _parse_rule_pattern_list(v) for k, v in (entry.get("js") or {}).items()},
    }


_catalog_cache: dict[str, dict[str, Any]] | None = None


def _load_catalog() -> dict[str, dict[str, Any]]:
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache

    categories: dict[str, str] = {}
    try:
        with open(_CATALOG_CATEGORIES_PATH, "r", encoding="utf-8") as f:
            raw_cats = json.load(f)
        categories = {cat_id: cat.get("name", cat_id) for cat_id, cat in raw_cats.items()}
    except (OSError, json.JSONDecodeError):
        pass

    catalog: dict[str, dict[str, Any]] = {}
    if os.path.isdir(_CATALOG_RULES_DIR):
        for fname in sorted(os.listdir(_CATALOG_RULES_DIR)):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(_CATALOG_RULES_DIR, fname), "r", encoding="utf-8") as f:
                    chunk = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            for name, entry in chunk.items():
                catalog[name] = _compile_catalog_entry(name, entry, categories)

    _catalog_cache = catalog
    return catalog


_js_prop_paths_cache: list[str] | None = None


def _collect_js_property_paths() -> list[str]:
    """Every distinct JS property path referenced anywhere in the catalog
    (e.g. "React.version", "$.fn.jquery") — computed once and cached, so
    the browser only needs a single page.evaluate() call per scan to check
    all of them at once instead of one round-trip per technology."""
    global _js_prop_paths_cache
    if _js_prop_paths_cache is not None:
        return _js_prop_paths_cache

    catalog = _load_catalog()
    paths: set[str] = set()
    for entry in catalog.values():
        paths.update(entry.get("js", {}).keys())
    _js_prop_paths_cache = sorted(paths)
    return _js_prop_paths_cache


def _rule_field_hit(patterns: list[_RulePattern], value: str) -> tuple[bool, int, str]:
    for p in patterns:
        if p.regex is None:
            return True, p.confidence, ""
        m = p.regex.search(value)
        if m:
            return True, p.confidence, _extract_rule_version(m, p.version_template)
    return False, 0, ""


def _match_catalog(
    *,
    url: str = "",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    html: str = "",
    meta: dict[str, str] | None = None,
    script_srcs: list[str] | None = None,
    js_properties: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Evaluates every catalog entry's rules against the supplied signals
    and returns a confidence-sorted list of
    {name, categories, description, confidence, version, evidence}."""
    catalog = _load_catalog()
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    cookies = {k.lower(): v for k, v in (cookies or {}).items()}
    meta = {k.lower(): v for k, v in (meta or {}).items()}
    script_srcs = (script_srcs or [])[:150]
    js_properties = js_properties or {}  # case-sensitive keys — never lowercased

    results: dict[str, dict[str, Any]] = {}

    def record_hit(name: str, confidence: int, version: str, evidence: str) -> None:
        r = results.setdefault(name, {"name": name, "confidence": 0, "version": "", "evidence": []})
        if confidence > r["confidence"]:
            r["confidence"] = confidence
        if version:
            r["version"] = version
        if len(r["evidence"]) < 5 and evidence not in r["evidence"]:
            r["evidence"].append(evidence)

    deadline = time.monotonic() + _CATALOG_MATCH_BUDGET_SECONDS
    for i, (name, entry) in enumerate(catalog.items()):
        if i % _CATALOG_MATCH_CHECK_EVERY == 0 and time.monotonic() > deadline:
            break

        if entry["url"] and url:
            for p in entry["url"]:
                if p.regex is None:
                    continue
                m = p.regex.search(url)
                if m:
                    record_hit(name, p.confidence, _extract_rule_version(m, p.version_template), f"url: {url[:150]}")

        for hname, patterns in entry["headers"].items():
            val = headers.get(hname)
            if val is None:
                continue
            matched, confidence, version = _rule_field_hit(patterns, val)
            if matched:
                record_hit(name, confidence, version, f"header: {hname}: {val[:100]}")

        for cname, patterns in entry["cookies"].items():
            val = cookies.get(cname)
            if val is None:
                continue
            matched, confidence, version = _rule_field_hit(patterns, val)
            if matched:
                record_hit(name, confidence, version, f"cookie: {cname}")

        for mname, patterns in entry["meta"].items():
            val = meta.get(mname)
            if val is None:
                continue
            matched, confidence, version = _rule_field_hit(patterns, val)
            if matched:
                record_hit(name, confidence, version, f"meta: {mname}")

        if entry["html"] and html:
            for p in entry["html"]:
                if p.regex is None:
                    continue
                m = p.regex.search(html)
                if m:
                    record_hit(name, p.confidence, _extract_rule_version(m, p.version_template), "html match")

        if entry["js"] and js_properties:
            for prop_path, patterns in entry["js"].items():
                val = js_properties.get(prop_path)
                if val is None:
                    continue
                matched, confidence, version = _rule_field_hit(patterns, val)
                if matched:
                    record_hit(name, confidence, version, f"js: {prop_path}")

        if entry["scriptSrc"] and script_srcs:
            for src in script_srcs:
                matched_this_tech = False
                for p in entry["scriptSrc"]:
                    if p.regex is None:
                        continue
                    m = p.regex.search(src)
                    if m:
                        record_hit(name, p.confidence, _extract_rule_version(m, p.version_template), f"script: {src[:150]}")
                        matched_this_tech = True
                        break
                if matched_this_tech:
                    break

    changed = True
    while changed:
        changed = False
        for name in list(results.keys()):
            entry = catalog.get(name)
            if not entry:
                continue
            for implied_name, confidence in entry["implies"]:
                if implied_name not in results:
                    results[implied_name] = {
                        "name": implied_name,
                        "confidence": confidence,
                        "version": "",
                        "evidence": [f"implied by {name}"],
                    }
                    changed = True

    detections = []
    for name, result in results.items():
        entry = catalog.get(name)
        detections.append({
            "name": name,
            "categories": entry["categories"] if entry else [],
            "description": entry["description"] if entry else "",
            "confidence": result["confidence"],
            "version": result["version"],
            "evidence": result["evidence"],
        })

    detections.sort(key=lambda d: (-d["confidence"], d["name"].lower()))
    return detections


def _confidence_bucket(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _clean_version(ver_str: str | None) -> str:
    """Normalize extracted version strings."""
    if not ver_str:
        return "Unknown"
    ver_str = ver_str.strip().lstrip("vV=/-_")
    match = re.match(r"^(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-]+)?)", ver_str)
    if match:
        return match.group(1)
    if re.match(r"^\d+$", ver_str):
        return ver_str
    return "Unknown"


def _build_components(detections: list[dict[str, Any]]) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Converts catalog detections into this module's output shapes:
    1. Legacy dict mapping category -> string list (e.g. "jQuery v3.6.0"),
       kept for callers that still read the older shape (the HTML report
       export).
    2. Rich list of detected component dicts with version, confidence,
       category, and evidence for the main UI.
    """
    legacy: dict[str, list[str]] = {}
    components: list[dict[str, Any]] = []

    for d in detections:
        category_label = d["categories"][0] if d["categories"] else "Other"
        category_key = re.sub(r"[^a-z0-9]+", "_", category_label.lower()).strip("_") or "other"
        version = _clean_version(d["version"]) if d["version"] else "Unknown"
        confidence = _confidence_bucket(d["confidence"])
        matched_by = d["evidence"][0] if d["evidence"] else "Signature match"

        legacy_str = f"{d['name']} v{version}" if version != "Unknown" else d["name"]
        legacy.setdefault(category_key, []).append(legacy_str)

        components.append({
            "name": d["name"],
            "version": version,
            "category": category_key,
            "category_label": category_label,
            "confidence": confidence,
            "matched_by": matched_by,
            "description": d["description"],
        })

    return legacy, components


def _extract_meta_tags(body: str) -> dict[str, Any]:
    """Extract page title, description, canonical URL, and OpenGraph parameters."""
    meta = {}
    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    if title_match:
        meta["title"] = title_match.group(1).strip()

    desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if not desc_match:
        desc_match = re.search(r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']description["\']', body, re.IGNORECASE)
    if desc_match:
        meta["description"] = desc_match.group(1).strip()[:300]

    gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if gen_match:
        meta["generator"] = gen_match.group(1).strip()

    canon_match = re.search(r'<link\s+rel=["\']canonical["\']\s+href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if canon_match:
        meta["canonical_url"] = canon_match.group(1).strip()

    return meta


def _extract_all_meta(body: str) -> dict[str, str]:
    """Extract every <meta name="..."/property="..." content="..."> pair —
    broader than _extract_meta_tags above, which only pulls out the handful
    of fields this module surfaces directly to users. The catalog's own
    meta-tag rules can key off any meta name (generator, referrer, various
    per-technology tags), so matching against them needs the full set."""
    meta: dict[str, str] = {}
    for m in re.finditer(
        r'<meta\s+(?=[^>]*(?:name|property)=["\'][^"\']+["\'])(?=[^>]*content=["\'][^"\']*["\'])[^>]*>',
        body,
        re.IGNORECASE,
    ):
        tag = m.group(0)
        key_match = re.search(r'(?:name|property)=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        val_match = re.search(r'content=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        if key_match and val_match:
            meta[key_match.group(1).strip().lower()] = val_match.group(1)
    return meta


def _extract_script_srcs(body: str) -> list[str]:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)


def _extract_external_domains(body: str, base_host: str) -> list[str]:
    """Extract unique third-party domain references loaded by scripts/styles."""
    domains = set()
    patterns = [
        r'src=["\']https?://([^/"\']+)',
        r'href=["\']https?://([^/"\']+)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            domain = match.group(1).lower().split(":")[0]
            if domain and domain != base_host and "." in domain:
                domains.add(domain)
    return sorted(list(domains))[:50]


# Fixed, not derived from TIMEOUTS["web_tech"] — that budget now also has
# to cover the JS-detection pass below (_JS_DETECTION_TIMEOUT), and coupling
# this to it would let a single slow aiohttp fetch balloon far past what a
# real HTTP GET ever needs.
_PER_URL_TIMEOUT = 30.0

_CATALOG_MATCH_HARD_TIMEOUT = 12.0

# ── Playwright-driven JS-property detection ─────────────────────────────────
#
# ~46% of the catalog's technologies (see _collect_js_property_paths) only
# carry a version/presence signal on a live `window.*` property — headers,
# cookies, HTML and script filenames never expose it (e.g. React's version
# lives at `React.version`, only set once React actually runs in a real
# browser). This section renders the page once with headless Chromium and
# reads those properties directly out of the live page, after the normal
# aiohttp-based pass has already picked which URL variant is reachable.
#
# One browser process is shared process-wide (launching a new one per scan
# would cost 1-2s just for the process spawn); _BROWSER_SEMAPHORE bounds how
# many pages can be open in it at once, the same "module owns its own
# concurrency limit" pattern already used for VirusTotal/AbuseIPDB pacing
# and email_gather's scrape concurrency elsewhere in this codebase.

# 15s looked fine in isolation but a real 5-target concurrent deep-scan
# burst (port scan + directory enum + subdomain enum all competing for
# DNS/CPU at once, see modules/web_tech.py's diagnostic notes) pushed real
# page-load times past that. 25s was measured to comfortably cover that
# same real burst.
_JS_DETECTION_TIMEOUT = 25.0
_BROWSER_CONCURRENCY = 4

_playwright_ctx = None
_browser = None
_browser_lock = asyncio.Lock()
_browser_semaphore = asyncio.Semaphore(_BROWSER_CONCURRENCY)

_JS_EVAL_SCRIPT = """(paths) => {
    const out = {};
    for (const p of paths) {
        try {
            const parts = p.split('.');
            let obj = window;
            for (const part of parts) {
                if (obj === null || obj === undefined) { obj = undefined; break; }
                obj = obj[part];
            }
            if (obj === undefined || obj === null) continue;
            const t = typeof obj;
            if (t === 'string') out[p] = obj;
            else if (t === 'number' || t === 'boolean') out[p] = String(obj);
            else out[p] = '';
        } catch (e) {}
    }
    return out;
}"""


async def _ensure_browser():
    """Lazily launches the shared headless Chromium instance, reused for
    the process lifetime. Returns None (never raises) if Playwright isn't
    installed or the browser fails to launch — callers treat that as "no
    JS evidence available" and fall back to the aiohttp-only detections."""
    global _playwright_ctx, _browser
    if _browser is not None:
        return _browser
    async with _browser_lock:
        if _browser is not None:
            return _browser
        try:
            from playwright.async_api import async_playwright
            _playwright_ctx = await async_playwright().start()
            _browser = await _playwright_ctx.chromium.launch(
                headless=True,
                args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
            )
        except Exception as e:
            logger.warning(f"[web_tech] Headless browser unavailable, JS-based version detection disabled: {type(e).__name__}: {e}")
            _playwright_ctx = None
            _browser = None
        return _browser


async def close_browser() -> None:
    """Called from the app's shutdown hook to release the browser cleanly."""
    global _playwright_ctx, _browser
    if _browser is not None:
        try:
            await _browser.close()
        except Exception:
            pass
        _browser = None
    if _playwright_ctx is not None:
        try:
            await _playwright_ctx.stop()
        except Exception:
            pass
        _playwright_ctx = None


async def _gather_js_properties(url: str, prop_paths: list[str]) -> tuple[dict[str, str], str | None]:
    """Renders `url` in a fresh browser context and reads every property in
    `prop_paths` off the live `window` object. Returns ({}, reason) on any
    failure — a missing browser, a navigation error, or a slow/hung page all
    degrade to "no JS evidence", never to a failed scan. The reason string
    is surfaced on the result (see _augment_with_js_detection) purely for
    diagnosability — earlier testing under real concurrent scan load (port
    scan + directory enum + subdomain enum all competing for DNS at once)
    showed this can legitimately come back empty, and debugging that with
    zero visibility into *why* is exactly the kind of thing that should
    never ship silent."""
    if not prop_paths:
        return {}, "no js-versioned technologies in catalog"
    browser = await _ensure_browser()
    if browser is None:
        return {}, "browser unavailable"

    async with _browser_semaphore:
        context = None
        try:
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()
            nav_ok = True
            try:
                # 15s, not the Playwright default 30s — bounded by
                # _JS_DETECTION_TIMEOUT above regardless, but a real
                # 5-concurrent-deep-scan burst (DNS contention from the
                # scan's own port/subdomain/directory modules, see the
                # module docstring) measured real page loads occasionally
                # exceeding the previous 10s figure.
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(600)
            except Exception as e:
                nav_ok = False
                logger.debug(f"[web_tech] JS-detection navigation to {url} failed, reading whatever loaded: {type(e).__name__}: {e}")

            # Real testing under concurrent load turned up pages that
            # client-side-redirect shortly after domcontentloaded (consent
            # banners, www/non-www bounces, SPA routers) — the evaluate()
            # below can land exactly as that navigation tears down the JS
            # context ("Execution context was destroyed"). That's a timing
            # race, not a real failure, so it's worth exactly one retry
            # after giving the new navigation a moment to settle, rather
            # than reporting "no JS evidence" for something the page
            # would've happily answered a few hundred ms later.
            try:
                values = await page.evaluate(_JS_EVAL_SCRIPT, prop_paths)
            except Exception as e:
                if "Execution context was destroyed" not in str(e):
                    raise
                logger.debug(f"[web_tech] JS eval hit a mid-flight navigation on {url}, retrying once")
                await page.wait_for_timeout(600)
                values = await page.evaluate(_JS_EVAL_SCRIPT, prop_paths)
            if not values:
                return {}, ("page loaded but no catalog js-properties were set" if nav_ok else "navigation failed before any script executed")
            return values, None
        except Exception as e:
            logger.debug(f"[web_tech] JS-detection failed for {url}: {type(e).__name__}: {e}")
            return {}, f"{type(e).__name__}: {e}"[:150]
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass


async def _augment_with_js_detection(result: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Re-runs catalog matching with live JS-property evidence added to the
    signals already gathered over HTTP, and merges the (usually richer)
    result back in. Any failure along the way just returns `result` with
    js_detection=False and a short note — this is a best-effort enhancement,
    never a hard dependency, but always reports its own outcome rather than
    silently doing nothing."""
    prop_paths = _collect_js_property_paths()
    try:
        js_properties, note = await asyncio.wait_for(
            _gather_js_properties(result["url_used"], prop_paths),
            timeout=_JS_DETECTION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        result["js_detection"] = False
        result["js_detection_note"] = f"timed out after {_JS_DETECTION_TIMEOUT:.0f}s"
        return result
    except Exception as e:
        result["js_detection"] = False
        result["js_detection_note"] = f"{type(e).__name__}: {e}"[:150]
        return result

    if not js_properties:
        result["js_detection"] = False
        result["js_detection_note"] = note or "no JS evidence found"
        return result

    loop = asyncio.get_event_loop()
    try:
        detections = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _match_catalog(
                    url=raw["url"],
                    headers=raw["headers"],
                    cookies=raw["cookies"],
                    html=raw["html"],
                    meta=raw["meta"],
                    script_srcs=raw["script_srcs"],
                    js_properties=js_properties,
                ),
            ),
            timeout=_CATALOG_MATCH_HARD_TIMEOUT,
        )
    except asyncio.TimeoutError:
        result["js_detection"] = False
        result["js_detection_note"] = "catalog re-match timed out"
        return result

    legacy_tech, components = _build_components(detections)
    version_count = sum(1 for c in components if c["version"] != "Unknown")
    result["technologies"] = legacy_tech
    result["detected_components"] = components
    result["tech_summary"] = {
        "total_detected": len(components),
        "version_count": version_count,
        "categories_count": len(set(c["category"] for c in components)),
    }
    result["js_detection"] = True
    return result


async def _fetch_and_match(
    session: aiohttp.ClientSession,
    url: str,
    per_url_timeout: aiohttp.ClientTimeout,
    ssl_ctx,
    weak_tls_downgrade: bool,
) -> dict[str, Any]:
    """One fetch-and-match attempt against `url` with the given SSL context.
    Split out of _try_url so it can be tried once with a standards-compliant
    context and, only on that specific failure, retried once more with a
    relaxed one (see _try_url)."""
    async with session.get(url, ssl=ssl_ctx, allow_redirects=True, timeout=per_url_timeout) as response:
        body = await response.text(errors="ignore")
        headers_dict = dict(response.headers)
        body_slice = body[:180000]
        cookies_dict = {name: morsel.value for name, morsel in response.cookies.items()}

        meta_all = _extract_all_meta(body_slice)
        script_srcs = _extract_script_srcs(body_slice)

        loop = asyncio.get_event_loop()
        try:
            detections = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _match_catalog(
                        url=str(response.url),
                        headers=headers_dict,
                        cookies=cookies_dict,
                        html=body_slice,
                        meta=meta_all,
                        script_srcs=script_srcs,
                    ),
                ),
                timeout=_CATALOG_MATCH_HARD_TIMEOUT,
            )
        except asyncio.TimeoutError:
            detections = []

        legacy_tech, components = _build_components(detections)
        meta = _extract_meta_tags(body_slice)
        parsed = urlparse(str(response.url))
        base_host = parsed.netloc.lower()
        external_domains = _extract_external_domains(body_slice, base_host)

        inline_scripts = len(re.findall(r"<script(?:\s[^>]*)?>", body_slice, re.IGNORECASE))
        external_scripts = len(re.findall(r'<script\s[^>]*src=["\']', body_slice, re.IGNORECASE))

        version_count = sum(1 for c in components if c["version"] != "Unknown")

        result = {
            "status": "ok",
            "url_used": str(response.url),
            "http_status": response.status,
            "technologies": legacy_tech,
            "detected_components": components,
            "tech_summary": {
                "total_detected": len(components),
                "version_count": version_count,
                "categories_count": len(set(c["category"] for c in components)),
            },
            "page_meta": meta,
            "external_domains": external_domains,
            "external_domain_count": len(external_domains),
            "inline_scripts": inline_scripts,
            "external_scripts": external_scripts,
            "meta": {
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
            },
            # Consumed by detect() to re-run catalog matching with JS
            # evidence added, then stripped before the result is returned.
            "_raw_signals": {
                "url": str(response.url),
                "headers": headers_dict,
                "cookies": cookies_dict,
                "html": body_slice,
                "meta": meta_all,
                "script_srcs": script_srcs,
            },
        }
        if weak_tls_downgrade:
            result["weak_tls_downgrade"] = True
            result["weak_tls_note"] = (
                "A standards-compliant TLS client refuses this server's certificate/handshake "
                "(e.g. an undersized DH key) — but a more permissive client (matching what curl / "
                "most browsers accept) can still connect, and got the response shown here. "
                "The server's TLS configuration doesn't meet modern security standards."
            )
        return result


async def _try_url(session: aiohttp.ClientSession, url: str) -> dict[str, Any] | None:
    """Fetches one URL and runs the full signature match + metadata extraction
    pipeline. Tries a standards-compliant TLS context first; only on an SSL
    handshake failure specifically (e.g. a legacy server's undersized DH key
    — confirmed against a real government-domain target, reachable to curl
    but hard-refused here by Python's default OpenSSL security level) does
    it retry once with a deliberately relaxed context, mirroring
    http_availability.py's _check_port_verified pattern — so weak-TLS
    targets still get fingerprinted instead of silently reading as
    unreachable, and the downgrade itself is reported, not hidden.
    Returns None on any other failure so the caller can just try the next
    URL variant."""
    per_url_timeout = aiohttp.ClientTimeout(total=_PER_URL_TIMEOUT, connect=8, sock_read=15)
    try:
        return await _fetch_and_match(session, url, per_url_timeout, get_safe_ssl_context(), False)
    except aiohttp.ClientConnectorSSLError:
        try:
            return await _fetch_and_match(session, url, per_url_timeout, get_relaxed_ssl_context(), True)
        except (asyncio.TimeoutError, aiohttp.ClientConnectorError, ssl_mod.SSLError):
            return None
        except Exception:
            return None
    except (asyncio.TimeoutError, aiohttp.ClientConnectorError, ssl_mod.SSLError):
        return None
    except Exception:
        return None


async def detect(target: str, enable_js_detection: bool = True) -> dict[str, Any]:
    """Main entry point — tries https/http and bare/www host combos
    *concurrently*, preferring the first successful result in that exact
    priority order (https bare host first, then http bare, then the www.
    variants). Fetching all variants at once rather than one at a time
    (the previous behavior) bounds this function's worst-case runtime to a
    single attempt's timeout instead of the sum of up to four — the same
    fix already applied to http_headers.py's fetch(), for the same reason:
    this whole function is wrapped in a fixed TIMEOUTS["web_tech"] budget
    by both the full-scan and any batch run, so stacking sequential
    attempts risks that outer timeout cutting off a later attempt that
    might have succeeded. asyncio.gather preserves input order in its
    results regardless of which attempt finishes first, so the
    priority-order selection below still works the same as before.

    Once a reachable URL variant wins that race, and only if
    `enable_js_detection` is True, one extra pass (_augment_with_js_detection)
    renders that specific URL in a real browser to pick up version/presence
    signals that only exist on the live page (see module docstring) —
    callers that only want the fast, passive HTTP-only signals (e.g. a
    fast-mode scan) can pass enable_js_detection=False to skip it."""
    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    host = _url_host(target_clean)
    try:
        ipaddress.ip_address(target_clean)
        target_is_ip = True
    except ValueError:
        target_is_ip = False

    urls_to_try = [f"https://{host}", f"http://{host}"]
    if not target_is_ip and not target_clean.startswith("www."):
        urls_to_try.extend([f"https://www.{target_clean}", f"http://www.{target_clean}"])

    timeout = aiohttp.ClientTimeout(total=_PER_URL_TIMEOUT, connect=6, sock_read=10)
    # Per-request ssl= (see _try_url/_fetch_and_match) always overrides this
    # connector default, so this is only ever a fallback.
    connector = aiohttp.TCPConnector(limit=70, limit_per_host=5, ssl=get_safe_ssl_context())
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            results = await asyncio.gather(*(_try_url(session, url) for url in urls_to_try), return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    continue
                if result:
                    raw = result.pop("_raw_signals", None)
                    if enable_js_detection and raw is not None:
                        result = await _augment_with_js_detection(result, raw)
                    return result
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    return {
        "status": "ok",
        "url_used": f"https://{host}",
        "http_status": 0,
        "technologies": {},
        "detected_components": [],
        "tech_summary": {"total_detected": 0, "version_count": 0, "categories_count": 0},
        "page_meta": {},
        "external_domains": [],
        "external_domain_count": 0,
        "inline_scripts": 0,
        "external_scripts": 0,
        "meta": {},
        "note": "Web technology detection notice: Target ports 80/443 did not accept connections or timed out."
    }
