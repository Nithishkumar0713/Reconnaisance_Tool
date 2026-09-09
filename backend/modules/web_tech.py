"""
Web Technology Fingerprinting & Version Extraction Module.
Inspects HTTP response headers, cookies, meta tags, script sources, and page
content against a large technology signature catalog (backend/data/wappalyzer/
— see NOTICE in that folder for where this data comes from) to pinpoint
thousands of possible technologies along with version numbers, confidence
levels, and detection evidence.
"""

import asyncio
import ipaddress
import json
import os
import re
import ssl as ssl_mod
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response


def _url_host(target: str) -> str:
    """Formats `target` for embedding directly in a URL string. A bare IPv6
    literal (e.g. "2404:6800:4007:808::200e") is only valid on the wire —
    inside a URL it's ambiguous with the ":port" separator, so RFC 3986
    requires it be wrapped in brackets ("[2404:...::200e]"). Verified
    directly: without this, yarl/aiohttp raises "Invalid URL: port can't be
    converted to integer" on any raw IPv6 target, which is a legitimate,
    reachable input here (classify_non_public_ip/is_valid_input both
    already accept public IPv6 addresses). Domains and IPv4 literals pass
    through unchanged."""
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
) -> list[dict[str, Any]]:
    """Evaluates every catalog entry's rules against the supplied signals
    and returns a confidence-sorted list of
    {name, categories, description, confidence, version, evidence}."""
    catalog = _load_catalog()
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    cookies = {k.lower(): v for k, v in (cookies or {}).items()}
    meta = {k.lower(): v for k, v in (meta or {}).items()}
    script_srcs = (script_srcs or [])[:150]

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


_PER_URL_TIMEOUT = max(10.0, TIMEOUTS.get("web_tech", 45) - 10)

_CATALOG_MATCH_HARD_TIMEOUT = 12.0


async def _try_url(session: aiohttp.ClientSession, url: str) -> dict[str, Any] | None:
    """Fetches one URL and runs the full signature match + metadata extraction pipeline.
    Returns None on any failure so the caller can just try the next URL variant."""
    try:
        per_url_timeout = aiohttp.ClientTimeout(total=_PER_URL_TIMEOUT, connect=8, sock_read=15)
        async with session.get(url, ssl=False, allow_redirects=True, timeout=per_url_timeout) as response:
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

            return {
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
            }
    except (asyncio.TimeoutError, aiohttp.ClientConnectorError, ssl_mod.SSLError):
        return None
    except Exception:
        return None


async def detect(target: str) -> dict[str, Any]:
    """Main entry point — tries https/http and bare/www host combos
    *concurrently*, preferring the first successful result in that exact
    priority order (https bare host first, then http bare, then the www.
    variants). Fetching all variants at once rather than one at a time
    (the previous behavior) bounds this function's worst-case runtime to a
    single attempt's timeout instead of the sum of up to four — the same
    fix already applied to http_headers.py's fetch(), for the same reason:
    this whole function is wrapped in a fixed TIMEOUTS["web_tech"] budget
    (45s) by both the full-scan and any batch run, so stacking sequential
    attempts risks that outer timeout cutting off a later attempt that
    might have succeeded. asyncio.gather preserves input order in its
    results regardless of which attempt finishes first, so the
    priority-order selection below still works the same as before."""
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

    timeout = aiohttp.ClientTimeout(total=TIMEOUTS.get("web_tech", 45), connect=6, sock_read=10)
    connector = aiohttp.TCPConnector(limit=70, limit_per_host=5, ssl=False)
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
