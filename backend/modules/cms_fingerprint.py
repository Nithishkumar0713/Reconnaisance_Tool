"""
CMS Fingerprinting Module.
Checks if a target runs a known CMS (WordPress, Joomla, Drupal, Shopify, Magento, Webflow etc.)
How this works:
  1. Downloads the homepage and extracts generator metadata tags (<meta name="generator" content="WordPress 6.2">).
  2. Scans body HTML and response headers for signatures of 20+ CMS platforms.
  3. Queries characteristic directories and files for each CMS concurrently (like /wp-login.php, /administrator/)
     to check if they respond with HTTP 200/302, reinforcing detection confidence.
"""

import asyncio
import re
import ssl as ssl_mod
import uuid
from typing import Any

import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response
from utils.helpers import get_safe_ssl_context

CMS_RULES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/", "/xmlrpc.php", "/wp-json/wp/v2/", "/wp-json/"],
        "meta_generator": [r"(?i)wordpress\s*([\d.]+)?"],
        "body_patterns": [r"(?i)wp-content", r"(?i)wp-includes", r"(?i)wp-embed\.min\.js", r"(?i)/wp-json/"],
        "header_patterns": [r"(?i)x-powered-by:.*wordpress", r"(?i)link:.*wp-json"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/administrator/index.php", "/media/jui/", "/media/system/js/", "/components/", "/templates/"],
        "meta_generator": [r"(?i)joomla[!\s]*([\d.]+)?"],
        "body_patterns": [r"(?i)/media/jui/", r"(?i)joomla", r"(?i)/components/com_"],
        "header_patterns": [],
    },
    "Drupal": {
        "paths": ["/core/misc/drupal.js", "/sites/default/files/", "/core/install.php", "/user/login", "/node/1", "/core/", "/modules/"],
        "meta_generator": [r"(?i)drupal\s*([\d.]+)?"],
        "body_patterns": [r"(?i)drupal\.js", r"(?i)sites/default", r"(?i)drupal\.settings", r"(?i)Drupal\.behaviors"],
        "header_patterns": [r"(?i)x-drupal-cache", r"(?i)x-generator:\s*drupal"],
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/js/mage/", "/index.php/admin/", "/downloader/", "/mage/", "/media/catalog/"],
        "meta_generator": [r"(?i)magento\s*([\d.]+)?"],
        "body_patterns": [r"(?i)mage\.cookies", r"(?i)/skin/frontend", r"(?i)Magento"],
        "header_patterns": [r"(?i)x-magento-"],
    },
    "Shopify": {
        "paths": ["/admin/", "/collections/all", "/products/", "/cart"],
        "meta_generator": [r"(?i)shopify"],
        "body_patterns": [r"(?i)cdn\.shopify\.com", r"(?i)Shopify\.theme", r"(?i)myshopify\.com", r"(?i)shopify\.loadFeatures"],
        "header_patterns": [r"(?i)x-shopid", r"(?i)x-shopify-stage"],
    },
    "Wix": {
        "paths": [],
        "meta_generator": [r"(?i)wix\.com"],
        "body_patterns": [r"(?i)wix\.com", r"(?i)wixstatic\.com", r"(?i)X-Wix-"],
        "header_patterns": [r"(?i)x-wix-"],
    },
    "Squarespace": {
        "paths": [],
        "meta_generator": [r"(?i)squarespace"],
        "body_patterns": [r"(?i)squarespace", r"(?i)static\.squarespace\.com", r"(?i)sqsp\.net"],
        "header_patterns": [r"(?i)x-servedby:\s*squarespace"],
    },
    "Ghost": {
        "paths": ["/ghost/", "/ghost/api/", "/ghost/api/admin/"],
        "meta_generator": [r"(?i)ghost\s*([\d.]+)?"],
        "body_patterns": [r"(?i)ghost-", r"(?i)@tryghost"],
        "header_patterns": [r"(?i)x-ghost-"],
    },
    "TYPO3": {
        "paths": ["/typo3/", "/typo3conf/", "/typo3temp/"],
        "meta_generator": [r"(?i)typo3\s*([\d.]+)?"],
        "body_patterns": [r"(?i)typo3conf", r"(?i)TYPO3", r"(?i)typo3temp"],
        "header_patterns": [],
    },
    "PrestaShop": {
        "paths": ["/themes/default-bootstrap/", "/controllers/", "/img/"],
        "meta_generator": [r"(?i)prestashop"],
        "body_patterns": [r"(?i)prestashop"],
        "header_patterns": [],
    },
    "OpenCart": {
        "paths": ["/index.php?route=common/home", "/catalog/view/", "/admin/index.php"],
        "meta_generator": [r"(?i)opencart"],
        "body_patterns": [r"(?i)opencart", r"(?i)catalog/view"],
        "header_patterns": [],
    },
    "Hugo": {
        "paths": [],
        "meta_generator": [r"(?i)hugo\s*([\d.]+)?"],
        "body_patterns": [r"(?i)hugo", r"(?i)gohugo\.io"],
        "header_patterns": [],
    },
    "Gatsby": {
        "paths": [],
        "meta_generator": [r"(?i)gatsby\s*([\d.]+)?"],
        "body_patterns": [r"(?i)___gatsby", r"(?i)gatsby-"],
        "header_patterns": [],
    },
    "Next.js": {
        "paths": ["/_next/static/", "/_next/"],
        "meta_generator": [],
        "body_patterns": [r"(?i)__next", r"(?i)_next/static", r"(?i)__NEXT_DATA__"],
        "header_patterns": [r"(?i)x-nextjs-", r"(?i)x-powered-by:\s*Next\.js"],
    },
    "Nuxt.js": {
        "paths": ["/_nuxt/"],
        "meta_generator": [],
        "body_patterns": [r"(?i)__nuxt", r"(?i)_nuxt/"],
        "header_patterns": [],
    },
    "Laravel": {
        "paths": ["/vendor/"],
        "meta_generator": [],
        "body_patterns": [r"(?i)laravel"],
        "header_patterns": [r"(?i)set-cookie:.*laravel_session"],
    },
    "Django": {
        "paths": ["/admin/", "/admin/login/"],
        "meta_generator": [],
        "body_patterns": [r"(?i)csrfmiddlewaretoken", r"(?i)django", r"(?i)__admin_media_prefix"],
        "header_patterns": [],
    },
    "Webflow": {
        "paths": [],
        "meta_generator": [r"(?i)webflow"],
        "body_patterns": [r"(?i)webflow", r"(?i)uploads-ssl\.webflow\.com"],
        "header_patterns": [],
    },
    "HubSpot CMS": {
        "paths": [],
        "meta_generator": [],
        "body_patterns": [r"(?i)hs-scripts", r"(?i)hubspot", r"(?i)hs\.jsforms"],
        "header_patterns": [],
    },
    "WooCommerce": {
        "paths": ["/shop/", "/cart/", "/checkout/", "/my-account/"],
        "meta_generator": [],
        "body_patterns": [r"(?i)woocommerce", r"(?i)wc-", r"(?i)WooCommerce"],
        "header_patterns": [],
    },
}


async def _try_head(session: aiohttp.ClientSession, url: str) -> int | None:
    """Probes a path using a HEAD request to check its status code."""
    try:
        async with session.head(url, ssl=get_safe_ssl_context(), allow_redirects=True, timeout=aiohttp.ClientTimeout(total=6, connect=3, sock_read=5)) as resp:
            return resp.status
    except Exception:
        return None


async def _fetch_page(session: aiohttp.ClientSession, url: str) -> dict | None:
    """Downloads the homepage body and headers."""
    try:
        async with session.get(url, ssl=get_safe_ssl_context(), allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            body = await resp.text(errors="ignore")
            headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            return {
                "status_code": resp.status,
                "headers_text": headers_text,
                "body": body[:120000],
            }
    except Exception:
        return None


def _random_bogus_path() -> str:
    """Generates an unpredictable, guaranteed-nonexistent path to use as a
    baseline probe. Verified directly against a real target
    (chatgpt.com, behind Cloudflare): every single CMS path-existence
    check (Rule 4 below) came back 2xx/3xx simultaneously — WordPress,
    Joomla, TYPO3, PrestaShop, WooCommerce, Drupal, and Magento all
    "detected" on the same site at once, which is obviously impossible.
    The site is a "soft-404" target — it returns a success status for any
    path regardless of whether it's real (common for SPA catch-all
    routing, or a WAF/CDN quirk) — so a bare status-code check can't tell
    a genuine CMS path apart from nothing at all. Probing one random path
    up front and checking whether *it* also "succeeds" detects this before
    it can produce a false positive, the same baseline-calibration
    technique tools like ffuf/gobuster use."""
    token = uuid.uuid4().hex[:20]
    return f"/__recon_baseline_check_{token}__/"


def _extract_generator(body: str) -> str | None:
    """Regex matches html source to locate meta generator tag content."""
    match = re.search(r"""<meta\s+[^>]*name\s*=\s*['"]generator['"][^>]*content\s*=\s*['"]([^'"]+)['"]""", body, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match = re.search(r"""<meta\s+[^>]*content\s*=\s*['"]([^'"]+)['"][^>]*name\s*=\s*['"]generator['"]""", body, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


async def detect(target: str) -> dict[str, Any]:
    """
    Main Entry Point: fetches the homepage, probes paths concurrently,
    and returns detected CMS details.
    """
    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    hosts_to_try = [target_clean]
    if not target_clean.startswith("www."):
        hosts_to_try.append(f"www.{target_clean}")

    timeout = aiohttp.ClientTimeout(total=TIMEOUTS.get("cms_fingerprint", 60))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            homepage = None
            base_url = None
            for h in hosts_to_try:
                for proto in ["https", "http"]:
                    b_url = f"{proto}://{h}"
                    homepage = await _fetch_page(session, b_url)
                    if homepage:
                        base_url = b_url
                        break
                if homepage:
                    break

            if not homepage:
                return {
                    "status": "ok",
                    "cms_detected": False,
                    "cms_name": None,
                    "version": None,
                    "confidence": "none",
                    "generator_tag": None,
                    "all_detected": [],
                    "paths_probed": 0,
                    "note": "Homepage did not respond on HTTP/HTTPS ports (80/443). Host may not run an open web server.",
                }

            generator_tag = _extract_generator(homepage["body"])
            detections = []

            all_path_checks = []
            path_to_cms = {}
            for cms_name, rules in CMS_RULES.items():
                for path in rules["paths"]:
                    key = (cms_name, path)
                    if key not in path_to_cms:
                        path_to_cms[key] = True
                        all_path_checks.append((cms_name, path))

            baseline_path = _random_bogus_path()
            path_urls = [f"{base_url}{path}" for _, path in all_path_checks] + [f"{base_url}{baseline_path}"]

            all_results = await asyncio.gather(
                *[_try_head(session, url) for url in path_urls],
                return_exceptions=True,
            )
            path_results, baseline_result = all_results[:-1], all_results[-1]
            baseline_status = None if isinstance(baseline_result, Exception) else baseline_result
            soft_404_detected = bool(baseline_status and 200 <= baseline_status < 400)

            path_status_map: dict[tuple, int | None] = {}
            for (cms_name, path), status in zip(all_path_checks, path_results):
                if not isinstance(status, Exception):
                    path_status_map[(cms_name, path)] = status

            per_cms = {}
            for cms_name, rules in CMS_RULES.items():
                other_evidence = []
                path_evidence = []
                version = None

                if generator_tag:
                    for pattern in rules["meta_generator"]:
                        match = re.search(pattern, generator_tag)
                        if match:
                            other_evidence.append(f"Meta generator: {generator_tag}")
                            if match.lastindex and match.group(1):
                                version = match.group(1)
                            break

                for pattern in rules["body_patterns"]:
                    try:
                        if re.search(pattern, homepage["body"]):
                            other_evidence.append(f"Body pattern: {pattern}")
                            break
                    except re.error:
                        continue

                for pattern in rules["header_patterns"]:
                    try:
                        if re.search(pattern, homepage["headers_text"]):
                            other_evidence.append(f"Header: {pattern}")
                            break
                    except re.error:
                        continue

                if not soft_404_detected:
                    for path in rules["paths"]:
                        status = path_status_map.get((cms_name, path))
                        if status and 200 <= status < 400:
                            path_evidence.append(f"Path found: {path} (HTTP {status})")

                if other_evidence or path_evidence:
                    per_cms[cms_name] = {"version": version, "other_evidence": other_evidence, "path_evidence": path_evidence}

            cms_with_path_evidence = [name for name, d in per_cms.items() if d["path_evidence"]]
            path_evidence_unreliable = soft_404_detected or len(cms_with_path_evidence) >= 4

            for cms_name, d in per_cms.items():
                evidence = list(d["other_evidence"])
                if not path_evidence_unreliable:
                    evidence.extend(d["path_evidence"])
                if evidence:
                    confidence = "high" if len(evidence) >= 3 else "medium" if len(evidence) >= 2 else "low"
                    detections.append({
                        "cms_name": cms_name,
                        "version": d["version"],
                        "confidence": confidence,
                        "evidence": evidence,
                        "evidence_count": len(evidence),
                    })

            detections.sort(key=lambda x: x["evidence_count"], reverse=True)
            cms_detected = len(detections) > 0
            primary = detections[0] if detections else None

            result = {
                "status": "ok",
                "cms_detected": cms_detected,
                "cms_name": primary["cms_name"] if primary else None,
                "version": primary["version"] if primary else None,
                "confidence": primary["confidence"] if primary else "none",
                "generator_tag": generator_tag,
                "all_detected": detections,
                "paths_probed": len(all_path_checks),
                "soft_404_detected": soft_404_detected,
                "path_evidence_suppressed": path_evidence_unreliable,
            }
            if soft_404_detected:
                result["note"] = (
                    "This site returns a success status for made-up, nonexistent paths too "
                    "(a random baseline path was probed to confirm) — likely SPA catch-all "
                    "routing or a WAF/CDN quirk. Path-based CMS detection was skipped as "
                    "unreliable here; only generator-tag, body-pattern, and header-based "
                    "evidence (which check real content, not just status codes) were used."
                )
            elif path_evidence_unreliable:
                result["note"] = (
                    f"Path-based checks matched {len(cms_with_path_evidence)} unrelated CMS "
                    "platforms at once, which isn't realistically possible for one real site — "
                    "this target likely returns success for specific reserved/common path names "
                    "without them really existing (e.g. some sites reserve admin-panel-shaped "
                    "names to block phishing/squatting, which incidentally collide with what "
                    "scanners check for). Path-based evidence was discarded as unreliable; only "
                    "generator-tag, body-pattern, and header-based evidence were used."
                )
            return result

    except asyncio.TimeoutError:
        return {
            "status": "ok",
            "cms_detected": False,
            "cms_name": None,
            "version": None,
            "confidence": "none",
            "generator_tag": None,
            "all_detected": [],
            "paths_probed": 0,
            "note": f"CMS fingerprinting timed out after {TIMEOUTS.get('cms_fingerprint', 40)}s.",
        }
    except Exception as e:
        return {
            "status": "ok",
            "cms_detected": False,
            "cms_name": None,
            "version": None,
            "confidence": "none",
            "generator_tag": None,
            "all_detected": [],
            "paths_probed": 0,
            "note": f"CMS fingerprinting notice: {str(e)[:120]}",
        }
