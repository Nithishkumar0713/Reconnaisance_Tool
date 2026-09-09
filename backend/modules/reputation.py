"""
IP Reputation Scanner Module.
Checks if a target IP/domain is flagged as malicious by security databases:
  - AbuseIPDB: community-reported abuse database (spam, hacking, DDoS etc.)
  - VirusTotal: aggregates 70+ antivirus engine scan results
Both require API keys (free tier available).
"""

import asyncio
import os
import socket
import time
import ipaddress
from typing import Any

import aiohttp
from dotenv import load_dotenv

from utils.safety import TIMEOUTS, ScanError, error_response, skip_response, classify_http_status
from utils.concurrency import PRIORITY_DNS_SEMAPHORE

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# Process-wide pacing for VirusTotal's free-tier limit (4 req/min = one every
# 16s). Lives here rather than in any one caller so every caller — a single
# scan, module_batch.py's batch checks, a full-scan batch running several
# targets' VirusTotal lookups concurrently — shares the same real limiter
# instead of each needing (and easily forgetting) its own pacing. This is
# proactive (waits before firing a request) rather than the old purely
# reactive 16s-sleep-after-a-429 below, which does nothing to stop several
# concurrent callers' first attempts from all landing at once.
_VT_MIN_INTERVAL_SECONDS = 16.0
_vt_rate_lock = asyncio.Lock()
_vt_last_call_monotonic = 0.0


async def _vt_wait_for_slot() -> None:
    global _vt_last_call_monotonic
    async with _vt_rate_lock:
        now = time.monotonic()
        elapsed = now - _vt_last_call_monotonic
        if elapsed < _VT_MIN_INTERVAL_SECONDS:
            await asyncio.sleep(_VT_MIN_INTERVAL_SECONDS - elapsed)
        _vt_last_call_monotonic = time.monotonic()


# AbuseIPDB's limit is much looser (1000 queries/day, no documented per-minute
# cap) — a hard time-based pace like VirusTotal's would be overkill, but an
# unbounded number of concurrent callers (e.g. 20 full-scan-batch targets,
# each itself checking up to 5 IPs concurrently) is still worth capping so
# one batch can't burn a large fraction of the daily quota in one burst.
_ABUSEIPDB_CONCURRENCY = asyncio.Semaphore(5)



async def check_abuseipdb(target_or_ip: str, api_key: str | None = None) -> dict[str, Any]:
    """Queries AbuseIPDB API to check if an IP has been reported for abuse."""
    key = (api_key or ABUSEIPDB_KEY or "").strip()
    if not key or key == "your_abuseipdb_key_here":
        return error_response(ScanError.API_KEY_MISSING, "AbuseIPDB API key is required. Please provide a valid API key.")

    is_ip = False
    try:
        ipaddress.ip_address(target_or_ip)
        is_ip = True
    except ValueError:
        pass

    ips_to_check = []
    if is_ip:
        ips_to_check = [target_or_ip]
    else:
        try:
            loop = asyncio.get_event_loop()
            async with PRIORITY_DNS_SEMAPHORE:
                addr_info = await loop.run_in_executor(None, socket.getaddrinfo, target_or_ip, None, socket.AF_INET, socket.SOCK_STREAM)
            ips_to_check = list(set([info[4][0] for info in addr_info if info[4]]))
        except Exception:
            ips_to_check = []

    if not ips_to_check:
        return error_response(
            ScanError.DNS_RESOLUTION_FAILED, 
            f"Domain '{target_or_ip}' could not be resolved to any IP address. Reputation check skipped."
        )

    ips_to_check = ips_to_check[:5]

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=TIMEOUTS["abuseipdb"], connect=5, sock_read=10)
    connector = aiohttp.TCPConnector(limit=15, limit_per_host=5, ssl=True)

    async def check_single_ip(session: aiohttp.ClientSession, single_ip: str) -> dict[str, Any]:
        """Check single IP with 429 backoff retry logic."""
        params = {"ipAddress": single_ip, "maxAgeInDays": 365, "verbose": ""}
        for attempt in range(2):
            try:
                async with _ABUSEIPDB_CONCURRENCY, session.get(url, headers=headers, params=params) as response:
                    if response.status in (401, 403):
                        return {"status": "unauthorized", "ip": single_ip}
                    if response.status == 429:
                        if attempt == 0:
                            await asyncio.sleep(3.0)
                            continue
                        return {"status": "rate_limited", "ip": single_ip}
                    if response.status == 422:
                        return {"status": "invalid", "ip": single_ip}
                    if response.status != 200:
                        return {"status": "error", "ip": single_ip, "code": response.status}
                    payload = await response.json()
                    return {"status": "ok", "ip": single_ip, "data": payload.get("data")}
            except asyncio.TimeoutError:
                if attempt == 0:
                    await asyncio.sleep(1.0)
                    continue
                return {"status": "timeout", "ip": single_ip}
            except Exception as e:
                if attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "fail", "ip": single_ip, "error": str(e)}
        return {"status": "fail", "ip": single_ip, "error": "Max retries exceeded"}

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [check_single_ip(session, ip) for ip in ips_to_check]
            results = await asyncio.gather(*tasks)

        ok_results = [r for r in results if r["status"] == "ok" and r["data"]]

        if not ok_results:
            if any(r["status"] == "unauthorized" for r in results):
                return error_response(ScanError.UNAUTHORIZED, "AbuseIPDB rejected the API key")
            if any(r["status"] == "rate_limited" for r in results):
                return error_response(ScanError.API_RATE_LIMITED, "AbuseIPDB rate limit reached (1000 queries/day on free tier)")
            if any(r["status"] == "timeout" for r in results):
                return error_response(ScanError.TIMEOUT, f"AbuseIPDB API did not respond within {TIMEOUTS['abuseipdb']}s")
            return error_response(ScanError.INVALID_RESPONSE, "AbuseIPDB rejected the query — IP may be invalid or private-range")

        best_result = max(
            ok_results,
            key=lambda r: (r["data"].get("totalReports", 0), r["data"].get("abuseConfidenceScore", 0))
        )
        data = best_result["data"]

        reports = data.get("reports", [])
        recent_reports = [
            {
                "reported_at": r.get("reportedAt"),
                "comment": (r.get("comment") or "")[:200],
                "categories": r.get("categories", []),
                "reporter_id": r.get("reporterId"),
                "reporter_country": r.get("reporterCountryCode"),
            }
            for r in reports[:10]
        ]

        score = data.get("abuseConfidenceScore", 0)
        threat_level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low" if score > 0 else "clean"

        return {
            "status": "ok",
            "ip": data.get("ipAddress"),
            "abuse_confidence_score": score,
            "threat_level": threat_level,
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_public": data.get("isPublic"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "hostnames": data.get("hostnames", []),
            "recent_reports": recent_reports,
            "report_count_shown": len(recent_reports),
        }
    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"AbuseIPDB API did not respond within {TIMEOUTS['abuseipdb']}s")
    except aiohttp.ClientConnectorError as e:
        return error_response(ScanError.API_UNREACHABLE, f"Cannot reach AbuseIPDB API: {str(e)[:120]}")
    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:150]}")


async def check_virustotal(target: str, is_domain: bool, api_key: str | None = None) -> dict[str, Any]:
    """Queries VirusTotal API to check domain/IP against 70+ antivirus engines."""
    key = (api_key or VIRUSTOTAL_KEY or "").strip()
    if not key or key == "your_virustotal_key_here":
        return error_response(ScanError.API_KEY_MISSING, "VirusTotal API key is required. Please provide a valid API key.")

    await _vt_wait_for_slot()

    if is_domain:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"

    headers = {"x-apikey": key, "Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=TIMEOUTS["virustotal"], connect=5, sock_read=10)
    connector = aiohttp.TCPConnector(limit=15, limit_per_host=5, ssl=True)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for attempt in range(2):
                async with session.get(url, headers=headers) as response:
                    if response.status == 401:
                        return error_response(ScanError.UNAUTHORIZED, "VirusTotal rejected the API key", http_status=401)
                    if response.status == 403:
                        return error_response(ScanError.UNAUTHORIZED, "VirusTotal returned 403 — key may lack permission", http_status=403)
                    if response.status == 404:
                        return {"status": "not_found", "note": "Target has never been analyzed by VirusTotal", "target": target}
                    if response.status == 429:
                        if attempt == 0:
                            await asyncio.sleep(16.0)
                            continue
                        return error_response(ScanError.API_RATE_LIMITED, "VirusTotal rate limit (4 req/min, 500/day on free tier)", http_status=429)

                    err = classify_http_status(response.status)
                    if err:
                        return err

                    try:
                        payload = await response.json()
                    except Exception:
                        if attempt == 0:
                            await asyncio.sleep(0.5)
                            continue
                        return error_response(ScanError.INVALID_RESPONSE, "VirusTotal returned malformed JSON")

                    data = payload.get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    results = attributes.get("last_analysis_results", {})

                    flagged_by = [
                        {
                            "engine": engine,
                            "category": result.get("category"),
                            "result": result.get("result"),
                            "engine_version": result.get("engine_version"),
                            "engine_update": result.get("engine_update"),
                        }
                        for engine, result in results.items()
                        if result.get("category") in ("malicious", "suspicious")
                    ]

                    clean_engines = [
                        engine for engine, result in results.items()
                        if result.get("category") == "harmless"
                    ]

                    total_engines = sum(stats.values()) if stats else 0
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    ratio = (malicious + suspicious) / max(total_engines, 1)
                    threat_level = "critical" if ratio > 0.5 else "high" if ratio > 0.2 else "medium" if ratio > 0.05 else "low" if ratio > 0 else "clean"

                    extra = {}
                    if is_domain:
                        extra["popularity_ranks"] = attributes.get("popularity_ranks", {})
                        extra["creation_date"] = attributes.get("creation_date")
                        extra["last_dns_records"] = attributes.get("last_dns_records", [])[:10]
                        extra["last_https_certificate"] = (attributes.get("last_https_certificate") or {}).get("subject", {})
                    else:
                        extra["as_owner"] = attributes.get("as_owner")
                        extra["asn"] = attributes.get("asn")
                        extra["continent"] = attributes.get("continent")
                        extra["country"] = attributes.get("country")
                        extra["network"] = attributes.get("network")

                    return {
                        "status": "ok",
                        "target": target,
                        "type": "domain" if is_domain else "ip",
                        "threat_level": threat_level,
                        "detection_stats": {
                            "harmless": stats.get("harmless", 0),
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "undetected": stats.get("undetected", 0),
                            "timeout": stats.get("timeout", 0),
                            "total_engines": total_engines,
                        },
                        "detection_ratio": f"{malicious + suspicious}/{total_engines}",
                        "reputation": attributes.get("reputation", 0),
                        "total_votes": attributes.get("total_votes", {}),
                        "categories": attributes.get("categories", {}),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                        "last_modification_date": attributes.get("last_modification_date"),
                        "flagged_by_count": len(flagged_by),
                        "flagged_by": flagged_by,
                        "clean_engine_count": len(clean_engines),
                        "whois_date": attributes.get("whois_date"),
                        "registrar": attributes.get("registrar"),
                        **extra,
                    }
    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"VirusTotal API did not respond within {TIMEOUTS['virustotal']}s")
    except aiohttp.ClientConnectorError as e:
        return error_response(ScanError.API_UNREACHABLE, f"Cannot reach VirusTotal API: {str(e)[:120]}")
    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:150]}")
