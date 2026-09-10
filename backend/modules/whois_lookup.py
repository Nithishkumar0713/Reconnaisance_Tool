"""
WHOIS Registration Scanner Module.
Fetches domain ownership info: who registered it, when, which registrar,
when it expires, what nameservers it uses.
Uses two sources in parallel:
  1. python-whois: traditional socket-based WHOIS query
  2. RDAP: modern HTTP-based registration API (rdap.org)
Merges both results to get the most complete data.
"""

import asyncio
from typing import Any

import whois
import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response
from utils.concurrency import PRIORITY_DNS_SEMAPHORE


def _get_first_attr(obj, attrs: list[str]) -> Any:
    """Helper: tries multiple attribute names and returns the first non-empty value."""
    if not obj:
        return None
    for attr in attrs:
        val = getattr(obj, attr, None)
        if val is not None and val != "":
            if isinstance(val, list):
                val = next((item for item in val if item), None)
            if val is not None and val != "":
                return val
        if isinstance(obj, dict):
            val = obj.get(attr)
            if val is not None and val != "":
                if isinstance(val, list):
                    val = next((item for item in val if item), None)
                if val is not None and val != "":
                    return val
    return None


def _extract_from_text(text: str, keys: list[str]) -> str | None:
    """Helper: searches raw WHOIS text for specific field values by line prefix."""
    if not text or not isinstance(text, str):
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        part_key, part_val = line.split(":", 1)
        part_key = part_key.strip().lower()
        if part_key in [k.lower() for k in keys]:
            return part_val.strip()
    return None


def _whois_sync(domain: str) -> dict[str, Any]:
    """
    Blocking WHOIS query using python-whois library.
    This connects to WHOIS servers (port 43) to get registration data.
    """
    try:
        import socket
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(30)
        try:
            w = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(old_timeout)
        if not w or not w.domain_name:
            return {
                "status": "not_found",
                "note": "WHOIS server returned no data (TLD may not support WHOIS, or domain is unregistered)",
            }
        days_until_expiry = None
        expiry_status = None
        from datetime import datetime, timezone
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0] if exp_date else None
        if exp_date and hasattr(exp_date, "date"):
            now = datetime.now(timezone.utc)
            if exp_date.tzinfo is None:
                exp_date = exp_date.replace(tzinfo=timezone.utc)
            delta = (exp_date - now).days
            days_until_expiry = delta
            expiry_status = "expired" if delta < 0 else "expiring_soon" if delta < 30 else "valid"

        raw_text = getattr(w, "text", "") or ""
        
        registrant_name = _get_first_attr(w, ["registrant_name", "name", "registrant"])
        if not registrant_name and raw_text:
            registrant_name = _extract_from_text(raw_text, ["registrant name", "registrant"])
            
        registrant_org = _get_first_attr(w, ["registrant_org", "org", "organization", "registrant_organization"])
        if not registrant_org and raw_text:
            registrant_org = _extract_from_text(raw_text, ["registrant organization", "registrant org", "org", "organization"])

        return {
            "status": "ok",
            "domain_name": _to_list(w.domain_name),
            "registrar": w.registrar,
            "registrar_url": getattr(w, "registrar_url", None),
            "registrar_iana_id": _get_first_attr(w, ["registrar_iana_id", "registrar_iana"]),
            "registrar_abuse_email": _get_first_attr(w, ["registrar_abuse_email", "registrar_abuse_email_address", "registrar_abuse_contact_email", "emails"]),
            "registrar_abuse_phone": _get_first_attr(w, ["registrar_abuse_phone", "registrar_abuse_contact_phone"]),
            "registry_domain_id": _get_first_attr(w, ["domain_id", "registry_domain_id"]),
            "creation_date": _format_date(w.creation_date),
            "expiration_date": _format_date(w.expiration_date),
            "updated_date": _format_date(w.updated_date),
            "days_until_expiry": days_until_expiry,
            "expiry_status": expiry_status,
            "name_servers": _to_list(w.name_servers),
            "status_flags": _to_list(w.status),
            "emails": _to_list(w.emails),
            "registrant_name": registrant_name,
            "registrant_org": registrant_org,
            "org": registrant_org,
            "country": _get_first_attr(w, ["country", "registrant_country"]),
            "state": _get_first_attr(w, ["state", "registrant_state", "registrant_state_province"]),
            "city": _get_first_attr(w, ["city", "registrant_city"]),
            "address": _get_first_attr(w, ["address", "registrant_address"]),
            "zipcode": _get_first_attr(w, ["zipcode", "registrant_postal_code"]),
            "dnssec": w.dnssec,
        }
    except ConnectionResetError:
        return error_response(ScanError.API_UNREACHABLE, "WHOIS server reset the connection (may be rate-limiting)")
    except (TimeoutError, OSError) as e:
        return error_response(ScanError.TIMEOUT, f"WHOIS server did not respond: {str(e)[:120]}")
    except Exception as e:
        msg = str(e).lower()
        if "no match" in msg or "not found" in msg:
            return {"status": "not_found", "note": "WHOIS server has no record for this domain"}
        if "quota" in msg or "limit" in msg or "exceeded" in msg:
            return error_response(ScanError.API_RATE_LIMITED, "WHOIS server rate-limited this query")
        return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:150]}")


def _format_date(date) -> Any:
    """Converts datetime objects to clean ISO format strings."""
    if not date:
        return None
    if isinstance(date, list):
        return [d.isoformat() if hasattr(d, "isoformat") else str(d) for d in date if d]
    return date.isoformat() if hasattr(date, "isoformat") else str(date)


def _to_list(value) -> list[str]:
    """Ensures values are returned as sorted, lowercase, deduplicated lists."""
    if not value:
        return []
    if isinstance(value, list):
        return list(set(str(v).lower() for v in value if v))
    return [str(value).lower()]


async def _rdap_lookup(domain: str) -> dict | None:
    """
    Queries the modern RDAP protocol (HTTP JSON API) as a secondary source.
    RDAP is newer than WHOIS and returns structured JSON data.
    """
    url = f"https://rdap.org/domain/{domain}"
    timeout = aiohttp.ClientTimeout(total=15)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return None
                data = await response.json()
                
                registrar = None
                registrant_name = None
                org = None
                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) >= 2:
                            for item in vcard[1]:
                                if len(item) >= 4 and item[0] == "fn":
                                    registrar = item[3]
                    if "registrant" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) >= 2:
                            for item in vcard[1]:
                                if len(item) >= 4 and item[0] == "fn":
                                    registrant_name = item[3]
                                if len(item) >= 4 and item[0] == "org":
                                    org = item[3]
                            if not org and registrant_name:
                                org = registrant_name

                registry_domain_id = data.get("handle")

                creation_date = None
                expiration_date = None
                updated_date = None
                events = data.get("events", [])
                for event in events:
                    action = event.get("eventAction", "")
                    date_str = event.get("eventDate", "")
                    if action == "registration":
                        creation_date = date_str
                    elif action == "expiration":
                        expiration_date = date_str
                    elif action == "last changed":
                        updated_date = date_str

                name_servers = []
                nameservers = data.get("nameservers", [])
                for ns in nameservers:
                    ldh_name = ns.get("ldhName", "")
                    if ldh_name:
                        name_servers.append(ldh_name.lower())

                return {
                    "registrar": registrar,
                    "registrant_name": registrant_name,
                    "registry_domain_id": registry_domain_id,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "updated_date": updated_date,
                    "name_servers": name_servers,
                    "org": org,
                    "registrant_org": org,
                }
    except Exception:
        return None


async def _whois_sync_gated(domain: str) -> dict[str, Any] | None:
    """_whois_sync, but only submitted to the executor once a priority DNS
    concurrency slot is free — python-whois resolves the right WHOIS
    server's hostname internally, a real DNS query competing for the same
    limited resolver capacity as every other module. This is where
    "WHOIS server did not respond: [Errno 11001] getaddrinfo failed" shows
    up under heavy concurrent batch load. Uses the small priority pool,
    not the large bulk pool, since this is a one-shot-per-target call
    whose failure directly fails the whole module."""
    loop = asyncio.get_event_loop()
    async with PRIORITY_DNS_SEMAPHORE:
        return await loop.run_in_executor(None, _whois_sync, domain)


async def lookup(domain: str) -> dict[str, Any]:
    """
    Main WHOIS function: runs both traditional WHOIS and RDAP in parallel,
    then merges the results to get the most complete registration data.
    """
    whois_task = asyncio.create_task(_whois_sync_gated(domain))
    rdap_task = _rdap_lookup(domain)
    
    try:
        whois_res, rdap_res = await asyncio.wait_for(
            asyncio.gather(whois_task, rdap_task, return_exceptions=True),
            timeout=TIMEOUTS["whois"]
        )
    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"WHOIS lookup exceeded {TIMEOUTS['whois']}s total time")

    final_result = {"status": "ok"}
    
    whois_ok = isinstance(whois_res, dict) and whois_res.get("status") == "ok"
    if whois_ok:
        final_result.update(whois_res)
    else:
        final_result["status"] = "partial"
        if isinstance(whois_res, dict):
            final_result["note"] = whois_res.get("note") or whois_res.get("error_message")

    if isinstance(rdap_res, dict):
        final_result["status"] = "ok"
        for k in ["registrar", "registrant_name", "registry_domain_id", "creation_date", "expiration_date", "updated_date", "org", "registrant_org"]:
            if rdap_res.get(k) and not final_result.get(k):
                final_result[k] = rdap_res[k]
                
        ns_whois = final_result.get("name_servers", [])
        ns_rdap = rdap_res.get("name_servers", [])
        if ns_rdap:
            final_result["name_servers"] = list(set(ns_whois + ns_rdap))

    if not whois_ok and not isinstance(rdap_res, dict):
        if isinstance(whois_res, dict):
            return whois_res
        return error_response(ScanError.API_UNREACHABLE, "WHOIS and RDAP queries both failed to fetch registration data.")

    return final_result

