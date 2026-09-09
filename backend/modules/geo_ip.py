"""
Geolocation and Network Information Module.
Given an IP address, queries three different public GeoIP databases in parallel:
  - ip-api.com (returns ISP details, ASN, geographic coordinates, and proxy/hosting flags)
  - freeipapi.com (provides currency, continent, languages, and backup geo coordinates)
  - ipinfo.io (provides organization detail, network ranges, and abuse email/phone contacts)
Merges data from all sources to build a complete profile of the server's network.
"""

import asyncio
from typing import Any

import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response


async def _fetch_ip_api(session: aiohttp.ClientSession, ip: str, timeout: aiohttp.ClientTimeout) -> dict | None:
    """Queries ip-api.com JSON endpoint for coordinates and proxy/hosting network flags."""
    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,country,countryCode,region,regionName,city,"
        "zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "region_code": data.get("region"),
                        "city": data.get("city"),
                        "postal_code": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "asn": data.get("as"),
                        "asn_name": data.get("asname"),
                        "reverse_dns": data.get("reverse"),
                        "is_mobile": data.get("mobile", False),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False),
                        "_source": "ip-api.com",
                    }
    except Exception:
        pass
    return None


async def _fetch_free_ip_api(session: aiohttp.ClientSession, ip: str, timeout: aiohttp.ClientTimeout) -> dict | None:
    """Queries freeipapi.com JSON endpoint for currency, continent, and geographical data."""
    url = f"https://freeipapi.com/api/json/{ip}"
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "ip": data.get("ipAddress"),
                    "country": data.get("countryName"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("cityName"),
                    "postal_code": data.get("zipCode"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "timezone": data.get("timeZone"),
                    "asn": data.get("asn"),
                    "asn_name": data.get("asName"),
                    "is_proxy": data.get("isProxy", False),
                    "continent": data.get("continent"),
                    "continent_code": data.get("continentCode"),
                    "language": data.get("language"),
                    "currency": data.get("currency", {}).get("name"),
                    "_source": "freeipapi.com",
                }
    except Exception:
        pass
    return None


async def _fetch_ipinfo(session: aiohttp.ClientSession, ip: str, timeout: aiohttp.ClientTimeout) -> dict | None:
    """Queries ipinfo.io JSON endpoint for network prefix ranges and abuse contacts."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                if data.get("bogon") or data.get("error"):
                    return None
                loc = data.get("loc", "").split(",")
                lat = float(loc[0]) if len(loc) == 2 else None
                lon = float(loc[1]) if len(loc) == 2 else None
                return {
                    "ip": data.get("ip"),
                    "hostname": data.get("hostname"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country_code": data.get("country"),
                    "postal_code": data.get("postal"),
                    "latitude": lat,
                    "longitude": lon,
                    "timezone": data.get("timezone"),
                    "organization": data.get("org"),
                    "network_prefix": data.get("prefix"),
                    "abuse_email": (data.get("abuse") or {}).get("email"),
                    "abuse_phone": (data.get("abuse") or {}).get("phone"),
                    "_source": "ipinfo.io",
                }
    except Exception:
        pass
    return None


async def _fetch_ipwhois(session: aiohttp.ClientSession, ip: str, timeout: aiohttp.ClientTimeout) -> dict | None:
    """Queries ipwho.is JSON endpoint for geo-coordinates and connection details."""
    url = f"https://ipwho.is/{ip}"
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                if data.get("success") is True:
                    return {
                        "ip": data.get("ip"),
                        "country": data.get("country"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region"),
                        "region_code": data.get("region_code"),
                        "city": data.get("city"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("timezone", {}).get("id"),
                        "isp": data.get("connection", {}).get("isp"),
                        "organization": data.get("connection", {}).get("org"),
                        "asn": f"AS{data.get('asn', {}).get('asn')}" if data.get("asn", {}).get("asn") else None,
                        "asn_name": data.get("asn", {}).get("org"),
                        "_source": "ipwho.is",
                    }
    except Exception:
        pass
    return None


async def lookup(ip: str) -> dict[str, Any]:
    """
    Main Entry Point: executes queries to four APIs concurrently,
    then merges properties to maximize results.
    """
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback:
            return {
                "status": "ok",
                "ip": ip,
                "country": "Localhost",
                "country_code": "LCL",
                "region": "Loopback",
                "city": "Localhost",
                "isp": "Local Loopback Network",
                "organization": "Localhost Org",
                "latitude": 0.0,
                "longitude": 0.0,
                "timezone": "UTC",
                "notes": "Private Loopback Address (127.0.0.1)",
                "data_sources": ["Local Loopback Detection"]
            }
        elif ip_obj.is_private:
            return {
                "status": "ok",
                "ip": ip,
                "country": "Private Network",
                "country_code": "PVT",
                "region": "Private Range",
                "city": "Private Range",
                "isp": "Private LAN Network",
                "organization": "Private Network Org",
                "latitude": 0.0,
                "longitude": 0.0,
                "timezone": "UTC",
                "notes": "Private LAN IP Address",
                "data_sources": ["Local LAN Detection"]
            }
    except Exception:
        pass

    total_timeout = aiohttp.ClientTimeout(total=TIMEOUTS["geo_ip"])
    query_timeout = aiohttp.ClientTimeout(total=12.0, connect=5, sock_read=8)
    connector = aiohttp.TCPConnector(limit=50, limit_per_host=6)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=total_timeout) as session:
            res_ipapi, res_free, res_ipinfo, res_ipwhois = await asyncio.gather(
                _fetch_ip_api(session, ip, query_timeout),
                _fetch_free_ip_api(session, ip, query_timeout),
                _fetch_ipinfo(session, ip, query_timeout),
                _fetch_ipwhois(session, ip, query_timeout),
                return_exceptions=True,
            )

            sources = [r for r in [res_ipapi, res_free, res_ipinfo, res_ipwhois] if isinstance(r, dict) and r]

            if not sources:
                return error_response(ScanError.API_UNREACHABLE, "All geolocation APIs failed to respond.")

            final_data = {}
            final_data.update(sources[0])
            for other in sources[1:]:
                for k, v in other.items():
                    if k not in ("_source",) and v is not None and v != "" and not final_data.get(k):
                        final_data[k] = v

            isp = final_data.get("isp")
            if not isp or str(isp).strip().lower() in ("unknown", "n/a", "none", ""):
                import re
                asn_name = final_data.get("asn_name")
                org = final_data.get("organization")
                asn_val = final_data.get("asn")

                if asn_name and str(asn_name).strip().lower() not in ("unknown", "n/a", "none", ""):
                    final_data["isp"] = str(asn_name).strip()
                elif org and str(org).strip().lower() not in ("unknown", "n/a", "none", ""):
                    clean_org = re.sub(r'^AS\d+\s+', '', str(org), flags=re.IGNORECASE).strip()
                    final_data["isp"] = clean_org
                elif asn_val and str(asn_val).strip().lower() not in ("unknown", "n/a", "none", ""):
                    clean_asn = re.sub(r'^AS\d+\s+', '', str(asn_val), flags=re.IGNORECASE).strip()
                    if clean_asn.isdigit():
                        final_data["isp"] = f"ASN {clean_asn}"
                    else:
                        final_data["isp"] = clean_asn
                else:
                    final_data["isp"] = "Unknown"

            lat = final_data.get("latitude")
            lon = final_data.get("longitude")
            if lat and lon:
                final_data["map_url"] = f"https://www.google.com/maps?q={lat},{lon}"

            final_data["data_sources"] = [r.get("_source") for r in sources]
            final_data.pop("_source", None)
            final_data["status"] = "ok"
            return final_data

    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"Geolocation module error: {type(e).__name__}: {str(e)[:120]}")
