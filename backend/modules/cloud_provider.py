"""
Cloud Provider Detection Scanner Module.
Detects if a target IP is hosted on a major cloud platform.
This is done in two phases:
  - Phase 1 (CIDR Matches): Downloads lists of IP ranges directly from cloud providers
    (AWS, GCP, Azure, Cloudflare, DigitalOcean, Oracle Cloud, Linode, Vultr, Fastly)
    and checks if the target IP lies inside any range.
  - Phase 2 (ASN Lookup): Performs a fallback IP organization query via ip-api.com
    and matches organization metadata keywords (e.g. "Alibaba", "Hetzner", "Scaleway").
"""

import asyncio
import ipaddress
from typing import Any

import aiohttp

from utils.safety import TIMEOUTS, ScanError, error_response

CLOUD_RANGE_SOURCES = {
    "AWS": {
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "parser": "_parse_aws",
    },
    "Google Cloud": {
        "url": "https://www.gstatic.com/ipranges/cloud.json",
        "parser": "_parse_gcp",
    },
    "Cloudflare": {
        "url": "https://www.cloudflare.com/ips-v4",
        "parser": "_parse_text_lines",
    },
    "DigitalOcean": {
        "url": "https://digitalocean.com/geo/google.csv",
        "parser": "_parse_do_csv",
    },
    "Oracle Cloud": {
        "url": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
        "parser": "_parse_oracle",
    },
    "Linode/Akamai": {
        "url": "https://geoip.linode.com/",
        "parser": "_parse_text_lines",
    },
    "Vultr": {
        "url": "https://bgp.vultr.com/prefixes.txt",
        "parser": "_parse_text_lines",
    },
    "Fastly": {
        "url": "https://api.fastly.com/public-ip-list",
        "parser": "_parse_fastly",
    },
}

ASN_KEYWORDS = {
    "Amazon": "AWS", "AMAZON": "AWS", "AWS": "AWS",
    "Google": "Google Cloud", "GOOGLE": "Google Cloud",
    "Microsoft": "Azure", "MICROSOFT": "Azure",
    "Cloudflare": "Cloudflare", "CLOUDFLARENET": "Cloudflare",
    "DigitalOcean": "DigitalOcean", "DIGITALOCEAN": "DigitalOcean",
    "Linode": "Linode/Akamai", "LINODE": "Linode/Akamai",
    "Akamai": "Akamai", "AKAMAI": "Akamai",
    "OVH": "OVH", "OVHcloud": "OVH",
    "Hetzner": "Hetzner", "HETZNER": "Hetzner",
    "Oracle": "Oracle Cloud", "ORACLE": "Oracle Cloud",
    "Vultr": "Vultr", "VULTR": "Vultr",
    "Fastly": "Fastly", "FASTLY": "Fastly",
    "IBM": "IBM Cloud", "SoftLayer": "IBM Cloud",
    "Alibaba": "Alibaba Cloud", "ALIBABA": "Alibaba Cloud",
    "Tencent": "Tencent Cloud", "TENCENT": "Tencent Cloud",
    "Scaleway": "Scaleway", "SCALEWAY": "Scaleway",
    "Packet": "Equinix Metal", "Equinix": "Equinix Metal",
    "Rackspace": "Rackspace", "RACKSPACE": "Rackspace",
    "Leaseweb": "Leaseweb", "LEASEWEB": "Leaseweb",
}


async def _fetch_json(session: aiohttp.ClientSession, url: str, timeout: aiohttp.ClientTimeout) -> dict | str | None:
    """Downloads range lists securely from a provider."""
    try:
        async with session.get(url, timeout=timeout, ssl=False) as resp:
            if resp.status == 200:
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct:
                    return await resp.json()
                return await resp.text()
    except Exception:
        pass
    return None


def _parse_aws(data: Any) -> list[str]:
    """Parses AWS range list format."""
    if not isinstance(data, dict):
        return []
    return [p["ip_prefix"] for p in data.get("prefixes", []) if "ip_prefix" in p]


def _parse_gcp(data: Any) -> list[str]:
    """Parses GCP range list format."""
    if not isinstance(data, dict):
        return []
    return [p["ipv4Prefix"] for p in data.get("prefixes", []) if "ipv4Prefix" in p]


def _parse_azure(data: Any) -> list[str]:
    """Parses Microsoft Azure ServiceTags range format."""
    if not isinstance(data, dict):
        return []
    prefixes = []
    for value in data.get("values", []):
        for prefix in value.get("properties", {}).get("addressPrefixes", []):
            if ":" not in prefix:
                prefixes.append(prefix)
    return prefixes


def _parse_text_lines(data: Any) -> list[str]:
    """Parses plain-text lines of IP/CIDR ranges, skipping comment characters."""
    if not isinstance(data, str):
        return []
    return [line.strip() for line in data.strip().splitlines() if line.strip() and not line.startswith("#")]


def _parse_do_csv(data: Any) -> list[str]:
    """Parses DigitalOcean CSV IP geographical ranges."""
    if not isinstance(data, str):
        return []
    prefixes = []
    for line in data.strip().splitlines():
        parts = line.split(",")
        if parts and "/" in parts[0]:
            prefixes.append(parts[0].strip())
    return prefixes


def _parse_oracle(data: Any) -> list[str]:
    """Parses Oracle Cloud ranges JSON format."""
    if not isinstance(data, dict):
        return []
    prefixes = []
    for region in data.get("regions", []):
        for cidr_entry in region.get("cidrs", []):
            cidr = cidr_entry.get("cidr")
            if cidr and ":" not in cidr:
                prefixes.append(cidr)
    return prefixes


def _parse_fastly(data: Any) -> list[str]:
    """Parses Fastly public ranges list."""
    if not isinstance(data, dict):
        return []
    return [p for p in data.get("addresses", []) if ":" not in p]


PARSERS = {
    "_parse_aws": _parse_aws,
    "_parse_gcp": _parse_gcp,
    "_parse_azure": _parse_azure,
    "_parse_text_lines": _parse_text_lines,
    "_parse_do_csv": _parse_do_csv,
    "_parse_oracle": _parse_oracle,
    "_parse_fastly": _parse_fastly,
}


def _check_ip_in_ranges(ip_str: str, cidrs: list[Any]) -> bool:
    """
    Evaluates whether an IP matches any CIDR network block in a list.
    E.g. Checks if '3.5.140.2' is inside '3.5.140.0/22'.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in cidrs:
            try:
                if ip in network:
                    return True
            except Exception:
                continue
    except ValueError:
        pass
    return False


async def _detect_from_asn(session: aiohttp.ClientSession, ip: str, timeout: aiohttp.ClientTimeout) -> dict:
    """Fallback: Performs an IP ASN registry query and keywords matches organization strings."""
    async def _query_ip_api():
        try:
            url = f"http://ip-api.com/json/{ip}?fields=org,isp,as,asname,hosting"
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None

    async def _query_ipwhois():
        try:
            url = f"https://ipwho.is/{ip}"
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("success"):
                        return {
                            "org": data.get("connection", {}).get("org"),
                            "isp": data.get("connection", {}).get("isp"),
                            "as": f"AS{data.get('asn', {}).get('asn')}" if data.get("asn", {}).get("asn") else None,
                            "asname": data.get("asn", {}).get("org"),
                            "hosting": False
                        }
        except Exception:
            pass
        return None

    try:
        res_ipapi, res_ipwhois = await asyncio.gather(_query_ip_api(), _query_ipwhois(), return_exceptions=True)
        data = None
        if isinstance(res_ipapi, dict) and res_ipapi.get("org"):
            data = res_ipapi
        elif isinstance(res_ipwhois, dict) and res_ipwhois.get("org"):
            data = res_ipwhois
            
        if data:
            combined = " ".join([
                data.get("org") or "", data.get("isp") or "",
                data.get("as") or "", data.get("asname") or "",
            ])
            result = {
                "asn_org": data.get("org"),
                "asn_isp": data.get("isp"),
                "as_number": data.get("as"),
                "is_hosting": data.get("hosting", False),
            }
            for keyword, provider in ASN_KEYWORDS.items():
                if keyword.lower() in combined.lower():
                    result.update({
                        "provider": provider,
                        "confidence": "medium",
                        "method": "asn_lookup",
                    })
                    return result
            return result
    except Exception:
        pass
    return {}


_RANGES_CACHE = {}
_CACHE_LOCK = asyncio.Lock()

async def _get_cloud_ranges(session: aiohttp.ClientSession, name: str, src: dict, timeout: aiohttp.ClientTimeout) -> list[Any]:
    """Retrieves IP prefix ranges for a given cloud provider, using cache if populated."""
    if name in _RANGES_CACHE:
        return _RANGES_CACHE[name]
        
    async with _CACHE_LOCK:
        if name in _RANGES_CACHE:
            return _RANGES_CACHE[name]
            
        raw = await _fetch_json(session, src["url"], timeout)
        if raw is None:
            return []
            
        parser_fn = PARSERS.get(src["parser"])
        if not parser_fn:
            return []
            
        try:
            cidrs = parser_fn(raw)
            parsed_networks = []
            if cidrs:
                for c in cidrs:
                    try:
                        parsed_networks.append(ipaddress.ip_network(c, strict=False))
                    except ValueError:
                        continue
                _RANGES_CACHE[name] = parsed_networks
            return parsed_networks
        except Exception:
            return []


async def detect(ip: str) -> dict[str, Any]:
    """
    Main Entry Point: downloads CIDR lists and matches coordinates concurrently.
    Uses in-memory cache to ensure extreme speed on subsequent calls.
    """
    if not ip:
        return error_response(ScanError.DNS_RESOLUTION_FAILED, "No IP address available for cloud provider detection.")

    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return {
                "status": "ok",
                "cloud_detected": False,
                "provider": None,
                "confidence": "high",
                "method": "local_private_range_check",
                "note": "IP is localhost or private LAN range (not a public cloud provider)",
                "providers_checked": []
            }
    except ValueError:
        pass

    timeout = aiohttp.ClientTimeout(total=2.0)
    providers_checked = []

    try:
        async with aiohttp.ClientSession() as session:
            range_tasks = {}
            for name, src in CLOUD_RANGE_SOURCES.items():
                if name in _RANGES_CACHE:
                    async def _get_cached(val):
                        return val
                    range_tasks[name] = _get_cached(_RANGES_CACHE[name])
                else:
                    range_tasks[name] = _get_cloud_ranges(session, name, src, timeout)

            asn_task = _detect_from_asn(session, ip, aiohttp.ClientTimeout(total=4.0))
            
            names = list(range_tasks.keys())
            tasks = list(range_tasks.values()) + [asn_task]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            parsed_ranges_results = results[:-1]
            asn_result = results[-1] if not isinstance(results[-1], Exception) else {}
            asn_result = asn_result or {}
            
            asn_base_data = {
                "asn_org": asn_result.get("asn_org"),
                "asn_isp": asn_result.get("asn_isp"),
                "as_number": asn_result.get("as_number"),
                "is_hosting": asn_result.get("is_hosting"),
            }
            asn_base_data = {k: v for k, v in asn_base_data.items() if v is not None}

            for provider_name, cidrs in zip(names, parsed_ranges_results):
                if isinstance(cidrs, Exception) or not cidrs:
                    providers_checked.append(f"{provider_name} (fetch failed or empty)")
                    continue
                if _check_ip_in_ranges(ip, cidrs):
                    return {
                        "status": "ok",
                        "cloud_detected": True,
                        "provider": provider_name,
                        "confidence": "high",
                        "method": "cidr_range_match",
                        "ranges_checked": len(cidrs),
                        "providers_checked": providers_checked + [provider_name],
                        **asn_base_data
                    }
                providers_checked.append(provider_name)

            if "provider" in asn_result:
                return {
                    "status": "ok",
                    "cloud_detected": True,
                    **asn_result,
                    "providers_checked": providers_checked,
                }

            return {
                "status": "ok",
                "cloud_detected": False,
                "provider": None,
                "confidence": "high",
                "method": "cidr_range_match + asn_lookup",
                "note": "IP does not belong to any known major cloud provider",
                "providers_checked": providers_checked,
                **asn_base_data
            }

    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"Cloud provider detection exceeded timeout")
    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"Cloud provider detection error: {type(e).__name__}: {str(e)[:120]}")
