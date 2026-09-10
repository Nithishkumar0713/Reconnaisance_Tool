"""
Shodan Intel Module (InternetDB).
Queries Shodan's free, keyless InternetDB endpoint for a given public IP:
open ports Shodan's own internet-wide scanner has found, detected CPEs
(software/versions), known CVEs tagged to those services, and hostnames.
This is passive/historical data from Shodan's own scans — a different
vantage point than our own live port probe, useful for cross-referencing.

No API key required (internetdb.shodan.io is public and keyless). But a 404
from this endpoint is ambiguous: it means either "nothing indexed for this
real target" or "the input itself was junk" (private IP, malformed string,
even a domain name — this endpoint is IP-only). Shodan doesn't distinguish
those cases in the response. We handle that ourselves by validating/rejecting
bad input *before* ever calling this API (see module_batch.py and main.py),
so by the time this module sees a 404 it can only mean one thing: no data
for a valid public IP.
"""

import asyncio
from typing import Any

import aiohttp

from modules.port_scanner import SERVICE_NAMES
from utils.safety import TIMEOUTS, ScanError, error_response

# internetdb.shodan.io has no documented rate limit (it's free and
# keyless), but shows signs of a real, undocumented concurrent-request
# ceiling under load. Bounding how many requests fire at once, process-
# wide, keeps us under whatever that ceiling actually is.
_SHODAN_CONCURRENCY = asyncio.Semaphore(3)

_CPE_PART_NAMES = {"a": "Application", "o": "Operating System", "h": "Hardware"}

TAG_DESCRIPTIONS = {
    "cloud": "Hosted on cloud infrastructure (AWS, GCP, Azure, etc.)",
    "compromised": "Shodan has flagged this host as potentially compromised or part of a malicious network",
    "database": "An exposed database service was detected",
    "eol-os": "Running an end-of-life operating system no longer receiving security updates",
    "eol-product": "Running end-of-life software no longer receiving security updates",
    "honeypot": "Suspected to be a honeypot/decoy system rather than a real production host",
    "ics": "Industrial Control System (ICS/SCADA) device detected",
    "iot": "Internet of Things (IoT) device",
    "malware": "Associated with known malware infrastructure",
    "medical": "Medical/healthcare device detected",
    "onion": "Associated with a Tor onion service",
    "peer-to-peer": "Part of a peer-to-peer network",
    "self-signed": "Uses a self-signed SSL/TLS certificate",
    "starttls": "Supports STARTTLS encryption upgrade on a plaintext protocol",
    "tor": "Associated with the Tor network",
    "vpn": "VPN service detected",
    "vulnerable": "Shodan has flagged known vulnerabilities on this host",
}


def _parse_cpe(cpe_str: str) -> dict[str, Any]:
    """Breaks a raw CPE 2.2 string (e.g. 'cpe:/a:apache:tomcat:9.0.1') into
    its Vendor/Product/Version parts instead of leaving it as a cryptic id."""
    parts = cpe_str.replace("cpe:/", "").split(":")
    part_type = _CPE_PART_NAMES.get(parts[0]) if parts and parts[0] else None
    vendor = parts[1] if len(parts) > 1 and parts[1] else None
    product = parts[2] if len(parts) > 2 and parts[2] else None
    version = parts[3] if len(parts) > 3 and parts[3] else None
    return {
        "raw": cpe_str,
        "type": part_type,
        "vendor": vendor,
        "product": product,
        "version": version,
    }


async def lookup(ip: str) -> dict[str, Any]:
    """Queries Shodan InternetDB for open ports, CPEs, hostnames, tags, and
    known CVEs associated with a public IP."""
    url = f"https://internetdb.shodan.io/{ip}"
    timeout = aiohttp.ClientTimeout(total=TIMEOUTS.get("shodan", 30), connect=5, sock_read=15)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with _SHODAN_CONCURRENCY, session.get(url) as response:
                if response.status == 404:
                    return {
                        "status": "ok",
                        "ip": ip,
                        "has_data": False,
                        "ports": [],
                        "port_count": 0,
                        "hostnames": [],
                        "cpes": [],
                        "tags": [],
                        "vulns": [],
                        "vuln_count": 0,
                        "note": "No Shodan data available for this IP — it hasn't been indexed, or has no discoverable open services.",
                    }
                if response.status != 200:
                    return error_response(
                        ScanError.API_UNREACHABLE,
                        f"Shodan InternetDB returned unexpected HTTP {response.status}",
                        http_status=response.status,
                    )

                data = await response.json()
                port_numbers = sorted(data.get("ports", []) or [])
                ports = [{"port": p, "service": SERVICE_NAMES.get(p)} for p in port_numbers]
                vulns = sorted(data.get("vulns", []) or [])
                cpes = [_parse_cpe(c) for c in (data.get("cpes", []) or [])]
                tags = [
                    {"tag": t, "description": TAG_DESCRIPTIONS.get(t)}
                    for t in (data.get("tags", []) or [])
                ]

                return {
                    "status": "ok",
                    "ip": data.get("ip", ip),
                    "has_data": True,
                    "ports": ports,
                    "port_count": len(ports),
                    "hostnames": data.get("hostnames", []) or [],
                    "cpes": cpes,
                    "tags": tags,
                    "vulns": vulns,
                    "vuln_count": len(vulns),
                }
    except asyncio.TimeoutError:
        return error_response(
            ScanError.TIMEOUT, f"Shodan InternetDB did not respond within {TIMEOUTS.get('shodan', 30)}s"
        )
    except aiohttp.ClientConnectorError as e:
        return error_response(ScanError.API_UNREACHABLE, f"Cannot reach Shodan InternetDB: {str(e)[:120]}")
    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:150]}")
