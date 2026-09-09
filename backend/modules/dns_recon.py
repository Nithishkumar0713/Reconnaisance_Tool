"""
DNS records reconnaissance scanner.
Queries A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, DNSKEY, DS, TLSA, NAPTR records.
Extracts SPF, DMARC, DKIM, BIMI email-security policies from TXT records.
Includes reverse DNS (PTR) via socket + nslookup fallback.
"""

import asyncio
import platform
import re
import socket
import sys
import time
import warnings
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

from utils.safety import TIMEOUTS, ScanError, error_response
from utils.helpers import _resolve_with_nslookup
from utils.concurrency import PRIORITY_DNS_SEMAPHORE

warnings.filterwarnings("ignore", category=RuntimeWarning)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "DNSKEY", "DS", "NAPTR"]


def _process_answers(answers, record_type: str) -> dict:
    """Turns a dnspython answer set into plain JSON-serializable dicts — each record type
    has different fields, so this unpacks the ones worth surfacing per type."""
    results = []
    for rdata in answers:
        if record_type == "MX":
            results.append({"priority": rdata.preference, "server": str(rdata.exchange)})
        elif record_type == "SOA":
            results.append({
                "primary_ns": str(rdata.mname),
                "responsible_email": str(rdata.rname),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum_ttl": rdata.minimum,
            })
        elif record_type == "TXT":
            results.append(b"".join(rdata.strings).decode("utf-8", errors="ignore"))
        elif record_type == "SRV":
            results.append({
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
                "target": str(rdata.target),
            })
        elif record_type == "DNSKEY":
            results.append({
                "flags": rdata.flags,
                "algorithm": rdata.algorithm,
                "protocol": rdata.protocol,
            })
        elif record_type == "DS":
            results.append({
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
                "digest": rdata.digest.hex(),
            })
        elif record_type == "NAPTR":
            results.append({
                "order": rdata.order,
                "preference": rdata.preference,
                "flags": rdata.flags.decode("utf-8", errors="ignore"),
                "service": rdata.service.decode("utf-8", errors="ignore"),
                "regexp": rdata.regexp.decode("utf-8", errors="ignore"),
                "replacement": str(rdata.replacement),
            })
        elif record_type == "CAA":
            results.append({
                "flags": rdata.flags,
                "tag": rdata.tag.decode("utf-8", errors="ignore"),
                "value": rdata.value.decode("utf-8", errors="ignore"),
            })
        else:
            results.append(str(rdata))
    return {"status": "ok", "records": results}


def _query_record(domain: str, record_type: str) -> dict:
    """Resolves one record type for one domain. Tries the system/local resolver first;
    if that errors for any reason (not just NXDOMAIN/NoAnswer), retries against public
    resolvers before giving up — local resolvers are sometimes misconfigured or blocked."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 6.0
        resolver.lifetime = 8.0
        answers = resolver.resolve(domain, record_type)
        return _process_answers(answers, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"status": "no_records", "records": []}
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "records": [], "note": "Domain does not exist"}
    except Exception:
        try:
            fallback = dns.resolver.Resolver(configure=False)
            fallback.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            fallback.timeout = 6.0
            fallback.lifetime = 8.0
            answers = fallback.resolve(domain, record_type)
            return _process_answers(answers, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return {"status": "no_records", "records": []}
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "records": [], "note": "Domain does not exist"}
        except Exception:
            return {"status": "no_records", "records": [], "note": f"No {record_type} records configured or nameserver did not respond"}


def _query_dmarc(domain: str) -> dict:
    """Query DMARC record on _dmarc.{domain}."""
    res = _query_record(f"_dmarc.{domain}", "TXT")
    if res.get("status") == "ok":
        dmarc_records = [r for r in res.get("records", []) if r.lower().startswith("v=dmarc1")]
        if dmarc_records:
            return {"status": "ok", "records": dmarc_records}
        else:
            return {"status": "no_records", "records": []}
    return res


async def _query_dkim(domain: str, sem: asyncio.Semaphore) -> dict:
    """Query common DKIM selectors concurrently using a semaphore."""
    selectors = ["default", "google", "k1", "mail", "smtp", "s1"]
    loop = asyncio.get_event_loop()
    
    async def _query_sel(sel: str) -> dict:
        async with sem, PRIORITY_DNS_SEMAPHORE:
            return await loop.run_in_executor(None, _query_record, f"{sel}._domainkey.{domain}", "TXT")
            
    tasks = [_query_sel(sel) for sel in selectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    records = []
    has_timeout = False
    has_ok = False
    for sel, res in zip(selectors, results):
        if isinstance(res, dict) and res.get("status") == "ok":
            has_ok = True
            for rec in res.get("records", []):
                if rec.lower().startswith("v=dkim1") or "p=" in rec.lower():
                    records.append(f"[{sel}] {rec}")
        elif isinstance(res, dict) and res.get("status") == "error" and res.get("error_code") == "timeout":
            has_timeout = True

    if records:
        return {"status": "ok", "records": records}
    if has_timeout and not has_ok:
        return error_response(ScanError.TIMEOUT, "DKIM query timed out", records=[])
    return {"status": "no_records", "records": []}


def _analyze_email_security(txt_records: list[str]) -> dict:
    """Extract and analyze SPF, DMARC, DKIM, BIMI policies from TXT records."""
    spf = None
    dmarc = None
    dkim_selectors = []
    bimi = None

    for txt in txt_records:
        tl = txt.lower()
        if tl.startswith("v=spf1"):
            spf = txt
        elif tl.startswith("v=dmarc1"):
            dmarc = txt
        elif tl.startswith("v=bimi1"):
            bimi = txt

    spf_analysis = None
    if spf:
        mechanisms = []
        for part in spf.split():
            if part.lower() not in ("v=spf1",):
                mechanisms.append(part)
        all_qualifier = next((p for p in spf.split() if p in ("+all", "-all", "~all", "?all")), None)
        spf_analysis = {
            "record": spf,
            "mechanisms": mechanisms,
            "all_qualifier": all_qualifier,
            "is_strict": all_qualifier in ("-all",),
            "is_soft_fail": all_qualifier == "~all",
            "is_permissive": all_qualifier in ("+all", "?all", None),
        }

    dmarc_analysis = None
    if dmarc:
        tags = {}
        for part in dmarc.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        dmarc_analysis = {
            "record": dmarc,
            "policy": tags.get("p", "none"),
            "subdomain_policy": tags.get("sp"),
            "pct": tags.get("pct", "100"),
            "rua": tags.get("rua"),
            "ruf": tags.get("ruf"),
            "adkim": tags.get("adkim", "r"),
            "aspf": tags.get("aspf", "r"),
            "is_enforced": tags.get("p", "none") in ("quarantine", "reject"),
        }

    security_score = 0
    notes = []
    if spf_analysis:
        security_score += 1
        if spf_analysis["is_strict"]:
            security_score += 1
        else:
            notes.append("SPF uses soft-fail (~all) or permissive qualifier — consider -all")
    else:
        notes.append("No SPF record — email spoofing is possible")

    if dmarc_analysis:
        security_score += 1
        if dmarc_analysis["is_enforced"]:
            security_score += 1
        else:
            notes.append(f"DMARC policy is '{dmarc_analysis['policy']}' — not enforcing quarantine/reject")
    else:
        notes.append("No DMARC record — no email authentication enforcement")

    return {
        "spf": spf_analysis,
        "dmarc": dmarc_analysis,
        "bimi": bimi,
        "email_security_score": f"{security_score}/4",
        "notes": notes,
    }



async def get_all_records(domain: str) -> dict[str, Any]:
    """Runs every record-type query, SPF/DMARC/DKIM lookups, all concurrently (capped by
    a semaphore so a slow/misbehaving nameserver can't be hammered with parallel requests)."""
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(3)
    
    async def _safe_std_query(rtype: str):
        async with sem, PRIORITY_DNS_SEMAPHORE:
            return await loop.run_in_executor(None, _query_record, domain, rtype)

    async def _safe_dmarc_query():
        async with sem, PRIORITY_DNS_SEMAPHORE:
            return await loop.run_in_executor(None, _query_dmarc, domain)

    std_tasks = {
        rtype: _safe_std_query(rtype)
        for rtype in RECORD_TYPES
    }
    
    dmarc_task = _safe_dmarc_query()
    
    dkim_task = _query_dkim(domain, sem)
    
    all_tasks = {
        **std_tasks,
        "DMARC": dmarc_task,
        "DKIM": dkim_task
    }

    try:
        keys = list(all_tasks.keys())
        gathered = await asyncio.wait_for(
            asyncio.gather(*[all_tasks[k] for k in keys], return_exceptions=True),
            timeout=TIMEOUTS["dns"],
        )
        results = gathered
    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"DNS lookups exceeded {TIMEOUTS['dns']}s total")

    output = {}
    for key, result in zip(keys, results):
        if isinstance(result, Exception):
            output[key] = error_response(ScanError.UNKNOWN_ERROR, f"{type(result).__name__}: {str(result)[:120]}", records=[])
        else:
            output[key] = result

    txt_res = output.get("TXT", {})
    if txt_res.get("status") == "ok":
        spf_recs = [r for r in txt_res.get("records", []) if r.lower().startswith("v=spf1")]
        if spf_recs:
            output["SPF"] = {"status": "ok", "records": spf_recs}
        else:
            output["SPF"] = {"status": "no_records", "records": []}
    else:
        output["SPF"] = txt_res

    return {
        "status": "ok",
        "records_by_type": output,
    }


async def reverse_dns(ip: str) -> dict:
    """Looks up the PTR record for an IP via two independent methods run in parallel
    (socket.gethostbyaddr and a raw nslookup call) since neither is reliable alone —
    whichever answers first with a hostname wins."""
    loop = asyncio.get_event_loop()

    def _do_lookup():
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(ip)
            return {
                "status": "ok",
                "ip": ip,
                "hostname": hostname,
                "aliases": aliases,
                "addresses": addresses,
            }
        except socket.herror:
            return {"status": "no_ptr", "ip": ip, "hostname": None, "note": "No PTR record configured"}
        except socket.gaierror as e:
            return error_response(ScanError.DNS_RESOLUTION_FAILED, f"Reverse DNS failed: {e}", ip=ip)
        except Exception as e:
            return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:120]}", ip=ip)

    async def _gated_lookup():
        async with PRIORITY_DNS_SEMAPHORE:
            return await loop.run_in_executor(None, _do_lookup)

    primary_task = asyncio.create_task(_gated_lookup())
    secondary_task = _resolve_with_nslookup(ip, is_ip=True)

    try:
        res_primary, res_secondary = await asyncio.wait_for(
            asyncio.gather(primary_task, secondary_task, return_exceptions=True),
            timeout=TIMEOUTS["reverse_dns"],
        )
    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"Reverse DNS timed out after {TIMEOUTS['reverse_dns']}s", ip=ip)

    primary_hostname = None
    secondary_hostname = None
    note = None

    if isinstance(res_primary, dict):
        if res_primary.get("status") == "ok":
            primary_hostname = res_primary.get("hostname")
        else:
            note = res_primary.get("note") or res_primary.get("error_message")

    if isinstance(res_secondary, str) and res_secondary:
        secondary_hostname = res_secondary

    resolved_hostname = primary_hostname or secondary_hostname

    if not resolved_hostname:
        return {"status": "no_ptr", "ip": ip, "hostname": None, "note": note or "No PTR record found."}

    return {
        "status": "ok",
        "ip": ip,
        "hostname": resolved_hostname,
        "aliases": res_primary.get("aliases", []) if isinstance(res_primary, dict) else [],
        "addresses": res_primary.get("addresses", []) if isinstance(res_primary, dict) else [],
        "primary_resolver_hostname": primary_hostname,
        "nslookup_resolver_hostname": secondary_hostname,
    }
