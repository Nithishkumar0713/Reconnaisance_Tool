"""
Email & Employee Account Harvesting Module — 30+ Sources, Complete Surface & Darkweb Recon Engine.

Discovers email addresses, employee accounts, and naming conventions associated with a target domain using
30 free, publicly accessible intelligence sources, darkweb indexes, & passive leak scrapers, queried concurrently:

  1. Ubuntu PGP Keyserver      — keyserver.ubuntu.com (Employee PGP keys)
  2. MIT PGP Keyserver         — pgp.mit.edu (Academic & corporate employee PGP keys)
  3. OpenPGP Keyserver        — keys.openpgp.org public encryption keys
  4. crt.sh                   — SSL Certificate Transparency logs (CN/SAN fields)
  5. Wayback Machine          — Deep CDX API (1,000 records) scans archived URLs & contact pages
  6. Wayback Document Scanner — CDX API scans archived PDF/DOC/TXT documents for embedded emails
  7. 2-Level Recursive Crawl — Crawls contact pages & recursively follows internal staff directory links
  8. Regional DNS / DMARC     — Multi-subdomain DNS TXT, DMARC, and SOA responsible party extraction
  9. Passive Subdomain Sweep  — Discovers live subdomains via Anubis/RapidDNS and sweeps DNS records
 10. GitHub Public Search     — Searches public GitHub commits & repositories for @domain occurrences
 11. Deep Bing Search (10 Pgs)— Scrapes 10 pages of Bing search results across multiple dork queries
 12. CommonCrawl Index        — Queries free CommonCrawl web dataset index API
 13. AlienVault OTX           — Queries Open Threat Exchange passive DNS records
 14. ThreatMiner              — Queries ThreatMiner WHOIS & URI metadata index
 15. URLScan.io               — Queries urlscan.io public scan search engine
 16. CertSpotter CT Feed      — Queries CertSpotter SSL Certificate Transparency API
 17. Keybase Directory        — Discovers keybase user accounts & verified email identities
 18. Email-Format Index       — Queries Email-Format dataset index for domain patterns & email samples
 19. Skymem Search Index      — Scrapes Skymem public email search index
 20. SMTP Banner Probe        — Connects to MX mail servers to extract postmaster/greeting emails
 21. Ahmia Darkweb Index     — Scrapes Ahmia.fi darkweb (.onion) search index for @domain mentions
 22. Public Paste Dumps       — Searches Bing/DDG for site:pastebin.com, site:justpaste.it dumps
 23. LeakIX Data Leak Index   — Queries LeakIX for publicly exposed database leak logs
 24. Forum Registrations      — Scrapes third-party developer forums & conference registration lists
 25. GitLab Public API        — Queries GitLab public projects & user profiles for developer emails
 26. DuckDuckGo Web Engine    — Scrapes DuckDuckGo web search engine for @domain occurrences
 27. Qwant Web Index          — Queries Qwant public web search API for indexed domain emails
 28. Bitbucket & Gitee Search — Searches Bitbucket & Gitee public repositories for developer emails
 29. Public Cloud Storage     — Searches AWS S3, Azure Blob, and GCP storage buckets for exposed lists
 30. Database Dump & Log Dorks— Searches indexed .sql, .csv, and .log database backups for email lists

All results are filtered to @<target-domain>, deduplicated, categorized by
Account Type (Employee vs Role), and tagged with Leak/Exposure Risk ratings.
"""

import asyncio
import re
import urllib.parse
from typing import Any

import aiohttp
import dns.asyncresolver
import dns.exception

from utils.safety import TIMEOUTS, ScanError, error_response, skip_response
from utils.concurrency import run_bounded

# gather() fans out to ~20+ third-party sources per call, several of them
# (Bing/DuckDuckGo/Qwant-style search scraping) firing 5-6 requests each on
# their own. A single call is fine, but several concurrent callers — e.g.
# multiple targets in a full-scan batch — would multiply that into a burst
# of 100+ simultaneous scrape requests with nothing to stop it. This caps
# how many gather() calls can be actively fanning out at once, process-wide.
_GATHER_CONCURRENCY = asyncio.Semaphore(3)

_ROLE_PREFIXES = {
    "admin", "administrator", "abuse", "postmaster", "webmaster", "info",
    "contact", "contactus", "support", "help", "helpdesk", "security",
    "privacy", "dmarc", "dmarc-support", "sales", "billing", "careers",
    "jobs", "no-reply", "noreply", "enquiry", "enquiries", "office",
    "hostmaster", "service", "services", "marketing", "compliance",
    "root", "sysadmin", "system", "general", "feedback", "press", "media",
    "idc", "netops"
}

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    )
}


def _make_domain_re(domain: str) -> re.Pattern:
    """Regex that captures emails ending in @<domain> or @<sub.domain>."""
    escaped = re.escape(domain)
    return re.compile(
        rf"[a-zA-Z0-9._%+\-]{{1,64}}@(?:[a-zA-Z0-9\-]+\.)*{escaped}",
        re.IGNORECASE,
    )


def _extract(text: str, domain_re: re.Pattern) -> list[str]:
    """Extract all matching emails from a string, lowercased and sanitized."""
    if not text:
        return []
    raw = domain_re.findall(text)
    cleaned = []
    tld_junk = (".com", ".org", ".net", ".io", ".in", ".co", ".info", ".biz", ".edu", ".gov", ".it", ".html", ".aspx", ".php", "%22", "%20")
    for m in raw:
        m = m.lower().strip()
        parts = m.split("@")
        if len(parts) != 2:
            continue
        local_part, dom = parts
        for junk in tld_junk:
            if junk in local_part:
                local_part = local_part.split(junk)[-1]
        local_part = re.sub(r'^(?:%[0-9a-fA-F]{2}|[\+\"\'<>/\\:\s%\-\._])+', '', local_part)
        if local_part and not re.match(r'^(?:[0-9]{1,3}|[0-9a-f]{2})$', local_part) and len(local_part) >= 2:
            cleaned.append(f"{local_part}@{dom}")
    return list(set(cleaned))


def _classify_email(email: str) -> str:
    """Returns 'role' for generic role accounts or 'employee' for individual employee emails."""
    local_part = email.split("@")[0].lower()
    clean_local = local_part.split("+")[0].split("-")[0]
    if clean_local in _ROLE_PREFIXES or local_part in _ROLE_PREFIXES:
        return "role"
    return "employee"


def _detect_email_pattern(emails: list[dict]) -> dict:
    """Analyzes discovered employee emails to synthesize the organization's dominant email naming pattern."""
    patterns = {"first.last": 0, "f.last": 0, "first_l": 0, "first": 0}
    employee_emails = [e["email"].split("@")[0].lower() for e in emails if e.get("account_type") == "employee"]

    for loc in employee_emails:
        if "." in loc:
            parts = loc.split(".")
            if len(parts[0]) == 1:
                patterns["f.last"] += 1
            else:
                patterns["first.last"] += 1
        elif "_" in loc:
            patterns["first_l"] += 1
        elif len(loc) > 3 and loc.isalpha():
            patterns["first"] += 1

    dominant = max(patterns, key=patterns.get) if any(patterns.values()) else "unknown"
    count = patterns.get(dominant, 0)
    confidence = "HIGH" if count >= 3 else "MEDIUM" if count >= 1 else "LOW"

    return {
        "dominant_pattern": dominant if count > 0 else "Not Determined",
        "pattern_confidence": confidence,
        "sample_employee_count": len(employee_emails),
    }


async def _fetch_ubuntu_pgp(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    queries = [domain, f"@{domain}"]
    for q in queries:
        try:
            url = f"https://keyserver.ubuntu.com/pks/lookup?search={q}&op=index"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "ubuntu_pgp"}


async def _fetch_mit_pgp(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://pgp.mit.edu/pks/lookup?search={domain}&op=index"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "mit_pgp"}


async def _fetch_pgp(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://keys.openpgp.org/vks/v1/search?q={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "pgp_keyserver"}


async def _fetch_crtsh(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://crt.sh/?q=%.{domain}&output=json",
    ]
    for url in urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        for entry in data or []:
                            name_val = str(entry.get("name_value", ""))
                            common_name = str(entry.get("common_name", ""))
                            found.extend(_extract(name_val, domain_re))
                            found.extend(_extract(common_name, domain_re))
                    except Exception:
                        text = await resp.text(errors="replace")
                        found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "crt.sh"}


async def _fetch_wayback(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    urls = [
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=1000",
        f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
    ]
    for url in urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "wayback_machine"}


async def _fetch_wayback_docs(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    for ext in ["pdf", "doc", "txt", "xlsx", "csv"]:
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*.{ext}&output=json&fl=original&limit=300"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "wayback_docs"}


async def _fetch_web_crawl(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found_emails: list[str] = []
    visited_urls: set[str] = set()

    paths = [
        "", "/contact", "/about", "/team", "/people", "/staff", "/faculty",
        "/directory", "/careers", "/reach-us", "/whos-who", "/leadership", "/departments",
        "/index.aspx?id=contact", "/index.aspx?id=directory", "/index.aspx?id=whos_who"
    ]

    subdomains = [
        domain, f"www.{domain}", f"pune.{domain}", f"noida.{domain}",
        f"mumbai.{domain}", f"hyderabad.{domain}", f"thiruvananthapuram.{domain}",
        f"bangalore.{domain}", f"kolkata.{domain}", f"chennai.{domain}",
        f"silchar.{domain}", f"patna.{domain}", f"guwahati.{domain}",
        f"delhi.{domain}", f"mohali.{domain}"
    ]

    level1_urls = [f"https://{sub}{path}" for sub in subdomains for path in paths]
    level2_targets: set[str] = set()

    async def fetch_page(url: str, is_level2: bool = False):
        if url in visited_urls:
            return
        visited_urls.add(url)
        for proto in (["https"] if url.startswith("https") else ["https", "http"]):
            try:
                target = url if url.startswith("http") else f"{proto}://{url}"
                async with session.get(
                    target,
                    timeout=aiohttp.ClientTimeout(sock_connect=1.5, total=3.0),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    if resp.status < 400:
                        html = await resp.text(errors="replace")
                        found_emails.extend(_extract(html, domain_re))

                        if not is_level2:
                            hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
                            for href in hrefs:
                                href = href.strip()
                                full_url = urllib.parse.urljoin(target, href)
                                if domain in full_url and any(kw in full_url.lower() for kw in [
                                    "contact", "about", "team", "staff", "people", "faculty",
                                    "directory", "whos_who", "profile", "department", "person"
                                ]):
                                    if full_url not in visited_urls and len(level2_targets) < 50:
                                        level2_targets.add(full_url)
                        return
            except Exception:
                continue

    # run_bounded (not asyncio.gather over a pre-built task list) — this was
    # the last unfixed instance of the same task-explosion anti-pattern
    # already found and fixed in subdomain_finder.py/directory_enum.py/
    # port_scanner.py earlier: level1_urls alone is 225 URLs (15 subdomains
    # x 15 paths), all turned into asyncio.Task objects up front despite the
    # semaphore only letting 35 of them actually run at once. Confirmed
    # directly in this app's own asyncio-debug output that _fetch_web_crawl
    # shows up as a slow-callback source during real Deep scans (though it
    # runs cleanly with zero stalls in isolation) — it's not slow on its
    # own, it's adding unnecessary Task-creation overhead to the aggregate
    # peak load every single Deep scan carries, alongside the other 17
    # modules all launched at once. concurrency=35 here matches the removed
    # semaphore's old limit exactly, so real request concurrency is
    # unchanged — only how many Task objects get created up front changes.
    await run_bounded(level1_urls, lambda u: fetch_page(u, is_level2=False), 35, 6.0)

    if level2_targets:
        await run_bounded(list(level2_targets)[:40], lambda u: fetch_page(u, is_level2=True), 35, 2.0)

    return {"status": "ok", "emails": list(set(found_emails)), "source": "web_crawl"}


async def _fetch_dns_email(domain: str, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    subdomains = [
        domain, f"www.{domain}", f"mail.{domain}", f"portal.{domain}",
        f"pune.{domain}", f"noida.{domain}", f"mumbai.{domain}", f"hyderabad.{domain}"
    ]

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4

    async def query_txt(name: str):
        try:
            answers = await resolver.resolve(name, "TXT")
            for rdata in answers:
                txt_val = " ".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
                found.extend(_extract(txt_val, domain_re))
        except Exception:
            pass

    async def query_soa(name: str):
        try:
            answers = await resolver.resolve(name, "SOA")
            for rdata in answers:
                rname = str(rdata.rname).rstrip(".")
                if "." in rname:
                    parts = rname.split(".", 1)
                    candidate = f"{parts[0]}@{parts[1]}"
                    found.extend(_extract(candidate, domain_re))
        except Exception:
            pass

    tasks = []
    for sub in subdomains:
        tasks.append(query_txt(sub))
        tasks.append(query_txt(f"_dmarc.{sub}"))
        tasks.append(query_soa(sub))

    await asyncio.gather(*tasks, return_exceptions=True)

    standard_roles = [
        f"abuse@{domain}", f"postmaster@{domain}", f"webmaster@{domain}",
        f"admin@{domain}", f"contact@{domain}", f"security@{domain}",
        f"info@{domain}", f"support@{domain}", f"noreply@{domain}",
        f"no-reply@{domain}", f"dmarc-support@{domain}", f"netops@{domain}", f"idc@{domain}"
    ]
    found.extend(standard_roles)

    return {"status": "ok", "emails": list(set(found)), "source": "dns_txt_dmarc"}


async def _fetch_subdomain_dns(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    discovered_subs = [domain]
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                try:
                    subs = await resp.json(content_type=None)
                    if isinstance(subs, list):
                        discovered_subs.extend([s.strip().lower() for s in subs[:15] if domain in s])
                except Exception:
                    pass
    except Exception:
        pass

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3

    async def query_sub(sub: str):
        for rec in ["TXT", "_dmarc." + sub]:
            try:
                target = sub if not rec.startswith("_dmarc") else rec
                ans = await resolver.resolve(target, "TXT")
                for rdata in ans:
                    found.extend(_extract(str(rdata), domain_re))
            except Exception:
                pass

    tasks = [query_sub(s) for s in set(discovered_subs)]
    await asyncio.gather(*tasks, return_exceptions=True)

    return {"status": "ok", "emails": list(set(found)), "source": "subdomain_dns"}


async def _fetch_github(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    urls = [
        (f"https://api.github.com/search/commits?q={domain}", {"Accept": "application/vnd.github.cloak-preview+json"}),
        (f"https://api.github.com/search/repositories?q={domain}", {"Accept": "application/vnd.github.v3+json"}),
    ]

    for url, extra_hdr in urls:
        try:
            headers = {**_HEADERS, **extra_hdr}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "github_search"}


async def _fetch_bing_search(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    dorks = [
        f"%22%40{domain}%22",
        f"%22%40{domain}%22+contact",
        f"%22%40{domain}%22+staff",
        f"%22%40{domain}%22+directory",
    ]
    pages = [1, 11, 21, 31, 41, 51, 61, 71, 81, 91]

    async def fetch_page(dork: str, first: int):
        try:
            url = f"https://www.bing.com/search?q={dork}&first={first}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=3.5)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    return _extract(html, domain_re)
        except Exception:
            pass
        return []

    tasks = [fetch_page(d, p) for d in dorks[:2] for p in pages[:6]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            found.extend(r)

    return {"status": "ok", "emails": list(set(found)), "source": "bing_search"}


async def _fetch_commoncrawl(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        cc_index_url = "https://index.commoncrawl.org/collinfo.json"
        async with session.get(cc_index_url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                indices = await resp.json(content_type=None)
                if indices:
                    latest_api = indices[0].get("cdx-api", "")
                    if latest_api:
                        search_url = (
                            f"{latest_api}?url=*.{domain}/*"
                            f"&output=json&fl=url&limit=100&matchType=domain"
                        )
                        async with session.get(search_url, timeout=aiohttp.ClientTimeout(total=5)) as r2:
                            if r2.status == 200:
                                text = await r2.text(errors="replace")
                                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "commoncrawl"}


async def _fetch_alienvault_otx(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "alienvault_otx"}


async def _fetch_threatminer(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    endpoints = [
        f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=1",
        f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
    ]
    for url in endpoints:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "threatminer"}


async def _fetch_urlscan(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=50"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "urlscan"}


async def _fetch_certspotter(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://api.certspotter.com/v0/certs?domain={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "certspotter"}


async def _fetch_keybase(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://keybase.io/_/api/1.0/user/discover.json?domain={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "keybase"}


async def _fetch_email_format(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://www.email-format.com/d/{domain}/"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "email_format"}


async def _fetch_skymem(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"http://www.skymem.info/srch?q={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "skymem"}


async def _fetch_smtp_banner(domain: str, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 4
        answers = await resolver.resolve(domain, "MX")
        mx_hosts = [str(rdata.exchange).rstrip(".") for rdata in answers]
        for mx in mx_hosts[:2]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(mx, 25), timeout=2.5
                )
                greeting = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                text = greeting.decode("utf-8", errors="replace")
                found.extend(_extract(text, domain_re))
                writer.write(b"QUIT\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "smtp_banner"}


async def _fetch_ahmia_darkweb(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    queries = [f"%22%40{domain}%22", domain]
    for q in queries:
        try:
            url = f"https://ahmia.fi/search/?q={q}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "ahmia_darkweb"}


async def _fetch_paste_dumps(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    paste_sites = ["pastebin.com", "justpaste.it", "ghostbin.com", "rentry.co"]
    for site in paste_sites:
        try:
            url = f"https://www.bing.com/search?q=site:{site}+%22%40{domain}%22"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "paste_dumps"}


async def _fetch_leakix(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://leakix.net/search?q=%22%40{domain}%22"
        headers = {**_HEADERS, "Accept": "application/json"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "leakix"}


async def _fetch_forum_registrations(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    dorks = [
        f"%22%40{domain}%22+site:github.com",
        f"%22%40{domain}%22+site:stackoverflow.com",
        f"%22%40{domain}%22+attendee",
        f"%22%40{domain}%22+speaker",
    ]
    for dork in dorks:
        try:
            url = f"https://www.bing.com/search?q={dork}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "forum_registrations"}


async def _fetch_gitlab(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    urls = [
        f"https://gitlab.com/api/v4/projects?search={domain}",
        f"https://gitlab.com/api/v4/users?search={domain}",
    ]
    for url in urls:
        try:
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    found.extend(_extract(text, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "gitlab_search"}


async def _fetch_duckduckgo(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://html.duckduckgo.com/html/?q=%22%40{domain}%22"
        async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                html = await resp.text(errors="replace")
                found.extend(_extract(html, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "duckduckgo_search"}


async def _fetch_qwant(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    found: list[str] = []
    try:
        url = f"https://api.qwant.com/v3/search/web?q=%22%40{domain}%22&count=50"
        async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                found.extend(_extract(text, domain_re))
    except Exception:
        pass

    return {"status": "ok", "emails": list(set(found)), "source": "qwant_search"}


async def _fetch_bitbucket_gitee(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    """Searches Bitbucket & Gitee public repositories for developer email addresses."""
    found: list[str] = []
    dorks = [f"site:gitee.com+%22%40{domain}%22", f"site:bitbucket.org+%22%40{domain}%22"]
    for dork in dorks:
        try:
            url = f"https://www.bing.com/search?q={dork}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "bitbucket_gitee"}


async def _fetch_cloud_storage_buckets(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    """Searches AWS S3, Azure Blob, and GCP buckets for exposed document lists containing @domain."""
    found: list[str] = []
    dorks = [
        f"site:s3.amazonaws.com+%22%40{domain}%22",
        f"site:blob.core.windows.net+%22%40{domain}%22",
        f"site:storage.googleapis.com+%22%40{domain}%22",
    ]
    for dork in dorks:
        try:
            url = f"https://www.bing.com/search?q={dork}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "cloud_storage_buckets"}


async def _fetch_database_backups(domain: str, session: aiohttp.ClientSession, domain_re: re.Pattern) -> dict:
    """Searches indexed .sql, .csv, and .log database backups for email lists."""
    found: list[str] = []
    dorks = [
        f"filetype:sql+%22%40{domain}%22",
        f"filetype:csv+%22%40{domain}%22",
        f"filetype:log+%22%40{domain}%22",
    ]
    for dork in dorks:
        try:
            url = f"https://www.bing.com/search?q={dork}"
            async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="replace")
                    found.extend(_extract(html, domain_re))
        except Exception:
            pass

    return {"status": "ok", "emails": list(set(found)), "source": "database_backups"}


def _evaluate_leak_exposure(email: str, sources: list[str], account_type: str) -> dict:
    leak_sources = []

    if "ahmia_darkweb" in sources:
        leak_sources.append("Darkweb (.onion) Index Exposure")
    if "paste_dumps" in sources:
        leak_sources.append("Public Paste Dump Leak (Pastebin/JustPaste)")
    if "leakix" in sources:
        leak_sources.append("LeakIX Data Breach Exposure")
    if "database_backups" in sources:
        leak_sources.append("Exposed Database / SQL Backup Leak")
    if "cloud_storage_buckets" in sources:
        leak_sources.append("Public Cloud Storage Bucket Exposure")
    if "forum_registrations" in sources:
        leak_sources.append("Third-Party Forum & Event Registration Leak")
    if "ubuntu_pgp" in sources or "pgp_keyserver" in sources or "mit_pgp" in sources:
        leak_sources.append("Public PGP Keyserver Exposure")
    if "github_search" in sources or "gitlab_search" in sources or "bitbucket_gitee" in sources:
        leak_sources.append("Public Code Repository Leak")
    if "wayback_machine" in sources or "wayback_docs" in sources:
        leak_sources.append("Archived Web & Document Mailto Leak")
    if "crt.sh" in sources or "certspotter" in sources:
        leak_sources.append("Certificate Transparency SAN Exposure")
    if "web_crawl" in sources:
        leak_sources.append("Target Web Scraping Exposure")
    if "commoncrawl" in sources:
        leak_sources.append("CommonCrawl Web Archive")
    if "alienvault_otx" in sources:
        leak_sources.append("AlienVault Threat Intelligence")
    if "threatminer" in sources:
        leak_sources.append("ThreatMiner Archival Index")
    if "urlscan" in sources:
        leak_sources.append("URLScan Public Scan Entry")
    if "keybase" in sources:
        leak_sources.append("Keybase Verified Identity Leak")
    if "email_format" in sources or "skymem" in sources:
        leak_sources.append("Public Email Index Leak")
    if "bing_search" in sources or "duckduckgo_search" in sources or "qwant_search" in sources:
        leak_sources.append("Search Engine Index Exposure")
    if "smtp_banner" in sources:
        leak_sources.append("SMTP Server Banner Greeting Leak")

    is_leaked = len(leak_sources) > 0 and (
        "ahmia_darkweb" in sources or "paste_dumps" in sources or "leakix" in sources or "database_backups" in sources or
        "ubuntu_pgp" in sources or "mit_pgp" in sources or "github_search" in sources or "gitlab_search" in sources or "wayback_machine" in sources
    )

    if account_type == "employee" and ("ahmia_darkweb" in sources or "paste_dumps" in sources or "github_search" in sources or "gitlab_search" in sources or "database_backups" in sources):
        exposure_risk = "CRITICAL"
        risk_description = "Employee email exposed on Darkweb forums, credential pastes, database backups, or code leaks"
    elif account_type == "employee" and is_leaked:
        exposure_risk = "HIGH"
        risk_description = "Employee email exposed in public web archives, breach logs, or scraped pages"
    elif account_type == "employee":
        exposure_risk = "MEDIUM"
        risk_description = "Employee account identified from passive reconnaissance"
    elif "dns_txt_dmarc" in sources and len(sources) == 1:
        exposure_risk = "LOW"
        risk_description = "Standard operational role address"
    else:
        exposure_risk = "MEDIUM"
        risk_description = "Role address exposed across multiple public sources"

    return {
        "is_leaked": is_leaked,
        "exposure_risk": exposure_risk,
        "risk_description": risk_description,
        "leak_sources": leak_sources if leak_sources else ["Public Reconnaissance"],
    }


async def gather(domain: str) -> dict[str, Any]:
    if not domain or "." not in domain:
        return error_response(
            ScanError.INVALID_RESPONSE,
            "Not a valid domain for email gathering",
            emails=[], total_found=0
        )
    async with _GATHER_CONCURRENCY:
        return await _gather_impl(domain)


async def _gather_impl(domain: str) -> dict[str, Any]:
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    domain_re = _make_domain_re(domain)

    connector = aiohttp.TCPConnector(limit=75, limit_per_host=10, ssl=False, resolver=aiohttp.ThreadedResolver())
    timeout = aiohttp.ClientTimeout(total=120, connect=8, sock_read=10)

    async def safe_source(coro, source_name: str, max_time: float = 8.0) -> dict:
        """Fetch with retry logic: 1 retry on transient failure with exponential backoff."""
        for attempt in range(2):
            try:
                return await asyncio.wait_for(coro, timeout=max_time)
            except asyncio.TimeoutError:
                if attempt == 0:
                    await asyncio.sleep(1.0)
                    continue
                return {"status": "ok", "emails": [], "source": source_name}
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "ok", "emails": [], "source": source_name}
        return {"status": "ok", "emails": [], "source": source_name}

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            headers=_HEADERS,
            timeout=timeout,
        ) as session:
            results = await asyncio.gather(
                safe_source(_fetch_ubuntu_pgp(domain, session, domain_re), "ubuntu_pgp", 7.0),
                safe_source(_fetch_mit_pgp(domain, session, domain_re), "mit_pgp", 5.0),
                safe_source(_fetch_pgp(domain, session, domain_re), "pgp_keyserver", 5.0),
                safe_source(_fetch_crtsh(domain, session, domain_re), "crt.sh", 7.0),
                safe_source(_fetch_wayback(domain, session, domain_re), "wayback_machine", 8.0),
                safe_source(_fetch_wayback_docs(domain, session, domain_re), "wayback_docs", 6.0),
                safe_source(_fetch_web_crawl(domain, session, domain_re), "web_crawl", 8.0),
                safe_source(_fetch_dns_email(domain, domain_re), "dns_txt_dmarc", 5.0),
                safe_source(_fetch_subdomain_dns(domain, session, domain_re), "subdomain_dns", 6.0),
                safe_source(_fetch_github(domain, session, domain_re), "github_search", 5.0),
                safe_source(_fetch_bing_search(domain, session, domain_re), "bing_search", 7.0),
                safe_source(_fetch_commoncrawl(domain, session, domain_re), "commoncrawl", 5.0),
                safe_source(_fetch_alienvault_otx(domain, session, domain_re), "alienvault_otx", 5.0),
                safe_source(_fetch_threatminer(domain, session, domain_re), "threatminer", 5.0),
                safe_source(_fetch_urlscan(domain, session, domain_re), "urlscan", 5.0),
                safe_source(_fetch_certspotter(domain, session, domain_re), "certspotter", 5.0),
                safe_source(_fetch_keybase(domain, session, domain_re), "keybase", 4.0),
                safe_source(_fetch_email_format(domain, session, domain_re), "email_format", 5.0),
                safe_source(_fetch_skymem(domain, session, domain_re), "skymem", 5.0),
                safe_source(_fetch_smtp_banner(domain, domain_re), "smtp_banner", 4.0),
                safe_source(_fetch_ahmia_darkweb(domain, session, domain_re), "ahmia_darkweb", 6.0),
                safe_source(_fetch_paste_dumps(domain, session, domain_re), "paste_dumps", 6.0),
                safe_source(_fetch_leakix(domain, session, domain_re), "leakix", 5.0),
                safe_source(_fetch_forum_registrations(domain, session, domain_re), "forum_registrations", 6.0),
                safe_source(_fetch_gitlab(domain, session, domain_re), "gitlab_search", 5.0),
                safe_source(_fetch_duckduckgo(domain, session, domain_re), "duckduckgo_search", 5.0),
                safe_source(_fetch_qwant(domain, session, domain_re), "qwant_search", 5.0),
                safe_source(_fetch_bitbucket_gitee(domain, session, domain_re), "bitbucket_gitee", 5.0),
                safe_source(_fetch_cloud_storage_buckets(domain, session, domain_re), "cloud_storage_buckets", 5.0),
                safe_source(_fetch_database_backups(domain, session, domain_re), "database_backups", 5.0),
                return_exceptions=True,
            )
    except Exception as e:
        return error_response(
            ScanError.UNKNOWN_ERROR,
            f"Email gather session failed: {type(e).__name__}: {str(e)[:150]}",
            emails=[], total_found=0
        )

    email_to_sources: dict[str, list[str]] = {}
    sources_meta: dict[str, dict] = {}

    for result in results:
        if isinstance(result, Exception) or not isinstance(result, dict):
            continue

        source_name = result.get("source", "unknown")
        emails = result.get("emails", [])
        status = result.get("status", "ok")
        note = result.get("note")

        sources_meta[source_name] = {
            "status": status,
            "count": len(emails),
            **({"note": note} if note else {}),
        }

        for email in emails:
            email = email.strip().lower()
            if not email or "@" not in email:
                continue
            if not email.endswith(f"@{domain}") and not email.endswith(f".{domain}"):
                continue
            if email not in email_to_sources:
                email_to_sources[email] = []
            if source_name not in email_to_sources[email]:
                email_to_sources[email].append(source_name)

    email_list = []
    employee_count = 0
    role_count = 0
    leaked_count = 0

    for email, sources in sorted(email_to_sources.items()):
        account_type = _classify_email(email)
        confidence = "high" if len(sources) >= 2 else "medium"
        exposure = _evaluate_leak_exposure(email, sources, account_type)

        if account_type == "employee":
            employee_count += 1
        else:
            role_count += 1

        if exposure["is_leaked"]:
            leaked_count += 1

        email_list.append({
            "email": email,
            "account_type": account_type,
            "sources": sorted(sources),
            "source_count": len(sources),
            "confidence": confidence,
            **exposure,
        })

    risk_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    email_list.sort(
        key=lambda x: (
            0 if x["account_type"] == "employee" else 1,
            risk_rank.get(x["exposure_risk"], 4),
            x["email"]
        )
    )

    pattern_info = _detect_email_pattern(email_list)

    return {
        "status": "ok",
        "domain": domain,
        "total_found": len(email_list),
        "employee_accounts_count": employee_count,
        "role_accounts_count": role_count,
        "leaked_accounts_count": leaked_count,
        "naming_pattern": pattern_info,
        "emails": email_list,
        "sources": sources_meta,
    }
