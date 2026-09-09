"""
Subdomain Discovery Module.
Finds subdomains of a target domain using passive OSINT sources:
  - crt.sh: queries Certificate Transparency logs (every SSL cert ever issued is logged here)
  - HackerTarget: free subdomain lookup API
  - RapidDNS: another passive subdomain database
  - AlienVault OTX: threat intelligence subdomain data
  - URLScan.io: live web scan results database
Then validates each found subdomain by checking if it resolves to an IP address.
"""

import asyncio
import socket
import shutil
import ssl
import warnings
from typing import Any
from concurrent.futures import ThreadPoolExecutor
import atexit

import aiohttp
import dns.asyncresolver
import dns.exception

from utils.safety import TIMEOUTS, ScanError, error_response
from utils.concurrency import run_bounded, BULK_DNS_SEMAPHORE

warnings.filterwarnings("ignore", category=RuntimeWarning)

_dns_executor = None

def _get_dns_executor():
    """Lazy-initialize and return the global DNS executor.

    Sized for worst-case full-scan-batch demand, not just one target: with
    Deep-mode batches running up to 5 targets concurrently, each target's
    own bruteforce stage alone can hold up to 60 of these threads busy
    (run_bounded's concurrency for is_single_module=False) for the
    duration of its own timeout, so 5 targets mid-bruteforce at once
    already wants ~300. 600 gives real headroom above that baseline for
    the unresolved-subdomain resolution stage below to run concurrently
    without queuing behind bruteforce and starving other targets' DNS
    calls (see _MAX_UNRESOLVED_TO_RESOLVE for the other half of this fix).
    """
    global _dns_executor
    if _dns_executor is None:
        _dns_executor = ThreadPoolExecutor(max_workers=600)
        atexit.register(_cleanup_dns_executor)
    return _dns_executor

def _cleanup_dns_executor():
    """Properly shutdown the DNS executor on exit."""
    global _dns_executor
    if _dns_executor is not None:
        _dns_executor.shutdown(wait=False)

COMMON_SUBDOMAINS_BASE = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin",
    "administrator", "portal", "test", "dev", "staging", "prod", "api",
    "api1", "api2", "app", "apps", "mobile", "m", "blog", "shop", "store",
    "cdn", "static", "media", "img", "images", "assets", "docs", "help",
    "support", "kb", "wiki", "forum", "community", "chat", "live",
    "download", "upload", "files", "cloud", "storage", "backup", "vpn",
    "ssh", "git", "jenkins", "ci", "build", "deploy", "monitor", "status",
    "stats", "analytics", "dashboard", "control", "panel", "cpanel",
    "secure", "auth", "sso", "login", "register", "signup", "account",
    "user", "profile", "beta", "demo", "sandbox", "old", "new", "internal",
    "web", "web1", "host", "server", "db", "mysql", "postgres", "mongo",
    "redis", "cache", "proxy", "gateway", "load", "lb", "firewall", "waf",
    "relay", "hub", "data", "report", "crm", "jira", "grafana", "kibana",
    "vault", "secret", "key", "cert", "pki", "ldap", "corp", "corporate",
    "marketing", "sales", "hr", "finance", "ops", "devops", "k8s", "docker",
    "v1", "v2", "v3", "partner", "vendor", "client", "customer",
    "backup", "test", "staging", "production", "console", "service",
    "identity", "sms", "email", "payment", "order", "billing", "invoice",
    "ticket", "helpdesk", "branch", "office", "hr", "finance",
]

_quick_subs = set(COMMON_SUBDOMAINS_BASE)

for p in ["api", "web", "app", "dev", "stage", "test", "prod", "qa", "demo", "node", "srv", "db", "mail", "ns", "portal", "admin", "cloud", "cdn", "assets", "static", "media", "data", "cache", "gateway", "proxy", "vpn", "auth", "user", "client"]:
    for i in range(1, 31):
        _quick_subs.add(f"{p}{i}")
        _quick_subs.add(f"{p}-{i}")

_quick_microservices = ["user", "account", "auth", "mail", "storage", "media", "analytics", "admin", "config", "api", "app", "dev", "test", "prod"]
_quick_suffixes = ["api", "app", "dev", "service", "portal"]
for p in _quick_microservices:
    for s in _quick_suffixes:
        _quick_subs.add(f"{p}-{s}")
        _quick_subs.add(f"{p}{s}")

COMMON_SUBDOMAINS_QUICK = sorted(list(_quick_subs))

_EXTRA_PREFIXES = [
    "api", "web", "app", "dev", "stage", "test", "prod", "qa", "uat", "demo",
    "node", "srv", "server", "host", "db", "mail", "ns", "dns", "mx", "auth",
    "sso", "portal", "admin", "gateway", "proxy", "k8s", "cloud", "vpn", "cdn"
]
_EXTRA_SUFFIXES = [
    "service", "api", "app", "dev", "stage", "test", "prod", "internal",
    "corp", "portal", "hub", "node", "gw", "db", "cache", "box", "zone"
]

_generated_subs = set(COMMON_SUBDOMAINS_BASE)

for p in ["api", "web", "app", "dev", "stage", "test", "prod", "node", "srv", "db", "mail", "ns", "dns", "portal", "admin", "cloud", "k8s", "cluster", "gw", "proxy", "vpn", "cdn", "assets", "static", "media", "data", "cache", "mfa", "otp", "sms", "gateway", "pay", "bank", "ins", "agent", "merchant", "user", "client", "corp", "internal"]:
    for i in range(1, 51):
        _generated_subs.add(f"{p}{i}")
        _generated_subs.add(f"{p}-{i}")
        _generated_subs.add(f"{p}0{i}" if i < 10 else f"{p}{i}")

for p in ["user", "account", "order", "pay", "payment", "billing", "auth", "sso", "notification", "mail", "sms", "push", "file", "storage", "media", "video", "chat", "event", "log", "metrics", "search", "cache", "db", "job", "task", "cron", "report", "analytics", "admin", "config", "vault", "key", "cert", "tenant", "client", "vendor", "partner", "ticket", "help", "support", "docs", "asset", "static", "build", "deploy", "registry", "k8s", "docker", "cloud", "vpn", "dns", "mfa", "otp", "auth", "token", "session", "bank", "card", "loan", "insure", "insurance", "premium", "claim", "claims", "renew", "renewal", "quote", "proposal", "agent", "broker", "merchant", "pos", "atm", "branch", "office", "hrms", "payroll", "career", "career-api", "epay", "enach", "nach", "mandate", "billing", "invoice", "receipt", "statement"]:
    for s in _EXTRA_SUFFIXES:
        _generated_subs.add(f"{p}-{s}")
        _generated_subs.add(f"{p}{s}")

COMMON_SUBDOMAINS = sorted(list(_generated_subs))



_FAST_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]

# Some real-world domains (large SaaS companies especially) have thousands
# of subdomains discoverable via crt.sh/wayback/etc. with no IP attached,
# and each one needs its own real DNS lookup to resolve. Verified directly
# (a 10-target Deep batch at concurrency 5) that one such target
# (bitbucket.org, ~9,700 unresolved subdomains) can keep all 60 of its
# resolution-stage worker threads busy for the *entire* 60s stage timeout,
# holding that many shared DNS-executor slots continuously rather than
# releasing them quickly — which starved every other concurrent target's
# DNS-dependent modules (geo_ip, whois, shodan_intel, etc.) in the same
# batch wave and caused widespread collateral timeouts. Capping how many
# get resolved bounds that worst case; only applied for is_single_module
# =False (full scans, solo or batched) so the dedicated single-module
# Subdomain Finder check keeps its existing unlimited behavior.
#
# Lowered from 1000 to 400 after further testing showed the real ceiling
# here isn't in-process thread-pool slot count (600 workers is far more
# than 5 concurrent targets' peak *simultaneous* demand) — it's genuine
# real-world DNS query *volume* leaving this one machine. Domains with a
# large raw discovery count (heroku.com: 35,334; salesforce.com: 55,663 in
# one run) still generate substantial real lookup traffic even with a
# 1000-item cap, and that traffic shares the same underlying network/
# resolver capacity as every other module's real DNS calls (resolve_target,
# whois, dns_recon) — verified directly: domains that failed with
# DNS-resolution errors mid-batch resolved instantly when tested seconds
# later in isolation, meaning it's contention, not a real outage. No
# thread-pool size fixes a real external throughput ceiling; cutting the
# self-inflicted query volume does.
_MAX_UNRESOLVED_TO_RESOLVE = 400


def _resolve_all_sync(hostname: str) -> list[str]:
    """Resolves all IPv4 (A) and IPv6 (AAAA) addresses using system getaddrinfo."""
    ips = []
    try:
        socket.setdefaulttimeout(1.5)
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for res in results:
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


async def _resolve_with_nameserver(hostname: str, nameserver: str) -> str | None:
    """Query a specific nameserver directly using dnspython async."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.lifetime = 2.5
    resolver.timeout = 2.5
    try:
        answers = await resolver.resolve(hostname, "A")
        if answers:
            return str(answers[0])
    except Exception:
        pass
    try:
        cname_answers = await resolver.resolve(hostname, "CNAME")
        if cname_answers:
            target = str(cname_answers[0].target).rstrip(".")
            a_answers = await resolver.resolve(target, "A")
            if a_answers:
                return str(a_answers[0])
    except Exception:
        pass
    return None


async def _resolve_async(hostname: str) -> list[str]:
    """Uses the system resolver inside the DNS thread pool to resolve all
    IPv4/IPv6 IPs, gated by BULK_DNS_SEMAPHORE — see its docstring for
    why: the thread pool's own size isn't the real ceiling, the actual
    network resolver's throughput is, and this is the highest-volume real
    DNS call site in the whole app (every bruteforce/unresolved-subdomain
    candidate goes through here) — capped separately from the smaller,
    higher-priority pool used by one-shot-per-target calls elsewhere."""
    loop = asyncio.get_event_loop()
    executor = _get_dns_executor()
    try:
        async with BULK_DNS_SEMAPHORE:
            ips = await asyncio.wait_for(
                loop.run_in_executor(executor, _resolve_all_sync, hostname),
                timeout=2.0,
            )
        return ips if ips else []
    except Exception:
        return []


async def _detect_wildcard_dns(base_domain: str) -> set[str]:
    """
    Probes 3 guaranteed-nonexistent random subdomains. If they all resolve
    to the same IP(s), the domain has wildcard DNS (every possible subdomain
    resolves, real or not) and returns that IP set; otherwise returns an
    empty set. Verified directly: bitbucket.org resolves random-uuid
    subdomains just like real ones, which is exactly what made bruteforcing
    it pointless (every one of ~10k wordlist guesses "succeeds") — see
    _bruteforce_subdomains for how this is used.
    """
    import uuid
    probes = [f"{uuid.uuid4().hex}-wc-probe.{base_domain}" for _ in range(3)]
    results = await asyncio.gather(*[_resolve_async(p) for p in probes], return_exceptions=True)
    ip_sets = [set(r) for r in results if isinstance(r, list) and r]
    if len(ip_sets) < 2:
        return set()
    common = ip_sets[0]
    for s in ip_sets[1:]:
        common &= s
    return common if common else set()


async def _bruteforce_subdomains(base_domain: str, wordlist: list[str], is_single_module: bool = False) -> dict:
    wildcard_ips = await _detect_wildcard_dns(base_domain)
    if wildcard_ips:
        return {
            "status": "skipped",
            "results": [],
            "note": "Wildcard DNS detected for this domain (every possible subdomain resolves) — bruteforce would only produce false positives, so it was skipped. Passively-sourced subdomains (crt.sh, hackertarget, etc.) are unaffected.",
        }

    concurrency = 300 if is_single_module else 60

    async def check_one(sub):
        ips = await _resolve_async(f"{sub}.{base_domain}")
        if ips:
            return [{"subdomain": f"{sub}.{base_domain}", "ip": ip, "source": "bruteforce"} for ip in ips]
        return None

    results_lists, timed_out = await run_bounded(wordlist, check_one, concurrency, 45 if is_single_module else 60)
    flat_results = [item for sub_results in results_lists for item in sub_results]
    if timed_out:
        return {"status": "partial", "results": flat_results, "note": "Bruteforce timed out"}
    return {"status": "ok", "results": flat_results}


async def _http_get_with_retry(
    url: str, 
    headers: dict | None = None, 
    response_format: str = "json",
    retries: int = 1,
    timeout_sec: float = 6.0
) -> dict:
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 429:
                        await asyncio.sleep(1.0 * (attempt + 1))
                        continue
                    if response.status != 200:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    
                    if response_format == "json":
                        try:
                            data = await response.json(content_type=None)
                            return {"status": "ok", "data": data}
                        except Exception:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                    else:
                        text = await response.text()
                        return {"status": "ok", "data": text}
        except Exception:
            await asyncio.sleep(0.5 * (attempt + 1))
            continue
            
    return {"status": "failed", "data": None}


async def _fetch_crtsh(domain: str, is_single_module: bool = False) -> dict:
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    retries = 2 if is_single_module else 1
    data = None
    for u in urls:
        res = await _http_get_with_retry(u, response_format="json", retries=retries, timeout_sec=10.0 if is_single_module else 5.0)
        if res["status"] == "ok" and res["data"]:
            data = res["data"]
            break

    if not data:
        return {"status": "failed", "results": [], "note": "crt.sh query failed or timed out"}

    subdomains = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line and "*" not in line and line.endswith(domain) and line != domain:
                subdomains.add(line)

    results = [{"subdomain": s, "ip": None, "source": "crt.sh"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_certspotter(domain: str, is_single_module: bool = False) -> dict:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    res = await _http_get_with_retry(url, response_format="json", retries=2 if is_single_module else 1, timeout_sec=10.0 if is_single_module else 5.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "CertSpotter query failed"}
        
    results = []
    subdomains = set()
    for item in res["data"]:
        for name in item.get("dns_names", []):
            name = name.strip().lower()
            if name.endswith(domain) and name != domain and "*" not in name:
                subdomains.add(name)
    for sub in subdomains:
        results.append({"subdomain": sub, "ip": None, "source": "certspotter"})
    return {"status": "ok", "results": results}


async def _fetch_hackertarget(domain: str) -> dict:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    res = await _http_get_with_retry(url, response_format="text", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "HackerTarget query failed"}
        
    text = res["data"]
    if "error" in text.lower() or "api count exceeded" in text.lower():
        return {"status": "rate_limited", "results": [], "note": "HackerTarget quota exhausted"}
        
    results = []
    for line in text.strip().split("\n"):
        parts = line.split(",")
        if len(parts) == 2:
            results.append({"subdomain": parts[0].strip().lower(), "ip": parts[1].strip() or None, "source": "hackertarget"})
    return {"status": "ok", "results": results}


async def _fetch_alienvault(domain: str) -> dict:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }
    res = await _http_get_with_retry(url, headers=headers, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "AlienVault query failed"}
        
    results = []
    for record in res["data"].get("passive_dns", []):
        hostname = record.get("hostname", "").lower()
        ip = record.get("address", "")
        if hostname and hostname.endswith(domain) and hostname != domain:
            results.append({"subdomain": hostname, "ip": ip or None, "source": "alienvault"})
    return {"status": "ok", "results": results}


async def _fetch_rapiddns(domain: str) -> dict:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
    res = await _http_get_with_retry(url, response_format="text", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "RapidDNS query failed"}
        
    text = res["data"]
    import re
    found = set(re.findall(r'([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', text))
    results = [
        {"subdomain": s.lower(), "ip": None, "source": "rapiddns"}
        for s in found if s.lower() != domain
    ]
    return {"status": "ok", "results": results}


async def _fetch_wayback(domain: str) -> dict:
    import urllib.parse
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=3000"
    res = await _http_get_with_retry(url, response_format="json", retries=2, timeout_sec=10.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "Wayback Machine query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, list) and len(data) > 1:
        for row in data[1:]:
            if isinstance(row, list) and len(row) > 0:
                raw_url = row[0]
                try:
                    host = urllib.parse.urlparse(raw_url).netloc.split(":")[0].lower()
                    if host.endswith(domain) and host != domain and "*" not in host:
                        subdomains.add(host)
                except Exception:
                    pass

    results = [{"subdomain": s, "ip": None, "source": "wayback"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_urlscan(domain: str) -> dict:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    res = await _http_get_with_retry(url, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "URLScan query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, dict):
        for item in data.get("results", []):
            task_dom = item.get("task", {}).get("domain", "").lower()
            page_dom = item.get("page", {}).get("domain", "").lower()
            for host in (task_dom, page_dom):
                if host and host.endswith(domain) and host != domain and "*" not in host:
                    subdomains.add(host)

    results = [{"subdomain": s, "ip": None, "source": "urlscan"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_anubis(domain: str) -> dict:
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    res = await _http_get_with_retry(url, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "Anubis query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, list):
        for s in data:
            if isinstance(s, str):
                s = s.strip().lower()
                if s.endswith(domain) and s != domain and "*" not in s:
                    subdomains.add(s)

    results = [{"subdomain": s, "ip": None, "source": "anubis"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_subdomain_center(domain: str) -> dict:
    url = f"https://subdomain.center/api/stream?domain={domain}"
    res = await _http_get_with_retry(url, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "SubdomainCenter query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, list):
        for s in data:
            if isinstance(s, str):
                s = s.strip().lower()
                if s.endswith(domain) and s != domain and "*" not in s:
                    subdomains.add(s)

    results = [{"subdomain": s, "ip": None, "source": "subdomain_center"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_threatminer(domain: str) -> dict:
    url = f"https://api.threatminer.org/v2/domain.json?q={domain}&rt=5"
    res = await _http_get_with_retry(url, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "ThreatMiner query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, dict):
        for s in data.get("results", []):
            if isinstance(s, str):
                s = s.strip().lower()
                if s.endswith(domain) and s != domain and "*" not in s:
                    subdomains.add(s)

    results = [{"subdomain": s, "ip": None, "source": "threatminer"} for s in subdomains]
    return {"status": "ok", "results": results}



async def _fetch_virustotal_public(domain: str) -> dict:
    """VirusTotal public UI endpoint — no API key required, returns up to 40 subdomains."""
    url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "X-Tool": "vt-ui-main",
        "Accept-Ianguage": "en-US,en;q=0.9",
        "X-VT-Anti-Abuse-Header": "MTcyMjY5NjQwMA==",
    }
    res = await _http_get_with_retry(url, headers=headers, response_format="json", retries=2, timeout_sec=10.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": [], "note": "VirusTotal public query failed"}

    subdomains = set()
    data = res["data"]
    if isinstance(data, dict):
        for item in data.get("data", []):
            host = item.get("id", "").strip().lower()
            if not host:
                attrs = item.get("attributes", {})
                host = attrs.get("id", "").strip().lower()
            if host and host.endswith(domain) and host != domain and "*" not in host:
                subdomains.add(host)

    results = [{"subdomain": s, "ip": None, "source": "virustotal"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _reverse_ip_lookup_shodan(ip: str, root_domain: str) -> list[str]:
    """
    Query Shodan InternetDB for a given IP — returns all known hostnames on that IP.
    Free, no key required. Rate limited but generous.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    res = await _http_get_with_retry(url, response_format="json", retries=1, timeout_sec=5.0)
    if res["status"] != "ok" or not res["data"]:
        return []
    data = res["data"]
    if not isinstance(data, dict):
        return []
    found = []
    for hostname in data.get("hostnames", []):
        host = hostname.strip().lower()
        if host.endswith(root_domain) and host != root_domain and "*" not in host:
            found.append(host)
    return found


async def _fetch_search_engines(domain: str) -> dict:
    """Scrape DuckDuckGo and Yahoo using site: dork to find indexed subdomains."""
    import re
    subdomains = set()
    pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9._-]*\.' + re.escape(domain) + r')')

    ddg_url = f"https://html.duckduckgo.com/html/?q=site%3A{domain}+-site%3Awww.{domain}&ia=web"
    res = await _http_get_with_retry(ddg_url, response_format="text", retries=2, timeout_sec=10.0)
    if res["status"] == "ok" and res["data"]:
        for m in pattern.findall(res["data"]):
            host = m.lower().strip(".")
            if host.endswith(domain) and host != domain and "*" not in host:
                subdomains.add(host)

    yahoo_url = f"https://search.yahoo.com/search?p=site%3A{domain}&n=100"
    res2 = await _http_get_with_retry(yahoo_url, response_format="text", retries=2, timeout_sec=10.0)
    if res2["status"] == "ok" and res2["data"]:
        for m in pattern.findall(res2["data"]):
            host = m.lower().strip(".")
            if host.endswith(domain) and host != domain and "*" not in host:
                subdomains.add(host)

    results = [{"subdomain": s, "ip": None, "source": "search_engines"} for s in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_robtex(domain: str) -> dict:
    url = f"https://freeapi.robtex.com/pdns_forward?domain={domain}"
    res = await _http_get_with_retry(url, response_format="text", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": []}
    
    results = []
    import json
    subdomains = set()
    for line in res["data"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict) and "records" in record:
                records_list = record["records"]
            else:
                records_list = [record]
        except Exception:
            records_list = []
                
        for rec in records_list:
            for key in ["rrname", "rrdata"]:
                val = rec.get(key, "").lower().strip(".")
                if val.endswith("." + domain) and val != domain and "*" not in val:
                    subdomains.add(val)
                    
    results = [{"subdomain": sub, "ip": None, "source": "robtex"} for sub in subdomains]
    return {"status": "ok", "results": results}


async def _fetch_bevigil(domain: str) -> dict:
    import os
    key = os.getenv("BEVIGIL_API_KEY", "").strip()
    if not key:
        return {"status": "skipped", "results": [], "note": "BeVigil API key not configured"}
    
    url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
    headers = {"X-Access-Token": key}
    res = await _http_get_with_retry(url, headers=headers, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": []}
        
    results = []
    subdomains = res["data"].get("subdomains", [])
    for sub in subdomains:
        sub = sub.lower().strip()
        if sub.endswith(domain) and sub != domain and "*" not in sub:
            results.append({"subdomain": sub, "ip": None, "source": "bevigil"})
    return {"status": "ok", "results": results}


async def _fetch_netlas(domain: str) -> dict:
    import os
    key = os.getenv("NETLAS_API_KEY", "").strip()
    if not key:
        return {"status": "skipped", "results": [], "note": "Netlas API key not configured"}
    
    url = f"https://app.netlas.io/api/v1/domains?q=domain:*.{domain}&indices=0&size=100"
    headers = {"Authorization": f"Bearer {key}"}
    res = await _http_get_with_retry(url, headers=headers, response_format="json", retries=2, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return {"status": "failed", "results": []}
        
    results = []
    items = res["data"].get("items", [])
    for item in items:
        sub = (item.get("domain") or item.get("data", {}).get("domain") or "").lower().strip()
        if sub.endswith(domain) and sub != domain and "*" not in sub:
            results.append({"subdomain": sub, "ip": None, "source": "netlas"})
    return {"status": "ok", "results": results}


async def _recursive_crtsh(sub_parent: str, root_domain: str) -> list[dict]:
    """Query crt.sh for nested wildcard certs: %.<sub_parent>."""
    url = f"https://crt.sh/?q=%25.{sub_parent}&output=json"
    res = await _http_get_with_retry(url, response_format="json", retries=1, timeout_sec=8.0)
    if res["status"] != "ok" or not res["data"]:
        return []
    results = []
    for entry in res["data"]:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line and "*" not in line and line.endswith(root_domain) and line != root_domain:
                results.append({"subdomain": line, "ip": None, "source": "recursive_crt"})
    return results


def _generate_permutations(discovered: list[str], root_domain: str) -> list[str]:
    """Generate subdomain permutations from discovered hostnames (altdns-style)."""
    env_mutations = [
        "dev", "stg", "stage", "staging", "prod", "production", "test", "qa", "uat",
        "api", "app", "web", "internal", "admin", "portal", "v2", "v3", "new", "old",
        "secure", "beta", "alpha", "2", "1", "01", "02", "ext", "corp", "cloud",
    ]
    candidates = set()
    prefixes = set()
    for sub in discovered:
        prefix = sub[: len(sub) - len(root_domain) - 1] if sub.endswith("." + root_domain) else ""
        if prefix and "." not in prefix:
            prefixes.add(prefix)

    for p in prefixes:
        for m in env_mutations:
            candidates.add(f"{p}-{m}.{root_domain}")
            candidates.add(f"{m}-{p}.{root_domain}")
            candidates.add(f"{p}{m}.{root_domain}")

    return [c for c in candidates if c not in set(discovered)]


async def _recursive_subdomain_discovery(wave1_entries: list[dict], root_domain: str) -> list[dict]:
    """
    Wave 2: For every subdomain found in wave 1, try to find its children.
    E.g. if wave1 found 'ebiz.licindia.in', we now look for '*.ebiz.licindia.in'.

    Strategies:
      1. crt.sh wildcard query for each sub-parent
      2. subfinder / findomain CLI against each sub-parent
      3. Mini wordlist bruteforce against top sub-parents
      4. Altdns-style permutation mutation + DNS resolve
    """
    wave1_subdomains = sorted(list(set(e["subdomain"] for e in wave1_entries)))
    all_results: list[dict] = []
    already_found = set(wave1_subdomains)

    subdomain_to_ips = {}
    for e in wave1_entries:
        sub = e["subdomain"]
        ip = e.get("ip")
        if ip:
            subdomain_to_ips.setdefault(sub, []).append(ip)

    SKIP_PREFIXES = {
        "www", "mail", "ftp", "smtp", "pop", "imap", "mx", "mx1", "mx2",
        "ns1", "ns2", "ns3", "ns4", "pop3", "imap2", "smtp2",
    }
    discovered_parents = set()
    root_parts_count = len(root_domain.split("."))
    for sub in wave1_subdomains:
        parts = sub.split(".")
        if len(parts) > root_parts_count + 1:
            parent_zone = ".".join(parts[len(parts) - root_parts_count - 1:])
            discovered_parents.add(parent_zone)

    fallback_parents = []
    for sub in wave1_subdomains:
        prefix = sub[: len(sub) - len(root_domain) - 1] if sub.endswith("." + root_domain) else ""
        if prefix and prefix.lower() not in SKIP_PREFIXES and sub not in discovered_parents:
            fallback_parents.append(sub)

    sub_parents = sorted(list(discovered_parents), key=lambda s: len(s)) + sorted(fallback_parents, key=lambda s: len(s))
    sub_parents = sub_parents[:50]
    print(f"DEBUG: Selected sub_parents: {sub_parents[:15]}")

    try:
        crt_tasks = [_recursive_crtsh(sp, root_domain) for sp in sub_parents[:20]]
        crt_results = await asyncio.wait_for(
            asyncio.gather(*crt_tasks, return_exceptions=True),
            timeout=30.0
        )
        for res in crt_results:
            if isinstance(res, list):
                all_results.extend(res)
    except Exception as e:
        import traceback
        print("ERROR in recursive crt.sh stage:")
        traceback.print_exc()

    try:
        cli_sub_parents = sub_parents[:8]
        cli_binaries = []
        for binary in ["subfinder", "findomain", "assetfinder"]:
            if shutil.which(binary):
                cli_binaries.append(binary)

        cli_sem = asyncio.Semaphore(5)

        async def run_cli_on_sub_parent(binary: str, sub_parent: str) -> list[dict]:
            async with cli_sem:
                if binary == "subfinder":
                    cmd = ["subfinder", "-d", sub_parent, "-silent"]
                elif binary == "findomain":
                    cmd = ["findomain", "-t", sub_parent, "-q"]
                elif binary == "assetfinder":
                    cmd = ["assetfinder", "--subs-only", sub_parent]
                else:
                    return []
                results = await _run_cli_tool(cmd, root_domain, timeout=20.0)
                for r in results:
                    r["source"] = f"recursive_{binary}"
                return results

        cli_tasks = [
            run_cli_on_sub_parent(binary, sp)
            for sp in cli_sub_parents
            for binary in cli_binaries
        ]
        cli_batch = await asyncio.wait_for(
            asyncio.gather(*cli_tasks, return_exceptions=True),
            timeout=80.0,
        )
        for batch in cli_batch:
            if isinstance(batch, list):
                all_results.extend(batch)
    except Exception as e:
        import traceback
        print("ERROR in recursive CLI stage:")
        traceback.print_exc()

    try:
        MINI_WORDLIST = [
            "www", "api", "app", "mail", "admin", "portal", "test", "dev", "staging",
            "prod", "secure", "cdn", "static", "media", "login", "auth", "docs",
            "support", "help", "blog", "shop", "m", "mobile", "web", "service",
            "vc", "ecms", "ebiz", "internal", "intranet", "gateway", "proxy",
            "node1", "node2", "server", "host", "db", "cache", "queue", "job",
            "agent", "agents", "policy", "claims", "online", "pay", "payment",
        ]
        bruteforce_sem = asyncio.Semaphore(300)

        async def bruteforce_sub_parent(word: str, parent: str):
            candidate = f"{word}.{parent}"
            if candidate in already_found:
                existing_ips = subdomain_to_ips.get(candidate, [])
                if existing_ips:
                    return [{"subdomain": candidate, "ip": ip, "source": "recursive_bruteforce"} for ip in existing_ips]
                return None
            async with bruteforce_sem:
                ips = await _resolve_async(candidate)
                if ips:
                    return [{"subdomain": candidate, "ip": ip, "source": "recursive_bruteforce"} for ip in ips]
            return None

        bf_tasks = [
            bruteforce_sub_parent(word, sp)
            for sp in sub_parents[:10]
            for word in MINI_WORDLIST
        ]
        bf_results = await asyncio.wait_for(
            asyncio.gather(*bf_tasks, return_exceptions=True),
            timeout=45.0,
        )
        for r in bf_results:
            if r and isinstance(r, list):
                all_results.extend(r)
    except Exception as e:
        import traceback
        print("ERROR in recursive bruteforce stage:")
        traceback.print_exc()

    try:
        permutation_candidates = _generate_permutations(wave1_subdomains, root_domain)

        async def resolve_permutation(candidate: str):
            if candidate in already_found:
                existing_ips = subdomain_to_ips.get(candidate, [])
                if existing_ips:
                    return [{"subdomain": candidate, "ip": ip, "source": "permutation"} for ip in existing_ips]
                return None
            ips = await _resolve_async(candidate)
            if ips:
                return [{"subdomain": candidate, "ip": ip, "source": "permutation"} for ip in ips]
            return None

        perm_results, _ = await run_bounded(permutation_candidates, resolve_permutation, 300, 45.0)
        for r in perm_results:
            if r and isinstance(r, list):
                all_results.extend(r)
    except Exception as e:
        import traceback
        print("ERROR in recursive permutation stage:")
        traceback.print_exc()

    return all_results



async def _run_cli_tool(cmd: list[str], domain: str, timeout: float = 25.0) -> list[dict]:
    exe = cmd[0]
    path = shutil.which(exe)
    if not path:
        return []
    full_cmd = list(cmd)
    full_cmd[0] = path
    try:
        proc = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return []
        lines = stdout.decode("utf-8", errors="ignore").splitlines()
        results = []
        import re
        for line in lines:
            line = line.strip().lower()
            if not line or line.startswith("[") or line.startswith("*"):
                continue
            
            parts = re.split(r'[:\s]+', line)
            if parts:
                sub = parts[0]
                if "." in sub and sub.endswith(domain) and sub != domain:
                    results.append({"subdomain": sub, "ip": None, "source": exe})
        return results
    except Exception:
        return []


async def _fetch_theharvester_custom(domain: str, is_single_module: bool = False) -> list[dict]:
    """Runs theHarvester using JSON output and parses the results directly."""
    import os
    import uuid
    import json as _json

    exe = "theHarvester"
    path = shutil.which(exe) or shutil.which(f"{exe}.exe")
    if not path:
        return []

    temp_id = str(uuid.uuid4())[:8]
    temp_filename = f"temp_harvester_{temp_id}"
    temp_json_path = f"{temp_filename}.json"
    temp_xml_path = f"{temp_filename}.xml"

    sources = "crtsh,certspotter,hackertarget,rapiddns,subdomaincenter,threatcrowd,urlscan,waybackarchive,yahoo,duckduckgo,commoncrawl,mojeek"
    limit = "500" if is_single_module else "200"

    cmd = [path, "-d", domain, "-b", sources, "-l", limit, "-f", temp_filename]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        timeout = 60.0 if is_single_module else 60.0
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass

        results = []
        if os.path.exists(temp_json_path):
            with open(temp_json_path, "r", encoding="utf-8", errors="ignore") as f:
                data = _json.load(f)
                hosts = data.get("hosts", []) or []
                for host in hosts:
                    if isinstance(host, str):
                        sub = host
                        ip = None
                        if ":" in host:
                            domain_idx = host.find(domain)
                            if domain_idx != -1:
                                after_domain = host[domain_idx + len(domain):]
                                if after_domain.startswith(":"):
                                    sub = host[:domain_idx + len(domain)]
                                    ip = after_domain[1:]
                        
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and sub != domain and "*" not in sub:
                            results.append({"subdomain": sub, "ip": ip.strip() if ip else None, "source": "theharvester"})
        return results
    except Exception:
        return []
    finally:
        for p in [temp_json_path, temp_xml_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


async def find(domain: str, is_single_module: bool = False, scan_mode: str = "detailed") -> dict[str, Any]:

    if not domain or "." not in domain:
        return error_response(ScanError.INVALID_RESPONSE, "Not a valid domain for subdomain enumeration", subdomains=[], count=0)

    try:
        from main import refresh_windows_path
        refresh_windows_path()
    except Exception:
        pass

    tasks = {
        "crt.sh": _fetch_crtsh(domain, is_single_module=is_single_module),
        "hackertarget": _fetch_hackertarget(domain),
        "alienvault": _fetch_alienvault(domain),
        "rapiddns": _fetch_rapiddns(domain),
        "certspotter": _fetch_certspotter(domain),
        "wayback": _fetch_wayback(domain),
        "urlscan": _fetch_urlscan(domain),
        "anubis": _fetch_anubis(domain),
        "subdomain_center": _fetch_subdomain_center(domain),
        "threatminer": _fetch_threatminer(domain),
        "virustotal": _fetch_virustotal_public(domain),
        "search_engines": _fetch_search_engines(domain),
        "robtex": _fetch_robtex(domain),
        "bevigil": _fetch_bevigil(domain),
        "netlas": _fetch_netlas(domain),
    }

    wordlist = COMMON_SUBDOMAINS_QUICK if is_single_module else COMMON_SUBDOMAINS
    tasks["bruteforce"] = _bruteforce_subdomains(domain, wordlist, is_single_module=is_single_module)

    cli_tools = {
        "subfinder": ["subfinder", "-d", domain, "-silent"],
        "findomain": ["findomain", "-t", domain, "-q"],
        "amass": ["amass", "enum", "-passive", "-d", domain],
        "assetfinder": ["assetfinder", "--subs-only", domain],
    }

    active_cli_tools = []
    skipped_cli_tools = []

    if shutil.which("theHarvester") or shutil.which("theHarvester.exe"):
        tasks["theharvester"] = _fetch_theharvester_custom(domain, is_single_module=is_single_module)
        active_cli_tools.append("theharvester")
    else:
        skipped_cli_tools.append("theharvester")

    for tool_name, cmd in cli_tools.items():
        if shutil.which(cmd[0]):
            if is_single_module or scan_mode == "detailed":
                timeout_val = 120.0
            elif scan_mode == "deep":
                timeout_val = 70.0
            else:
                timeout_val = 30.0
            tasks[tool_name] = _run_cli_tool(cmd, domain, timeout=timeout_val)
            active_cli_tools.append(tool_name)
        else:
            skipped_cli_tools.append(tool_name)

    task_keys = list(tasks.keys())
    task_futures = [asyncio.create_task(coro) for coro in tasks.values()]

    if is_single_module:
        sub_timeout = 90.0
    elif scan_mode == "detailed":
        sub_timeout = 120.0
    elif scan_mode == "deep":
        sub_timeout = 80.0
    else:
        sub_timeout = 45.0

    try:
        done, pending = await asyncio.wait(task_futures, timeout=sub_timeout)
    except Exception:
        done, pending = set(), set(task_futures)

    for p in pending:
        p.cancel()

    output_results = {}
    for key, fut in zip(task_keys, task_futures):
        if fut in done:
            try:
                output_results[key] = fut.result()
            except Exception as e:
                output_results[key] = {"status": "error", "results": [], "note": f"{key}: {type(e).__name__}"}
        else:
            output_results[key] = {"status": "timeout", "results": [], "note": f"{key} timed out"}

    sources_meta = {}
    merged_subdomains = []

    passive_keys = (
        "crt.sh", "hackertarget", "alienvault", "rapiddns", "certspotter",
        "wayback", "urlscan", "anubis", "subdomain_center", "threatminer",
        "virustotal", "search_engines", "bruteforce", "robtex", "bevigil", "netlas"
    )
    for key, res in output_results.items():
        if key in passive_keys:
            status = res.get("status", "unknown") if isinstance(res, dict) else "unknown"
            note = res.get("note") if isinstance(res, dict) else None
            items = res.get("results", []) if isinstance(res, dict) else []
            sources_meta[key] = {"status": status, "note": note, "count": len(items)}
            merged_subdomains.extend(items)
        else:
            items = res if isinstance(res, list) else []
            sources_meta[key] = {"status": "ok" if items else "no_results_or_skipped", "count": len(items)}
            merged_subdomains.extend(items)

    for tool_name in skipped_cli_tools:
        sources_meta[tool_name] = {"status": "not_installed", "count": 0}

    seen = {}
    for entry in merged_subdomains:
        if not isinstance(entry, dict):
            continue
        sub = entry.get("subdomain", "").lower()
        if not sub:
            continue
        ip = entry.get("ip")
        key = (sub, ip)
        if key not in seen:
            seen[key] = dict(entry)
            seen[key]["sources"] = [entry.get("source")] if entry.get("source") else []
        else:
            source = entry.get("source")
            if source and source not in seen[key]["sources"]:
                seen[key]["sources"].append(source)

    for entry in seen.values():
        if "sources" in entry:
            entry["source"] = ", ".join(sorted(set(entry["sources"])))

    unresolved = [entry for entry in seen.values() if not entry.get("ip")]
    resolve_map = {}
    if unresolved:
        concurrency = 150 if is_single_module else 60

        async def resolve_one(subdomain):
            ips = await _resolve_async(subdomain)
            return (subdomain, ips) if ips else None

        to_resolve = [e["subdomain"] for e in unresolved]
        if not is_single_module and len(to_resolve) > _MAX_UNRESOLVED_TO_RESOLVE:
            to_resolve = to_resolve[:_MAX_UNRESOLVED_TO_RESOLVE]
        try:
            resolved_results, _ = await run_bounded(to_resolve, resolve_one, concurrency, 60.0)
            for sub, ips in resolved_results:
                resolve_map[sub] = ips
        except Exception:
            pass

    new_seen = {}
    for key, entry in seen.items():
        sub = entry["subdomain"]
        ip = entry.get("ip")
        if not ip and sub in resolve_map:
            for resolved_ip in resolve_map[sub]:
                new_key = (sub, resolved_ip)
                if new_key not in new_seen:
                    new_seen[new_key] = dict(entry)
                    new_seen[new_key]["ip"] = resolved_ip
                    new_seen[new_key]["sources"] = list(entry.get("sources", []))
                else:
                    for src in entry.get("sources", []):
                        if src not in new_seen[new_key]["sources"]:
                            new_seen[new_key]["sources"].append(src)
        else:
            new_key = (sub, ip)
            if new_key not in new_seen:
                new_seen[new_key] = dict(entry)
                new_seen[new_key]["sources"] = list(entry.get("sources", []))
            else:
                for src in entry.get("sources", []):
                    if src not in new_seen[new_key]["sources"]:
                        new_seen[new_key]["sources"].append(src)
    seen = new_seen

    if is_single_module:
        unique_ips = list({e["ip"] for e in seen.values() if e.get("ip")})
        shodan_sem = asyncio.Semaphore(20)

        async def shodan_reverse(ip: str):
            async with shodan_sem:
                return await _reverse_ip_lookup_shodan(ip, domain)

        try:
            shodan_batches = await asyncio.wait_for(
                asyncio.gather(*[shodan_reverse(ip) for ip in unique_ips], return_exceptions=True),
                timeout=30.0,
            )
            shodan_new = 0
            for batch in shodan_batches:
                if not isinstance(batch, list):
                    continue
                for host in batch:
                    exists = any(e["subdomain"] == host for e in seen.values())
                    if not exists:
                        new_key = (host, None)
                        seen[new_key] = {"subdomain": host, "ip": None, "source": "shodan_reverse", "sources": ["shodan_reverse"]}
                        shodan_new += 1
                    else:
                        for entry in seen.values():
                            if entry["subdomain"] == host:
                                if "shodan_reverse" not in entry.setdefault("sources", []):
                                    entry["sources"].append("shodan_reverse")
            sources_meta["shodan_reverse"] = {"status": "ok", "count": shodan_new}
        except asyncio.TimeoutError:
            sources_meta["shodan_reverse"] = {"status": "timeout", "count": 0}

    wave2_results = []

    for entry in seen.values():
        if "sources" in entry:
            entry["source"] = ", ".join(sorted(set(entry["sources"])))

    sorted_subs = sorted(seen.values(), key=lambda x: x["subdomain"])
    active_subs = [s for s in sorted_subs if s.get("ip")]

    return {
        "status": "ok" if sorted_subs else "no_subdomains_found",
        "count": len(sorted_subs),
        "active_count": len(active_subs),
        "subdomains": sorted_subs,
        "sources": sources_meta,
    }



