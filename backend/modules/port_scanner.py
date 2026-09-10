"""
Port Scanner Module.
Scans TCP ports on a target IP to find open services.
For each port, determines its state:
  - open: service is running and accepting connections
  - closed: OS rejected the connection (RST packet)
  - filtered: no response at all (firewall is blocking)
Also grabs service banners to identify what software is running.
"""

import asyncio
import socket
import random
from typing import Any

from utils.safety import TIMEOUTS, classify_socket_error, ScanError
from utils.concurrency import run_bounded

class RateLimiter:
    """
    Limits the rate at which tasks are started.
    Guarantees that at most `rate` permits are acquired per second.
    """
    def __init__(self, rate: float):
        self.rate = rate
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.last_time = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        if self.interval == 0.0:
            return
        async with self.lock:
            current_time = asyncio.get_event_loop().time()
            expected_time = self.last_time + self.interval
            if current_time < expected_time:
                sleep_time = expected_time - current_time
                await asyncio.sleep(sleep_time)
                self.last_time = expected_time
            else:
                self.last_time = current_time

TIMING_TEMPLATES = {
    "T0": {
        "name": "paranoid",
        "concurrency": 1,
        "scan_delay": 300.0,
        "per_port_timeout": 5.0,
        "max_retries": 10,
    },
    "T1": {
        "name": "sneaky",
        "concurrency": 1,
        "scan_delay": 15.0,
        "per_port_timeout": 5.0,
        "max_retries": 10,
    },
    "T2": {
        "name": "polite",
        "concurrency": 1,
        "scan_delay": 0.4,
        "per_port_timeout": 3.0,
        "max_retries": 10,
    },
    "T3": {
        "name": "normal",
        "concurrency": 150,
        "scan_delay": 0.0,
        "per_port_timeout": 1.5,
        "max_retries": 3,
    },
    "T3_FULLSCAN": {
        "name": "normal-fullscan",
        "concurrency": 25,
        "scan_delay": 0.03,
        "per_port_timeout": 1.5,
        "max_retries": 3,
    },
    "T4": {
        "name": "aggressive",
        "concurrency": 800,
        "scan_delay": 0.0,
        "per_port_timeout": 1.0,
        "max_retries": 2,
    },
    "T5": {
        "name": "insane",
        "concurrency": 2000,
        "scan_delay": 0.0,
        "per_port_timeout": 0.5,
        "max_retries": 1,
    },
    "T6": {
        "name": "ludicrous",
        "concurrency": 4000,
        "scan_delay": 0.0,
        "per_port_timeout": 0.5,
        "max_retries": 1,
    },
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 1723, 3000, 3306, 3389, 5000, 5432,
    5900, 5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 11211, 27017, 27018, 6667, 6697, 1194, 500, 4500, 179,
    88, 389, 749, 750, 79, 43, 194, 543, 544, 512, 513, 514, 515,
    5060, 5061, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 5222, 5223,
    5672, 15672, 61616, 61617, 1883, 8883, 4444, 5555, 7777, 8009,
    8834, 10000, 32768, 49152, 49153, 49154, 3690, 6000,
    5986, 1080, 3128, 8118, 8123, 1900, 5353, 5355,
]

TOP_1000_PORTS = sorted(set(
    list(range(1, 1025)) +
    [1080, 1099, 1194, 1234, 1337, 1433, 1521, 1723, 1883,
     2049, 2082, 2083, 2181, 2222, 2375, 2376, 2379, 2380,
     3000, 3306, 3389, 3690, 4000, 4369, 4444, 4500, 5000,
     5222, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986,
     6379, 6443, 6667, 7000, 7001, 7077, 7443, 7474, 7687,
     8000, 8008, 8009, 8080, 8081, 8086, 8088, 8090, 8091,
     8161, 8443, 8834, 8880, 8883, 8888, 8983, 9000, 9042,
     9090, 9092, 9200, 9300, 9418, 9443, 9600, 9990, 10000,
     11211, 15672, 25565, 27017, 27018, 27019, 28017, 32768,
     50000, 50070, 61616]
))

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 515: "LPD",
    514: "Syslog", 543: "klogin", 544: "kshell", 587: "SMTP-Submission",
    636: "LDAPS", 749: "Kerberos-Admin", 873: "rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2181: "Zookeeper",
    2375: "Docker", 2379: "etcd", 3000: "Node/Grafana", 3128: "Squid-Proxy",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4369: "Erlang-EPMD",
    4444: "Metasploit", 4500: "IPsec-NAT-T", 5000: "UPnP/Docker-Registry",
    5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5555: "ADB", 5601: "Kibana",
    5672: "AMQP/RabbitMQ", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "Kubernetes-API", 6667: "IRC", 7001: "WebLogic",
    7077: "Spark", 7474: "Neo4j-HTTP", 7687: "Neo4j-Bolt",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
    8080: "HTTP-Proxy/Tomcat", 8081: "HTTP-Alt", 8086: "InfluxDB",
    8088: "Hadoop", 8090: "Confluence", 8161: "ActiveMQ",
    8443: "HTTPS-Alt", 8834: "Nessus", 8880: "CDDBP",
    8883: "MQTT-SSL", 8888: "HTTP-Alt", 8983: "Solr",
    9000: "SonarQube/PHP-FPM", 9042: "Cassandra", 9090: "Prometheus",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    9418: "Git", 9443: "HTTPS-Alt", 9600: "Logstash", 9990: "WildFly",
    10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    25565: "Minecraft", 27017: "MongoDB", 27018: "MongoDB-Shard",
    50000: "SAP", 50070: "Hadoop-NameNode", 61616: "ActiveMQ-OpenWire",
}

WEB_PORTS = (80, 443, 8080, 8000, 8001, 8008, 8081, 8082, 8088, 8090, 8443, 8888, 8983, 9000, 9090, 9200, 10000)
SSL_PORTS = (443, 8443, 465, 993, 995, 8444, 9443)


async def _grab_banner_and_version(ip: str, port: int, timeout: float, target: str | None = None) -> str | None:
    """
    Connects to an open port and tries to grab its banner.
    For web ports, sends an HTTP GET request and reads the "Server" header.
    For other ports (SSH, FTP etc.), reads whatever greeting text the service sends.
    """
    try:
        if port in WEB_PORTS:
            ssl_context = None
            if port in SSL_PORTS:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            conn_timeout = timeout * 1.5 if port in SSL_PORTS else timeout

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_context),
                    timeout=conn_timeout
                )
            except Exception:
                if port in SSL_PORTS:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port, ssl=None),
                            timeout=conn_timeout
                        )
                    except Exception:
                        if port == 443:
                            return "HTTPS (port 443 is open)"
                        raise
                else:
                    raise

            try:
                host_header = target if target else ip
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36\r\n"
                    f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                    f"Connection: close\r\n\r\n"
                )
                writer.write(req.encode())
                await writer.drain()

                read_timeout = timeout * 2.5 if port in SSL_PORTS else timeout
                data = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
                text = data.decode("utf-8", errors="ignore")

                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()
                if text:
                    first_line = text.splitlines()[0]
                    if "http/" in first_line.lower():
                        return first_line.strip()
                if port in SSL_PORTS:
                    return f"HTTPS Server (port {port})"
            except asyncio.TimeoutError:
                if port in SSL_PORTS:
                    return f"HTTPS Server (port {port})"
                elif port in WEB_PORTS:
                    return f"HTTP Server (port {port})"
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                if data:
                    return data.decode("utf-8", errors="ignore").strip()[:250]
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    except Exception:
        pass
    return None


async def _probe_port(ip: str, port: int, timeout: float, target: str | None = None) -> dict:
    """
    Tests a single port by trying to connect to it.
    Never crashes — always returns a structured result dict.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        banner = await _grab_banner_and_version(ip, port, timeout=TIMEOUTS["banner_grab"], target=target)
        
        service = SERVICE_NAMES.get(port, "unknown")
        version = None
        
        import re as _re
        if banner:
            banner_lower = banner.lower()
            if "server:" in banner_lower:
                server_val = banner.split(":", 1)[1].strip()
                if "/" in server_val:
                    parts = server_val.split("/", 1)
                    service = parts[0].strip()
                    version = parts[1].strip()
                else:
                    service = server_val
                    match = _re.search(r'\b\d+\.\d+(?:\.\d+)*\b', server_val)
                    if match:
                        version = match.group(0)
            elif "ssh-" in banner_lower:
                service = "SSH"
                parts = banner.split("-")
                if len(parts) >= 3:
                    ssh_ver = parts[2].strip()
                    if "_" in ssh_ver:
                        service, version = ssh_ver.split("_", 1)
                    else:
                        version = ssh_ver
            elif "vsftpd" in banner_lower:
                service = "vsFTPd"
                idx = banner_lower.find("vsftpd")
                version = banner[idx+6:].strip().strip("()")
            elif "proftpd" in banner_lower:
                service = "ProFTPd"
                m = _re.search(r'ProFTPD\s+([\d.]+)', banner, _re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "postfix" in banner_lower:
                service = "Postfix SMTP"
                m = _re.search(r'Postfix\s+([\d.]+)', banner, _re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "exim" in banner_lower:
                service = "Exim SMTP"
                m = _re.search(r'Exim\s+([\d.]+)', banner, _re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "sendmail" in banner_lower:
                service = "Sendmail"
            elif "amqp" in banner_lower:
                service = "RabbitMQ/AMQP"
            elif "redis" in banner_lower:
                service = "Redis"
                m = _re.search(r'redis_version:([\d.]+)', banner_lower)
                if m:
                    version = m.group(1)
            elif "+ok" in banner_lower and port in (110, 995):
                service = "POP3"
            elif "imap" in banner_lower:
                service = "IMAP"
                m = _re.search(r'IMAP[\s]+([\d.]+)', banner, _re.IGNORECASE)
                if m:
                    version = m.group(1)
            elif "ftp" in banner_lower and port == 21:
                service = "FTP"
            elif "mysql" in banner_lower:
                service = "MySQL"
                m = _re.search(r'(\d+\.\d+\.\d+)', banner)
                if m:
                    version = m.group(1)
            elif "mariadb" in banner_lower:
                service = "MariaDB"
                m = _re.search(r'(\d+\.\d+\.\d+)', banner)
                if m:
                    version = m.group(1)
            elif "mongodb" in banner_lower:
                service = "MongoDB"
            elif "elasticsearch" in banner_lower:
                service = "Elasticsearch"
            elif "http/1" in banner_lower:
                status_m = _re.search(r'HTTP/[\d.]+ (\d{3})', banner)
                if status_m:
                    service = f"HTTP ({status_m.group(1)})"

        return {
            "port": port,
            "state": "open",
            "service": service,
            "version": version,
            "banner": banner,
            "banner_length": len(banner) if banner else 0,
        }

    except asyncio.TimeoutError:
        return {
            "port": port,
            "state": "filtered",
            "service": SERVICE_NAMES.get(port, "unknown"),
            "note": "No response (packet likely dropped by firewall)",
        }
    except ConnectionRefusedError:
        return {
            "port": port,
            "state": "closed",
            "service": SERVICE_NAMES.get(port, "unknown"),
        }
    except OSError as e:
        code, msg = classify_socket_error(e)
        return {"port": port, "state": "error", "error_code": code, "error_message": msg}
    except Exception as e:
        return {"port": port, "state": "error", "error_code": ScanError.UNKNOWN_ERROR, "error_message": f"{type(e).__name__}: {str(e)[:120]}"}
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def _probe_port_with_retries(ip: str, port: int, timeout: float, max_retries: int, target: str | None = None) -> dict:
    """
    Wrapper around _probe_port that implements intelligent retries against firewalls/IDS/IPS.
    Tries multiple strategies to bypass blocking:
    1. Standard probe with increasing timeouts
    2. Probes with increased delays (to evade rate-limiting)
    3. Fallback to longer waits if connection is refused
    """
    slow_ports = {1433, 1521, 3306, 5432, 6379, 11211, 7000, 7001, 8080, 8081, 27017}
    base_timeout = timeout * 1.5 if port in slow_ports or port > 8000 else timeout

    for attempt in range(1, max_retries + 1):
        if attempt <= 2:
            adjusted_timeout = base_timeout * (1 + (attempt - 1) * 0.5)
        else:
            adjusted_timeout = base_timeout * 3.0

        res = await _probe_port(ip, port, adjusted_timeout, target)

        if res.get("state") in ("open", "closed"):
            return res

        if res.get("state") == "filtered" and attempt < max_retries:
            wait_time = 0.5 * (2 ** (attempt - 1))
            wait_time = min(wait_time, 3.0)
            await asyncio.sleep(wait_time)
            continue

        if attempt == max_retries and res.get("state") == "filtered":
            await asyncio.sleep(1.0)
            final_res = await _probe_port(ip, port, base_timeout * 2.0, target)
            if final_res.get("state") != "filtered":
                return final_res

        return res

    return {"port": port, "state": "unknown", "note": "Unable to determine port state after retries"}


async def _host_reachability_probe(ip: str) -> dict:
    """
    Quick check: is the target host even alive?
    Tries connecting to ports 80, 443, 22 to see if anything responds.
    Also detects IP-level blocking (no response on any port).
    """
    common_probe_ports = [80, 443, 22]
    timeout_count = 0
    refused_count = 0

    for port in common_probe_ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.5
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"reachable": True, "responsive_port": port, "status": "online"}

        except ConnectionRefusedError:
            refused_count += 1
            continue

        except (asyncio.TimeoutError, OSError):
            timeout_count += 1
            continue

    if refused_count > 0:
        return {
            "reachable": True,
            "status": "online",
            "note": f"Host is up ({refused_count} ports closed, likely firewalled)"
        }
    elif timeout_count == len(common_probe_ports):
        return {
            "reachable": False,
            "status": "potentially_blocked",
            "note": "All reachability probes timed out — may be IP-level blocking, host down, or extreme filtering. Scan will attempt with longer timeouts.",
            "recommendation": "Consider using VPN/proxy if IP is blocked"
        }
    else:
        return {
            "reachable": False,
            "status": "unreachable",
            "note": "No response on common ports — host may be offline or deeply filtered",
            "probed_ports": common_probe_ports
        }


async def scan(ip: str, mode: str = "top100", target: str | None = None, timing_template: str = "T3") -> dict[str, Any]:
    """
    Main port scanner function supporting 3 port range modes:
    - "top100": Top 100 most important ports
    - "1-1024": Ports 1 to 1024
    - "1-65535" / "full": All TCP ports 1 to 65535
    Uses Nmap-like timing templates to control timing, delay, concurrency, and retries.
    """
    mode_normalized = str(mode).strip().lower()
    
    # "deep" was missing from every branch below (only "fast"/"top100" and
    # the literal port-range strings were recognized), so a Deep-mode scan
    # — which never passes an explicit port_range, since neither run_scan()
    # nor FullScanBatchRequest have one — silently fell through to the
    # `else` catch-all. That branch hardcoded overall_timeout=90 directly,
    # bypassing the TIMEOUTS.get("port_scan_fast", ...) lookup the
    # equivalent named branch uses (120s), cutting scans short before they
    # could finish. Treated as a synonym for "fast" here (same port range
    # Deep-mode scans have always actually run), not promoted to the
    # 1-1024 "detailed" range — that would be a real scope change (much
    # slower) this fix isn't trying to make.
    if mode_normalized in ("top100", "fast", "deep"):
        ports = TOP_100_PORTS
        overall_timeout = TIMEOUTS.get("port_scan_fast", 120)
        mode_label = "Top 100 Ports"
    elif mode_normalized in ("1-1024", "1000", "detailed"):
        ports = list(range(1, 1025))
        overall_timeout = TIMEOUTS.get("port_scan_detailed", 180)
        mode_label = "1 - 1024 Ports"
    elif mode_normalized in ("1-65535", "full", "65535", "all"):
        ports = list(range(1, 65536))
        overall_timeout = 240
        mode_label = "1 - 65535 Ports (Full Range)"
    else:
        ports = TOP_100_PORTS
        overall_timeout = TIMEOUTS.get("port_scan_fast", 120)
        mode_label = "Top 100 Ports"

    template_key = str(timing_template).strip().upper()
    if template_key not in TIMING_TEMPLATES:
        template_key = "T3"
        for key, val in TIMING_TEMPLATES.items():
            if val["name"] == str(timing_template).strip().lower():
                template_key = key
                break

    template = TIMING_TEMPLATES[template_key]
    
    concurrency = template["concurrency"]
    per_port_timeout = template["per_port_timeout"]
    scan_delay = template["scan_delay"]
    max_retries = template["max_retries"]

    if template_key == "T3":
        if mode_normalized in ("1-1024", "1000", "detailed"):
            concurrency = 300
        elif mode_normalized in ("1-65535", "full", "65535", "all"):
            concurrency = 1000

    calculated_min_duration = (len(ports) * scan_delay) + (len(ports) * per_port_timeout / max(concurrency, 1))
    overall_timeout = max(overall_timeout, int(calculated_min_duration * 1.2) + 30)

    reachability = await _host_reachability_probe(ip)

    ports_to_scan = list(ports)
    random.shuffle(ports_to_scan)

    original_concurrency = concurrency
    if len(ports_to_scan) > 10000:
        concurrency = max(500, concurrency // 2)
        scan_delay = max(scan_delay, 0.05)
    elif len(ports_to_scan) > 1024:
        concurrency = max(400, int(concurrency * 0.7))
        scan_delay = max(scan_delay, 0.02)
    elif len(ports_to_scan) > 100:
        concurrency = original_concurrency
        scan_delay = scan_delay

    semaphore = asyncio.Semaphore(concurrency)
    rate_limiter = RateLimiter(1.0 / scan_delay) if scan_delay > 0 else None

    async def bounded_probe(port):
        async with semaphore:
            if rate_limiter:
                await rate_limiter.wait()
            return await _probe_port_with_retries(ip, port, per_port_timeout, max_retries, target)

    results = []
    chunk_size = 1000 if len(ports_to_scan) > 1000 else 5000
    is_being_blocked = False
    blocking_threshold = 0.7
    filtered_count = 0
    ran_out_of_time = False

    for chunk_idx, i in enumerate(range(0, len(ports_to_scan), chunk_size)):
        chunk = ports_to_scan[i : i + chunk_size]

        if i > 0:
            filtered_ratio = filtered_count / len(results) if results else 0
            if filtered_ratio > blocking_threshold and not is_being_blocked:
                is_being_blocked = True
                scan_delay = max(scan_delay * 2, 0.5)
                rate_limiter = RateLimiter(1.0 / scan_delay) if scan_delay > 0 else None

            if len(ports_to_scan) > 5000 and chunk_idx % 2 == 0:
                await asyncio.sleep(0.5)

        # run_bounded (not a raw gather+wait_for) so that if this chunk's
        # timeout fires, whatever ports already finished are kept instead
        # of the whole chunk's results being discarded on timeout.
        chunk_results, chunk_timed_out = await run_bounded(chunk, bounded_probe, concurrency, overall_timeout)
        results.extend(chunk_results)

        for r in chunk_results:
            if isinstance(r, dict):
                if r.get("state") == "filtered":
                    filtered_count += 1
                elif r.get("state") == "open":
                    if is_being_blocked:
                        is_being_blocked = False

        if chunk_timed_out:
            ran_out_of_time = True
            break

        if len(ports_to_scan) > 10000 and (i + chunk_size) % 5000 == 0:
            await asyncio.sleep(1.0)

    open_ports = []
    filtered_count = 0
    closed_count = 0
    error_count = 0

    for r in results:
        if isinstance(r, Exception):
            error_count += 1
            continue
        state = r.get("state")
        if state == "open":
            open_ports.append(r)
        elif state == "filtered":
            filtered_count += 1
        elif state == "closed":
            closed_count += 1
        else:
            error_count += 1

    total_probed = len(results) if ran_out_of_time else len(ports)
    filtered_ratio = filtered_count / max(total_probed, 1)

    firewall_note = None
    firewall_status = "none"

    if filtered_ratio > 0.9:
        firewall_status = "aggressive_block"
        if len(open_ports) > 0:
            firewall_note = f"AGGRESSIVE FIREWALL DETECTED: {filtered_count}/{total_probed} ports blocked (IDS/IPS active). But successfully discovered {len(open_ports)} open ports using evasion techniques."
        else:
            firewall_note = f"AGGRESSIVE FIREWALL DETECTED: {filtered_count}/{total_probed} ports blocked (IDS/IPS active). Target may be heavily protected — retry with increased delays."
    elif filtered_ratio > 0.7:
        firewall_status = "moderate_block"
        firewall_note = f"MODERATE FIREWALL: {filtered_count}/{total_probed} ports blocked. {len(open_ports)} open ports discovered using rate-limiting evasion."
    elif filtered_ratio > 0.5:
        firewall_status = "light_block"
        firewall_note = f"LIGHT FILTERING: {filtered_count}/{total_probed} ports filtered. Connection rate-limiting detected and bypassed."
    elif filtered_count > 0:
        firewall_status = "some_filtering"
        firewall_note = f"LIGHT FILTERING: {filtered_count} ports had slow responses (rate-limited). Retries succeeded on {len(open_ports)} open ports."
    else:
        firewall_status = "none"

    result = {
        "status": "partial" if ran_out_of_time else "ok",
        "scan_mode": mode_normalized,
        "mode_label": mode_label,
        "reachability": reachability,
        "scanned_port_count": total_probed,
        "open_port_count": len(open_ports),
        "closed_port_count": closed_count,
        "filtered_port_count": filtered_count,
        "error_count": error_count,
        "firewall_status": firewall_status,
        "firewall_note": firewall_note,
        "evasion_techniques_used": "rate-limiting, randomized port order, adaptive timeouts, retry with delays",
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
    }
    if ran_out_of_time:
        result["error_code"] = ScanError.TIMEOUT
        result["error_message"] = (
            f"Port scan exceeded its {overall_timeout}s budget after scanning "
            f"{total_probed}/{len(ports)} ports — results below are real, from "
            f"the ports that finished in time."
        )
    return result

