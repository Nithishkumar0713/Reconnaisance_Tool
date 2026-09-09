"""
SSL/TLS Certificate Inspector Module.
Connects to the target on port 443 (HTTPS) and extracts:
  - Certificate details (subject, issuer, expiry dates, SANs)
  - Fingerprints (SHA-256, SHA-1)
  - Supported TLS protocol versions (1.0, 1.1, 1.2, 1.3)
  - Active cipher suites
  - Security issues (expired, self-signed, weak protocols)
  - Alternate SSL ports (8443, 465, 993, 995)
"""

import asyncio
import hashlib
import socket
import ssl
from datetime import datetime
from typing import Any

from utils.safety import TIMEOUTS, ScanError, error_response, classify_socket_error




async def _scan_protocols_and_ciphers_async(hostname: str, port: int) -> dict[str, list[str]]:
    supported = {}
    tls_versions = []
    if hasattr(ssl, "TLSVersion"):
        tls_versions = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ]
    else:
        tls_versions = [("TLSv1.3", None), ("TLSv1.2", None), ("TLSv1.1", None), ("TLSv1.0", None)]

    try:
        addrinfo = socket.getaddrinfo(hostname, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        ip_address = addrinfo[0][4][0]
    except Exception:
        ip_address = hostname


    async def test_protocol(proto_name, proto_ver):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if proto_ver is not None:
                context.minimum_version = proto_ver
                context.maximum_version = proto_ver
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip_address, port, ssl=context, server_hostname=hostname),
                    timeout=2.5
                )
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                return
            if proto_name == "TLSv1.3":
                supported[proto_name] = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]
                return
            if proto_name == "TLSv1.2":
                supported[proto_name] = ["Negotiated default ciphers (Standard Protocol Supported)"]
                return
            if proto_name in ("TLSv1.1", "TLSv1.0"):
                supported[proto_name] = ["Negotiated default ciphers (Legacy Protocol Supported)"]
                return
        except Exception:
            pass

    await asyncio.gather(*[test_protocol(name, ver) for name, ver in tls_versions])
    ordered = {}
    for proto in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]:
        if proto in supported:
            ordered[proto] = supported[proto]
    return ordered


def _get_cert_sync(hostname: str, port: int) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        try:
            addrinfo = socket.getaddrinfo(hostname, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
            target_ip = addrinfo[0][4][0]
        except Exception:
            target_ip = hostname

        with socket.create_connection((target_ip, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

        import tempfile, os, _ssl
        cert = {}
        fingerprint_sha256 = None
        fingerprint_sha1 = None
        pem_cert = None

        if der_cert:
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest().upper()
            fingerprint_sha1 = hashlib.sha1(der_cert).hexdigest().upper()
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, pem_cert.encode())
                os.close(fd)
                cert = _ssl._test_decode_cert(path)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(path)
                except Exception:
                    pass

        subject = {k: v for tup in cert.get("subject", []) for k, v in tup}
        issuer = {k: v for tup in cert.get("issuer", []) for k, v in tup}
        sans = [san[1] for san in cert.get("subjectAltName", [])]

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        days_until_expiry = None
        expiry_status = None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                delta_days = (expiry - datetime.utcnow()).days
                days_until_expiry = delta_days
                if delta_days < 0:
                    expiry_status = "expired"
                elif delta_days < 14:
                    expiry_status = "critical"
                elif delta_days < 30:
                    expiry_status = "expiring_soon"
                else:
                    expiry_status = "valid"
            except Exception:
                pass

        is_self_signed = (
            subject.get("commonName") == issuer.get("commonName") and
            subject.get("organizationName") == issuer.get("organizationName")
        )

        cn = subject.get("commonName", "")
        is_wildcard = cn.startswith("*.")
        wildcard_covers = [s for s in sans if s.startswith("*.")]

        key_algorithm = None
        if cipher and cipher[0]:
            c = cipher[0].upper()
            if "ECDHE-ECDSA" in c or "ECDSA" in c:
                key_algorithm = "ECDSA"
            elif "ECDHE-RSA" in c or "RSA" in c:
                key_algorithm = "RSA"
            elif "DSS" in c:
                key_algorithm = "DSS"

        weak_protocols_present = []
        security_issues = []
        if is_self_signed:
            security_issues.append("Self-signed certificate — not trusted by browsers")
        if expiry_status == "expired":
            security_issues.append("Certificate has expired")
        elif expiry_status in ("critical", "expiring_soon"):
            security_issues.append(f"Certificate expires in {days_until_expiry} days")

        return {
            "status": "ok",
            "port": port,
            "subject_common_name": subject.get("commonName"),
            "subject_organization": subject.get("organizationName"),
            "subject_org_unit": subject.get("organizationalUnitName"),
            "subject_country": subject.get("countryName"),
            "subject_state": subject.get("stateOrProvinceName"),
            "subject_locality": subject.get("localityName"),
            "issuer_common_name": issuer.get("commonName"),
            "issuer_organization": issuer.get("organizationName"),
            "issuer_country": issuer.get("countryName"),
            "issuer_org_unit": issuer.get("organizationalUnitName"),
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "valid_from": not_before,
            "valid_until": not_after,
            "days_until_expiry": days_until_expiry,
            "expiry_status": expiry_status,
            "subject_alternative_names": sans,
            "san_count": len(sans),
            "is_self_signed": is_self_signed,
            "is_wildcard": is_wildcard,
            "wildcard_domains": wildcard_covers,
            "fingerprint_sha256": fingerprint_sha256,
            "fingerprint_sha1": fingerprint_sha1,
            "protocol": protocol,
            "key_algorithm": key_algorithm,
            "cipher_suite": cipher[0] if cipher else None,
            "cipher_version": cipher[1] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "security_issues": security_issues,
        }
    except socket.timeout:
        return error_response(ScanError.FIREWALL_FILTERED, f"No response on port {port} (likely filtered by firewall)", port=port)
    except ConnectionRefusedError:
        return error_response(ScanError.CONNECTION_REFUSED, f"Port {port} is closed (no HTTPS service)", port=port)
    except ssl.SSLError as e:
        error_str = str(e).lower()
        if "certificate_verify_failed" in error_str:
            if "expired" in error_str or "certificate has expired" in error_str:
                msg = "⚠️ Certificate Verification Failed: The SSL/TLS certificate has EXPIRED and is no longer valid. This is a security concern — the domain owner should renew their certificate."
            elif "self signed" in error_str or "self-signed" in error_str:
                msg = "⚠️ Certificate Verification Failed: The certificate is self-signed and not trusted by standard certificate authorities. Browsers will show security warnings."
            elif "ip address mismatch" in error_str:
                msg = (
                    f"⚠️ Certificate Not Valid For This IP: The certificate presented by '{hostname}' is issued "
                    "for a domain name, not this raw IP address. TLS uses the domain name (SNI) to select and "
                    "verify the right certificate — most servers (including major CDNs and cloud providers) don't "
                    "list their IP as a Subject Alternative Name, so this failure is expected and doesn't mean the "
                    "certificate is invalid. Scan the domain name instead to get a meaningful result."
                )
            elif "hostname mismatch" in error_str or "doesn't match" in error_str:
                msg = "⚠️ Certificate Verification Failed: The certificate's domain name doesn't match the target domain. This is a configuration error."
            elif "too weak" in error_str or "weak signature" in error_str:
                msg = "⚠️ Certificate Verification Failed: The certificate chain uses a deprecated, weak signature algorithm (e.g. SHA-1), which modern systems no longer trust. The certificate should be reissued with a stronger algorithm (SHA-256 or better)."
            elif "unable to get local issuer certificate" in error_str or "unable to get issuer certificate" in error_str:
                msg = "⚠️ Certificate Verification Failed: The certificate's issuing authority (CA) could not be verified — the chain is incomplete or issued by an untrusted/unknown CA."
            else:
                msg = "⚠️ Certificate Verification Failed: The certificate could not be verified. It may be expired, self-signed, or issued by an untrusted authority."
        elif "connection refused" in error_str or "refused" in error_str:
            msg = "❌ Cannot establish HTTPS connection: Port 443 is not accepting SSL/TLS connections or the service is not running."
        elif "timeout" in error_str:
            msg = "⏱️ SSL Handshake Timeout: The server did not respond within the time limit. It may be overloaded or not properly configured for HTTPS."
        else:
            msg = f"⚠️ TLS Handshake Failed: {str(e)[:100]}"
        return error_response(ScanError.SSL_HANDSHAKE_FAILED, msg, port=port)
    except socket.gaierror:
        return error_response(ScanError.DNS_RESOLUTION_FAILED, f"Cannot resolve {hostname}", hostname=hostname)
    except OSError as e:
        code, msg = classify_socket_error(e)
        return error_response(code, msg, port=port)
    except Exception as e:
        return error_response(ScanError.UNKNOWN_ERROR, f"{type(e).__name__}: {str(e)[:150]}")


async def get_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
    loop = asyncio.get_event_loop()

    try:
        cert_res = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert_sync, hostname, port),
            timeout=TIMEOUTS["ssl"] + 2,
        )

        if cert_res.get("status") == "ok":
            alt_ports = [8443, 465, 993, 995]

            async def check_alt_port(p):
                r, w = None, None
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(hostname, p, ssl=ssl.create_default_context()),
                        timeout=3.0
                    )
                    return p
                except Exception:
                    return None
                finally:
                    if w is not None:
                        try:
                            w.close()
                            await w.wait_closed()
                        except Exception:
                            pass

            cipher_task = asyncio.wait_for(_scan_protocols_and_ciphers_async(hostname, port), timeout=6.0)
            alt_tasks = [check_alt_port(p) for p in alt_ports]

            try:
                supported, *alt_results = await asyncio.gather(cipher_task, *alt_tasks, return_exceptions=True)
                if isinstance(supported, dict) and supported:
                    cert_res["supported_protocols"] = supported
                else:
                    cert_res["supported_protocols"] = {}

                active_alt_ports = [p for p, r in zip(alt_ports, alt_results) if r and not isinstance(r, Exception)]
                cert_res["ssl_also_on_ports"] = active_alt_ports
            except Exception:
                cert_res["supported_protocols"] = {}

            main_proto = cert_res.get("protocol")
            main_cipher = cert_res.get("cipher_suite")
            if main_proto and main_cipher:
                if main_proto not in cert_res["supported_protocols"]:
                    cert_res["supported_protocols"][main_proto] = [main_cipher]
                elif cert_res["supported_protocols"][main_proto] == ["Negotiated default ciphers (Standard Protocol Supported)"]:
                    cert_res["supported_protocols"][main_proto] = [main_cipher]

            weak = [p for p in ["TLSv1.0", "TLSv1.1"] if p in cert_res["supported_protocols"]]
            if weak:
                cert_res.setdefault("security_issues", []).extend(
                    [f"Weak protocol supported: {p}" for p in weak]
                )

        return cert_res

    except asyncio.TimeoutError:
        return error_response(ScanError.TIMEOUT, f"SSL check exceeded timeout (host unresponsive on port {port})", port=port)
