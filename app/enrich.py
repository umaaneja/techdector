# app/enrich.py
import socket
import ssl
from ipwhois import IPWhois
import whois
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return [str(r.target).rstrip('.') for r in answers]
    except Exception:
        return []

def resolve_a(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except Exception:
        return []

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return dict(w)
    except Exception as e:
        return {"error": str(e)}

def get_tls_certificate(domain, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "san": [str(s.value) for s in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip_asn(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return {"asn": res.get("asn"), "asn_cidr": res.get("asn_cidr"), "network": res.get("network",{})}
    except Exception as e:
        return {"error": str(e)}
