# DNS detection module
#
# detects suspicious DNS indicators including:
# - dynamic DNS providers
# - abused top-level domains
# - DNS tunneling record types
# - DNS over HTTPS providers
# - public DNS resolvers
#
# most detections are low-confidence indicators and are
# intended to be correlated with additional telemetry.
# ==========================================================

# ==========================================================
# keywords
# ==========================================================
#providers commonly used for legitamite dynamic dns, and sometimes abused by attackers
#one signal correlation (dont flag by themselves)
DYNAMIC_DNS_PROVIDERS = {

    "duckdns.org",
    "no-ip.com",
    "noip.com",
    "dyndns.org",
    "dynu.com",
    "hopto.org",
    "zapto.org",
    "ddns.net",
    "serveftp.com",
    "myftp.org",
    "sytes.net",
    "freeddns.org",
    "afraid.org",

}
#also needs correlation
COMMON_ABUSED_TLDS = {

    ".xyz",
    ".top",
    ".click",
    ".live",
    ".online",
    ".site",
    ".icu",
    ".buzz",
    ".monster",
    ".work",
    ".rest",
    ".cam",
    ".club",
    ".space",
    ".fit",
    ".fun",
    ".support",
    ".review",
    ".stream",
    ".loan",
    ".download",
    ".gq",
    ".cf",
    ".ml",
    ".ga",
    ".tk",

}
#record types that are encountered msot often
DNS_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "PTR",
    "SRV",
    "SOA",
    "CAA",
    "NAPTR",
    "DNSKEY",
    "DS",
    "RRSIG",

}
#attackers frequently use record types for DNS tunneling to command and control
DNS_TUNNELING_RECORDS = {
    "TXT",
    "NULL",
    "CNAME",
    "MX",
    "AAAA",

}

#analyzing network security
DNS_OVER_HTTPS_PROVIDERS = {
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.extdns.io",
    "security.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",

}
#destination ips
PUBLIC_DNS_RESOLVERS = {

    "1.1.1.1",
    "1.0.0.1",

    "8.8.8.8",
    "8.8.4.4",

    "9.9.9.9",
    "149.112.112.112",

    "208.67.222.222",
    "208.67.220.220",
}    


#defined behaviors; common dns abuse patterns 
DNS_SUSPICIOUS_CHARACTERISTICS = {

    "very_long_subdomain",

    "high_entropy_subdomain",

    "many_unique_subdomains",

    "frequent_nxdomain",

    "dynamic_dns",

    "rare_tld",

    "dns_tunneling_record",
}
# ==========================================================
# helper functions
# ==========================================================
#keyword matcher helper 

def contains_keyword(text, keywords):

    if not text:
        return None

    text = str(text).strip().lower()

    for keyword in keywords:

        if keyword.lower() in text:
            return keyword

    return None
# ==========================================================
# individual detections
# ==========================================================

def detect_dynamic_dns(dns):
    if not dns:
        return{
            "matched": False,
            "name":"Dynamic DNS Provider",
            "reason": None
    }
    dynamic_dns = contains_keyword(
        dns, 
        DYNAMIC_DNS_PROVIDERS
    )
    if dynamic_dns:
        return {
            "matched": True,
            "correlation_required":True,
            "name":"Dynamic DNS Provider",
            "category": "DNS",
            "severity": "Low",
            "mitre": ["T1071.004"],
            "reason": f"Dynamic DNS Provider'{dynamic_dns}' detected."
        }
    return {
        "matched": False,
        "name": "Dynamic DNS Provider",
        "reason": None,
    }

def detect_abused_tld(dns):
    if not dns:
        return {
            "matched": False,
            "name": "Commonly Abused TLD",
            "reason": None,
        }

    abused_tld = contains_keyword(
        dns,
        COMMON_ABUSED_TLDS
    )

    if abused_tld:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Commonly Abused TLD",
            "category": "DNS",
            "severity": "Low",
            "mitre": [],
            "reason": f"Commonly abused top-level domain '{abused_tld}' detected.",
        }

    return {
        "matched": False,
        "name": "Commonly Abused TLD",
        "reason": None,
    }

def detect_dns_tunneling_record(record_type):
    if not record_type:
        return {
            "matched": False,
            "name": "DNS Tunneling Record",
            "reason": None,
        }

    tunneling_record = contains_keyword(
    record_type,
    DNS_TUNNELING_RECORDS
)

    if tunneling_record:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "DNS Tunneling Record",
            "category": "DNS",
            "severity": "Low",
            "mitre": ["T1071.004"],
            "reason": f"Potential DNS tunneling record type '{tunneling_record}' detected.",
        }

    return {
        "matched": False,
        "name": "DNS Tunneling Record",
        "reason": None,
    }

def detect_dns_over_https(dns):
    if not dns:
        return {
            "matched": False,
            "name": "DNS over HTTPS",
            "reason": None,
        }

    doh_provider = contains_keyword(
        dns,
        DNS_OVER_HTTPS_PROVIDERS
    )

    if doh_provider:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "DNS over HTTPS",
            "category": "DNS",
            "severity": "Low",
            "mitre": ["T1071.004"],
            "reason": f"DNS over HTTPS provider '{doh_provider}' detected.",
        }

    return {
        "matched": False,
        "name": "DNS over HTTPS",
        "reason": None,
    }


def detect_public_dns_resolver(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Public DNS Resolver",
            "reason": None,
        }

    resolver = contains_keyword(
        ip,
        PUBLIC_DNS_RESOLVERS
    )

    if resolver:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Public DNS Resolver",
            "category": "DNS",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Public DNS resolver '{resolver}' detected.",
        }

    return {
        "matched": False,
        "name": "Public DNS Resolver",
        "reason": None,
    }

# ==========================================================
# main detector
# ==========================================================

def detect_dns(
    dns,
    record_type,
    resolver_ip,
):

    detections = []

    checks = [
        (detect_dynamic_dns, dns),
        (detect_abused_tld, dns),
        (detect_dns_tunneling_record, record_type),
        (detect_dns_over_https, dns),
        (detect_public_dns_resolver, resolver_ip),
    ]

    for detector, artifact in checks:

        result = detector(artifact)

        if result["matched"]:
            detections.append(result)

    return detections
