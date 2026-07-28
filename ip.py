import ipaddress 
# ==========================================================
# ip detection module
#
# detects suspicious IP indicators including:
# - private address ranges
# - loopback addresses
# - multicast addresses
# - link-local addresses
# - broadcast addresses
# - documentation ranges
# - reserved address ranges
#
# most detections are low-confidence indicators and are
# intended to be correlated with additional telemetry.
# ==========================================================
# ==========================================================
# keywords
# ==========================================================
#RC 1918 private ipv4 addresses
PRIVATE_IP_RANGES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",

}

#traffic that never leaves the local machine
LOOPBACK_ADDRESSES = {
    "127.0.0.0/8",
    "::1",
}
#used for multicasr comms 
MULTICAST_RANGES = {
    "224.0.0.0/4",
    "ff00::/8",
}
#addresses automatically assigne when dhcp FAILS or for local comms
LINK_LOCAL_RANGES = {
    "169.254.0.0/16",
    "fe80::/10",
}
#sprcial broadcast destintions  
BROADCAST_ADDRESSES = {
    "255.255.255.255",
}
#never appear on the public internet, they are used in documentation and examples
DOCUMENTATION_RANGES = {
    "192.0.2.0/24",      # TEST-NET-1
    "198.51.100.0/24",   # TEST-NET-2
    "203.0.113.0/24",    # TEST-NET-3
    "2001:db8::/32",     # IPv6 Documentation
}
RESERVED_IP_RANGES = {
    "0.0.0.0/8",          # "This network"
    "100.64.0.0/10",      # Carrier-grade NAT
    "192.0.0.0/24",
    "240.0.0.0/4",        # Reserved
    "::",
}

# ==========================================================
# helper functions
# ==========================================================
#ip range helper 
def ip_in_ranges(ip, ranges):

    if not ip:
        return None

    try:
        ip_obj = ipaddress.ip_address(ip)

        for network in ranges:

            if ip_obj in ipaddress.ip_network(network, strict=False):
                return network

    except ValueError:
        return None

    return None
# ==========================================================
# individual detections
# ==========================================================
def detect_private_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Private IP Address",
            "reason": None,
        }

    private = ip_in_ranges(
        ip,
        PRIVATE_IP_RANGES
    )

    if private:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Private IP Address",
            "category": "IP",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Private IP address within '{private}' detected.",
        }

    return {
        "matched": False,
        "name": "Private IP Address",
        "reason": None,
    }


def detect_loopback_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Loopback Address",
            "reason": None,
        }

    loopback = ip_in_ranges(
        ip,
        LOOPBACK_ADDRESSES
    )

    if loopback:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Loopback Address",
            "category": "IP",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Loopback address within '{loopback}' detected.",
        }

    return {
        "matched": False,
        "name": "Loopback Address",
        "reason": None,
    }


def detect_multicast_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Multicast Address",
            "reason": None,
        }

    multicast = ip_in_ranges(
        ip,
        MULTICAST_RANGES
    )

    if multicast:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Multicast Address",
            "category": "IP",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Multicast address within '{multicast}' detected.",
        }

    return {
        "matched": False,
        "name": "Multicast Address",
        "reason": None,
    }



def detect_link_local_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Link-Local Address",
            "reason": None,
        }

    link_local = ip_in_ranges(
        ip,
        LINK_LOCAL_RANGES
    )

    if link_local:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Link-Local Address",
            "category": "IP",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Link-local address within '{link_local}' detected.",
        }

    return {
        "matched": False,
        "name": "Link-Local Address",
        "reason": None,
    }



def detect_broadcast_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Broadcast Address",
            "reason": None,
        }

    if ip in BROADCAST_ADDRESSES:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Broadcast Address",
            "category": "IP",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Broadcast address '{ip}' detected.",
        }

    return {
        "matched": False,
        "name": "Broadcast Address",
        "reason": None,
    }



def detect_documentation_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Documentation Address",
            "reason": None,
        }

    documentation = ip_in_ranges(
        ip,
        DOCUMENTATION_RANGES
    )

    if documentation:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Documentation Address",
            "category": "IP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Documentation address within '{documentation}' detected.",
        }

    return {
        "matched": False,
        "name": "Documentation Address",
        "reason": None,
    }


def detect_reserved_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Reserved Address",
            "reason": None,
        }

    reserved = ip_in_ranges(
        ip,
        RESERVED_IP_RANGES
    )

    if reserved:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Reserved Address",
            "category": "IP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Reserved IP address within '{reserved}' detected.",
        }

    return {
        "matched": False,
        "name": "Reserved Address",
        "reason": None,
    }


#validates invalid up from a normal not matched ip 
def validate_ip(ip):
    if not ip:
        return {
            "matched": False,
            "name": "Invalid IP Address",
            "reason": None,
        }

    try:
        ipaddress.ip_address(ip)

    except ValueError:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Invalid IP Address",
            "category": "IP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Invalid IP address '{ip}' detected.",
        }

    return {
        "matched": False,
        "name": "Invalid IP Address",
        "reason": None,
    }



==
# ==========================================================
# main detector
# ==========================================================

def detect_ip(ip):

    detections = []

    validation = validate_ip(ip)

    if validation["matched"]:
        detections.append(validation)
        return detections

    detectors = [
        detect_private_ip,
        detect_loopback_ip,
        detect_multicast_ip,
        detect_link_local_ip,
        detect_broadcast_ip,
        detect_documentation_ip,
        detect_reserved_ip,
    ]

    for detector in detectors:

        result = detector(ip)

        if result["matched"]:
            detections.append(result)

    return detections
