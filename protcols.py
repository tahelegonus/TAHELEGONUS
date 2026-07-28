
# ==========================================================
# keywords
# ==========================================================
#common protocols seen all the time 
COMMON_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "ARP",
    "IPv4",
    "IPv6",
    "DNS",
    "DHCP",
    "HTTP",
    "HTTPS",
    "TLS",
    "FTP",
    "SMTP",
    "POP3",
    "IMAP",
    "SNMP",
    "NTP",
    "SMB",
    "LDAP",
    "Kerberos",
    "SSH",
    "RDP",
    "RPC",
    "WinRM",
    "MQTT",
    "SIP",
}
#commonluy abused to bypass monitoring r create covert channels 
TUNNELING_PROTOCOLS = {
    "DNS",
    "ICMP",
    "HTTP",
    "HTTPS",
    "TLS",
    "SSH",
    "SOCKS",
    "GRE",
    "IPsec",
    "L2TP",
    "PPTP",
    "OpenVPN",
    "WireGuard",
    "QUIC",
}
#protocols used for remote access, admin or remote exectuon
REMOTE_PROTOCOLS = {
    "RDP",
    "SSH",
    "WinRM",
    "VNC",
    "Telnet",
    "SMB",
    "RPC",
    "WMI",
    "RFB",
    "PsExec",
    "RSH",
}
#malware commonlu moves files
FILE_TRANSFER_PROTOCOLS = {
    "FTP",
    "FTPS",
    "SFTP",
    "SCP",
    "SMB",
    "NFS",
    "TFTP",
    "WebDAV",
    "HTTP",
    "HTTPS",
}
AUTHENTICATION_PROTOCOLS = {
    "Kerberos",
    "NTLM",
    "LDAP",
    "LDAPS",
    "RADIUS",
    "TACACS+",
    "OAuth",
    "SAML",
}
ENCRYPTED_PROTOCOLS = {
    "HTTPS",
    "TLS",
    "SSH",
    "SFTP",
    "FTPS",
    "IPsec",
    "LDAPS",
    "SMTPS",
    "IMAPS",
    "POP3S",
    "OpenVPN",
    "WireGuard",
}

MANAGEMENT_PROTOCOLS = {
    "SNMP",
    "SSH",
    "WinRM",
    "RDP",
    "SMB",
    "RPC",
    "WMI",
    "LDAP",
}

# ==========================================================
# helper functions
# ==========================================================

def protocol_in_list(protocol, protocol_list):

    if not protocol:
        return None

    protocol = str(protocol).strip().upper()

    for item in protocol_list:

        if protocol == item.upper():
            return item

    return None


# ==========================================================
# validation
# ==========================================================
#validates protocols first 
def validate_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Unknown Protocol",
            "reason": None,
        }

    protocol = str(protocol).strip().upper()

    if protocol not in {p.upper() for p in COMMON_PROTOCOLS}:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Unknown Protocol",
            "category": "Protocol",
            "severity": "Low",
            "mitre": [],
            "reason": f"Unknown protocol '{protocol}' detected.",
        }

    return {
        "matched": False,
        "name": "Unknown Protocol",
        "reason": None,
    }

# ==========================================================
# individual detections
# ==========================================================

def detect_tunneling_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Tunneling Protocol",
            "reason": None,
        }

    tunnel = protocol_in_list(
        protocol,
        TUNNELING_PROTOCOLS
    )

    if tunnel:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Tunneling Protocol",
            "category": "Protocol",
            "severity": "Low",
            "mitre": ["T1090"],
            "reason": f"Tunneling protocol '{tunnel}' detected.",
        }

    return {
        "matched": False,
        "name": "Tunneling Protocol",
        "reason": None,
    }

def detect_remote_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Remote Administration Protocol",
            "reason": None,
        }

    remote = protocol_in_list(
        protocol,
        REMOTE_PROTOCOLS
    )

    if remote:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Remote Administration Protocol",
            "category": "Protocol",
            "severity": "Low",
            "mitre": ["T1021"],
            "reason": f"Remote administration protocol '{remote}' detected.",
        }

    return {
        "matched": False,
        "name": "Remote Administration Protocol",
        "reason": None,
    }

def detect_file_transfer_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "File Transfer Protocol",
            "reason": None,
        }

    transfer = protocol_in_list(
        protocol,
        FILE_TRANSFER_PROTOCOLS
    )

    if transfer:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "File Transfer Protocol",
            "category": "Protocol",
            "severity": "Informational",
            "mitre": ["T1105"],
            "reason": f"File transfer protocol '{transfer}' detected.",
        }

    return {
        "matched": False,
        "name": "File Transfer Protocol",
        "reason": None,
    }

def detect_authentication_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Authentication Protocol",
            "reason": None,
        }

    authentication = protocol_in_list(
        protocol,
        AUTHENTICATION_PROTOCOLS
    )

    if authentication:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Authentication Protocol",
            "category": "Protocol",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Authentication protocol '{authentication}' detected.",
        }

    return {
        "matched": False,
        "name": "Authentication Protocol",
        "reason": None,
    }

def detect_encrypted_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Encrypted Protocol",
            "reason": None,
        }

    encrypted = protocol_in_list(
        protocol,
        ENCRYPTED_PROTOCOLS
    )

    if encrypted:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Encrypted Protocol",
            "category": "Protocol",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Encrypted protocol '{encrypted}' detected.",
        }

    return {
        "matched": False,
        "name": "Encrypted Protocol",
        "reason": None,
    }

def detect_management_protocol(protocol):

    if not protocol:
        return {
            "matched": False,
            "name": "Management Protocol",
            "reason": None,
        }

    management = protocol_in_list(
        protocol,
        MANAGEMENT_PROTOCOLS
    )

    if management:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Management Protocol",
            "category": "Protocol",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Management protocol '{management}' detected.",
        }

    return {
        "matched": False,
        "name": "Management Protocol",
        "reason": None,
    }
  
# ==========================================================
# main detector
# ==========================================================
def detect_protocol(protocol):

    detections = []

    validation = validate_protocol(protocol)

    if validation["matched"]:
        detections.append(validation)
        return detections

    detectors = [
        detect_tunneling_protocol,
        detect_remote_protocol,
        detect_file_transfer_protocol,
        detect_authentication_protocol,
        detect_encrypted_protocol,
        detect_management_protocol,
    ]

    for detector in detectors:

        result = detector(protocol)

        if result["matched"]:
            detections.append(result)

    return detections
