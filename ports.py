# ==========================================================
# port detection module
#
# detects suspicious network port activity including:
# - remote administration ports
# - database ports
# - web service ports
# - email service ports
# - high-risk ports commonly abused by attackers
#
# most detections are low-confidence indicators and are
# intended to be correlated with additional telemetry.
# ==========================================================

# ==========================================================
# keywords
# ==========================================================
#ports commonly used by attackers for remote admin and lateral movement 

REMOTE_ADMIN_PORTS = {
    22,     # SSH
    23,     # Telnet
    3389,   # RDP
    5900,   # VNC
    5901,
    5902,
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS

}

DATABASE_PORTS = {
    1433,   # Microsoft SQL Server
    1434,
    1521,   # Oracle
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    9042,   # Cassandra
}
WEB_PORTS = {
    80,
    443,
    8080,
    8081,
    8000,
    8443,
    8888,
}
#ports that frequently apear in malware, exploitation or lateral movement 
HIGH_RISK_PORTS = {
    135,     # RPC
    137,
    138,
    139,
    445,     # SMB
    1433,    # MSSQL
    3389,    # RDP
    4444,    # Metasploit default
    5555,
    6666,
    6667,
    9001,
    9050,    # Tor
    1080,    # SOCKS Proxy

}
SYSTEM_PORTS = range(0,1024)
#REGISTERED_PORTS = range(1024, 49152)
#DYNAMIC_PORTS = range(49152, 65536)
#phising investigations and malware delivery 
EMAIL_PORTS = {
    25,     # SMTP
    110,    # POP3
    143,    # IMAP
    465,    # SMTPS
    587,    # Submission
    993,    # IMAPS
    995,    # POP3S
}
# ==========================================================
# validation
# ==========================================================
#validates ports first 
def validate_port(port):

    if port is None:
        return {
            "matched": False,
            "name": "Invalid Port",
            "reason": None,
        }

    try:
        port = int(port)

    except (TypeError, ValueError):
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Invalid Port",
            "category": "Port",
            "severity": "Low",
            "mitre": [],
            "reason": f"Invalid port '{port}' detected.",
        }

    if not 0 <= port <= 65535:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Invalid Port",
            "category": "Port",
            "severity": "Low",
            "mitre": [],
            "reason": f"Port '{port}' is outside the valid range.",
        }

    return {
        "matched": False,
        "name": "Invalid Port",
        "reason": None,
    }

# ==========================================================
# individual detections
# ==========================================================
def detect_remote_admin_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "Remote Administration Port",
            "reason": None,
        }

    if port in REMOTE_ADMIN_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Remote Administration Port",
            "category": "Port",
            "severity": "Low",
            "mitre": ["T1021"],
            "reason": f"Remote administration port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "Remote Administration Port",
        "reason": None,
    }

def detect_database_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "Database Port",
            "reason": None,
        }

    if port in DATABASE_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Database Port",
            "category": "Port",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Database service port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "Database Port",
        "reason": None,
    }

def detect_web_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "Web Service Port",
            "reason": None,
        }

    if port in WEB_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Web Service Port",
            "category": "Port",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Web service port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "Web Service Port",
        "reason": None,
    }

def detect_high_risk_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "High-Risk Port",
            "reason": None,
        }

    if port in HIGH_RISK_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "High-Risk Port",
            "category": "Port",
            "severity": "Medium",
            "mitre": ["T1571"],
            "reason": f"High-risk port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "High-Risk Port",
        "reason": None,
    }

def detect_system_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "System Port",
            "reason": None,
        }

    if port in SYSTEM_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "System Port",
            "category": "Port",
            "severity": "Informational",
            "mitre": [],
            "reason": f"System port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "System Port",
        "reason": None,
    }

def detect_email_port(port):
    if port is None:
        return {
            "matched": False,
            "name": "Email Service Port",
            "reason": None,
        }

    if port in EMAIL_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Email Service Port",
            "category": "Port",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Email service port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "Email Service Port",
        "reason": None,
    }

    
# ==========================================================
# main detector
# ==========================================================
def detect_port(port):

    detections = []

    # validate the port first
    validation = validate_port(port)

    if validation["matched"]:
        detections.append(validation)
        return detections

    # safe to convert now because validation passed
    port = int(port)

    detectors = [
        detect_remote_admin_port,
        detect_database_port,
        detect_web_port,
        detect_high_risk_port,
        detect_system_port,
        detect_email_port,
    ]

    for detector in detectors:

        result = detector(port)

        if result["matched"]:
            detections.append(result)

    return detections
