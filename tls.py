# ==========================================================
# tls detection module
#
# detects suspicious TLS indicators including:
# - deprecated protocol versions
# - weak cipher suites
# - self-signed certificates
# - invalid certificate properties
#
# most detections are low-confidence indicators and are
# intended to be correlated with additional telemetry.
# ==========================================================

# ==========================================================
# keywords
# ==========================================================
#versions that are deprecated or generally should not be seen on moddern systems 
WEAK_TLS_VERSIONS = {
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1",
}
#most common ports that carrt TLS encrypted traffic 
TLS_PORTS = {
    443,    # HTTPS
    465,    # SMTPS
    563,    # NNTPS
    636,    # LDAPS
    853,    # DNS over TLS
    989,    # FTPS Data
    990,    # FTPS Control
    992,    # TelnetS
    993,    # IMAPS
    995,    # POP3S
    8443,   # Alternate HTTPS
}
TLS_CIPHER_KEYWORDS = {
    "RC4",
    "DES",
    "3DES",
    "NULL",
    "EXPORT",
    "MD5",

}
CERTIFICATE_SIGNATURE_ALGORITHMS = {

    "md5",
    "sha1",

}


# ==========================================================
# helper functions
# ==========================================================
def contains_keyword(text, keywords):

    if not text:
        return None

    text = str(text).strip().lower()

    for keyword in keywords:

        if keyword.lower() in text:
            return keyword

    return None

# ==========================================================
# validation
# ==========================================================
def validate_tls_port(port):

    if port is None:
        return {
            "matched": False,
            "name": "Invalid TLS Port",
            "reason": None,
        }

    try:
        port = int(port)

    except (TypeError, ValueError):

        return {
            "matched": True,
            "correlation_required": True,
            "name": "Invalid TLS Port",
            "category": "TLS",
            "severity": "Low",
            "mitre": [],
            "reason": f"Invalid TLS port '{port}' detected.",
        }

    if not 0 <= port <= 65535:

        return {
            "matched": True,
            "correlation_required": True,
            "name": "Invalid TLS Port",
            "category": "TLS",
            "severity": "Low",
            "mitre": [],
            "reason": f"Port '{port}' is outside the valid range.",
        }

    return {
        "matched": False,
        "name": "Invalid TLS Port",
        "reason": None,
    }
# ==========================================================
# individual detections
# ==========================================================
def detect_weak_tls_version(version):

    if not version:
        return {
            "matched": False,
            "name": "Weak TLS Version",
            "reason": None,
        }

    weak_version = contains_keyword(
        version,
        WEAK_TLS_VERSIONS
    )

    if weak_version:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Weak TLS Version",
            "category": "TLS",
            "severity": "Medium",
            "mitre": ["T1573"],
            "reason": f"Weak TLS version '{weak_version}' detected.",
        }

    return {
        "matched": False,
        "name": "Weak TLS Version",
        "reason": None,
    }

def detect_tls_port(port):

    if port is None:
        return {
            "matched": False,
            "name": "TLS Port",
            "reason": None,
        }

    if port in TLS_PORTS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "TLS Port",
            "category": "TLS",
            "severity": "Informational",
            "mitre": [],
            "reason": f"TLS service port '{port}' detected.",
        }

    return {
        "matched": False,
        "name": "TLS Port",
        "reason": None,
    }

def detect_weak_cipher(cipher):

    if not cipher:
        return {
            "matched": False,
            "name": "Weak TLS Cipher",
            "reason": None,
        }

    weak_cipher = contains_keyword(
        cipher,
        TLS_CIPHER_KEYWORDS
    )

    if weak_cipher:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Weak TLS Cipher",
            "category": "TLS",
            "severity": "Medium",
            "mitre": ["T1573"],
            "reason": f"Weak TLS cipher '{weak_cipher}' detected.",
        }

    return {
        "matched": False,
        "name": "Weak TLS Cipher",
        "reason": None,
    }


def detect_weak_signature_algorithm(signature):

    if not signature:
        return {
            "matched": False,
            "name": "Weak Certificate Signature",
            "reason": None,
        }

    weak_signature = contains_keyword(
        signature,
        CERTIFICATE_SIGNATURE_ALGORITHMS
    )

    if weak_signature:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Weak Certificate Signature",
            "category": "TLS",
            "severity": "Medium",
            "mitre": ["T1573"],
            "reason": f"Weak certificate signature algorithm '{weak_signature}' detected.",
        }

    return {
        "matched": False,
        "name": "Weak Certificate Signature",
        "reason": None,
    }

# ==========================================================
# main detector
# ==========================================================
def detect_tls(
    version,
    port,
    cipher,
    signature_algorithm,
):

    detections = []

    validation = validate_tls_port(port)

    if validation["matched"]:
        detections.append(validation)
        return detections

    detectors = [
        (detect_weak_tls_version, version),
        (detect_tls_port, port),
        (detect_weak_cipher, cipher),
        (detect_weak_signature_algorithm, signature_algorithm),
    ]

    for detector, artifact in detectors:

        result = detector(artifact)

        if result["matched"]:
            detections.append(result)

    return detections
