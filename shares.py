# ==========================================================
# keywords
# ==========================================================
#identify execution from windows unc netowrk paths 

UNC_PATH_PATTERNS = {
    r"\\",
    r"UNC\\",
}
#admin shares that attackers commonly abuse 
ADMIN_SHARE_PATHS = {
    "ADMIN$",
    "C$",
    "D$",
    "E$",
    "IPC$",
    "PRINT$",
    "SYSVOL",
    "NETLOGON",
}
#gen networl share indicators(doesnt mean malware, just indicate executable orgniated from network share)
NETWORK_SHARE_PATTERNS = {
    r"\\",
    r"\\server",
    r"\\hostname",
    r"\\fileserver",
    r"\\share",
    r"\\public",
    r"\\users",
    r"\\software",
    r"\\install",
    r"\\deployment",
}
#webdav can be abused to execute remote content 
WEB_DAV_PATTERNS = {
    "@SSL",
    "DavWWWRoot",
    "WebDAV",
    "http://",
    "https://",
    "dav:",
}
#common service executable locations 
SERVICE_IMAGE_PATH_PATTERNS = {
    r"\System32",
    r"\SysWOW64",
    r"\Program Files",
    r"\Program Files (x86)",
    r"\Windows",
    r"\ProgramData",
    r"\Services",
}
#indicators that a serivce path may be vulnerable to unqoted service path issues 
UNQUOTED_SERVICE_PATTERNS = {
    "Program Files",
    "Program Files (x86)",
    "Common Files",
    "Windows Services",
}
#common arguements seen in service image paths 
SERVICE_ARGUMENT_PATTERNS = {
    "-k",
    "-s",
    "/service",
    "-service",
    "--service",
    "/runservice",
    "/svc",
    "-svc",
    "--daemon",
    "/background",
    "-run",
    "/start",
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
# individual detections
# ==========================================================
def detect_unc_path(path):

    if not path:
        return {
            "matched": False,
            "name": "UNC Path",
            "reason": None,
        }

    unc = contains_keyword(
        path,
        UNC_PATH_PATTERNS
    )

    if unc:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "UNC Path",
            "category": "Share",
            "severity": "Informational",
            "mitre": ["T1021.002"],
            "reason": f"UNC path '{unc}' detected.",
        }

    return {
        "matched": False,
        "name": "UNC Path",
        "reason": None,
    }

def detect_admin_share(path):

    if not path:
        return {
            "matched": False,
            "name": "Administrative Share",
            "reason": None,
        }

    admin_share = contains_keyword(
        path,
        ADMIN_SHARE_PATHS
    )

    if admin_share:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Administrative Share",
            "category": "Share",
            "severity": "Low",
            "mitre": ["T1021.002"],
            "reason": f"Administrative share '{admin_share}' detected.",
        }

    return {
        "matched": False,
        "name": "Administrative Share",
        "reason": None,
    }

def detect_network_share(path):

    if not path:
        return {
            "matched": False,
            "name": "Network Share",
            "reason": None,
        }

    share = contains_keyword(
        path,
        NETWORK_SHARE_PATTERNS
    )

    if share:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Network Share",
            "category": "Share",
            "severity": "Informational",
            "mitre": ["T1021.002"],
            "reason": f"Network share '{share}' detected.",
        }

    return {
        "matched": False,
        "name": "Network Share",
        "reason": None,
    }
def detect_webdav(path):

    if not path:
        return {
            "matched": False,
            "name": "WebDAV Path",
            "reason": None,
        }

    webdav = contains_keyword(
        path,
        WEB_DAV_PATTERNS
    )

    if webdav:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "WebDAV Path",
            "category": "Share",
            "severity": "Low",
            "mitre": ["T1105"],
            "reason": f"WebDAV indicator '{webdav}' detected.",
        }

    return {
        "matched": False,
        "name": "WebDAV Path",
        "reason": None,
    }

def detect_service_image_path(path):

    if not path:
        return {
            "matched": False,
            "name": "Service Image Path",
            "reason": None,
        }

    service = contains_keyword(
        path,
        SERVICE_IMAGE_PATH_PATTERNS
    )

    if service:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Service Image Path",
            "category": "Service",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Service image path '{service}' detected.",
        }

    return {
        "matched": False,
        "name": "Service Image Path",
        "reason": None,
    }

#does not use contains_keyword
def detect_unquoted_service_path(path):

    if not path:
        return {
            "matched": False,
            "name": "Unquoted Service Path",
            "reason": None,
        }

    unquoted = contains_keyword(
        path,
        UNQUOTED_SERVICE_PATTERNS
    )

    if unquoted and not path.strip().startswith('"'):

        return {
            "matched": True,
            "correlation_required": True,
            "name": "Unquoted Service Path",
            "category": "Service",
            "severity": "Medium",
            "mitre": ["T1574.009"],
            "reason": "Potential unquoted service path detected.",
        }

    return {
        "matched": False,
        "name": "Unquoted Service Path",
        "reason": None,
    }

def detect_service_arguments(path):

    if not path:
        return {
            "matched": False,
            "name": "Service Arguments",
            "reason": None,
        }

    argument = contains_keyword(
        path,
        SERVICE_ARGUMENT_PATTERNS
    )

    if argument:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Service Arguments",
            "category": "Service",
            "severity": "Informational",
            "mitre": [],
            "reason": f"Service argument '{argument}' detected.",
        }

    return {
        "matched": False,
        "name": "Service Arguments",
        "reason": None,
    }


# ==========================================================
# main detector
# ==========================================================

def detect_share(path):

    detections = []

    detectors = [
        detect_unc_path,
        detect_admin_share,
        detect_network_share,
        detect_webdav,
        detect_service_image_path,
        detect_unquoted_service_path,
        detect_service_arguments,
    ]

    for detector in detectors:

        result = detector(path)

        if result["matched"]:
            detections.append(result)

    return detections
