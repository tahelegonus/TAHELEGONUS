
# ==========================================================
# keywords
# ==========================================================
#identify execution from windows unc netowrk paths 
UNC_PATH_PATTERNS = {
    r"\\",
    r"UNC\\",
}
#admin shares that attackers commonlu abuse 
ADMIN_SHARE_PATTERNS = {
    "ADMIN$",
    "C$",
    "D$",
    "E$",
    "F$",
    "IPC$",
    "PRINT$",
    "SYSVOL",
    "NETLOGON",
    "\\admin$\\",
    "\\c$\\",
    "\\d$\\",
    "\\e$\\",
    "\\ipc$\\",
    "\\print$\\",

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
    "DavWWWRoot",
    "@SSL",
    "WebDAV",
    "dav:",
    "http://",
    "https://",
    "\\DavWWWRoot\\",

}

REMOTE_EXECUTION_PATHS = {

    r"\\",

    "http://",
    "https://",

    "ftp://",

    "DavWWWRoot",

    "@SSL",

    "UNC",

}
# ==========================================================
# helper functions
# ==========================================================
#keyword matcher helper 

def contains_keyword(image_path, keywords):

    command = image_path.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None
# ==========================================================
# individual detections
# ==========================================================

def detect_unc_path(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "UNC Path Execution",
            "reason": None
        }

    unc = contains_keyword(
        image_path,
        UNC_PATH_PATTERNS
    )

    if unc:
        return {
            "matched": True,
            "name": "UNC Path Execution",
            "category": "Network Path",
            "severity": "High",
            "mitre": ["T1021"],
            "reason": f"UNC path '{unc}' detected."
        }

    return {
        "matched": False,
        "name": "UNC Path Execution",
        "reason": None
    }

def detect_admin_share(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Administrative Share",
            "reason": None
        }
    share = contains_keyword(
        image_path,
        ADMIN_SHARE_PATTERNS
    )

    if share:
        return {
            "matched": True,
            "name": "Administrative Share",
            "category": "Network Path",
            "severity": "High",
            "mitre": ["T1021.002"],
            "reason": f"Administrative share '{share}' detected."
        }

    return {
        "matched": False,
        "name": "Administrative Share",
        "reason": None
    }

def detect_webdav_execution(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "WebDav Execution",
            "reason": None
        }

    webdav = contains_keyword(
        image_path,
        WEB_DAV_PATTERNS
    )

    if webdav:
        return {
            "matched": True,
            "name": "WebDAV Execution",
            "category": "Network Path",
            "severity": "High",
            "mitre": ["T1105"],
            "reason": f"WebDAV path '{webdav}' detected."
        }

    return {
        "matched": False,
        "name": "WebDAV Execution",
        "reason": None
    }

def detect_remote_execution(image_path): 
    if not image_path:
        return {
            "matched": False,
            "name": "Remote Execution Path",
            "reason": None
        }
    remote = contains_keyword(
        image_path,
        REMOTE_EXECUTION_PATHS
    )

    if remote:
        return {
            "matched": True,
            "name": "Remote Execution Path",
            "category": "Network Path",
            "severity": "High",
            "mitre": ["T1021"],
            "reason": f"Remote execution path '{remote}' detected."
        }

    return {
        "matched": False,
        "name": "Remote Execution Path",
        "reason": None
    }


def detect_network_share(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Network Share Path",
            "reason": None
        }
    network = contains_keyword(
            image_path,
            NETWORK_SHARE_PATTERNS
        )
    
    if network:
            return {
                "matched": True,
                "name": "Network Share Path",
                "category": "Network Path",
                "severity": "High",
                "mitre": ["T1021"],
                "reason": f"Network Share Path '{network}' detected."
            }
    
    return {
            "matched": False,
            "name": "Network Share Path",
            "reason": None
        }
    

# ==========================================================
# main detector
# ==========================================================
def detect_network_paths(image_path):

    detections = []

    detectors = [

    detect_unc_path,
    detect_admin_share,
    detect_webdav_execution,
    detect_remote_execution,
    detect_network_share

    ]
    for detector in detectors:

        result = detector(image_path)

        if result["matched"]:
            detections.append(result)

    return detections




