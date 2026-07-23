# ==========================================================
# imports
# ==========================================================
import os
# ==========================================================
# keywords
# ==========================================================
SERVICE_IMAGE_PATH_PATTERNS = {

    r"\system32",
    r"\syswow64",
    r"\program files",
    r"\program files (x86)",
    r"\windows",
    r"\programdata",
    r"\winsxs",

}

UNQUOTED_SERVICE_PATTERNS = {
    r"c:\program files\\",
    r"c:\program files (x86)\\",
    r"c:\users\\",
}
#command commoand line switches
SERVICE_ARGUMENT_PATTERNS = {
    "-k",
    "-s",
    "-service",
    "/service",
    "/svc",
    "--service",
    "--daemon",
}

#directoreis where services executables are more suspicious 
WEAK_SERVICE_DIRECTORIES = {
    r"c:\programdata",
    r"c:\users\public",
    r"c:\temp",
    r"c:\windows\temp",
    r"\appdata\local",
    r"\appdata\roaming",

}
#high risk writeable locations 

WORLD_WRITABLE_SERVICE_PATHS = {
    r"c:\users\public",
    r"c:\windows\temp",
    r"c:\temp",
    r"\appdata\local\temp",
    r"\downloads",
    r"\desktop",

}
#locations commonly abused for service hijacking and perssitance 
COMMON_SERVICE_HIJACK_PATHS = {
    r"\programdata",
    r"\users\public",
    r"\windows\tasks",
    r"\startup",
    r"\common startup",
    r"\appdata\roaming",
    r"\appdata\local",

}


# ==========================================================
# helper functions
# ==========================================================

def contains_keyword(image_path, keywords):

    path = image_path.lower()

    for keyword in keywords:

        if keyword.lower() in path:

            return keyword

    return None

# ==========================================================
# individual detectors
# ==========================================================
def detect_service_arguments(image_path):
    if not image_path:
            return {
                "matched": False,
                "name": "Suspicious Service Arguments",
                "reason": None
            }
    service_argument = contains_keyword(
        image_path,
        SERVICE_ARGUMENT_PATTERNS
    )

    if service_argument:
        return {
            "matched": True,
            "name": "Suspicious Service Arguments",
            "category": "Image Path",
            "severity": "Low",
            "mitre": ["T1543.003"],
            "reason": f"Service argument '{service_argument}' detected."
        }

    return {
        "matched": False,
        "name": "Suspicious Service Arguments",
        "reason": None
    }

def detect_weak_service_directory(image_path):
    if not image_path:
            return {
                "matched": False,
                "name": "Weak Service Directory",
                "reason": None
            }

    weak_service_path = contains_keyword(
        image_path,
        WEAK_SERVICE_DIRECTORIES
    )

    if weak_service_path:
        return {
            "matched": True,
            "name": "Weak Service Directory",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1574"],
            "reason": f"Weak service directory '{weak_service_path}' detected."
        }

    return {
        "matched": False,
        "name": "Weak Service Directory",
        "reason": None
    }

def detect_world_writable_service(image_path):
    if not image_path:
            return {
                "matched": False,
                "name": "World Writable Service Path",
                "reason": None
            }
    world_writable = contains_keyword(
        image_path,
        WORLD_WRITABLE_SERVICE_PATHS
    )

    if world_writable:
        return {
            "matched": True,
            "name": "World Writable Service Path",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1574"],
            "reason": f"World-writable service path '{world_writable}' detected."
        }

    return {
        "matched": False,
        "name": "World Writable Service Path",
        "reason": None
    }

def detect_service_hijack_path(image_path):
    if not image_path:
            return {
                "matched": False,
                "name": "Service Hijack Path",
                "reason": None
            }
    hijack = contains_keyword(
        image_path,
        COMMON_SERVICE_HIJACK_PATHS
    )

    if hijack:
        return {
            "matched": True,
            "name": "Service Hijack Path",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1574"],
            "reason": f"Potential service hijack path '{hijack}' detected."
        }

    return {
        "matched": False,
        "name": "Service Hijack Path",
        "reason": None
    }

def detect_unquoted_service_path(image_path):
    if not image_path:
            return {
                "matched": False,
                "name": "Unquoted Service Path",
                "reason": None
            }
    unquoted_service_path = image_path.lower()

    #only care about paths with spaces
    if "program files" not in unquoted_service_path:
        return {
            "matched": False,
            "name": "Unquoted Service Path",
            "reason": None
        }

    # Already quoted -> not vulnerable
    if '"' in image_path:
        return {
            "matched": False,
            "name": "Unquoted Service Path",
            "reason": None
        }

    return {
        "matched": True,
        "name": "Unquoted Service Path",
        "category": "Image Path",
        "severity": "High",
        "mitre": ["T1574.009"],
        "reason": "Potential unquoted service path detected."
    }

def detect_service_image_path(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Service Image Path",
            "reason": None
        }

    service_path = contains_keyword(
        image_path,
        SERVICE_IMAGE_PATH_PATTERNS
    )

    if service_path:
        return {
            "matched": True,
            "name": "Service Image Path",
            "category": "Image Path",
            "severity": "Low",
            "mitre": ["T1543.003"],
            "reason": f"Service image path '{service_path}' detected."
        }

    return {
        "matched": False,
        "name": "Service Image Path",
        "reason": None
    }

# ==========================================================
# main detector
# ==========================================================

def detect_service_paths(image_path):

    detections = []

    detectors = [

        detect_service_image_path,
        detect_unquoted_service_path,
        detect_service_arguments,
        detect_weak_service_directory,
        detect_world_writable_service,
        detect_service_hijack_path,

    ]

    for detector in detectors:

        result = detector(image_path)

        if result["matched"]:

            detections.append(result)

    return detections
