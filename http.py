# ===========================================================
# http detection module
#
# detects suspicious HTTP indicators including:
# - suspicious user agents
# - suspicious download file extensions
# - suspicious URIs
# - suspicious content and MIME types
# - HTTP CONNECT requests
#
# validates HTTP methods and status codes to identify
# unexpected or malformed protocol usage.
#
# most detections are low-confidence indicators and are
# intended to be correlated with additional telemetry.
# ==========================================================
# ==========================================================
# keywords
# ==========================================================
#user agents commnlu seen in malware, automated tools, or scripting , also needs correlation
SUSPICIOUS_USER_AGENTS = {

    # command line tools
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "python-httpx",
    "curl/",
    "wget/",
    # powershell
    "powershell",
    "winhttp",
    #python
    "python",
    "aiohttp",
    "httpx",
    #reconnaissance
    "ffuf",
    "gobuster",
    "feroxbuster",
    "dirbuster",
    "whatweb",
    # scripting
    "libwww-perl",
    "Go-http-client",
    "Java/",
    "Apache-HttpClient",
    # scanners
    "nmap",
    "masscan",
    "zgrab",
    "sqlmap",
    "nikto",
    # exploitation
    "metasploit",
    "cobaltstrike",

}
#file types commnly downloaded during malware delivery 
SUSPICIOUS_FILE_EXTENSIONS = {

    # executables
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".com",
    ".scr",
    # scripts
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    # archives
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
    # office
    ".doc",
    ".docm",
    ".docx",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".ppt",
    ".pptm",
    ".pptx",
    # shortcuts
    ".lnk",
    # installers
    ".appx",
    ".msix",
    #extensions 
    ".cab",
    ".chm",
    ".jar",
    ".reg",
    ".psm1",
    ".psd1",

}
#http MIME types that are often correspond to downloadable executables or scripts
SUSPICIOUS_CONTENT_TYPES = {

    # executables
    "application/octet-stream",
    "application/x-msdownload",
    # installers
    "application/x-msi",
    # scripts
    "application/x-powershell",
    "text/javascript",
    "application/javascript",
    # archives
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    # office
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    # html applications
    "application/hta",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/java-archive",
    "text/x-powershell",
    #mime 
    "application/x-httpd-php",
    "text/x-php",
    "application/x-sh",

}

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "CONNECT",
    "TRACE",
    "PATCH",
}

HTTP_STATUS_CODES = {

    200,
    201,
    202,
    204,
    301,
    302,
    307,
    308,
    400,
    401,
    403,
    404,
    500,
    502,
    503,
    504,

}
SUSPICIOUS_URI_KEYWORDS = {
    "cmd",
    "shell",
    "upload",
    "download",
    "execute",
    "exec",
    "powershell",
    "base64",
    "eval",
    "invoke",
    "webshell",
    "reverse",
    "payload",
    "backdoor",
    "connect",
    "beacon",
    
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


def detect_suspicious_user_agent(user_agent):
    if not user_agent:
        return {
            "matched": False,
            "name": "Suspicious HTTP User Agent",
            "reason": None,
        }

    suspicious_agent = contains_keyword(
        user_agent,
        SUSPICIOUS_USER_AGENTS
    )

    if suspicious_agent:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Suspicious HTTP User Agent",
            "category": "HTTP",
            "severity": "Low",
            "mitre": ["T1071.001"],
            "reason": f"Suspicious HTTP user agent '{suspicious_agent}' detected.",
        }

    return {
        "matched": False,
        "name": "Suspicious HTTP User Agent",
        "reason": None,
    }

def detect_download_extension(url):
    if not url:
        return {
            "matched": False,
            "name": "Download Extension",
            "reason": None,
        }

    download_extension = contains_keyword(
        url,
        SUSPICIOUS_FILE_EXTENSIONS
    )

    if download_extension:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Download Extension",
            "category": "HTTP",
            "severity": "Low",
            "mitre": ["T1105"],
            "reason": f"Downloadable file extension '{download_extension}' detected.",
        }

    return {
        "matched": False,
        "name": "Download Extension",
        "reason": None,
    }

def detect_suspicious_content_type(content_type):
    if not content_type:
        return {
            "matched": False,
            "name": "Suspicious Content Type",
            "reason": None,
        }

    suspicious_content = contains_keyword(
        content_type,
        SUSPICIOUS_CONTENT_TYPES
    )

    if suspicious_content:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Suspicious Content Type",
            "category": "HTTP",
            "severity": "Low",
            "mitre": ["T1105"],
            "reason": f"Suspicious content type '{suspicious_content}' detected.",
        }

    return {
        "matched": False,
        "name": "Suspicious Content Type",
        "reason": None,
    }
# ==========================================================
# validation
# ==========================================================
#checks if the method is not in the library
def validate_http_method(method):
    if not method:
        return {
            "matched": False,
            "name": "Unknown HTTP Method",
            "reason": None,
        }

    method = method.upper()

    if method not in HTTP_METHODS:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Unknown HTTP Method",
            "category": "HTTP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Unexpected HTTP method '{method}' detected.",
        }

    return {
        "matched": False,
        "name": "Unknown HTTP Method",
        "reason": None,
    }

def detect_suspicious_uri(uri):
    if not uri:
        return {
            "matched": False,
            "name": "Suspicious URI",
            "reason": None,
        }

    suspicious_uri = contains_keyword(
        uri,
        SUSPICIOUS_URI_KEYWORDS
    )

    if suspicious_uri:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Suspicious URI",
            "category": "HTTP",
            "severity": "Low",
            "mitre": ["T1071.001"],
            "reason": f"Suspicious URI keyword '{suspicious_uri}' detected.",
        }

    return {
        "matched": False,
        "name": "Suspicious URI",
        "reason": None,
    }




def detect_http_connect(method):
    if not method:
        return {
            "matched": False,
            "name": "HTTP CONNECT Method",
            "reason": None,
        }

    if method.upper() == "CONNECT":
        return {
            "matched": True,
            "correlation_required": True,
            "name": "HTTP CONNECT Method",
            "category": "HTTP",
            "severity": "Low",
            "mitre": ["T1090"],
            "reason": "HTTP CONNECT method detected.",
        }

    return {
        "matched": False,
        "name": "HTTP CONNECT Method",
        "reason": None,
    }
# ==========================================================
# validation
# ==========================================================
def validate_http_status(status_code):

    if status_code is None:
        return {
            "matched": False,
            "name": "Unknown HTTP Status Code",
            "reason": None,
        }

    try:
        status_code = int(status_code)
    except (ValueError, TypeError):
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Unknown HTTP Status Code",
            "category": "HTTP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Invalid HTTP status code '{status_code}' detected.",
        }

    if status_code not in HTTP_STATUS_CODES:
        return {
            "matched": True,
            "correlation_required": True,
            "name": "Unknown HTTP Status Code",
            "category": "HTTP",
            "severity": "Low",
            "mitre": [],
            "reason": f"Unexpected HTTP status code '{status_code}' detected.",
        }

    return {
        "matched": False,
        "name": "Unknown HTTP Status Code",
        "reason": None,
    }


# ==========================================================
# main detector
# ==========================================================

def detect_http(
    user_agent,
    url,
    uri,
    content_type,
    method,
    status_code,
):

    detections = []

    detectors = [
        detect_suspicious_user_agent,
        detect_download_extension,
        detect_suspicious_uri,
        detect_suspicious_content_type,
        detect_http_connect,
    ]

    arguments = [
        user_agent,
        url,
        uri,
        content_type,
        method,
    ]

    for detector, argument in zip(detectors, arguments):

        result = detector(argument)

        if result["matched"]:
            detections.append(result)

    validation = validate_http_method(method)
      # validate HTTP method
    validation = validate_http_method(method)

    if validation["matched"]:
        detections.append(validation)

    # validate HTTP status
    validation = validate_http_status(status_code)

    if validation["matched"]:
        detections.append(validation)

    return detections

