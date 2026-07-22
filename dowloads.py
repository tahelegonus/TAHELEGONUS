
# ==========================================================
# keyword libraries
# ==========================================================



#download command line parameters


DOWNLOAD_KEYWORDS = {
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadstring",
    "downloadfile",
    "start-bitstransfer",
}


#T1197
BITSADMIN_PATTERNS ={

    "bitsadmin /transfer",
    "bitsadmin /create",
    "bitsadmin /addfile",
    "bitsadmin /setnotifycmdline",
    "bitsadmin /resume",
    "bitsadmin /complete",
    "bitsadmin /cancel",
    "bitsadmin /reset",
    "/addfile",
    "/setnotifycmdline",
    "/setnotifyflags",
    "/setpriority",
    "/setcustomheaders",
    "/setminretrydelay",

}


#T1105/T1140
CERTUTIL_PATTERNS = {

    "certutil -urlcache",
    "certutil -verifyctl",
    "certutil -decode",
    "certutil -decodehex",
    "certutil -encode",
    "certutil -split",
    "certutil -f",
    "certutil -ping",
    "-generateSSTFromWU",


}


CURL_PATTERNS = {
    "curl",
    "curl.exe",
    "curl http",
    "curl https",
    "curl ftp",
    "curl -o",
    "curl -O",
    "curl -k",
    "curl --output",
}

WGET_PATTERNS = {
    "wget",
    "wget.exe",
    "wget http",
    "wget https",
    "wget ftp",
    "wget -O",
}

#T1105 ingress tool transfer
DOWNLOAD_PATTERNS = {


    "invoke-webrequest http",
    "invoke-restmethod http",
    "downloadfile(",
    "curl http",
    "wget http",
    "certutil -urlcache",
    "bitsadmin /transfer",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "curl http",
    "wget http"
}

DOWNLOAD_FILE_EXTENSIONS = {

    ".exe",
    ".dll",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",

}

URL_PATTERNS = {

    "http://",
    "https://",
    "ftp://",
    "ftps://",

}


POWERSHELL_DOWNLOAD_PATTERNS = {
    "downloadstring(",
    "downloadfile(",
    "openread(",


}

INVOKE_REST_METHOD = {
    "invoke-restmethod",
    "irm",
}




INVOKE_WEBREQUEST_PATTERNS = {

    "invoke-webrequest",
    "iwr",

}


WEB_REQUEST_PATTERNS  = {

    "system.net.webrequest",
    "webrequest.create",
    "webrequest",

}


WEB_CLIENT_PATTERNS = {
    "system.net.webclient",
    "net.webclient",
    "new-object system.net.webclient",
    "downloadstring",
    "downloadfile",
    "openread",


}


OUTPUT_FILE_PATTERNS = {

    "-o",
    "-O",
    "--output",
    "/output",
    "/out",

}


DOWNLOAD_DESTINATIONS = {

    "appdata",
    "temp",
    "downloads",
    "desktop",
    "programdata",
    "public",
    "startup",

}


ARCHIVE_PATTERNS = {

    ".zip",
    ".rar",
    ".7z",
    ".cab",
    ".tar",
    ".gz",
    ".iso",

}

# ==========================================================
# helper functions
# ==========================================================

#keyword matcher helper 

def contains_keyword(command_line, keywords):

    command = command_line.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None





# ==========================================================
# individual detections
# ==========================================================
def detect_download_keywords(command_line):
    download_keywords = contains_keyword(
    command_line, DOWNLOAD_KEYWORDS
    )
    if download_keywords:
        return {
            "matched": True,
            "name":"Download",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Download Keyword '{download_keywords}' detected."
    }

    return {
        "matched": False,
        "name": "Download Activity",
        "reason": None
        }

def detect_download_patterns(command_line):
    download_pattern = contains_keyword(
    command_line, DOWNLOAD_PATTERNS
    )
    if download_pattern:
        return {
            "matched": True,
            "name":"Download Pattern",
            "category": "Download",
            "severity": "High",
            "mitre": ["T1105"],
            "reason": f" Download pattern '{download_pattern}' detected."
    }

    return {
        "matched": False,
        "name": "Download Pattern",
        "reason": None
        }



def detect_url_patterns(command_line):
    url_patterns = contains_keyword(
    command_line, URL_PATTERNS
    )
    if url_patterns:
        return {
            "matched": True,
            "name":"Remote URL",
            "category": "Download",
            "severity": "Low",
            "mitre": ["T1105"],
            "reason": f" Remote URL '{url_patterns}' detected."
    }

    return {
        "matched": False,
        "name": "Remote URL",
        "reason": None
        }


def detect_curl_patterns(command_line):
    curl = contains_keyword(
    command_line, CURL_PATTERNS
    )
    if curl:
        return {
            "matched": True,
            "name":"Curl",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Curl keyword '{curl}' detected."
    }

    return {
        "matched": False,
        "name": "Curl",
        "reason": None
        }



def detect_wget_patterns(command_line):
    wget = contains_keyword(
    command_line, WGET_PATTERNS
    )
    if wget:
        return {
            "matched": True,
            "name":"Wget",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f" keyword '{wget}' detected."
    }

    return {
        "matched": False,
        "name": "Wget",
        "reason": None
        }


def detect_bitsadmin_patterns(command_line):
    bitsadmin = contains_keyword(
    command_line, BITSADMIN_PATTERNS
    )
    if bitsadmin:
        return {
            "matched": True,
            "name":"BITSAdmin",
            "category": "Download",
            "severity": "High",
            "mitre": ["T1197"],
            "reason": f"BITSAdmin pattern '{bitsadmin}' detected."
    }

    return {
        "matched": False,
        "name": "BITSAdmin",
        "reason": None
        }


def detect_certutil_patterns(command_line):
    certutil = contains_keyword(
    command_line, CERTUTIL_PATTERNS
    )
    if certutil:
        return {
            "matched": True,
            "name":"CertUtil",
            "category": "Download",
            "severity": "High",
            "mitre": ["T1105", "T1140"],
            "reason": f"CerUtil pattern '{certutil}' detected."
    }

    return {
        "matched": False,
        "name": "CertUtil",
        "reason": None
        }


def detect_output_file(command_line):

    output = contains_keyword(
        command_line,
        OUTPUT_FILE_PATTERNS
    )

    if output:
        return {
            "matched": True,
            "name": "Output File",
            "category": "Download",
            "severity": "Low",
            "mitre": ["T1105"],
            "reason": f"Output file option '{output}' detected."
        }

    return {
        "matched": False,
        "name": "Output File",
        "reason": None
    }

def detect_invoke_webrequest_patterns(command_line): #.NET
    invoke_webrequest = contains_keyword(
    command_line, INVOKE_WEBREQUEST_PATTERNS
    )
    if invoke_webrequest:
        return {
            "matched": True,
            "name":"Invoke Web-Request",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Invoke-WebRequest keyword '{invoke_webrequest}' detected."
    }

    return {
        "matched": False,
        "name": "Invoke-WebRequest",
        "reason": None
        }



def detect_invoke_restmethod_patterns(command_line):
    restmethod = contains_keyword(
    command_line, INVOKE_REST_METHOD
    )
    if restmethod:
        return {
            "matched": True,
            "name":"Invoke-RestMethod",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Invoke -RestMethod keyword '{restmethod}' detected."
    }

    return {
        "matched": False,
        "name": "Invoke-RestMethod",
        "reason": None
        }

def detect_webclient_patterns(command_line):
    webclient_patterns = contains_keyword(
    command_line, WEB_CLIENT_PATTERNS
    )
    if webclient_patterns:
        return {
            "matched": True,
            "name":".NET WebClient",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f".NET WebClient keyword '{webclient_patterns}' detected."
    }

    return {
        "matched": False,
        "name": ".NET WebClient",
        "reason": None
        }


def detect_webrequest_patterns(command_line):
    webrequest_patterns = contains_keyword(
    command_line, WEB_REQUEST_PATTERNS
    )
    if webrequest_patterns:
        return {
            "matched": True,
            "name":".NET WebRequest",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f".NET WebRequest pattern '{webrequest_patterns}' detected."
    }

    return {
        "matched": False,
        "name": ".NET WebRequest",
        "reason": None
        }

def detect_powershell_downloads(command_line):
    powershell_downloads = contains_keyword(
    command_line, POWERSHELL_DOWNLOAD_PATTERNS
    )
    if powershell_downloads:
        return {
            "matched": True,
            "name":"PowerShell Download",
            "category": "Download",
            "severity": "High",
            "mitre": ["T1105"],
            "reason": f" PowerShell Download keyword '{powershell_downloads}' detected."
    }

    return {
        "matched": False,
        "name": "PowerShell Download",
        "reason": None
        }



def detect_downloaded_file(command_line):

    file = contains_keyword(
        command_line,
        DOWNLOAD_FILE_EXTENSIONS
    )

    if file:
        return {
            "matched": True,
            "name": "Downloaded File",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Downloaded file extension '{file}' detected."
        }

    return {
        "matched": False,
        "name": "Downloaded File",
        "reason": None
    }

def detect_archive_download(command_line):

    archive = contains_keyword(
        command_line,
        ARCHIVE_PATTERNS
    )

    if archive:
        return {
            "matched": True,
            "name": "Archive Download",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Archive download '{archive}' detected."
        }

    return {
        "matched": False,
        "name": "Archive Download",
        "reason": None
    }


def detect_download_destination(command_line):

    destination = contains_keyword(
        command_line,
        DOWNLOAD_DESTINATIONS
    )

    if destination:
        return {
            "matched": True,
            "name": "Download Destination",
            "category": "Download",
            "severity": "Medium",
            "mitre": ["T1105"],
            "reason": f"Download destination '{destination}' detected."
        }

    return {
        "matched": False,
        "name": "Download Destination",
        "reason": None
    }


# ==========================================================
# main detector
# ==========================================================

def detect_downloads(command_line):

    detections = []

    detectors = [

    detect_download_keywords,
    detect_download_patterns,
    detect_url_patterns,

    detect_curl_patterns,
    detect_wget_patterns,
    detect_bitsadmin_patterns,
    detect_certutil_patterns,

    detect_invoke_webrequest_patterns,
    detect_invoke_restmethod_patterns,
    detect_webclient_patterns,
    detect_webrequest_patterns,

    detect_powershell_downloads,

    detect_downloaded_file,
    detect_output_file,
    detect_download_destination,
    detect_archive_download,

    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
