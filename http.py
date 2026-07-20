#user agents commnlu seen in malware, automated tools, or scripting , also needs correlation


SUSPICIOUS_USER_AGENTS = {

    # command line tools
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "python-httpx",

    # powershell
    "powershell",
    "winhttp",

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

COMMON_DOWNLOAD_EXTENSIONS = {

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
