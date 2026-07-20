#identify execution from windows unc netowrk paths 

UNC_PATH_PATTERNS = {

    r"\\",
    r"UNC\\",

}

#admin shares that attackers commonlu abuse 


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
