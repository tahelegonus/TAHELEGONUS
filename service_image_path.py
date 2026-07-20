SERVICE_IMAGE_PATH_PATTERNS = {
    r"\system32\\",
    r"\syswow64\\",
    r"\program files\\",
    r"\program files (x86)\\",
    r"\programdata\\",
    r"\windows\\",
    r"\users\\",
    r"\appdata\\",
    r"\System32",
    r"\SysWOW64",
    r"\Program Files",
    r"\Program Files (x86)",
    r"\Windows",
    r"\ProgramData",
    r"\Services",
    r"\WinSxS",
    r"\System",
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
    r"C:\ProgramData",
    r"C:\Users\Public",
    r"C:\Temp",
    r"C:\Windows\Temp",
    r"\AppData\Local",
    r"\AppData\Roaming",
}


#high risk writeable locations 

WORLD_WRITABLE_SERVICE_PATHS = {
    r"C:\Users\Public",
    r"C:\Windows\Temp",
    r"C:\Temp",
    r"\AppData\Local\Temp",
    r"\Downloads",
    r"\Desktop",
}

#locations commonly abused for service hijacking and perssitance 
COMMON_SERVICE_HIJACK_PATHS = {
    r"\ProgramData",
    r"\Users\Public",
    r"\Windows\Tasks",
    r"\Startup",
    r"\Common Startup",
    r"\AppData\Roaming",
    r"\AppData\Local",
}


SERVICE_EXECUTABLE_PATTERNS = {
    ".exe",
    ".dll",
    ".sys",
}

SERVICE_PATH_KEYWORDS = {
    "system32",
    "syswow64",
    "program files",
    "program files (x86)",
    "programdata",
    "windows",
    "users",
    "public",
    "appdata",
    "temp",
    "startup",
    "tasks",
} 
