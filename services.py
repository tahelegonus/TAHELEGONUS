KNOWN_SERVICE_NAMES = {
    "AeLookupSvc",
    "AppIDSvc",
    "Appinfo",
    "AudioSrv",
    "BITS",
    "CryptSvc",
    "DcomLaunch",
    "Dhcp",
    "Dnscache",
    "EventLog",
    "LanmanServer",
    "LanmanWorkstation",
    "MpsSvc",
    "PlugPlay",
    "RpcSs",
    "SamSs",
    "Schedule",
    "Spooler",
    "TermService",
    "Themes",
    "TrustedInstaller",
    "WinDefend",
    "W32Time",
    "WSearch",
    "wuauserv",
}

#built in accounts that legitmate services commonly run under 
DEFAULT_SERVICE_ACCOUNTS = {
    "LocalSystem",
    "Local Service",
    "Network Service",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
}

SERVICE_START_TYPES = {
    "Automatic",
    "Automatic (Delayed Start)",
    "Manual",
    "Disabled",
    "Boot",
    "System",
}

KNOWN_SERVICE_PATHS = {
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
}


##SERVICE_DLL_PATHS

##SERVICE_REGISTRY_KEYS

##CRITICAL_WINDOWS_SERVICES

##PROTECTED_SERVICES

##SERVICE_FAILURE_ACTIONS

##SERVICE_DEPENDENCIES

##SERVICE_EXECUTABLES




