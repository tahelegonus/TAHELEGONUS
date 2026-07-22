
# ==========================================================
# keyword libraries
# ==========================================================

# run keys (T1547.001)
RUN_KEY_PATTERNS = {

    "currentversion\\run",
    "currentversion\\runonce",
    "reg add hkcu",
    "reg add hklm",
    "reg.exe add",
    "reg.exe add hkcu",
    "reg.exe add hklm",
}

# scheduled tasks (T1053.005)
SCHTASK_PATTERNS = {

    "schtasks /create",
    "/sc onlogon",
    "/sc onstart",
    "/sc daily",
    "/sc minute",
    "/ru system",
    "/sc once",
}

# services (T1543.003)
SERVICE_PATTERNS = {

    "sc create",
    "sc config",
    "new-service",
    "set-service",
    "start= auto",
    "start= demand",
}

# startup folder
STARTUP_PATTERNS = {

    "\\startup\\",
    "shell:startup",
    "common startup",
    "startup\\"
}

# Winlogon Persistence
WINLOGON_PATTERNS = {

    "currentversion\\winlogon",
    "userinit",
    "notify",
}

#schduled task persistance (T1053)
SCHTASK_ARGUMENTS = {

    "/create",
    "/change",
    "/delete",
    "/sc",
    "/tn",
    "/tr",
    "/ru",
    "/f",
    "/xml",
    "/mo",

}

#event subscription (T1546.003)
WMI_PERSISTENCE_PATTERNS = {

    "wmic /namespace:\\\\root\\subscription",

    "__eventfilter",
    "__eventconsumer",
    "__filtertoconsumerbinding",

    "set-wmiinstance",
    "new-ciminstance",

    "commandlineeventconsumer",
    "activescripteventconsumer",

    "register-wmievent",


}


#image file exe (T1546.012)
IFEO_PATTERNS = {
    "\\image file execution options\\",
    "debugger",
    "silentprocessexit",
    "globalflag",
    "reg add hklm\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
    "reg add hkcu\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
    "reg.exe add",

}

#logon scripts (T1037)
LOGON_SCRIPT_PATTERNS = {

    "gpupdate /force",
    "scripts\\logon",
    "scripts\\startup",
    "\\netlogon\\",
    "user logon script",
    "gpedit.msc",


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
def detect_run_key_persistence(command_line):

    run_key = contains_keyword(
        command_line,
        RUN_KEY_PATTERNS
    )

    if run_key:
        return {
            "matched": True,
            "name": "Run Key Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1547.001"],
            "reason": f"Run key persistence pattern '{run_key}' detected."
        }

    return {
        "matched": False,
        "name": "Run Key Persistence",
        "reason": None
    }

def detect_schtask_persistence(command_line):

    schtask = contains_keyword(
        command_line,
        SCHTASK_PATTERNS
    )

    if schtask:
        return {
            "matched": True,
            "name": "Scheduled Task Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1053.005"],
            "reason": f"Scheduled task persistence pattern '{schtask}' detected."
        }

    return {
        "matched": False,
        "name": "Scheduled Task Persistence",
        "reason": None
    }

#checks for schtasks 
def detect_schtask_arguments(command_line):

    command = command_line.lower()

    if "schtasks" not in command:
        return {
            "matched": False,
            "name": "Scheduled Task Arguments",
            "reason": None
        }

    argument = contains_keyword(
        command_line,
        SCHTASK_ARGUMENTS
    )

    if argument:
        return {
            "matched": True,
            "name": "Scheduled Task Arguments",
            "category": "Persistence",
            "severity": "Medium",
            "mitre": ["T1053.005"],
            "reason": f"Scheduled task argument '{argument}' detected."
        }

    return {
        "matched": False,
        "name": "Scheduled Task Arguments",
        "reason": None
    }

def detect_service_persistence(command_line):

    service = contains_keyword(
        command_line,
        SERVICE_PATTERNS
    )

    if service:
        return {
            "matched": True,
            "name": "Service Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1543.003"],
            "reason": f"Service persistence pattern '{service}' detected."
        }

    return {
        "matched": False,
        "name": "Service Persistence",
        "reason": None
    }

def detect_startup_persistence(command_line):

    startup = contains_keyword(
        command_line,
        STARTUP_PATTERNS
    )

    if startup:
        return {
            "matched": True,
            "name": "Startup Folder Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1547.001"],
            "reason": f"Startup folder pattern '{startup}' detected."
        }

    return {
        "matched": False,
        "name": "Startup Folder Persistence",
        "reason": None
    }

def detect_winlogon_persistence(command_line):

    winlogon = contains_keyword(
        command_line,
        WINLOGON_PATTERNS
    )

    if winlogon:
        return {
            "matched": True,
            "name": "Winlogon Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1547.004"],
            "reason": f"Winlogon persistence pattern '{winlogon}' detected."
        }

    return {
        "matched": False,
        "name": "Winlogon Persistence",
        "reason": None
    }

def detect_wmi_persistence(command_line):

    wmi = contains_keyword(
        command_line,
        WMI_PERSISTENCE_PATTERNS
    )

    if wmi:
        return {
            "matched": True,
            "name": "WMI Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1546.003"],
            "reason": f"WMI persistence pattern '{wmi}' detected."
        }

    return {
        "matched": False,
        "name": "WMI Persistence",
        "reason": None
    }

def detect_ifeo_persistence(command_line):

    ifeo = contains_keyword(
        command_line,
        IFEO_PATTERNS
    )

    if ifeo:
        return {
            "matched": True,
            "name": "IFEO Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1546.012"],
            "reason": f"IFEO persistence pattern '{ifeo}' detected."
        }

    return {
        "matched": False,
        "name": "IFEO Persistence",
        "reason": None
    }

def detect_logon_script_persistence(command_line):

    logon_script = contains_keyword(
        command_line,
        LOGON_SCRIPT_PATTERNS
    )

    if logon_script:
        return {
            "matched": True,
            "name": "Logon Script Persistence",
            "category": "Persistence",
            "severity": "High",
            "mitre": ["T1037"],
            "reason": f"Logon script persistence pattern '{logon_script}' detected."
        }

    return {
        "matched": False,
        "name": "Logon Script Persistence",
        "reason": None
    }


# ==========================================================
# main detector
# ==========================================================

def detect_persistence(command_line):

    detections = []

    detectors = [

        detect_run_key_persistence,
        detect_schtask_persistence,
        detect_schtask_arguments,
        detect_service_persistence,
        detect_startup_persistence,
        detect_winlogon_persistence,
        detect_wmi_persistence,
        detect_ifeo_persistence,
        detect_logon_script_persistence,


    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
