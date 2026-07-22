
# ==========================================================
# keyword libraries
# ==========================================================

#lolbiN command line paramters 
#LOLBin abuse and how they are abused 

LOLBIN_NAMES = {

    "rundll32",
    "regsvr32",
    "mshta",
    "installutil",
    "msbuild",
    "certutil",
    "bitsadmin",
    "forfiles",
    "cmstp",
    "odbcconf",
    "control",
    "hh",
    "desktopimgdownldr",
    "verclsid",
    "regasm",
    "regsvcs",
    "wmic",
    "msiexec",
    "schtasks",
    

}

LOLBIN_EXECUTABLES = {

    "bitsadmin.exe",
    "certutil.exe",
    "cmstp.exe",
    "control.exe",
    "desktopimgdownldr.exe",
    "forfiles.exe",
    "hh.exe",
    "installutil.exe",
    "msbuild.exe",
    "odbcconf.exe",
    "regasm.exe",
    "regsvcs.exe",
    "regsvr32.exe",
    "verclsid.exe",
    "wmic.exe",
    "msiexec.exe",
    "schtasks.exe",
    "rundll32.exe",
    "mshta.exe",
}



RUNDLL32_PATTERNS = {
    "rundll32 javascript:",
    "rundll32 url.dll",
    "rundll32 advpack.dll",
    "rundll32 shell32.dll",
    "rundll32 zipfldr.dll",
    "rundll32 scrobj.dll",
    "rundll32 mshtml",
    "rundll32 printui.dll",
}


REGSVR32_PATTERNS = {

    "regsvr32 /i:http",
    "regsvr32 /i:https",
    "regsvr32 /s",
    "regsvr32 /u",
    "regsvr32 /n",
    "regsvr32 /i:",
    "scrobj.dll",

}


#T1218.005
MSHTA_PATTERNS = {

    "mshta http://",
    "mshta.exe http://",

    "mshta https://",
    "mshta.exe https://",

    "mshta vbscript:",
    "mshta.exe vbscript:",

    "mshta javascript:",
    "mshta.exe javascript:",

    "mshta about:",
    "mshta.exe about:",

    "mshta file://",
    "mshta.exe file://",

    ".hta",

}

MSBUILD_PATTERNS = {
    
    "msbuild /target",
    "msbuild.exe /target",

    "msbuild /property",
    "msbuild.exe /property",

    "msbuild /p:",
    "msbuild.exe /p:",

    "msbuild .csproj",
    "msbuild.exe .csproj",

    "msbuild .proj",
    "msbuild.exe .proj",

}


#T1218.004
INSTALLUTIL_PATTERNS = {

    "installutil /logfile=",
    "installutil.exe /logfile=",

    "installutil /logtoconsole",
    "installutil.exe /logtoconsole",

    "installutil /u",
    "installutil.exe /u",

    "installutil /installstate",
    "installutil.exe /installstate",

}

CERTUTIL_PATTERNS = {

    "certutil -urlcache",
    "certutil.exe -urlcache",

    "certutil -decode",
    "certutil.exe -decode",

    "certutil -decodehex",
    "certutil.exe -decodehex",

    "certutil -encode",
    "certutil.exe -encode",

    "certutil -verifyctl",
    "certutil.exe -verifyctl",

}


BITSADMIN_PATTERNS = {

    "bitsadmin /transfer",
    "bitsadmin.exe /transfer",

    "bitsadmin /create",
    "bitsadmin.exe /create",

    "bitsadmin /addfile",
    "bitsadmin.exe /addfile",

    "bitsadmin /resume",
    "bitsadmin.exe /resume",

    "bitsadmin /complete",
    "bitsadmin.exe /complete",

}


CMSTP_PATTERNS = {
    "cmstp /au",
    "cmstp /ni",
    "cmstp.exe /au",
    "cmstp.exe /ni",
}

ODBCCONF_PATTERNS = {

    "odbcconf /a",
    "odbcconf regsvr",
    "odbcconf.exe /a"
    "odbcconf.exe regsvr"
}


HH_PATTERNS = {

    "hh.exe",
    "hh ",
    ".chm",

}


FORFILES_PATTERNS = {

    "forfiles /c",

}

MSIEXEC_PATTERNS = {

    "msiexec /i",
    "msiexec /q",
    "msiexec /package",
    "msiexec /a",
    "msiexec /x",

}

SCHTASKS_PATTERNS = {

    "schtasks /create",
    "schtasks /run",
    "schtasks /change",
    "schtasks /delete",

}

WMIC_PATTERNS = {

    "wmic process call create",
    "wmic shadowcopy",
    "wmic startup",

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

def detect_lolbin_names(command_line):

    lolbin = contains_keyword(
        command_line,
        LOLBIN_NAMES
    )

    if lolbin:
        return {
            "matched": True,
            "name": "LOLBin",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1218"],
            "reason": f"LOLBin '{lolbin}' detected."
        }

    return {
        "matched": False,
        "name": "LOLBin",
        "reason": None
    }

def detect_lolbin_executables(command_line):

    executable = contains_keyword(
        command_line,
        LOLBIN_EXECUTABLES
    )

    if executable:
        return {
            "matched": True,
            "name": "LOLBin Executable",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1218"],
            "reason": f"LOLBin executable '{executable}' detected."
        }

    return {
        "matched": False,
        "name": "LOLBin Executable",
        "reason": None
    }

def detect_rundll32_abuse(command_line):

    rundll32 = contains_keyword(
        command_line,
        RUNDLL32_PATTERNS
    )

    if rundll32:
        return {
            "matched": True,
            "name": "Rundll32 Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.011"],
            "reason": f"Rundll32 abuse pattern '{rundll32}' detected."
        }

    return {
        "matched": False,
        "name": "Rundll32 Abuse",
        "reason": None
    }

def detect_regsvr32_abuse(command_line):

    regsvr32 = contains_keyword(
        command_line,
        REGSVR32_PATTERNS
    )

    if regsvr32:
        return {
            "matched": True,
            "name": "Regsvr32 Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.010"],
            "reason": f"Regsvr32 abuse pattern '{regsvr32}' detected."
        }

    return {
        "matched": False,
        "name": "Regsvr32 Abuse",
        "reason": None
    }

def detect_mshta_abuse(command_line):

    mshta = contains_keyword(
        command_line,
        MSHTA_PATTERNS
    )

    if mshta:
        return {
            "matched": True,
            "name": "MSHTA Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.005"],
            "reason": f"MSHTA abuse pattern '{mshta}' detected."
        }

    return {
        "matched": False,
        "name": "MSHTA Abuse",
        "reason": None
    }

def detect_msbuild_abuse(command_line):

    msbuild = contains_keyword(
        command_line,
        MSBUILD_PATTERNS
    )

    if msbuild:
        return {
            "matched": True,
            "name": "MSBuild Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1127.001"],
            "reason": f"MSBuild abuse pattern '{msbuild}' detected."
        }

    return {
        "matched": False,
        "name": "MSBuild Abuse",
        "reason": None
    }

def detect_installutil_abuse(command_line):

    installutil = contains_keyword(
        command_line,
        INSTALLUTIL_PATTERNS
    )

    if installutil:
        return {
            "matched": True,
            "name": "InstallUtil Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.004"],
            "reason": f"InstallUtil abuse pattern '{installutil}' detected."
        }

    return {
        "matched": False,
        "name": "InstallUtil Abuse",
        "reason": None
    }


def detect_certutil_abuse(command_line):

    certutil = contains_keyword(
        command_line,
        CERTUTIL_PATTERNS
    )

    if certutil:
        return {
            "matched": True,
            "name": "CertUtil Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1105"],
            "reason": f"CertUtil pattern '{certutil}' detected."
        }

    return {
        "matched": False,
        "name": "CertUtil Abuse",
        "reason": None
    }

def detect_bitsadmin_abuse(command_line):

    bitsadmin = contains_keyword(
        command_line,
        BITSADMIN_PATTERNS
    )

    if bitsadmin:
        return {
            "matched": True,
            "name": "BITSAdmin Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1197"],
            "reason": f"BITSAdmin pattern '{bitsadmin}' detected."
        }

    return {
        "matched": False,
        "name": "BITSAdmin Abuse",
        "reason": None
    }

def detect_cmstp_abuse(command_line):

    cmstp = contains_keyword(
        command_line,
        CMSTP_PATTERNS
    )

    if cmstp:
        return {
            "matched": True,
            "name": "CMSTP Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.003"],
            "reason": f"CMSTP pattern '{cmstp}' detected."
        }

    return {
        "matched": False,
        "name": "CMSTP Abuse",
        "reason": None
    }

def detect_odbcconf_abuse(command_line):

    odbcconf = contains_keyword(
        command_line,
        ODBCCONF_PATTERNS
    )

    if odbcconf:
        return {
            "matched": True,
            "name": "ODBCConf Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1218.008"],
            "reason": f"ODBCConf pattern '{odbcconf}' detected."
        }

    return {
        "matched": False,
        "name": "ODBCConf Abuse",
        "reason": None
    }

def detect_hh_abuse(command_line):

    hh_abuse = contains_keyword(
        command_line,
        HH_PATTERNS
    )

    if hh_abuse:
        return {
            "matched": True,
            "name": "HH Abuse",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1218.001"],
            "reason": f"HH.exe pattern '{hh_abuse}' detected."
        }

    return {
        "matched": False,
        "name": "HH Abuse",
        "reason": None
    }

def detect_forfiles_abuse(command_line):

    forfiles = contains_keyword(
        command_line,
        FORFILES_PATTERNS
    )

    if forfiles:
        return {
            "matched": True,
            "name": "ForFiles Abuse",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1202"],
            "reason": f"ForFiles pattern '{forfiles}' detected."
        }

    return {
        "matched": False,
        "name": "ForFiles Abuse",
        "reason": None
    }

def detect_msiexec_abuse(command_line):

    msiexec = contains_keyword(
        command_line,
        MSIEXEC_PATTERNS
    )

    if msiexec:
        return {
            "matched": True,
            "name": "MSIExec Abuse",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1218.007"],
            "reason": f"MSIExec pattern '{msiexec}' detected."
        }

    return {
        "matched": False,
        "name": "MSIExec Abuse",
        "reason": None
    }

def detect_schtasks_abuse(command_line):

    schtasks = contains_keyword(
        command_line,
        SCHTASKS_PATTERNS
    )

    if schtasks:
        return {
            "matched": True,
            "name": "Scheduled Task",
            "category": "LOLBin",
            "severity": "Medium",
            "mitre": ["T1053.005"],
            "reason": f"Scheduled task pattern '{schtasks}' detected."
        }

    return {
        "matched": False,
        "name": "Scheduled Task",
        "reason": None
    }

def detect_wmic_abuse(command_line):

    wmic = contains_keyword(
        command_line,
        WMIC_PATTERNS
    )

    if wmic:
        return {
            "matched": True,
            "name": "WMIC Abuse",
            "category": "LOLBin",
            "severity": "High",
            "mitre": ["T1047"],
            "reason": f"WMIC pattern '{wmic}' detected."
        }

    return {
        "matched": False,
        "name": "WMIC Abuse",
        "reason": None
    }

# ==========================================================
# main detector
# ==========================================================

def detect_lolbins(command_line):

    detections = []

    detectors = [
        detect_lolbin_names,
        detect_lolbin_executables,
        detect_rundll32_abuse,
        detect_regsvr32_abuse,
        detect_mshta_abuse,
        detect_msbuild_abuse,
        detect_installutil_abuse,
        detect_certutil_abuse,
        detect_bitsadmin_abuse,
        detect_cmstp_abuse,
        detect_odbcconf_abuse,
        detect_hh_abuse,
        detect_forfiles_abuse,
        detect_msiexec_abuse,
        detect_schtasks_abuse,
        detect_wmic_abuse,
        ]

    for detector in detectors:
        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
