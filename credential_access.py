
# ==========================================================
# keyword libraries
# ==========================================================


#credential access comand line paramters

CREDENTIAL_PATTERNS = {

    "sekurlsa",

    "lsass",

    "comsvcs.dll"

}

LSASS_PATTERNS = {
    "lsass",
    "lsass.exe",
    "sekurlsa",
    "minidump",
    "comsvcs.dll",
    "procdump -ma lsass",
    "procdump64 -ma lsass",
    "rundll32 comsvcs.dll",
    "dumpert",
    "nanodump",
}

#mimkatz patterns T1003

MIMIKATZ_PATTERNS = {
    "mimikatz",
    "privilege::debug",
    "sekurlsa::logonpasswords",
    "sekurlsa::tickets",
    "sekurlsa::ekeys",
    "sekurlsa::pth",
    "lsadump::sam",
    "lsadump::lsa",
    "lsadump::secrets",
    "kerberos::golden",
    "kerberos::ptt",
    "vault::list",
    "token::elevate",
}

#T1003.002
SAM_PATTERNS = {
    "reg save hklm\\sam",
    "reg save hklm\\system",
    "reg save hklm\\security",
    "reg export hklm\\sam",
    "reg export hklm\\system",
    "reg export hklm\\security",
    "hklm\\sam",
    "hklm\\system",
    "hklm\\security",
    "windows\\system32\\config\\sam",
    "windows\\system32\\config\\system",
    "windows\\system32\\config\\security",
}
#DOMAIN CONTROLLERS 
NTDS_PATTERNS = {
    "ntds.dit",
    "esentutl",
    "diskshadow",
    "vssadmin create shadow",
    "wmic shadowcopy",
    "ifm",
}

DPAPI_PATTERNS = {
    "dpapi",
    "dpapi::masterkey",
    "dpapi::cred",
    "masterkey",
    "credhist",
    "protecteddata",
}

KERBEROS_PATTERNS = {
    "kerberos",
    "kerberos::golden",
    "kerberos::silver",
    "kerberos::ptt",
    "kerberos::list",
    "ticket",
    "krbtgt",
    "tgt",
}

CMDKEY_PATTERNS = {
    "cmdkey",
    "cmdkey /list",
    "cmdkey /add",
    "cmdkey /delete",
}

VAULT_PATTERNS = {
    "vaultcmd",
    "vault::list",
    "vault::cred",
    "vault::policy",
    "credential manager",
}

BROWSER_CREDENTIAL_PATTERNS = {
    "login data",
    "cookies",
    "local state",
    "web data",
    "chrome",
    "edge",
    "firefox",
    "browser credentials",
}

RUNAS_PATTERNS = {
    "runas",
    "runas /savecred",
    "/savecred",
}

CREDENTIAL_DUMPING_PATTERNS = {
    "credential",
    "credentials",
    "password",
    "passwords",
    "hash",
    "hashes",
    "hashdump",
    "dump",
    "dumpcreds",
    "creddump",
    "cachedump",
    "logonpasswords",
    "secrets",
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


def detect_credential_dumping(command_line):
    dumping = contains_keyword(
        command_line, CREDENTIAL_DUMPING_PATTERNS
    )
    if dumping:
        return {
            "matched": True,
            "name": "Credential Dumping",
            "category":"Credential Access",
            "severity":"High",
            "mitre": ["T1003"],
            "reason": f" Credential Dumping pattern keyword' {dumping}' detected."
        }

    return {
        "matched": False,
        "name": "Credential Dumping",
        "reason": None
    }


def detect_lsass_patterns(command_line):
    lsass_patterns = contains_keyword(
        command_line, LSASS_PATTERNS
    )
    if lsass_patterns:
        return {
            "matched": True,
            "name": "LSASS Access",
            "category": "Credential Access",
            "severity": "Critical",
            "mitre": ["T1003.001"],
            "reason": f" LSASS Pattern keyword' {lsass_patterns}' detected."
        }

    return {
        "matched": False,
        "name": "LSASS Access",
        "reason": None
    }



def detect_mimikatz_patterns(command_line):
    mimikatz = contains_keyword(
        command_line, MIMIKATZ_PATTERNS
    )
    if mimikatz:
        return {
            "matched": True,
            "name": "Mimikatz Activity",
            "category": "Credential Access",
            "severity": "Critical",
            "mitre": ["T1003"],
            "reason": f" Mimikatz Activity keyword' {mimikatz}' detected."
        }

    return {
        "matched": False,
        "name": "Mimikatz Activity",
        "reason": None
    }

def detect_sam_patterns(command_line):
    sam = contains_keyword(
        command_line, SAM_PATTERNS
    )
    if sam:
        return {
            "matched": True,
            "name": "SAM Database Access",
            "category": "Credential Access",
            "severity": "High",
            "mitre": ["T1003.002"],
            "reason": f" LSASS Pattern' {sam}' detected."
        }

    return {
        "matched": False,
        "name": "SAM Database Access",
        "reason": None
    }

def detect_ntds_patterns(command_line):
    ntds = contains_keyword(
        command_line, NTDS_PATTERNS
    )
    if ntds:
        return {
            "matched": True,
            "name": "NTDS Database Access",
            "category":"Credential Access",
            "severity": "Critical",
            "mitre": ["T1003.003"],
            "reason": f" NTDS Pattern keyword' {ntds}' detected."
        }

    return {
        "matched": False,
        "name": "NTDS Database Access",
        "reason": None
    }

def detect_dpapi_patterns(command_line):
    dpapi = contains_keyword(
        command_line, DPAPI_PATTERNS
    )
    if dpapi:
        return {
            "matched": True,
            "name": "DPAPI Access",
            "category":"Credential Access",
            "severity": "High",
            "mitre": ["T1003"],
            "reason": f" DPAPI Pattern keyword' {dpapi}' detected."
        }

    return {
        "matched": False,
        "name": "DPAPI Access",
        "reason": None
    }

def detect_kerberos_patterns(command_line):
    kerberos = contains_keyword(
        command_line, KERBEROS_PATTERNS
    )
    if kerberos:
        return {
            "matched": True,
            "name": "Kerberos Abuse",
            "category":"Credential Access",
            "severity":"High",
            "mitre": ["T1558"],
            "reason": f" Kerberos Pattern keyword' {kerberos}' detected."
        }

    return {
        "matched": False,
        "name": "Kerberos Abuse",
        "reason": None
    }

def detect_vault_patterns(command_line):
    vault = contains_keyword(
        command_line, VAULT_PATTERNS
    )
    if vault:
        return {
            "matched": True,
            "name": "Credential Vault Access",
            "category":"Credential Access",
            "severity": "High",
            "mitre": ["T1555"],
            "reason": f" Credential Vault Access keyword' {vault}' detected."
        }

    return {
        "matched": False,
        "name": "Credential Vault Access",
        "reason": None
    }

def detect_browser_credential_patterns(command_line):
    browser = contains_keyword(
        command_line, BROWSER_CREDENTIAL_PATTERNS
    )
    if browser:
        return {
            "matched": True,
            "name": "Browser Credential Access",
            "category":"Credential Access",
            "severity": "Medium",
            "mitre": ["T1555"],
            "reason": f" Browser Credential keyword' {browser}' detected."
        }

    return {
        "matched": False,
        "name": "Browser Credential Access",
        "reason": None
    }

def detect_runas_patterns(command_line):
    runas = contains_keyword(
        command_line, RUNAS_PATTERNS
    )
    if runas:
        return {
            "matched": True,
            "name": "RunAs Credential Usage",
            "category":"Credential Access",
            "severity": "Medium",
            "mitre": ["T1550"],
            "reason": f" RunAs Credential Usage keyword' {runas}' detected."
        }

    return {
        "matched": False,
        "name":"RunAs Credential Usage",
        "reason": None
    }

def detect_cmdkey_patterns(command_line):
    cmdkey = contains_keyword(
        command_line, CMDKEY_PATTERNS
    )
    if cmdkey:
        return {
            "matched": True,
            "name": "CmdKey Usage",
            "category":"Credential Access",
            "severity": "Medium",
            "mitre": ["T1555"],
            "reason": f" CmdKey Usage keyword' {cmdkey}' detected."
        }

    return {
        "matched": False,
        "name": "CmdKey Usage",
        "reason": None
    }


# ==========================================================
# main detector
# ==========================================================

def detect_credential_access(command_line):

    detections = []

    detectors = [

    detect_credential_dumping,
    detect_lsass_patterns,
    detect_sam_patterns,
    detect_ntds_patterns,
    detect_dpapi_patterns,
    detect_kerberos_patterns,
    detect_cmdkey_patterns,
    detect_vault_patterns,
    detect_browser_credential_patterns,
    detect_runas_patterns,
    detect_mimikatz_patterns
    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
