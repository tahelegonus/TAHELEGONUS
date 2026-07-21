


# ==========================================================
# keyword libraries
# ==========================================================

POWERSHELL_KEYWORDS = {

    "powershell",
    "pwsh"
}


POWERSHELL_SUSPICIOUS_FUNCTIONS = {

    "invoke-expression",

    "invoke-command",

    "invoke-webrequest",

    "invoke-restmethod",

    "invoke-wmimethod",

    "downloadstring",

    "downloadfile",

    "start-process"

}


#T1059.001
POWERSHELL_EVASION_FLAGS ={

    "-nop",
    "-noprofile",
    "-ep bypass",
    "-executionpolicy bypass",
    "-windowstyle hidden",
    "-w hidden",
    "-noninteractive",
    "-ep",
    "-windowstyle",
    "-noninteractive",
    "-command",
    "-file",
    "-enc"
    
},

#T1027
POWERSHELL_ENCODED_COMMAND_PATTERNS = {

    "-enc",
    "-encodedcommand",
    "frombase64string",
    "[convert]::frombase64string",
}



POWERSHELL_DOWNLOAD_KEYWORDS = {

    "invoke-webrequest",

    "invoke-restmethod",

    "downloadstring",

    "downloadfile",

    "net.webclient",

    "start-bitstransfer",

    "curl",

    "wget"
}

POWERSHELL_EXECUTION_POLICY_KEYWORDS = {

"-executionpolicy bypass",

    "-ep bypass",

    "-executionpolicy unrestricted",

    "-ep unrestricted"
}

POWERSHELL_HIDDEN_WINDOW_KEYWORDS = {

  "-windowstyle hidden",

    "-w hidden"
}

POWERSHELL_DEFENDER_TAMPERING_KEYWORDS = {


    "set-mppreference",

    "add-mppreference",

    "remove-mppreference",

    "disablerealtimemonitoring",

    "disablebehaviormonitoring",

    "disableioavprotection"
}

POWERSHELL_AMSI_BYPASS_KEYWORDS = {

    "amsiutils",

    "amsiinitfailed",

    "amsiscanbuffer",

    "system.management.automation.amsi"

}

POWERSHELL_CREDENTIAL_ACCESS_KEYWORDS = {
 
    "invoke-mimikatz",

    "sekurlsa",

    "lsadump",

    "dumpcreds",

    "get-credential"
}


POWERSHELL_OBFUSCATION_KEYWORDS = {

 "frombase64string",

    "iex",

    "invoke-expression",

    "char[]",

    "join",

    "`",

    "[char]"
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
#powershell command line helper functions 



def detect_powershell_execution(command_line):
    powershell = contains_keyword(
        command_line, POWERSHELL_KEYWORDS
    )
    if powershell:
        return {
            "matched": True,
            "name": "Powershell Execution",
            "category": "Execution",
            "severity": "Low",
            "mitre": ["T1059.001"],
            "reason": f"PowerShell execution keyword '{powershell}' detected."

        }

    return {
        "matched": False,
        "name": "PowerShell Execution",
        "reason": None
    }



def detect_encoded_command(command_line):
    encoded = contains_keyword(
        command_line, POWERSHELL_ENCODED_COMMAND_PATTERNS
        )
    if encoded:

        return {
            "matched": True,
            "name": "Encoded Command",
            "category": "Defense Evasion",
            "severity": "Medium",
            "mitre": ["T1027"],
            "reason": f" PowerShell Encoded Command pattern '{encoded}' detected."
        }

    return {
        "matched": False,
        "name": "Encoded Command",
        "reason": None
    }
             

def detect_download_activity(command_line):
    download = contains_keyword(
        command_line, POWERSHELL_DOWNLOAD_KEYWORDS
    )
    if download:
        return {
            "matched": True,
            "name": "Download Activity",
            "category": "Command and Control",
            "severity": "High",
            "mitre": ["T1105"],
            "reason": f"PowerShell Download Keyword '{download}' detected."
        }

    return {
        "matched": False,
        "name": "Download Activity",
        "reason": None
    }

def detect_hidden_window(command_line):
    hidden_window = contains_keyword(
        command_line, POWERSHELL_HIDDEN_WINDOW_KEYWORDS
    )
    if hidden_window:
        return {
            "matched": True,
            "name": "Hidden Window",
            "category": "Defense Evasion",
            "severity": "Medium",
            "mitre": ["T1564"],
            "reason": f"PowerShell Hidden Window keyword '{hidden_window}' detected."
        }

    return {
        "matched": False,
        "name": "Hidden Window",
        "reason": None
    }


def detect_obfuscation(command_line):
    obfuscation = contains_keyword(
        command_line, POWERSHELL_OBFUSCATION_KEYWORDS
    )
    if obfuscation:
        return {
            "matched": True,
            "name": "Obfuscation",
            "category": "Defense Evasion",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"PowerShell Obfuscation keyword '{obfuscation}' detected."
        }

    return {
        "matched": False,
        "name": "Obfuscation",
        "reason": None
    }

def detect_defender_tampering(command_line):
    defender_tampering = contains_keyword(
        command_line, POWERSHELL_DEFENDER_TAMPERING_KEYWORDS
    )
    if defender_tampering:
        return {
            "matched": True,
            "name": "Defender Tampering",
            "category": "Defense Evasion",
            "severity": "Critical",
            "mitre": ["T1562.001"],
            "reason": f"PowerShell Defender Tampering keyword '{defender_tampering}' detected."
        }

    return {
        "matched": False,
        "name": "Defender Tampering",
        "reason": None
    }

def detect_amsi_bypass(command_line):
    amsi = contains_keyword(
        command_line, POWERSHELL_AMSI_BYPASS_KEYWORDS
    )
    if amsi:
        return {
            "matched": True,
            "name": "AMSI Bypass",
            "category": "Defense Evasion",
            "severity": "Critical",
            "confidence": "High",
            "mitre": ["T1562"],
            "reason": f"PowerShell AMSI Bypass keyword '{amsi}' detected."
        }

    return {
        "matched": False,
        "name": "AMSI Bypass",
        "reason": None
    }

def detect_credential_access(command_line):
    credential= contains_keyword(
        command_line, POWERSHELL_CREDENTIAL_ACCESS_KEYWORDS
    )
    if credential:
        return {
            "matched": True,
            "name": "Credential Access",
            "category": "Credential Access",
            "severity": "Critical",
            "mitre": ["T1003"],
            "reason": f"PowerShell Credential Access keyword '{credential}' detected."
        }

    return {
        "matched": False,
        "name": "Credential Access",
        "reason": None
    }

def detect_evasion_flags(command_line):
    evasion_flags = contains_keyword(
        command_line, POWERSHELL_EVASION_FLAGS
    )
    if evasion_flags:
        return {
            "matched": True,
            "name": "Evasion Flags",
            "category": "Defense Evasion",
            "severity": "Medium",
            "mitre": ["T1059.001"],
            "reason": f"PowerShell Evasion Flags keyword '{evasion_flags}' detected."
        }

    return {
        "matched": False,
        "name": "Evasion Flags",
        "reason": None
    }


def detect_suspicious_function(command_line):
    suspicious_function = contains_keyword(
        command_line, POWERSHELL_SUSPICIOUS_FUNCTIONS
    )
    if suspicious_function:
        return {
            "matched": True,
            "name": "Suspicious Function",
            "category": "Execution",
            "severity": "Medium",
            "mitre": ["T1059.001"],
            "reason": f"PowerShell Suspicious Function '{suspicious_function}' detected."
        }

    return {
        "matched": False,
        "name": "Suspicious Function",
        "reason": None
    }

def detect_execution_policy_bypass(command_line):
    execution_policy = contains_keyword(
        command_line, POWERSHELL_EXECUTION_POLICY_KEYWORDS
    )
    if execution_policy:
        return {
            "matched": True,
            "name": "Execution Policy Bypass",
            "category": "Defense Evasion",
            "severity": "Medium",
            "mitre": ["T1059.001"],
            "reason": f"PowerShell Execution Policy keyword '{execution_policy}' detected."
        }

    return {
        "matched": False,
        "name": "Execution Policy Bypass",
        "reason": None
    }


# ==========================================================
# main detector
# ==========================================================

def detect_powershell(command_line):

    detections = []

    detectors = [

        detect_powershell_execution,
        detect_encoded_command,
        detect_download_activity,
        detect_execution_policy_bypass,
        detect_hidden_window,
        detect_obfuscation,
        detect_defender_tampering,
        detect_credential_access,
        detect_amsi_bypass,
        detect_suspicious_function,
        detect_evasion_flags,

    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
