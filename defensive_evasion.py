
# ==========================================================
# keyword libraries
# ==========================================================


#defense evasion command line parameters




DEFENDER_TAMPERING = {

    "set-mppreference",
    "add-mppreference",
    "remove-mppreference",
    "-disablerealtimemonitoring",
    "-disablebehaviormonitoring",
    "-disableioavprotection",
    "-disablescriptscanning",
    "-disablearchiveScanning",
    "-disableintrusionpreventionsystem",
    "disableantispyware"

}


DEFENDER_EXCLUSION_PATTERNS = {

    "exclusionpath",
    "exclusionprocess",
    "exclusionextension",
    "add-mppreference -exclusionpath",
    "add-mppreference -exclusionprocess",
    "add-mppreference -exclusionextension"

}

AMSI_BYPASS_PATTERNS = {

    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "system.management.automation.amsi",
    "bypass-amsi"

}

LOG_CLEARING_PATTERNS = {

    "wevtutil cl",
    "clear-eventlog",
    "remove-eventlog",
    "eventvwr"

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


def detect_defender_tampering(command_line):
        defender_tampering = contains_keyword(
        command_line, DEFENDER_TAMPERING
        )
        if defender_tampering:
            return {
                "matched": True,
                "name": "Defender Tampering",
                "category": "Defensive Evasion",
                "severity": "Critical",
                "mitre": ["T1562.001"],
                "reason": f"Defender Tampering keyword '{defender_tampering}' detected."

        }

        return {
            "matched": False,
            "name": "Defender Tampering",
            "reason": None
        }


def detect_defender_exclusions(command_line):
    defender_exclusions = contains_keyword(
    command_line, DEFENDER_EXCLUSION_PATTERNS
    )
    if defender_exclusions:
        return {
            "matched": True,
            "name": "Defender Exclusions",
            "category": "Defensive Evasion",
            "severity": "High",
            "mitre": ["T1562.001"],
            "reason": f"Defender Exclusion keyword '{defender_exclusions}' detected."

    }

    return {
        "matched": False,
        "name": "Defender Exclusions",
        "reason": None
        }


def detect_amsi_bypass(command_line):
    amsi_bypass = contains_keyword(
    command_line, AMSI_BYPASS_PATTERNS
    )
    if amsi_bypass:
        return {
            "matched": True,
            "name": "AMSI Bypass",
            "category": "Defensive Evasion",
            "severity": "Crtical",
            "mitre": ["T1562"],
            "reason": f"AMSI Bypass keyword '{amsi_bypass}' detected."
    }

    return {
        "matched": False,
        "name": "AMSI Bypass",
        "reason": None
        }



def detect_log_clearing(command_line):
    log_clearing = contains_keyword(
    command_line, LOG_CLEARING_PATTERNS
    )
    if log_clearing:
        return {
            "matched": True,
            "name":"Log Clearing",
            "category": "Defensive Evasion",
            "severity": "High",
            "mitre": ["T0170.001"],
            "reason": f"Log Clearing keyword '{log_clearing}' detected."
    }

    return {
        "matched": False,
        "name": "Log Clearing",
        "reason": None
        }


# ==========================================================
# main detector
# ==========================================================

def detect_defense_evasion(command_line):

    detections = []

    detectors = [

        detect_defender_tampering,
        detect_defender_exclusions,
        detect_amsi_bypass,
        detect_log_clearing,

    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
