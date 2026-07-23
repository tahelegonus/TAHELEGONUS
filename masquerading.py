
# ==========================================================
# keywords
# ==========================================================

FAKE_WINDOWS_NAMES = {
    # svchost
    "svch0st.exe",
    "svchosts.exe",
    "svhost.exe",
    "scvhost.exe",
    "svcchost.exe",
    "svchost32.exe",
    # lsass
    "lsasss.exe",
    "1sass.exe",
    "isass.exe",
    "lsaas.exe",
    "lsass32.exe",
    # explorer
    "expl0rer.exe",
    "explorrer.exe",
    "explorer32.exe",
    "explore.exe",
    "explorer .exe",
    # services
    "service.exe",
    "servicess.exe",
    "servlces.exe",
    "servicess.exe",
    # winlogon
    "winlog0n.exe",
    "winlogonn.exe",
    "wlnlogon.exe",
    # csrss
    "csrsss.exe",
    "csrss32.exe",
    "crss.exe",
    # spoolsv
    "spo0lsv.exe",
    "spoolsvc.exe",
    "spoolss.exe",
    # taskhost
    "taskhost32.exe",
    "taskhostw32.exe",
    "taskh0st.exe",
    # runtimebroker
    "runtimebroker32.exe",
    # dllhost
    "dlhost.exe",
    "dllh0st.exe",
    # smss
    "smsss.exe",
    # conhost
    "conh0st.exe",
    "conhost32.exe",
    # wmiprvse
    "wmiprvse.exe",
    "wmiprvse32.exe",
    # generic
    "chromee.exe",
    "firefoxx.exe",
    "msteamss.exe",
    "outlookk.exe",
    "onedrivee.exe",
    "searchhost32.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "runtimebrocker.exe",
    "fontdrvhost32.exe",
    "dllhost32.exe",
}
COMMON_MISSPELLINGS = {
    "svhost",
    "scvhost",
    "svch0st",
    "isass",
    "1sass",
    "lsaas",
    "expl0rer",
    "explorrer",
    "servlces",
    "servicess",
    "winlog0n",
    "wlnlogon",
    "csrsss",
    "taskh0st",
    "dllh0st",
    "runtimebrocker",
    "spo0lsv",
    "runtimebrokerr",
    "searchhost",
    "dllhost32",
    "wmiprvse1",
}
HIDDEN_CHARACTER_PATTERNS = {
    "\u200B",   # zero Width space
    "\u200C",   # zero width non-joiner
    "\u200D",   # zero width joiner
    "\u2060",   # word joiner
    "\uFEFF",   # zero width no-break space
    "\u202E",   # right-to-left override
    "\u202D",   # left-to-right override
    "\u202A",
    "\u202B",
    "\u202C",
}

LOOKALIKE_CHARACTERS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
}
# ==========================================================
# helper functions
# ==========================================================
#keyword matcher helper 

def contains_keyword(image_path, keywords):

    command = image_path.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None
# ==========================================================
# individual detections
# ==========================================================


def detect_fake_windows_name(image_path):
    fake_windows = contains_keyword(
        image_path,
        FAKE_WINDOWS_NAMES
    )

    if fake_windows:
        return {
            "matched": True,
            "name": "Fake Windows Filename",
            "category": "Image Path",
            "severity": "Critical",
            "mitre": ["T1036.005"],
            "reason": f"Masquerading filename '{fake_windows}' detected."
        }

    return {
        "matched": False,
        "name": "Fake Windows Filename",
        "reason": None
    }

def detect_common_misspelling(image_path):
    misspelling = contains_keyword(
        image_path,
        COMMON_MISSPELLINGS
    )

    if misspelling:
        return {
            "matched": True,
            "name": "Common Misspelling",
            "category": "Image Path",
            "severity": "Critical",
            "mitre": ["T1036"],
            "reason": f"Common misspelling '{misspelling}' detected."
        }

    return {
        "matched": False,
        "name": "Common Misspelling",
        "reason": None
    }

def detect_hidden_unicode(image_path):
    unicode_character = contains_keyword(
        image_path,
        HIDDEN_CHARACTER_PATTERNS
    )

    if unicode_character:
        return {
            "matched": True,
            "name": "Hidden Unicode Characters",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1036"],
            "reason": f"Hidden Unicode character detected."
        }

    return {
        "matched": False,
        "name": "Hidden Unicode Characters",
        "reason": None
    }


def detect_lookalike_filename(image_path):
    lookalike = contains_keyword(
        image_path,
        LOOKALIKE_CHARACTERS
    )

    if lookalike:
        return {
            "matched": True,
            "name": "Lookalike Filename",
            "category": "Image Path",
            "severity": "Medium",
            "mitre": ["T1036"],
            "reason": f"Lookalike character '{lookalike}' detected."
        }

    return {
        "matched": False,
        "name": "Lookalike Filename",
        "reason": None
    }

# ==========================================================
# main detector
# ==========================================================
def detect_filenames(image_path):

    detections = []

    detectors = [


    detect_fake_windows_name,
    detect_common_misspelling,
    detect_hidden_unicode,
    detect_lookalike_filename,
    ]

    for detector in detectors:

            result = detector(image_path)

            if result["matched"]:
                detections.append(result)

    return detections


