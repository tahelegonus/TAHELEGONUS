EXPECTED_PROCESS_CHAINS = {
    "explorer.exe": {
        "cmd.exe",
        "powershell.exe",
        "notepad.exe",
        "calc.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
    },

    "services.exe": {
        "svchost.exe",
        "spoolsv.exe",
    },

    "wininit.exe": {
        "services.exe",
        "lsass.exe",
        "lsm.exe",
    },

    "winlogon.exe": {
        "userinit.exe",
        "LogonUI.exe",
    },

    "userinit.exe": {
        "explorer.exe",
    },

    "svchost.exe": {
        "dllhost.exe",
    },
}

KNOWN_PROCESS_RELATIONSHIPS = {
    "smss.exe": {
        "csrss.exe",
        "wininit.exe",
    },
    "wininit.exe": {
        "services.exe",
        "lsass.exe",
        "lsm.exe",
    },
    "winlogon.exe": {
        "userinit.exe",
    },
    "userinit.exe": {
        "explorer.exe",
    },
    "services.exe": {
        "svchost.exe",
        "spoolsv.exe",
    },
    "explorer.exe": {
        "cmd.exe",
        "powershell.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
    },
}
