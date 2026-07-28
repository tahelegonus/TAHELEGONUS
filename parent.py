EXPECTED_WINDOWS_PROCESS_CHAINS = {

    "smss.exe": {
        "csrss.exe",
        "wininit.exe",
    },

    "wininit.exe": {
        "services.exe",
        "lsass.exe",
    },

    "services.exe": {
        "svchost.exe",
        "spoolsv.exe",
    },

    "winlogon.exe": {
        "userinit.exe",
        "LogonUI.exe",
    },

    "userinit.exe": {
        "explorer.exe",
    },
    

}


EXPECTED_PROCESS_CHILDREN = {
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




EXPECTED_PARENT_PROCESSES = {

    "cmd.exe": {
        "explorer.exe",
        "powershell.exe",
        "pwsh.exe",
        "conhost.exe",
    },

    "powershell.exe": {
        "explorer.exe",
        "cmd.exe",
        "pwsh.exe",
    },

    "pwsh.exe": {
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
    },

    "conhost.exe": {
        "cmd.exe",
        "powershell.exe",
    },

    "notepad.exe": {
        "explorer.exe",
    },

    "calc.exe": {
        "explorer.exe",
    },

    "mspaint.exe": {
        "explorer.exe",
    },

    "chrome.exe": {
        "explorer.exe",
    },

    "msedge.exe": {
        "explorer.exe",
    },

    "firefox.exe": {
        "explorer.exe",
    },

    "explorer.exe": {
        "userinit.exe",
    },

    "svchost.exe": {
        "services.exe",
    },

    "spoolsv.exe": {
        "services.exe",
    },

    "dllhost.exe": {
        "svchost.exe",
        "explorer.exe",
    },

}

WINDOWS_TRUSTED_PARENT_PROCESSES = {

    "smss.exe",

    "wininit.exe",

    "winlogon.exe",

    "services.exe",

    "lsass.exe",

    "csrss.exe",

    "svchost.exe",

    "explorer.exe",

}



EXPECTED_OFFICE_CHILDREN = {

    "winword.exe": {
        "explorer.exe",
    },

    "excel.exe": {
        "explorer.exe",
    },

    "powerpnt.exe": {
        "explorer.exe",
    },

}

EXPECTED_BROWSER_PARENTS = {

    "chrome.exe": {
        "explorer.exe",
    },

    "msedge.exe": {
        "explorer.exe",
    },

    "firefox.exe": {
        "explorer.exe",
    },

}
