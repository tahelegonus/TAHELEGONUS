LOLBIN_EXECUTABLES = {
    "powershell.exe": {
        "description": "Windows PowerShell",
        "category": "Scripting",
    },

    "cmd.exe": {
        "description": "Windows Command Prompt",
        "category": "Shell",
    },

    "certutil.exe": {
        "description": "Certificate Utility",
        "category": "Certificate",
    },

    "bitsadmin.exe": {
        "description": "BITS Administration Utility",
        "category": "Download",
    },

    "mshta.exe": {
        "description": "Microsoft HTML Application Host",
        "category": "Execution",
    },

    "rundll32.exe": {
        "description": "Run DLL Utility",
        "category": "Execution",
    },

    "regsvr32.exe": {
        "description": "Register DLL Utility",
        "category": "Execution",
    },
}


# windows/lolbins.py

LOLBIN_EXECUTABLES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "installutil.exe",
    "msbuild.exe",
    "wmic.exe",
    "schtasks.exe",
    "forfiles.exe",
    "reg.exe",
    "sc.exe",
    "curl.exe",
    "ftp.exe",
    "net.exe",
    "net1.exe",
    "msiexec.exe",
    "wscript.exe",
    "cscript.exe",
}


LOLBIN_PATHS = {

    "powershell.exe": (
        r"C:\Windows\System32\WindowsPowerShell\v1.0",
    ),

    "cmd.exe": (
        r"C:\Windows\System32",
    ),

    "certutil.exe": (
        r"C:\Windows\System32",
    ),

    "rundll32.exe": (
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    ),

}


LOLBIN_SIGNATURES = {

    "powershell.exe": "Microsoft Windows",

    "cmd.exe": "Microsoft Windows",

    "certutil.exe": "Microsoft Windows",

    "bitsadmin.exe": "Microsoft Windows",

}


LOLBIN_DEFAULT_PARENTS = {

    "powershell.exe": {
        "explorer.exe",
        "cmd.exe",
        "pwsh.exe",
    },

    "cmd.exe": {
        "explorer.exe",
        "powershell.exe",
    },

    "mshta.exe": {
        "explorer.exe",
    },

}


LOLBIN_PURPOSE = {

    "powershell.exe": "Automation",

    "cmd.exe": "Command Interpreter",

    "bitsadmin.exe": "File Transfer",

    "certutil.exe": "Certificate Management",

    "mshta.exe": "HTML Applications",

}

