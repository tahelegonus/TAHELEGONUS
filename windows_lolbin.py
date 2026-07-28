

LOLBIN_PATHS = {

    "rundll32.exe": (
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    ),
      "powershell.exe": {
        r"C:\Windows\System32\WindowsPowerShell\v1.0",
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0",
    },

    "cmd.exe": {
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    },

    "certutil.exe": {
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    },

    "rundll32.exe": {
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    },


}

LOLBIN_EXPECTED_PUBLISHERS = {

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

    "pwsh.exe": {
        "explorer.exe",
        "cmd.exe",
    },

    "cmd.exe": {
        "explorer.exe",
        "powershell.exe",
    },

    "mshta.exe": {
        "explorer.exe",
    },

    "certutil.exe": {
        "explorer.exe",
        "cmd.exe",
    },

}



LOLBIN_MITRE = {

     "powershell.exe": [
        "T1059.001"
    ],

    "cmd.exe": [
        "T1059.003"
    ],

    "wscript.exe": [
        "T1059.005"
    ],

    "cscript.exe": [
        "T1059.005"
    ],

    "bitsadmin.exe": [
        "T1197",
        "T1105"
    ],

    "certutil.exe": [
        "T1105",
        "T1140"
    ],

    "mshta.exe": [
        "T1218.005"
    ],

    "rundll32.exe": [
        "T1218.011"
    ],

    "regsvr32.exe": [
        "T1218.010"
    ],

}
WINDOWS_BUILTIN_LOLBINS = {

    "powershell.exe",
    "cmd.exe",
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "installutil.exe",
    "wmic.exe",

}

WINDOWS_BUILTIN_LOLBINS = {

    "powershell.exe",
    "cmd.exe",
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "installutil.exe",
    "wmic.exe",

}

LOLBIN_SUSPICIOUS_ARGUMENTS = {

    "powershell.exe": {
        "-enc",
        "-encodedcommand",
        "-nop",
        "-windowstyle hidden",
        "invoke-expression",
        "downloadstring",
    },

    "certutil.exe": {
        "-urlcache",
        "-decode",
    },

    "bitsadmin.exe": {
        "/transfer",
    },

    "mshta.exe": {
        "http://",
        "javascript:",
        "vbscript:",
    },

}

THIRD_PARTY_LOLBINS = {

    "psexec.exe",

}

LOLBIN_DATABASE = {

    "powershell.exe": {
        "description": "Windows PowerShell",
        "category": "Scripting",
        "mitre": [
            "T1059.001"
        ],
    },

    "pwsh.exe": {
        "description": "PowerShell Core",
        "category": "Scripting",
        "mitre": [
            "T1059.001"
        ],
    },

    "cmd.exe": {
        "description": "Windows Command Prompt",
        "category": "Shell",
        "mitre": [
            "T1059.003"
        ],
    },

    "certutil.exe": {
        "description": "Certificate Utility",
        "category": "Certificate",
        "mitre": [
            "T1105",
            "T1140"
        ],
    },

    "bitsadmin.exe": {
        "description": "BITS Administration Utility",
        "category": "Download",
        "mitre": [
            "T1105",
            "T1197"
        ],
    },

    "mshta.exe": {
        "description": "Microsoft HTML Application Host",
        "category": "Execution",
        "mitre": [
            "T1218.005"
        ],
    },

    "rundll32.exe": {
        "description": "Windows DLL Execution Utility",
        "category": "Execution",
        "mitre": [
            "T1218.011"
        ],
    },

    "regsvr32.exe": {
        "description": "Register DLL Utility",
        "category": "Execution",
        "mitre": [
            "T1218.010"
        ],
    },

    "regasm.exe": {
        "description": "Assembly Registration Utility",
        "category": "Execution",
        "mitre": [
            "T1218"
        ],
    },

    "installutil.exe": {
        "description": "Microsoft Installer Utility",
        "category": "Execution",
    },

    "msbuild.exe": {
        "description": "Microsoft Build Engine",
        "category": "Compilation",
    },

    "wmic.exe": {
        "description": "Windows Management Instrumentation Command",
        "category": "System Management",
    },

    "schtasks.exe": {
        "description": "Scheduled Task Utility",
        "category": "Persistence",
    },

    "sc.exe": {
        "description": "Service Control Utility",
        "category": "Service Management",
    },

    "wscript.exe": {
        "description": "Windows Script Host",
        "category": "Scripting",
    },

    "cscript.exe": {
        "description": "Command Script Host",
        "category": "Scripting",
    },

    "msiexec.exe": {
        "description": "Windows Installer",
        "category": "Installation",
    },

    "curl.exe": {
        "description": "Command Line Transfer Tool",
        "category": "Download",
    },

    "ftp.exe": {
        "description": "FTP Command Utility",
        "category": "Download",
    },

    "forfiles.exe": {
        "description": "File Selection Utility",
        "category": "Execution",
    },

    "makecab.exe": {
        "description": "Cabinet Creation Utility",
        "category": "Compression",
    },

    "expand.exe": {
        "description": "Cabinet Extraction Utility",
        "category": "Extraction",
    },

    "wevtutil.exe": {
        "description": "Windows Event Utility",
        "category": "Logging",
    },

    "odbcconf.exe": {
        "description": "ODBC Configuration Utility",
        "category": "Execution",
    },

    "cmstp.exe": {
        "description": "Connection Manager Profile Installer",
        "category": "Execution",
    },

}

LOLBIN_EXECUTABLES = set(LOLBIN_DATABASE.keys())
