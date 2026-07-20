SUSPICIOUS_PARENT_RELATIONSHIPS = {

    ("winword.exe", "powershell.exe"),

    ("excel.exe", "cmd.exe"),

    ("outlook.exe", "powershell.exe"),

    ("powerpnt.exe", "cmd.exe"),

    ("chrome.exe", "powershell.exe"),

    ("firefox.exe", "cmd.exe"),

    ("services.exe", "powershell.exe"),

}

SUSPICIOUS_PARENT_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "psexec.exe",
}
