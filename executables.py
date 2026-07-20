#windows core executables windows relies on

WINDOWS_SYSTEM_EXECUTABLES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "explorer.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe",
    "conhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "SearchIndexer.exe",
}

WINDOWS_COMMON_INSTALLERS = {
    "msiexec.exe",
    "setup.exe",
    "install.exe",
    "uninstall.exe",
    "update.exe",
    "patch.exe",
}


#legitamate microsoft signed exe that appera in enviorment
SIGNED_WINDOWS_BINARIES = {
    "cmd.exe",
    "powershell.exe",
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "taskhostw.exe",
    "winlogon.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
}


SYSTEM_DLLS = {
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "user32.dll",
    "advapi32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "crypt32.dll",
    "combase.dll",
    "comsvcs.dll",
    "wininet.dll",
    "ws2_32.dll",
    "bcrypt.dll",
}




