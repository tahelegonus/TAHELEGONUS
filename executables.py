#windows core executables windows relies on

WINDOWS_SYSTEM_EXECUTABLES = {

    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "conhost.exe",
    "dllhost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "dwm.exe",
    "spoolsv.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    "audiodg.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wuauclt.exe",
    "trustedinstaller.exe",
    "sihost.exe",
    "logonui.exe",
    "userinit.exe",
    "consent.exe",
    "werfault.exe",
    "notepad.exe",
    "calc.exe",

}

WINDOWS_EXECUTABLE_EXTENSIONS = {

    ".exe",

    ".dll",

    ".sys",

    ".com",

    ".scr",

    ".cpl",

    ".ocx",

    ".drv",

    ".efi",

    ".mui",

}


WINDOWS_SYSTEM_EXECUTABLES.update({

    "taskmgr.exe",
    "control.exe",
    "mmc.exe",
    "eventvwr.exe",
    "compmgmtlauncher.exe",
    "fodhelper.exe",
    "cleanmgr.exe",
    "mobsync.exe",
    "dxdiag.exe",
    "verclsid.exe",

})

WINDOWS_COMMON_INSTALLERS = {

    "msiexec.exe",
    "setup.exe",
    "install.exe",
    "uninstall.exe",
    "update.exe",
    "patch.exe",

    "installutil.exe",
    "appinstaller.exe",

}


#legitamate microsoft signed exe that appera in enviorment
SIGNED_WINDOWS_BINARIES = {

    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",

    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "winlogon.exe",

    "rundll32.exe",
    "regsvr32.exe",
    "reg.exe",
    "mshta.exe",
    "msiexec.exe",

    "certutil.exe",
    "bitsadmin.exe",
    "wscript.exe",
    "cscript.exe",

    "net.exe",
    "netsh.exe",
    "ping.exe",
    "ipconfig.exe",

    "schtasks.exe",
    "sc.exe",
    "wevtutil.exe",
    "wmic.exe",

}
SYSTEM_DLLS = {

    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",

    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",

    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",

    "crypt32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",

    "wininet.dll",
    "winhttp.dll",
    "urlmon.dll",
    "ws2_32.dll",

    "rpcrt4.dll",
    "dnsapi.dll",
    "netapi32.dll",

    "secur32.dll",
    "samlib.dll",

    "combase.dll",
    "comsvcs.dll",

}

COMMON_SERVICE_EXECUTABLES = {

    "svchost.exe",
    "services.exe",

    "lsass.exe",
    "spoolsv.exe",

    "searchindexer.exe",

    "msmpeng.exe",
    "sense.exe",
    "securityhealthservice.exe",

}

COMMON_USER_APPLICATIONS = {

    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "opera.exe",
    "brave.exe",

    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",

    "teams.exe",

    "notepad.exe",
    "calc.exe",
    "mspaint.exe",

    "vlc.exe",
    "spotify.exe",

    "discord.exe",
    "slack.exe",

    "onedrive.exe",
    "dropbox.exe",
    "acrobat.exe",
    "acrord32.exe",
    "steam.exe",
    "zoom.exe",
     "obs64.exe",

}

COMMON_DEVELOPMENT_EXECUTABLES = {

    "code.exe",
    "devenv.exe",

    "dotnet.exe",

    "msbuild.exe",

    "git.exe",

    "python.exe",
    "pythonw.exe",

    "java.exe",
    "javac.exe",

    "node.exe",
    "npm.exe",

    "gcc.exe",
    "clang.exe",
    "python3.exe",
    "pip.exe",
    "pip3.exe",
    "cargo.exe",
    "rustc.exe",
    "go.exe",
    "make.exe",
    "cmake.exe",

}

COMMON_NETWORK_EXECUTABLES = {

    "ping.exe",
    "tracert.exe",
    "ipconfig.exe",
    "net.exe",
    "net1.exe",
    "netsh.exe",
    "ap.exe",
    "route.exe",
    "nslookup.exe",
    "ftp.exe",
    "tftp.exe",
    "curl.exe",
    "wget.exe",
    "telnet.exe",
    "netstat.exe",
    "pathping.exe",
    "hostname.exe",
    "whoami.exe",
    "nbtstat.exe",
    "arp.exe",
    "route.exe",
    "netstat.exe",
    "pathping.exe",
    "nbtstat.exe",
    "hostname.exe",
    "whoami.exe",

}

