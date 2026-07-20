WINDOWS_CORE_PROCESSES = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe",
    "conhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "fontdrvhost.exe",
}

EXPECTED_PARENT_PROCESSES = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "cmd.exe",
    "powershell.exe",
}

WINDOWS_USER_PROCESSES = {
    "explorer.exe",
    "SearchHost.exe",
    "StartMenuExperienceHost.exe",
    "ShellExperienceHost.exe",
    "RuntimeBroker.exe",
    "TextInputHost.exe",
    "ApplicationFrameHost.exe",
    "LockApp.exe",
}

WINDOWS_SYSTEM_SERVICES = {
    "services.exe",
    "svchost.exe",
    "lsass.exe",
    "wininit.exe",
    "smss.exe",
    "csrss.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "fontdrvhost.exe",
}

SECURITY_PROCESSES = {
    "lsass.exe",
    "winlogon.exe",
    "wininit.exe",
    "smss.exe",
    "csrss.exe",
    "LogonUI.exe",
}

AV_PROCESSES = {
    "MsMpEng.exe",
    "NisSrv.exe",
    "SenseIR.exe",
    "SenseCE.exe",
    "SenseNdr.exe",
    "SenseSampleUploader.exe",
    "SecurityHealthService.exe",
    "SecurityHealthSystray.exe",
}

BROWSER_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "opera.exe",
    "brave.exe",
}
