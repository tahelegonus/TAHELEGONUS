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
    "runtimebrocker.exe",
    "runtimebroker32.exe",

    # dllhost
    "dlhost.exe",
    "dllh0st.exe",

    # smss
    "smsss.exe",
    "smss.exe",

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

    "searchhost.exe",
    "searchhost32.exe",

    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",

    "runtimebroker.exe",
    "runtimebrokerr.exe",

    "fontdrvhost32.exe",

    "dllhost32.exe",

    "wmiprvse1.exe",
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

    "\u200B",   # Zero Width Space
    "\u200C",   # Zero Width Non-Joiner
    "\u200D",   # Zero Width Joiner
    "\u2060",   # Word Joiner
    "\uFEFF",   # Zero Width No-Break Space

    "\u202E",   # Right-to-Left Override
    "\u202D",   # Left-to-Right Override
    "\u202A",
    "\u202B",
    "\u202C",

}


SUSPICIOUS_FILENAME_PATTERNS = {

    "update.exe",
    "patch.exe",
    "installer.exe",
    "setup.exe",

    "document.exe",
    "invoice.exe",
    "receipt.exe",
    "payment.exe",

    "scan.exe",
    "report.exe",
    "statement.exe",

    "chrome_update.exe",
    "windows_update.exe",
    "adobe_update.exe",

    "security_update.exe",
    "office_update.exe",

    "temp.exe",
    "tmp.exe",
    "new.exe",
    "copy.exe",
    "backup.exe",

    "crack.exe",
    "keygen.exe",
    "loader.exe",
    "injector.exe",
    "stub.exe",
    "dropper.exe",

    "license.exe",
    "activation.exe",
    "unlock.exe",

    "invoice_2025.exe",
    "resume2025.exe",

    "scanner.exe",
    "update_service.exe",

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
