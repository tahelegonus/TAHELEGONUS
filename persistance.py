# persistansce command line parameters


RUN_KEY_PATTERNS = {


    "currentversion\\run",
    "currentversion\\runonce",
    "reg add hkcu",
    "reg add hklm"
}

#schduled task persistance (T1053)

SCHTASK_PATTERNS = {


    "schtasks /create",

    "/sc onlogon",
    "/sc onstart",
    "/ru system"
}

PERSISTENCE_KEYWORDS = { 
"currentversion\\run",
"currentversion\\runonce",
"startup",
"schtasks",
"sc create",
"new-service",
"winlogon",
"userinit"

}


POWERSHELL_PATTERNS = {

    "powershell -enc",
    "powershell -nop",
    "powershell invoke-webrequest"

}

#schduled task persistance (T1053)

SCHTASK_PATTERNS = {


    "schtasks /create",

    "/sc onlogon",
    "/sc onstart",
    "/ru system"
}

SCHEDULED_TASK_KEYWORDS = {

    "schtasks",
    "/create",
    "/change",
    "/delete",
    "/sc",
    "/tn",
    "/tr",
    "/ru",
    "/f"

}

SERVICE_PATTERNS = {

    "sc create",

    "sc config",

    "new-service"

}

