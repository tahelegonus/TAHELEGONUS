
#execution command line parameters
COMMAND_SHELL_KEYWORDS = {

    "cmd.exe",

    "/c",

    "/k",

    "&&",

    "||",

    "|"

}


FILE_OPERATION_KEYWORDS = {

    "copy",

    "move",

    "del",

    "erase",

    "rename",

    "attrib",

    "xcopy",

    "robocopy"

}

WMI_KEYWORDS = {

    "wmic",
    "win32_process",
    "process call create",
    "wmic process",
    "invoke-wmimethod",
    "get-wmiobject",
    "wmic process call create"
}


WMI_PATTERNS = {

    "wmic process call create",

    "wmic shadowcopy",

    "invoke-wmimethod"

}

NETWORK_KEYWORDS = {

    "http://",
    "https://",
    "ftp://",
    "\\\\",
    ".com",
    ".net",
    ".org",
    "webclient",
    "\\server\share"
}
