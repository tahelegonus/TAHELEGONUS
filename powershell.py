#all powershell command line paramaters 


POWERSHELL_KEYWORDS = {

    "powershell",
    "pwsh",
    "-nop",
    "-noprofile",
    "-ep",
    "-executionpolicy",
    "-windowstyle",
    "-noninteractive",
    "-command",
    "-file",
    -"enc"
}


POWERSHELL_PATTERNS = {

    "powershell -enc",
    "powershell -nop",
    "powershell invoke-webrequest"

}


SUSPICIOUS_POWERSHELL_FUNCTIONS = {

    "invoke-expression",

    "invoke-command",

    "invoke-webrequest",

    "invoke-restmethod",

    "invoke-wmimethod",

    "downloadstring",

    "downloadfile",

    "start-process"

}


#T1059.001
POWERSHELL_EVASION_FLAGS ={

    "-nop",
    "-noprofile",
    "-ep bypass",
    "-executionpolicy bypass",
    "-windowstyle hidden",
    "-w hidden",
    "-noninteractive"
},


POWERSHELL_PATTERNS = {

    "powershell -enc",
    "powershell -nop",
    "powershell invoke-webrequest"

}


#T1027
ENCODED_COMMAND_PATTERNS = {

    "-enc",
    "-encodedcommand",
    "frombase64string",
    "[convert]::frombase64string",
}
