#obfuscation command line parameters


OBFUSCATION_KEYWORDS = {


    "^",
    "'",
    "$(",
    "${",
    "%%",
    "!",
    "char",
    "join",
    "iex",
    "invoke-expression",
    "FromBase64String",
    "[char]",


}

OBFUSCATION_PATTERNS = {

    "invoke-expression",

    "iex(",

    "frombase64string",

    "[char]",

    "[convert]::frombase64string"

}
