#common cli synta across many detections 
COMMAND_CHAIN_OPERATORS = {
    "&",
    "&&",
    "||",
    ";"
}

PIPE_OPERATORS = {
    "|"
}

REDIRECTION_OPERATORS = {
    ">",
    ">>",
    "<",
    "2>",
    "2>>",
    "2>&1",
    "1>",
    "1>>"
}


COMMON_ARGUMENT_FLAGS = {
    "/c",
    "/k",
    "/q",
    "/s",
    "-c",
    "-f",
    "-n",
}
