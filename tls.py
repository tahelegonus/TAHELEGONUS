


#versions that are deprecated or generally should not be seen on moddern systems 


WEAK_TLS_VERSIONS = {

    "SSL 2.0",

    "SSL 3.0",

    "TLS 1.0",

    "TLS 1.1",

}

#most common ports that carrt TLS encrypted traffic 
TLS_PORTS = {

    443,    # HTTPS

    465,    # SMTPS

    563,    # NNTPS

    636,    # LDAPS

    853,    # DNS over TLS

    989,    # FTPS Data

    990,    # FTPS Control

    992,    # TelnetS

    993,    # IMAPS

    995,    # POP3S

    8443,   # Alternate HTTPS

}


TLS_CIPHER_KEYWORDS = {

    "RC4",

    "DES",

    "3DES",

    "NULL",

    "EXPORT",

    "MD5",

}
