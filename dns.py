#providers commonly used for legitamite dynamic dns, and sometimes abused by attackers
#one signal correlation (dont flag by themselves)
DYNAMIC_DNS_PROVIDERS = {

    "duckdns.org",

    "no-ip.com",
    "noip.com",

    "dyndns.org",

    "dynu.com",

    "hopto.org",

    "zapto.org",

    "ddns.net",

    "serveftp.com",

    "myftp.org",

    "sytes.net",

    "freeddns.org",

    "afraid.org",

}
#also needs correlation
COMMON_ABUSED_TLDS = {

    ".xyz",

    ".top",

    ".click",

    ".live",

    ".shop",

    ".online",

    ".site",

    ".icu",

    ".buzz",

    ".rest",

    ".monster",

    ".work",

}


#record types that are encountered msot often


DNS_RECORD_TYPES = {

    "A",

    "AAAA",

    "CNAME",

    "MX",

    "NS",

    "TXT",

    "PTR",

    "SRV",

    "SOA",

    "CAA",

}

#attackers frequently use record types for DNS tunneling to command and control
DNS_TUNNELING_RECORDS = {

    "TXT",

    "NULL",

    "CNAME",

}

