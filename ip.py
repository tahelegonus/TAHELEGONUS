#RC 1918 private ipv4 addresses

PRIVATE_IP_RANGES = {

    "10.0.0.0/8",

    "172.16.0.0/12",

    "192.168.0.0/16",

}

#traffic that never leaves the local machine
LOOPBACK_ADDRESSES = {

    "127.0.0.0/8",

    "::1",

}
#used for multicasr comms 
MULTICAST_RANGES = {

    "224.0.0.0/4",

    "ff00::/8",

}
#addresses automatically assigne when dhcp FAILS or for local comms
LINK_LOCAL_RANGES = {

    "169.254.0.0/16",

    "fe80::/10",

}
#sprcial broadcast destintions  
BROADCAST_ADDRESSES = {

    "255.255.255.255",

}

#never appear on the public internet, they are used in documentation and examples

DOCUMENTATION_RANGES = {

    "192.0.2.0/24",      # TEST-NET-1

    "198.51.100.0/24",   # TEST-NET-2

    "203.0.113.0/24",    # TEST-NET-3

    "2001:db8::/32",     # IPv6 Documentation

}


RESERVED_IP_RANGES = {

    "0.0.0.0/8",          # "This network"

    "100.64.0.0/10",      # Carrier-grade NAT

    "192.0.0.0/24",

    "240.0.0.0/4",        # Reserved

    "::",

}


