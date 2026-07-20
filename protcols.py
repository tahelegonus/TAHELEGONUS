#common protocols seen all the time 


COMMON_PROTOCOLS = {

    "TCP",

    "UDP",

    "ICMP",

    "ARP",

    "IPv4",

    "IPv6",

    "DNS",

    "DHCP",

    "HTTP",

    "HTTPS",

    "TLS",

    "FTP",

    "SMTP",

    "POP3",

    "IMAP",

    "SNMP",

    "NTP",

    "SMB",

    "LDAP",

    "Kerberos",

    "SSH",

    "RDP",

}


#commonluy abused to bypass monitoring r create covert channels 

TUNNELING_PROTOCOLS = {

    "DNS",

    "ICMP",

    "HTTP",

    "HTTPS",

    "TLS",

    "SSH",

    "SOCKS",

    "GRE",

    "IPsec",

    "L2TP",

    "PPTP",

    "OpenVPN",

    "WireGuard",

}



#protocols used for remote access, admin or remote exectuon


REMOTE_PROTOCOLS = {

    "RDP",

    "SSH",

    "WinRM",

    "VNC",

    "Telnet",

    "SMB",

    "RPC",

    "WMI",

    "RFB",

}

#malware commonlu moves files
FILE_TRANSFER_PROTOCOLS = {

    "FTP",

    "FTPS",

    "SFTP",

    "SCP",

    "SMB",

    "NFS",

    "TFTP",

    "WebDAV",

}


AUTHENTICATION_PROTOCOLS = {

    "Kerberos",

    "NTLM",

    "LDAP",

    "LDAPS",

    "RADIUS",

    "TACACS+",

}
