#ports commonly used by attackers for remote admin and lateral movement 

REMOTE_ADMIN_PORTS = {

    22,     # SSH

    23,     # Telnet

    3389,   # RDP

    5900,   # VNC

    5901,

    5902,

    5985,   # WinRM HTTP

    5986,   # WinRM HTTPS

}



REMOTE_ADMIN_PORTS = {

    22,     # SSH

    23,     # Telnet

    3389,   # RDP

    5900,   # VNC

    5901,

    5902,

    5985,   # WinRM HTTP

    5986,   # WinRM HTTPS

}


DATABASE_PORTS = {

    1433,   # Microsoft SQL Server

    1434,

    1521,   # Oracle

    3306,   # MySQL

    5432,   # PostgreSQL

    6379,   # Redis

    27017,  # MongoDB

    9042,   # Cassandra

}

WEB_PORTS = {

    80,

    443,

    8080,

    8081,

    8000,

    8443,

    8888,

}

#ports that frequently apear in malware, exploitation or lateral movement 
HIGH_RISK_PORTS = {

    135,     # RPC

    137,

    138,

    139,

    445,     # SMB

    1433,    # MSSQL

    3389,    # RDP

    4444,    # Metasploit default

    5555,

    6666,

    6667,

    9001,

    9050,    # Tor

    1080,    # SOCKS Proxy

}


SYSTEM_PORTS = {

    range(0, 1024)
}
#phising investigations and malware delivery 
EMAIL_PORTS = {

    25,     # SMTP

    110,    # POP3

    143,    # IMAP

    465,    # SMTPS

    587,    # Submission

    993,    # IMAPS

    995,    # POP3S

}
