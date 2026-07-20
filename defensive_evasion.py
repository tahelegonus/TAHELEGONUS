#credential access comand line paramters

CREDENTIAL_PATTERNS = {

    "sekurlsa",

    "lsass",

    "comsvcs.dll"

}

LSASS_PATTERNS = {
    "lsass",
    "lsass.exe",
    "sekurlsa",
    "minidump",
    "comsvcs.dll",
    "procdump -ma lsass",
    "procdump64 -ma lsass",
    "rundll32 comsvcs.dll",
    "dumpert",
    "nanodump",
}

#mimkatz patterns T1003

MIMIKATZ_PATTERNS = {
    "mimikatz",
    "privilege::debug",
    "sekurlsa::logonpasswords",
    "sekurlsa::tickets",
    "sekurlsa::ekeys",
    "sekurlsa::pth",
    "lsadump::sam",
    "lsadump::lsa",
    "lsadump::secrets",
    "kerberos::golden",
    "kerberos::ptt",
    "vault::list",
    "token::elevate",
}

#T1003.002
SAM_PATTERNS = {
    "reg save hklm\\sam",
    "reg save hklm\\system",
    "reg save hklm\\security",
    "reg export hklm\\sam",
    "reg export hklm\\system",
    "reg export hklm\\security",
    "hklm\\sam",
    "hklm\\system",
    "hklm\\security",
    "windows\\system32\\config\\sam",
    "windows\\system32\\config\\system",
    "windows\\system32\\config\\security",
}
#DOMAIN CONTROLLERS 
NTDS_PATTERNS = {
    "ntds.dit",
    "esentutl",
    "diskshadow",
    "vssadmin create shadow",
    "wmic shadowcopy",
    "ifm",
}

DPAPI_PATTERNS = {
    "dpapi",
    "dpapi::masterkey",
    "dpapi::cred",
    "masterkey",
    "credhist",
    "protecteddata",
}

KERBEROS_PATTERNS = {
    "kerberos",
    "kerberos::golden",
    "kerberos::silver",
    "kerberos::ptt",
    "kerberos::list",
    "ticket",
    "krbtgt",
    "tgt",
}

CMDKEY_PATTERNS = {
    "cmdkey",
    "cmdkey /list",
    "cmdkey /add",
    "cmdkey /delete",
}

VAULT_PATTERNS = {
    "vaultcmd",
    "vault::list",
    "vault::cred",
    "vault::policy",
    "credential manager",
}

BROWSER_CREDENTIAL_PATTERNS = {
    "login data",
    "cookies",
    "local state",
    "web data",
    "chrome",
    "edge",
    "firefox",
    "browser credentials",
}

RUNAS_PATTERNS = {
    "runas",
    "runas /savecred",
    "/savecred",
}

CREDENTIAL_DUMPING_PATTERNS = {
    "credential",
    "credentials",
    "password",
    "passwords",
    "hash",
    "hashes",
    "hashdump",
    "dump",
    "dumpcreds",
    "creddump",
    "cachedump",
    "logonpasswords",
    "secrets",
}
