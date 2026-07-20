#lolbin command line paramters 


#LOLBin abuse and how they are abused 

LOLBIN_PATTERNS = {

    "mshta http",
    "rundll32 javascript:",
    "regsvr32 /i:http",
    "installutil /logfile=",
    "msbuild",
    "rundll32",
    "regsvr32",
    "mshta",
    "installutil",
    "msbuild",
    "certutil",
    "bitsadmin",
    "forfiles",
    "cmstp",
    "odbcconf",
    "control",
    "hh",
    "desktopimgdownldr",
    "verclsid",
    "regasm",
    "regsvcs"

}

LOLBIN_EXECUTABLES = {

    "bitsadmin.exe",
    "certutil.exe",
    "cmstp.exe",
    "control.exe",
    "desktopimgdownldr.exe",
    "forfiles.exe",
    "hh.exe",
    "installutil.exe",
    "msbuild.exe",
    "mshta.exe",
    "odbcconf.exe",
    "regasm.exe",
    "regsvcs.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "verclsid.exe"
}



RUNDLL32_PATTERNS = {

    "rundll32 javascript:",

    "rundll32 url.dll",

    "rundll32 advpack.dll",

    "rundll32 shell32.dll"

}

RUNDLL32_KEYWORDS = {

    "rundll32",
    "javascript:",
    "shell32.dll",
    "url.dll",
    "advpack.dll",
    "zipfldr.dll"

}
REGSVR32_PATTERNS = {

    "regsvr32 /i:http",

    "regsvr32 /s",

    "regsvr32 /u"

}


#T1218.005
MSHTA_PATTERNS = {

    "mshta http://",
    "mshta https://",
    "mshta vbscript:",
    "mshta javascript:",
    "mshta about:",
    "mshta file://",
    ".hta",
    ".hta "
}



MSHTA_KEYWORDS = {

    "mshta",
    "http://",
    "https://",
    ".hta",
    "vbscript:",
    "javascript:"
}


MSBUILD_PATTERNS = {

    "msbuild.exe",
    "msbuild ",
    "msbuild /target",
    "msbuild /property",
    "msbuild /p:",
    "msbuild .csproj",
    "msbuild .proj"
}


#T1218.004
INSTALLUTIL_PATTERNS = {

    "installutil /logfile=",
    "installutil /logtoconsole",
    "installutil /u",
    "installutil /installstate",
    "installutil.exe"


}



