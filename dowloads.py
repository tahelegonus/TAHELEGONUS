#download command line parameters


DOWNLOAD_KEYWORDS = {

    "invoke-webrequest",
    "invoke-restmethod",
    "downloadfile",
    "start-bitstransfer", 
    "curl",
    "wget",
    "bitsadmin",
    "certutil",
    "urlcache"
}


BITSADMIN_KEYWORDS = {

    "bitsadmin",
    "/transfer",
    "/create",
    "addfile",
    "/resume",
    "/complete"
}

#T1197
BITSADMIN_PATTERNS ={

    "bitsadmin /transfer",
    "bitsadmin /create",
    "bitsadmin /addfile",
    "bitsadmin /setnotifycmdline",
    "bitsadmin /resume",
    "bitsadmin /complete",
    "bitsadmin /cancel",
    "bitsadmin /reset"

}


CERTUTIL_KEYWORDS = {

    "certutil",
    "urlcache",
    "-split",
    "-f",
    "-decode",
    "-decodehex",
    "-encode"
}

#T1105/T1140
CERTUTIL_PATTERNS = {

    "certutil -urlcache",
    "certutil -verifyctl",
    "certutil -decode",
    "certutil -decodehex",
    "certutil -encode",
    "certutil -split",
    "certutil -f",
    "certutil -ping"


}


#T1105 ingress tool transfer
DOWNLOAD_PATTERNS = {


    "invoke-webrequest http",
    "invoke-restmethod http",
    "downloadfile(",
    "curl http",
    "wget http",
    "certutil -urlcache",
    "bitsadmin /transfer",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "curl http",
    "wget http"
}



