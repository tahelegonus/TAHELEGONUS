#directories where legitamte windows exectuables generlly SHOULD NOT be launched from

HIGH_RISK_EXECUTION_PATHS = {

    # user profile
    r"\Users\Public",
    r"\Users\Default",
    r"\Users\Default User",

    # appdata
    r"\AppData\Roaming",
    r"\AppData\Local",
    r"\AppData\LocalLow",

    # temp
    r"\Temp",
    r"\Windows\Temp",

    # downloads
    r"\Downloads",

    # desktop
    r"\Desktop",

    # startup
    r"\Start Menu\Programs\Startup",

    # recycle bin
    r"\$Recycle.Bin",

    # tasks
    r"\System32\Tasks",

    # spool
    r"\System32\spool",

    # printer drivers
    r"\System32\spool\drivers",

    # inetpub
    r"\inetpub",

    # perf logs
    r"\PerfLogs",

    # one drive
    r"\OneDrive",

    # public shares
    r"\Public",

    r"\Windows\Tasks",

    r"\Windows\Tracing",

    r"\Windows\Debug",

    r"\Recovery",

    r"\ProgramData\Microsoft",

    r"\ProgramData\Temp",

}


#directories where a normal user can write files 

USER_WRITABLE_PATHS = {

    r"\Users",

    r"\Desktop",

    r"\Downloads",

    r"\Documents",

    r"\Pictures",

    r"\Videos",

    r"\Music",

    r"\Favorites",

    r"\AppData",

    r"\AppData\Local",

    r"\AppData\Roaming",

    r"\AppData\LocalLow",

    r"\Temp",

    r"\OneDrive",

}

#malware loves temp folders


TEMP_EXECUTION_PATHS = {

    r"\Temp",

    r"\Windows\Temp",

    r"\AppData\Local\Temp",

    r"\Local Settings\Temp",

    r"\Temporary Internet Files",

    r"\INetCache",

}

#usb and removalble storage

REMOVABLE_MEDIA_PATHS = {

    r"A:\\",
    r"B:\\",

    r"D:\\",
    r"E:\\",
    r"F:\\",
    r"G:\\",
    r"H:\\",
    r"I:\\",
    r"J:\\",

    r"USB",

    r"Removable",
    r"X:\\",
    r"Y:\\",
    r"Z:\\",

}
