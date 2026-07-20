#filenames that are commonly abused but require additnal context 
SUSPICIOUS_FILENAMES = {

    # generic
    "update.exe",
    "patch.exe",
    "install.exe",
    "installer.exe",
    "setup.exe",
    "service.exe",
    "helper.exe",
    "host.exe",

    # document themed
    "document.exe",
    "invoice.exe",
    "receipt.exe",
    "statement.exe",
    "payment.exe",
    "resume.exe",
    "contract.exe",
    "quote.exe",
    "purchase_order.exe",

    # business themed
    "report.exe",
    "scan.exe",
    "fax.exe",
    "form.exe",

    # archive themed
    "photos.exe",
    "images.exe",
    "backup.exe",
    "archive.exe",
    "documents.exe",

    # misc
    "copy.exe",
    "new.exe",
    "temp.exe",
    "tmp.exe",
}
#assoicated with malware toolingn
MALWARE_LIKE_NAMES = {

    "payload.exe",
    "loader.exe",
    "dropper.exe",
    "injector.exe",
    "implant.exe",
    "backdoor.exe",
    "beacon.exe",
    "stager.exe",
    "stub.exe",

    "rat.exe",
    "miner.exe",
    "bot.exe",
    "client.exe",
    "server.exe",

    "keylogger.exe",
    "stealer.exe",
    "grabber.exe",
    "clipper.exe",

    "shell.exe",
    "reverse_shell.exe",

    "crypt.exe",
    "crypter.exe",
    "packer.exe",
    "unpacker.exe",
    "shellcode.exe",
    "downloader.exe",
    "uploader.exe",

    "implant64.exe",

    "ratclient.exe",

    "c2.exe",
}


#impersonates software updates 

GENERIC_UPDATE_NAMES = {

    "windows_update.exe",
    "security_update.exe",
    "critical_update.exe",
    "system_update.exe",

    "chrome_update.exe",
    "edge_update.exe",
    "firefox_update.exe",

    "adobe_update.exe",
    "acrobat_update.exe",

    "office_update.exe",
    "word_update.exe",
    "excel_update.exe",

    "java_update.exe",
    "flash_update.exe",

    "driver_update.exe",

    "update_service.exe",
    "teams_update.exe",
    "onedrive_update.exe",
    "windows_defender_update.exe",
}


#filenames often seen for first stage malware or droppers

COMMON_DROPPER_NAMES = {

    "run.exe",
    "start.exe",
    "execute.exe",

    "launcher.exe",
    "bootstrap.exe",
    "installer.exe",

    "agent.exe",
    "worker.exe",

    "client.exe",
    "host.exe",

    "servicehost.exe",

    "runtime.exe",

    "payload.exe",

    "dropper.exe",

    "loader.exe",

    "stage1.exe",

    "stage2.exe",
    "setup64.exe",
    "installer64.exe",

    "agent64.exe",

    "payload64.exe",

    "dropper64.exe",
    }
