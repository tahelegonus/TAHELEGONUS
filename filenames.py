
# ==========================================================
# keywords
# ==========================================================
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
    "zoom_update.exe",
    "discord_update.exe",
    "steam_update.exe",
    "spotify_update.exe",
}

COMMON_DROPPER_NAMES = {

    "loader.exe",
    "dropper.exe",
    "payload.exe",
    "stub.exe",
    "stage1.exe",
    "stage2.exe",

    "bootstrap.exe",
    "launcher.exe",

    "agent.exe",
    "worker.exe",

    "runtime.exe",
    "host.exe",
    "client.exe",

    "setup64.exe",
    "installer64.exe",
    "payload64.exe",
    "dropper64.exe",

    "implant.exe",
    "implant64.exe",
    "run.exe",
    "execute.exe",
    "servicehost.exe",
    "update64.exe",
    "runtime64.exe",
    "host64.exe",
    "agent64.exe",

}
# ==========================================================
# helper functions
# ==========================================================
#keyword matcher helper 

def contains_keyword(image_path, keywords):

    command = image_path.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None
# ==========================================================
# individual detections
# ==========================================================


def detect_suspicious_filename(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Suspicious Filename",
            "reason": None
        }

    filename = contains_keyword(
        image_path,
        SUSPICIOUS_FILENAMES
    )

    if filename:
        return {
            "matched": True,
            "name": "Suspicious Filename",
            "category": "File Name",
            "severity": "Medium",
            "mitre": ["T1036"],
            "reason": f"Suspicious filename '{filename}' detected."
        }

    return {
        "matched": False,
        "name": "Suspicious Filename",
        "reason": None
    }



def detect_malware_filename(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Malware-like Filename",
            "reason": None
        }
    malware = contains_keyword(
        image_path,
        MALWARE_LIKE_NAMES
    )

    if malware:
        return {
            "matched": True,
            "name": "Malware-like Filename",
            "category": "File Name",
            "severity": "High",
            "mitre": ["T1036"],
            "reason": f"Malware-like filename '{malware}' detected."
        }

    return {
        "matched": False,
        "name": "Malware-like Filename",
        "reason": None
    }


def detect_fake_update_filename(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Fake UpdateFilename",
            "reason": None
        }
    fake_update = contains_keyword(
        image_path,
        GENERIC_UPDATE_NAMES
    )

    if fake_update:
        return {
            "matched": True,
            "name": "Fake Update Filename",
            "category": "File Name",
            "severity": "Medium",
            "mitre": ["T1036"],
            "reason": f"Fake update filename '{fake_update}' detected."
        }

    return {
        "matched": False,
        "name": "Fake Update Filename",
        "reason": None
    }

def detect_dropper_filename(image_path):
    if not image_path:
        return {
            "matched": False,
            "name": "Dropper Filename",
            "reason": None
        }
    dropper = contains_keyword(
        image_path,
        COMMON_DROPPER_NAMES
    )

    if dropper:
        return {
            "matched": True,
            "name": "Dropper Filename",
            "category": "File Name",
            "severity": "High",
            "mitre": ["T1036"],
            "reason": f"Dropper-style filename '{dropper}' detected."
        }

    return {
        "matched": False,
        "name": "Dropper Filename",
        "reason": None
    }

# ==========================================================
# main detector
# ==========================================================
def detect_filenames(image_path):

    detections = []

    detectors = [

        detect_suspicious_filename,
        detect_malware_filename,
        detect_fake_update_filename,
        detect_dropper_filename,

    ]

    for detector in detectors:

        result = detector(image_path)

        if result["matched"]:
            detections.append(result)

    return detections
