import os 
# ==========================================================
# keyword libraries
# ==========================================================

DOUBLE_EXTENSION_PATTERNS = {
    #office
    ".doc.exe",
    ".docx.exe",
    ".docm.exe",
    ".xls.exe",
    ".xlsx.exe",
    ".xlsm.exe",
    ".ppt.exe",
    ".pptx.exe",
    ".pptm.exe",
    #docs
    ".pdf.exe",
    ".txt.exe",
    ".rtf.exe",
    ".csv.exe",
    ".xml.exe",
    #images
    ".jpg.exe",
    ".jpeg.exe",
    ".png.exe",
    ".gif.exe",
    ".bmp.exe",
    ".svg.exe",
    #archives
    ".zip.exe",
    ".rar.exe",
    ".7z.exe",
    ".cab.exe",
    ".iso.exe",
    ".img.exe",
    #scripts
    ".js.exe",
    ".jse.exe",
    ".vbs.exe",
    ".vbe.exe",
    ".wsf.exe",
    ".hta.exe",
    ".ps1.exe",
    ".bat.exe",
    ".cmd.exe",
    #misc
    ".lnk.exe",
    ".url.exe",
    ".scr.exe",
    ".com.exe",
}
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".pif",
    ".hta",
    ".cpl",
    ".msc",
    ".msi",
    ".msp",
    ".dll",
    ".sys",
    ".lnk",
}
SAFE_FILE_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".txt",
    ".rtf",
    ".csv",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".zip",
    ".rar",
    ".7z",
    ".mp3",
    ".wav",
    ".mp4",
    ".avi",
    ".mov",
    ".html",
    ".htm",
    ".xml",
}


# ==========================================================
# helper functions
# ==========================================================
#keyword matcher helper 

def contains_keyword(image_path, keywords):

    path = image_path.lower()

    for keyword in keywords:

        if keyword.lower() in path:

            return keyword

    return None
# ==========================================================
# individual detections
# ==========================================================

# known double extension detection

def detect_known_double_extensions(image_path):
    if not image_path:
        return {
        "matched": False,
        "name": "Known Double Extension",
        "reason": None
    }

    extension = contains_keyword(
        image_path,
        DOUBLE_EXTENSION_PATTERNS
    )

    if extension:
        return {
            "matched": True,
            "name": "Known Double Extension",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1036.007"],
            "reason": f"Known double extension '{extension}' detected."
        }

    return {
        "matched": False,
        "name": "Known Double Extension",
        "reason": None
    }


#double extensions detection

def detect_generic_double_extensions(image_path):
    if not image_path:
        return {
        "matched": False,
        "name": "Generic Double Extension",
        "reason": None
    }

    filename = os.path.basename(image_path.lower())

    parts = filename.split(".")

    if len(parts) < 3:
        return {
            "matched": False,
            "name": "Generic Double Extension",
            "reason": None
        }

    first_extension = "." + parts[-2]
    second_extension = "." + parts[-1]

    if (
        first_extension in SAFE_FILE_EXTENSIONS
        and second_extension in EXECUTABLE_EXTENSIONS
    ):

        return {
            "matched": True,
            "name": "Generic Double Extension",
            "category": "Image Path",
            "severity": "High",
            "mitre": ["T1036.007"],
            "reason": (
                f"File masquerades as "
                f"'{first_extension}' but executes as "
                f"'{second_extension}'."
            )
        }

    return {
        "matched": False,
        "name": "Generic Double Extension",
        "reason": None
    }

# ==========================================================
# main detector
# ==========================================================

def detect_double_extensions(image_path):

    detections = []

    detectors = [

        detect_known_double_extensions,
        detect_generic_double_extensions,

    ]

    for detector in detectors:

        result = detector(image_path)

        if result["matched"]:

            detections.append(result)

    return detections
