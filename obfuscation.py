
# ==========================================================
# keyword libraries
# ==========================================================

#obfuscation command line parameters


OBFUSCATION_KEYWORDS = {

  # execution
    "iex",
    "invoke-expression",

    # base64
    "frombase64string",
    "[convert]::frombase64string",

    # character manipulation
    "[char]",
    "char",
    "char[]",
    "join",

    # variables
    "$(",
    "${",

    # escaping
    "`",
    "^",

    # delayed expansion
    "!",

    # string building
    "+",
    ".replace(",
    ".split(",



}

OBFUSCATION_PATTERNS = {

   "invoke-expression",
    "iex(",

    "frombase64string",
    "[convert]::frombase64string",

    "[char]",
    "char[]",

    "join",

    "$(",
    "${",

    "`",

    "&&",
    "||",

}


BASE64_PATTERNS = {

    "-enc",
    "-encodedcommand",
    "frombase64string",
    "[convert]::frombase64string",
    "tobase64string",

}

IEX_PATTERNS = {

    "iex",
    "invoke-expression",
    "iex(",
    "| iex",

}


CHARACTER_PATTERNS = {

    "[char]",
    "char[]",
    "[byte[]]",
    "[text.encoding]",
    "[system.text.encoding]",

}


VARIABLE_PATTERNS = {

    "$(",
    "${",
    "$env:",
    "$executioncontext",

}


STRING_MANIPULATION_PATTERNS = {

    "-join",
    "-split",
    "-replace",
    ".replace(",
    ".split(",
    ".substring(",
    ".trim(",
    ".insert(",
    ".remove(",

}


ESCAPE_PATTERNS = {

    "`",
    "^",
    "^^",

}



HEX_PATTERNS = {

    "0x",
    "\\x",
    "[byte[]]",

}



XOR_PATTERNS = {

    "-bxor",
    "-xor",

}



COMPRESSION_PATTERNS = {

    "gzipstream",
    "deflatestream",
    "compressionmode",

}


REFLECTION_PATTERNS = {

    "system.reflection",
    "reflection.assembly",
    "gettype(",
    "getmethod(",
    "invoke(",

}





# ==========================================================
# helper functions
# ==========================================================

#keyword matcher helper 

def contains_keyword(command_line, keywords):

    command = command_line.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None


# ==========================================================
# individual detections
# ==========================================================


def detect_obfuscation_keywords(command_line):

    obfuscation_keywords = contains_keyword(
        command_line,
        OBFUSCATION_KEYWORDS
    )

    if obfuscation_keywords:
        return {
            "matched": True,
            "name": "Obfuscation Keyword",
            "category": "Obfuscation",
            "severity": "High",
            "confidence": "High",
            "mitre": ["T1027"],
            "reason": f"Obfuscation keyword'{obfuscation_keywords}' detected."
        }

    return {
        "matched": False,
        "name": "Obfuscation Keyword",
        "reason": None
    }





def detect_obfuscation_patterns(command_line):
    obfuscation_patterns = contains_keyword(
    command_line, OBFUSCATION_PATTERNS
    )
    if obfuscation_patterns:
        return {
            "matched": True,
            "name": "Obfuscation Pattern",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"Obfuscation pattern '{obfuscation_patterns}' detected."
        }

    return {
        "matched": False,
        "name": "Obfuscation Pattern",
        "reason": None
    }




def detect_base64(command_line):
    base64 = contains_keyword(
    command_line, BASE64_PATTERNS
    )
    if base64:
        return {
            "matched": True,
            "name": "Base64 Encoding",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"bASE64 pattern '{base64}' detected."
        }

    return {
        "matched": False,
        "name": "Base64 Encoding",
        "reason": None
    }



def detect_iex(command_line):
    iex = contains_keyword(
    command_line, IEX_PATTERNS
    )
    if iex:
        return {
            "matched": True,
            "name": "Invoke-Expression",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"Invoke-Expression pattern '{iex}' detected."
        }

    return {
        "matched": False,
        "name": "Invoke-Expression",
        "reason": None
    }


def detect_char_obfuscation(command_line):
    char = contains_keyword(
    command_line, CHARACTER_PATTERNS
    )
    if char:
        return {
            "matched": True,
            "name": "Character Obfuscation",
            "category": "Obfuscation",
            "severity": "Medium",
            "mitre": ["T1027"],
            "reason": f"Character Obfuscation'{char}' detected."
        }

    return {
        "matched": False,
        "name": "Character Obfuscation",
        "reason": None
    }



def detect_variable_expansion(command_line):
    variable_expansion = contains_keyword(
    command_line, VARIABLE_PATTERNS
    )
    if variable_expansion:
        return {
            "matched": True,
            "name": "Variable Expansion",
            "category": "Obfuscation",
            "severity": "Medium",
            "mitre": ["T1027"],
            "reason": f"Variable Expansion pattern '{variable_expansion}' detected."
        }

    return {
        "matched": False,
        "name": "Varaible Expanison Pattern",
        "reason": None
    }




def detect_string_manipulation(command_line):
    string_manipulation = contains_keyword(
    command_line, STRING_MANIPULATION_PATTERNS
    )
    if string_manipulation:
        return {
            "matched": True,
            "name": "String Manipulation",
            "category": "Obfuscation",
            "severity": "Medium",
            "mitre": ["T1027"],
            "reason": f"String Maniuplation pattern '{string_manipulation}' detected."
        }

    return {
        "matched": False,
        "name": "String Manipulation",
        "reason": None
    }



def detect_escape_sequences(command_line):
    escape_sequences = contains_keyword(
    command_line, ESCAPE_PATTERNS
    )
    if escape_sequences:
        return {
            "matched": True,
            "name": "Escape Sequence ",
            "category": "Obfuscation",
            "severity": "Low",
            "mitre": ["T1027"],
            "reason": f"Escape Sequence'{escape_sequences}' detected."
        }

    return {
        "matched": False,
        "name": "Escape Sequence",
        "reason": None
    }



def detect_hex(command_line):
    hex_pattern = contains_keyword(
    command_line, HEX_PATTERNS
    )
    if hex_pattern:
        return {
            "matched": True,
            "name": "Hexadecimal Encoding ",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"Hexadecimal Encoding '{hex_pattern}' detected."
        }

    return {
        "matched": False,
        "name": "Hexadecimal Encoding",
        "reason": None
    }



def detect_compression(command_line):
    compression = contains_keyword(
    command_line, COMPRESSION_PATTERNS
    )
    if compression:
        return {
            "matched": True,
            "name": "Compressed Payload",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"Compression pattern '{compression}' detected."
        }

    return {
        "matched": False,
        "name": "Compressed Payload",
        "reason": None
    }



def detect_reflection(command_line):                                    
    reflection = contains_keyword(
    command_line, REFLECTION_PATTERNS
    )
    if reflection:
        return {
            "matched": True,
            "name": "Reflection",
            "category": "Obfuscation",
            "severity": "High",
            "mitre": ["T1027"],
            "reason": f"Reflection pattern '{reflection}' detected."
        }

    return {
        "matched": False,
        "name": "Reflection",
        "reason": None
    }



# ==========================================================
# main detector
# ==========================================================

def detect_obfuscation(command_line):

    detections = []

    detectors = [

        detect_obfuscation_keywords,
        detect_obfuscation_patterns,
        detect_base64,
        detect_iex,
        detect_char_obfuscation,
        detect_variable_expansion,
        detect_string_manipulation,
        detect_escape_sequences,
        detect_hex,
        detect_compression,
        detect_reflection,

    ]

    for detector in detectors:

        result = detector(command_line)

        if result["matched"]:
            detections.append(result)

    return detections
