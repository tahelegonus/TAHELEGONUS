from windows import categories
from windows import envirorment
from windows import executables
from windows import parents 
from windows import extensions 
from windows import paths 
from windows import processes 
from windows import registry
from windows import windows_lolbins
from windows import eventidsecuirty



#checking to see if process is known, parent reationship normal, and if it is a executable lolbin
def check_process(process_name):

    if process_name in processes.WINDOWS_CORE_PROCESSES:

        return {
            "known": True,
            "type": "Windows Core Process"
        }

    return {
        "known": False
    }

def check_parent(process_name, parent_name):

    expected = parents.EXPECTED_PARENT_PROCESSES.get(
        process_name
    )

    if expected and parent_name in expected:

        return {
            "expected": True
        }


    return {
        "expected": False
    }

def check_lolbin(process_name):

    if process_name in windows_lolbins.LOLBIN_EXECUTABLES:

        return {
            "lolbin": True,
            "metadata": windows_lolbins.LOLBIN_DATABASE.get(process_name)
        }


    return {
        "lolbin": False
    }

def check_event_id(event_id):

    event = eventidsecuirty.EVENT_IDS.get(
        str(event_id)
    )


    if event:

        return {
            "known": True,
            "metadata": event
        }


    return {
        "known": False
    }

def check_extension(file_path):

    extension = file_path.lower().split(".")[-1]


    if "." + extension in extensions.WINDOWS_EXECUTABLE_EXTENSIONS:

        return {
            "executable": True,
            "extension": extension
        }


    return {
        "executable": False
    }
def check_registry(key):

    if key in registry.KNOWN_PERSISTENCE_KEYS:

        return {

            "persistence_location": True

        }


    return {

        "persistence_location": False

    }

def check_executable(process):

    if process.lower() in executables.KNOWN_WINDOWS_EXECUTABLES:

        return {

        "known":True

        }


    return {

    "known":False

    }
def check_environment(file_path):

    for file_path, metadata in envirorment.WINDOWS_ENVIRONMENTS.items():

        if metadata["example"].lower() in file_path.lower():

            return {
                "known": True,
                "metadata": metadata
            }


    return {
        "known": False
    }
def check_category(process_name):

    category = categories.PROCESS_CATEGORIES.get(
        process_name.lower()
    )

    if category:

        return {
            "known": True,
            "category": category
        }


    return {
        "known": False,
        "category": None
    }
def check_path(image_path):

    for expected_path in paths.WINDOWS_EXPECTED_PATHS:

        if image_path.startswith(expected_path):

            return {
                "known": True,
                "type": "Expected Windows Path"
            }


    return {
        "known": False
    }



def enrich_event(event):

    return {

        "event":
            check_event_id(
                event["event_id"]
            ),

        "process":
            check_process(
                event["process_name"]
            ),

        "parent":
            check_parent(
                event["process_name"],
                event["parent_process"]
            ),

        "lolbin":
            check_lolbin(
                event["process_name"]
            ),

        "category":
            check_category(
                event["process_name"]
            ),

        "path":
            check_path(
                event["image_path"]
            ),

        "extension":
            check_extension(
                event["image_path"]
            ),
        "environment":
        check_environment(
            event["image_path"]
        ),

        "registry":
            check_registry(
                event["registry_key"]
            ),

    }
