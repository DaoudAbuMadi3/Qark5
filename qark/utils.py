import os
from functools import partial

def create_directories_to_path(path):
    """Create directories to a path if they don't exist."""
    try:
        os.makedirs(os.path.dirname(path))
    except Exception:
        # directory already exists
        pass
 
def file_has_extension(extension, file_path):
    file_path = str(file_path).lower()  # Ensure file_path is a string before calling .lower()
    return os.path.splitext(file_path)[1] == extension.lower()

is_java_file = partial(file_has_extension, ".java")

def environ_path_variable_exists(variable_name):
    """Determines if the os.environ variable exists and is a valid path.

    :rtype: bool
    """
    try:
        return os.path.exists(os.environ[variable_name])
    except KeyError:
        return False

