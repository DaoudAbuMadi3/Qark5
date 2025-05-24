import logging
import os
import re
import shutil
from io import open

from javalang.tree import MethodInvocation
from qark.plugins.manifest_helpers import get_min_sdk
from qark.utils import is_java_file

log = logging.getLogger(__name__)
 
EXCLUDE_REGEXES = (
    r'^\s*(//|/\*)',
    r'^\s*\*',
    r'.*\*/$',
    r'^\s*Log\..\(',
    r'(.*)(public|private)\s(String|List)'
)

EXCLUSION_REGEX = re.compile("|".join(EXCLUDE_REGEXES))


def run_regex(filename, rex, encoding="utf-8"):
    """
    Run regex against file content and return matching lines as tuples of (line_number, line_content).
    Excludes matches based on EXCLUSION_REGEX.
    
    :param filename: Path to the file to scan.
    :param rex: Regular expression pattern to match.
    :param encoding: File encoding.
    :return: List of (line_number, line_content) tuples.
    """
    results = []
    try:
        with open(filename, encoding=encoding) as f:
            for i, curr_line in enumerate(f, 1):
                if re.search(rex, curr_line) and not re.match(EXCLUSION_REGEX, curr_line):
                    results.append((i, curr_line.strip()))
    except IOError:
        log.debug("Unable to open file: %s; results may be incomplete.", filename)
    except UnicodeDecodeError:
        log.debug("UnicodeDecodeError in file: %s; skipping.", filename)
    except Exception:
        log.exception("Unexpected error reading file: %s", filename)
    return results


def java_files_from_files(files):
    """Return generator of .java file paths."""
    return (file_path for file_path in files if is_java_file(file_path))


def remove_dict_entry_by_value(dictionary, value):
    """Remove entries in a dict by value."""
    new_dict = {k: v for k, v in dictionary.items() if v != dictionary.get(value)}
    if value in dictionary.values():
        log.debug("Removed WebView '%s' from tracking dictionary", value)
    return new_dict


def valid_method_invocation(method_invocation, method_name, num_arguments):
    """
    Check if MethodInvocation matches the given name and number of arguments.
    Accepts method_invocation.member as string or expression.

    :param method_invocation: Instance of MethodInvocation.
    :param method_name: Method name to match.
    :param num_arguments: Expected number of arguments.
    :return: True if matches, False otherwise.
    """
    member_name = getattr(method_invocation, "member", None)
    args = getattr(method_invocation, "arguments", [])
    is_valid = (
        isinstance(member_name, str)
        and member_name == method_name
        and isinstance(args, list)
        and len(args) == num_arguments
    )
    if is_valid:
        log.debug("Matched method invocation: %s with %d arguments", method_name, num_arguments)
    return is_valid


def get_min_sdk_from_files(files, apk_constants=None):
    """Get minSdkVersion from apk_constants or manifest; default 1."""
    try:
        return int(apk_constants["min_sdk"])
    except (KeyError, TypeError):
        for decompiled_file in files:
            if decompiled_file.lower().endswith(f"{os.sep}androidmanifest.xml"):
                return get_min_sdk(decompiled_file)
    log.debug("No minSdkVersion found; defaulting to 1")
    return 1


def copy_directory_to_location(directory_to_copy, destination):
    """Copy directory to destination."""
    log.debug("Copying directory from %s to %s", directory_to_copy, destination)
    try:
        shutil.copytree(src=directory_to_copy, dst=destination)
    except Exception:
        log.exception("Failed to copy directory from %s to %s", directory_to_copy, destination)
        raise


if __name__ == "__main__":
    print("Testing run_regex on self...")
    matches = run_regex(__file__, r"def ")
    for lineno, line in matches:
        print(f"{lineno}: {line}")

