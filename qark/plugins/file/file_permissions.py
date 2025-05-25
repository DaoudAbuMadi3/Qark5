import logging
import re
from qark.issue import Severity, Issue
from qark.plugins.helpers import run_regex
from qark.scanner.plugin import FileContentsPlugin

log = logging.getLogger(__name__)

STANDARD_ID = "MSTG-STORAGE-3"
STANDARD_DESCRIPTION = (
    "Files must be created with the least privilege. Avoid MODE_WORLD_READABLE or global access."
)
 
PERMISSION_PATTERNS = {
    re.compile(r"MODE_WORLD_READABLE"): "World readable file found. Any application or file browser can access and read this file.",
    re.compile(r"MODE_WORLD_WRITEABLE"): "World writable file found. Any application or file browser can write to this file.",
    re.compile(r"\.setReadable\s*\(\s*true\s*,\s*false\s*\)"): "setReadable(true, false) makes file globally readable.",
    re.compile(r"\.setWritable\s*\(\s*true\s*,\s*false\s*\)"): "setWritable(true, false) makes file globally writable.",
}

class FilePermissions(FileContentsPlugin):
    """
    This plugin scans Java files for insecure file permissions.
    """
    def __init__(self):
        super().__init__(category="file", name="Insecure File Permissions")
        self.severity = Severity.VULNERABILITY

    def run(self):
        for pattern, description in PERMISSION_PATTERNS.items():
            matches = run_regex(self.file_path, pattern)
            if matches:
                for match_line in matches:
                    if isinstance(match_line, tuple):
                        content = match_line[0]
                    else:
                        content = match_line

                    line = str(content).strip()
                    # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=f"Insecure permission: {pattern.pattern}",
                    severity=self.severity,
                    description=description,
                    file_object=self.file_path,
                    standard_id=STANDARD_ID,
                    standard_description=STANDARD_DESCRIPTION,
                    owasp_refs=["M2"]
                ))

plugin = FilePermissions()

