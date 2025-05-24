# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography), M10 (Extraneous Functionality)
# ✅ MSTG-STORAGE-7 / MSTG-ARCH-9: Do not hardcode API keys or secrets in the source code.
# This plugin scans for hardcoded API keys, tokens, and secrets that may be exposed at runtime or via reverse engineering.

import logging
import re
from qark.issue import Severity, Issue
from qark.scanner.plugin import FileContentsPlugin

log = logging.getLogger(__name__)
 
BLACKLISTED_EXTENSIONS = {".apk", ".dex", ".png", ".jar"}

API_KEY_PATTERNS = [
    r'(?=.{20,})(?=.+\d)(?=.+[a-z])(?=.+[A-Z])(?=.+[-_])',  # General pattern
    r'API_KEY\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',         # API_KEY=...
    r'SECRET_KEY\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',      # SECRET_KEY=...
    r'access_token\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']'     # access_token=...
]

SPECIAL_CHAR_REGEX = re.compile(r'(?=.+[!$%^&*()_+|~=`{}\[\]:<>?,./])')

STANDARD_ID = "MSTG-STORAGE-7"
STANDARD_DESCRIPTION = (
    "Secrets and API keys must not be hardcoded or stored in source code."
)

class JavaAPIKeys(FileContentsPlugin):
    def __init__(self):
        super().__init__(category="file", name="Potential API Key found",
                         description="Potential API Key or secret detected; please verify manually.")
        self.severity = Severity.VULNERABILITY
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in API_KEY_PATTERNS]

    def run(self):
        if any(self.file_path.endswith(ext) for ext in BLACKLISTED_EXTENSIONS):
            log.debug("Skipping blacklisted file: %s", self.file_path)
            return

        for line_number, line in enumerate(self.file_contents.splitlines(), start=1):
            words = line.strip().split()
            for word in words:
                if SPECIAL_CHAR_REGEX.search(word):
                    continue  # Skip words with strong symbols
                for pattern in self.compiled_patterns:
                    if pattern.search(word):
                        description = f"Potential API key detected: '{word}' (line {line_number})"
                        # log.warning removed to silence CLI output during vulnerability detection
                        self.issues.append(Issue(
                            category=self.category,
                            severity=self.severity,
                            name=self.name,
                            description=description,
                            file_object=self.file_path,
                            line_number=(line_number, 0),
                            standard_id=STANDARD_ID,
                            standard_description=STANDARD_DESCRIPTION,
                            owasp_refs=["M6", "M10"]
                        ))
                        break

plugin = JavaAPIKeys()

