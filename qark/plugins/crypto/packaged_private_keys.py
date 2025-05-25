# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography)
# ✅ MSTG-CRYPTO-6: Private keys must never be stored or embedded in the application.
# This plugin detects embedded private key materials (RSA/DSA/EC) in app files.
 
import logging
import re
from qark.issue import Severity, Issue
from qark.plugins.helpers import run_regex
from qark.scanner.plugin import FileContentsPlugin

log = logging.getLogger(__name__)

PRIVATE_KEY_PATTERNS = [
    r'PRIVATE\sKEY',
    r'BEGIN\sRSA\sPRIVATE\sKEY',
    r'BEGIN\sDSA\sPRIVATE\sKEY',
    r'BEGIN\sEC\sPRIVATE\sKEY'
]

STANDARD_ID = "MSTG-CRYPTO-6"
STANDARD_DESCRIPTION = "Private keys must never be embedded in the application package."

class PackagedPrivateKeys(FileContentsPlugin):
    def __init__(self):
        super().__init__(category="crypto", name="Packaged Private Keys")
        self.severity = Severity.VULNERABILITY
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in PRIVATE_KEY_PATTERNS]

    def run(self):
        for pattern in self.compiled_patterns:
            matches = run_regex(self.file_path, pattern)
            if matches:
                desc = f"Potential private key embedded in file: {self.file_path}"
                for line in matches:
                    # log.warning removed to silence CLI output during vulnerability detection
                    pass
                self.issues.append(Issue(
                    category=self.category,
                    name=self.name,
                    severity=self.severity,
                    description=desc,
                    file_object=self.file_path,
                    standard_id=STANDARD_ID,
                    standard_description=STANDARD_DESCRIPTION,
                    owasp_refs=["M6"]
                ))

plugin = PackagedPrivateKeys()

