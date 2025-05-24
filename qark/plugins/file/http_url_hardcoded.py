# ✅ OWASP Mobile Top 10: M3 (Insecure Communication)
# ✅ MSTG-NETWORK-1: All network traffic must be transmitted over HTTPS.
# This plugin detects hardcoded http:// URLs which can lead to MITM attacks if not protected by HSTS or network layer security.

import logging
import re

from qark.issue import Severity, Issue
from qark.utils import is_java_file
from qark.scanner.plugin import FileContentsPlugin

log = logging.getLogger(__name__)
 
HARDCODED_HTTP_DESCRIPTION = (
    "Application contains hardcoded HTTP URL: {http_url}. Unless HSTS is implemented, "
    "this request can be intercepted and modified by a man-in-the-middle attack."
)

HTTP_URL_PATTERNS = [
    r'http://(?:[a-zA-Z0-9$-_@.&+!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
    r'new\s+URL\s*\(\s*["\']http://[^"\']+["\']\s*\)',
    r'Uri\.parse\s*\(\s*["\']http://[^"\']+["\']\s*\)'
]

STANDARD_ID = "MSTG-NETWORK-1"
STANDARD_DESCRIPTION = (
    "Apps must use HTTPS for all network communications to prevent MITM attacks."
)

class HardcodedHTTP(FileContentsPlugin):
    def __init__(self):
        super().__init__(category="network", name="Hardcoded HTTP URL found",
                         description=HARDCODED_HTTP_DESCRIPTION)
        self.severity = Severity.VULNERABILITY
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in HTTP_URL_PATTERNS]

    def run(self):
        if not is_java_file(self.file_path):
            log.debug("Skipping non-Java file: %s", self.file_path)
            return

        for line_number, line in enumerate(self.file_contents.splitlines(), start=1):
            for pattern in self.compiled_patterns:
                for match in pattern.finditer(line):
                    matched_url = match.group(0)
                    # log.warning removed to silence CLI output during vulnerability detection
                    self.issues.append(Issue(
                        category=self.category,
                        severity=self.severity,
                        name=self.name,
                        description=self.description.format(http_url=matched_url),
                        file_object=self.file_path,
                        line_number=(line_number, match.start()),
                        standard_id=STANDARD_ID,
                        standard_description=STANDARD_DESCRIPTION,
                        owasp_refs=["M3"]
                    ))

plugin = HardcodedHTTP()

