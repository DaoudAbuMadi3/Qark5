# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage), M9 (Insecure Communication)
# ✅ MSTG-STORAGE-3: Secrets and keys must not be hardcoded in the app code.
# This plugin detects hardcoded credentials such as passwords, API keys, and access tokens.

import logging
import re
from javalang.tree import Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

# Keywords we search for in Strings
CREDENTIAL_KEYWORDS = [
    r"(?i).*password.*",
    r"(?i).*passwd.*",
    r"(?i).*pwd.*",
    r"(?i).*api[_-]?key.*",
    r"(?i).*access[_-]?token.*",
    r"(?i).*secret.*",
    r"(?i).*username.*",
]

CRED_PATTERNS = [re.compile(k) for k in CREDENTIAL_KEYWORDS]

class HardcodedCredentialsPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="generic",
            name="Hardcoded credentials detected",
            description="Detects hardcoded passwords, secrets, and API tokens in source code."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, Literal) and isinstance(node.value, str):
                clean_val = node.value.strip('"').strip("'")
                if any(p.match(clean_val) for p in CRED_PATTERNS):
                    self._report(node, clean_val)

    def _report(self, node, value):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=self.name,
            severity=self.severity,
            description=(
                f"Found hardcoded value: `{value}`\n"
                "Sensitive information like passwords, secrets, or API keys must not be embedded in code.\n\n"
                "📌 OWASP M2 / M9\n"
                "📌 MSTG-STORAGE-3"
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-STORAGE-3",
            standard_description="Secrets or credentials must not be hardcoded into the application.",
            owasp_refs=["M2", "M9"]
        ))

plugin = HardcodedCredentialsPlugin()

