# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage)
# ✅ MSTG-STORAGE-4: Temporary files must be protected and deleted when no longer needed.
# This plugin detects use of temporary files that may expose sensitive data if left unprotected.

import logging
from javalang.tree import MethodInvocation, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

TEMP_METHODS = {
    "createTempFile",
    "getCacheDir",
    "getExternalCacheDir"
}

class TempFileUsagePlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Temporary file usage detected",
            description="Detects creation of temporary or cache files that may be insecure."
        )
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in TEMP_METHODS:
                    self._add_issue(
                        "Temporary file created",
                        f"Method `{node.member}` used. Ensure file is not used to store sensitive data, and is deleted properly.",
                        node
                    )

    def _add_issue(self, name, description, node):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=name,
            severity=self.severity,
            description=(
                description + "\n\n"
                "📌 OWASP M2 - Insecure Data Storage\n"
                "📌 MSTG-STORAGE-4 - Temporary files must be encrypted or securely deleted.\n"
                "🛠️ Make sure to protect temporary files and not use them to store sensitive information."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-STORAGE-4",
            standard_description="Temporary files must be protected and deleted when no longer needed.",
            owasp_refs=["M2"]
        ))

plugin = TempFileUsagePlugin()

