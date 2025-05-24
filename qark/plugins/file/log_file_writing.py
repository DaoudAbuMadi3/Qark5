# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage)
# ✅ MSTG-STORAGE-8: Logging data to files must be avoided or protected.
# This plugin detects creation of log or debug files which may expose sensitive information.

import logging
import re
from javalang.tree import MethodInvocation, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

LOG_FILE_REGEX = re.compile(r"(log|debug).*\.txt", re.IGNORECASE)
WRITE_METHODS = {"FileOutputStream", "BufferedWriter", "PrintWriter", "FileWriter"}
 
class LogFileWritingPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Suspicious log file writing detected",
            description="Detects potential logging of sensitive data into local files."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in WRITE_METHODS:
                    for arg in node.arguments:
                        if isinstance(arg, Literal) and isinstance(arg.value, str):
                            if LOG_FILE_REGEX.search(arg.value):
                                self._add_issue(
                                    "Log file written",
                                    f"Detected logging to file `{arg.value}`. Avoid storing logs in unprotected locations.",
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
                "📌 MSTG-STORAGE-8 - Log files must be protected or disabled in production.\n"
                "🛠️ Do not store sensitive data in files on external or unprotected storage."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-STORAGE-8",
            standard_description="Sensitive data must not be logged to accessible files.",
            owasp_refs=["M2"]
        ))

plugin = LogFileWritingPlugin()

