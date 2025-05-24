# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-7: Do not expose file:// URIs; use content:// with proper permissions.
# This plugin detects file URI exposure, which can cause security exceptions or unauthorized file access.

import logging
import re
from javalang.tree import MethodInvocation, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

FILE_URI_PATTERN = re.compile(r'file://', re.IGNORECASE)
 
class FileUriExposurePlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Use of file:// URI detected",
            description="Detects unsafe usage of file:// URI, which may expose files to unauthorized access."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                for arg in node.arguments:
                    if isinstance(arg, Literal):
                        if isinstance(arg.value, str) and FILE_URI_PATTERN.search(arg.value):
                            self._add_issue(
                                "Potential file:// URI exposure",
                                f"Found usage of file URI: {arg.value}. Use content:// via FileProvider instead.",
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
                "📌 OWASP M1 - Improper Platform Usage\n"
                "📌 MSTG-PLATFORM-7 - Use content:// instead of file:// when sharing files.\n"
                "🛠️ Replace file:// with FileProvider or Content Provider to avoid vulnerabilities and control Android 7+."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-PLATFORM-7",
            standard_description="Apps must not use file:// URIs for sharing files. Use content:// via FileProvider instead.",
            owasp_refs=["M1"]
        ))

plugin = FileUriExposurePlugin()

