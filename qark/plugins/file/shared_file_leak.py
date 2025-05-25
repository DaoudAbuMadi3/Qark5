# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage), M10 (Extraneous Functionality)
# ✅ MSTG-STORAGE-3 / MSTG-PLATFORM-7: File sharing must be done securely via content:// URIs and with correct permissions.
# This plugin detects potentially unsafe sharing of files via intents or content URIs.

import logging
from javalang.tree import MethodInvocation, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

UNSAFE_METHODS = {
    "setData", "putExtra", "setDataAndType"
}
SUSPICIOUS_SCHEMES = ("file://", "content://")

class SharedFileLeakPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Potential insecure file sharing",
            description="Detects unsafe file sharing via intents or URIs without secure configuration."
        )
        self.severity = Severity.VULNERABILITY
 
    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in UNSAFE_METHODS:
                    for arg in node.arguments:
                        if isinstance(arg, Literal):
                            if any(scheme in arg.value for scheme in SUSPICIOUS_SCHEMES):
                                self._add_issue(
                                    "Unsafe file URI shared",
                                    f"Detected `{arg.value}` in `{node.member}`. Ensure proper FileProvider and permission flags are used.",
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
                "📌 OWASP M10 - Extraneous Functionality\n"
                "📌 MSTG-STORAGE-3 / MSTG-PLATFORM-7\n"
                "🛠️ Make sure to use `FileProvider` with appropriate permissions, and do not use `file://` or `content://` directly in Intents without protection."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-STORAGE-3",
            standard_description="Do not expose files via public URIs without access control.",
            owasp_refs=["M2", "M10"]
        ))

plugin = SharedFileLeakPlugin()

