# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-5: Input paths must be validated to prevent path traversal attacks.
# This plugin detects unsafe file access using user-controllable paths.

import logging
from javalang.tree import MethodInvocation, MemberReference, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

SENSITIVE_METHODS = {
    "openFileInput",
    "openFileOutput",
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "new File",
}

SUSPICIOUS_NAMES = {"input", "path", "filename", "fileName", "filepath", "userFile"}

STANDARD_ID = "MSTG-PLATFORM-5"
STANDARD_DESCRIPTION = "Validate file paths before access to prevent path traversal attacks."

class PathTraversalPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Potential path traversal via unsafe file access",
            description="Detects file access using unvalidated user input, which can lead to path traversal vulnerabilities."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                method_name = node.member
                if method_name in SENSITIVE_METHODS:
                    if node.arguments:
                        arg = node.arguments[0]
                        # Only flag if the argument is a variable (e.g. from user input), not a hardcoded string
                        if isinstance(arg, MemberReference):
                            if arg.member.lower() in SUSPICIOUS_NAMES:
                                self._add_issue(
                                    name="Unvalidated input used in file access",
                                    description=f"Potential path traversal: file access using variable `{arg.member}`. Validate user input.",
                                    node=node
                                )

    def _add_issue(self, name, description, node):
        line = getattr(node, "position", None)
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=name,
            severity=self.severity,
            description=(
                description + "\n\n"
                "📌 OWASP M1 - Improper Platform Usage\n"
                "📌 MSTG-PLATFORM-5 - Validate paths before file access.\n"
                "🛠️ Make sure to filter user input or use only a fixed file name."
            ),
            file_object=self.file_path,
            line_number=line,
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION,
            owasp_refs=["M1"]
        ))

plugin = PathTraversalPlugin()

