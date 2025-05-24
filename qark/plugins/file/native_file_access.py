# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-5 / 10: Native file access must enforce same security rules as Java layer.
# This plugin detects calls to native libraries and potential file access via JNI.

import logging
from javalang.tree import MethodInvocation, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

JNI_LOAD_METHODS = {"loadLibrary", "load"}
NATIVE_KEYWORDS = {"fopen", "fwrite", "fread", "open", "fclose", "unlink", "chmod"}

class NativeFileAccessPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Unsafe native file access detected",
            description="Detects native file access via JNI which may bypass Android file protection."
        )
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                # Detect loading of native libraries
                if node.member in JNI_LOAD_METHODS:
                    self._add_issue(
                        "Native library loaded",
                        f"Detected call to `System.{node.member}`. Ensure native code follows secure file access rules.",
                        node
                    )

                # Detect literal mentions of unsafe file access functions (within native call strings)
                for arg in node.arguments:
                    if isinstance(arg, Literal) and isinstance(arg.value, str):
                        if any(keyword in arg.value.lower() for keyword in NATIVE_KEYWORDS):
                            self._add_issue(
                                "Suspicious native file access",
                                f"Detected native call referencing `{arg.value}`. Review file access in native code.",
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
                "📌 MSTG-PLATFORM-5 / 10 - Native code must enforce same data and permission policies.\n"
                "🛠️ Check file access protection in C/C++ code as in Java, especially when using fopen or open."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-PLATFORM-10",
            standard_description="Native code must enforce access control and data protection like Java layer.",
            owasp_refs=["M1"]
        ))

plugin = NativeFileAccessPlugin()

