# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage), M10 (Extraneous Functionality)
# ✅ MSTG-STORAGE-8: Logging must be removed or disabled in production apps.
# This plugin detects calls to android.util.Log methods that may expose sensitive data.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

ANDROID_LOGGING_DESCRIPTION = (
    "Logs are detected. This may allow potential leakage of information from Android applications. "
    "Logs should never be compiled into an application except during development. "
    "Reference: https://developer.android.com/reference/android/util/Log.html"
)

ANDROID_LOGGING_METHODS = ["v", "d", "i", "w", "e", "f", "println"]

class AndroidLogging(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="file", name="Logging found", description=ANDROID_LOGGING_DESCRIPTION)
        self.severity = Severity.WARNING
        self.detected_logs = {}  # {file_path: set(line_numbers)}

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if isinstance(method_invocation, MethodInvocation):
                if method_invocation.qualifier == "Log" and method_invocation.member in ANDROID_LOGGING_METHODS:
                    position = method_invocation.position.line if method_invocation.position else None
                    if self.file_path not in self.detected_logs:
                        self.detected_logs[self.file_path] = set()
                    if position:
                        # log.warning removed to silence CLI output during vulnerability detection
                        self.detected_logs[self.file_path].add(position)

    def finalize(self):
        if self.detected_logs:
            descriptions = []
            for file, lines in self.detected_logs.items():
                line_list = ", ".join(str(ln) for ln in sorted(lines))
                descriptions.append(f"- {file} (lines: {line_list})")
            file_list_str = "\n".join(descriptions)

            description = (
                f"⚠️ Logging statements detected in {len(self.detected_logs)} file(s):\n"
                f"{file_list_str}\n"
                "⚠️ Ensure all logging is removed or disabled before releasing to production.\n"
                "Reference: https://developer.android.com/reference/android/util/Log.html"
            )

            self.issues.append(Issue(
                category=self.category,
                severity=self.severity,
                name="Logging statements detected",
                description=description,
                standard_id="MSTG-STORAGE-8",
                standard_description="Apps must not leak sensitive data through logs. Logging should be disabled in production builds.",
                owasp_refs=["M2", "M10"]
            ))

plugin = AndroidLogging()

