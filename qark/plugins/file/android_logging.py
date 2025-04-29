import logging
from javalang.tree import MethodInvocation
from issue import Severity, Issue
from scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

ANDROID_LOGGING_DESCRIPTION = (
    "Logs are detected. This may allow potential leakage of information from Android applications. "
    "Logs should never be compiled into an application except during development. "
    "Reference: https://developer.android.com/reference/android/util/Log.html"
)

ANDROID_LOGGING_METHODS = ("v", "d", "i", "w", "e")


class AndroidLogging(CoroutinePlugin):
    def __init__(self):
        super(AndroidLogging, self).__init__(category="file", name="Logging found",
                                             description=ANDROID_LOGGING_DESCRIPTION)
        self.severity = Severity.WARNING
        self.detected_logging_files = set()

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if method_invocation.qualifier == "Log" and method_invocation.member in ANDROID_LOGGING_METHODS:
                self.detected_logging_files.add(self.file_path)

    def finalize(self):
        if self.detected_logging_files:
            file_list_str = "\n".join(f"- {file}" for file in sorted(self.detected_logging_files))

            description = (
                f"⚠️ Logging statements were detected in {len(self.detected_logging_files)} files:\n"
                f"{file_list_str}\n"
                "⚠️ Make sure to remove all logging before releasing to production.\n"
                "Reference: https://developer.android.com/reference/android/util/Log.html"
            )

            self.issues.append(Issue(
                category=self.category,
                severity=self.severity,
                name="Logging found in multiple files",
                description=description
            ))


plugin = AndroidLogging()
