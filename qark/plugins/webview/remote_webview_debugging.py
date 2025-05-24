# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: setWebContentsDebuggingEnabled(true) must be disabled in production.
# This plugin flags WebView instances where remote debugging is enabled, which can expose sensitive data or allow runtime JavaScript injection.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.plugins.webview.helpers import valid_set_method_bool
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)
 
JAVASCRIPT_REMOTE_DEBUGGING_TEMPLATE = (
    "WebView '{webview_object}' enables remote debugging via setWebContentsDebuggingEnabled(true). "
    "This exposes the WebView to debugging from connected debuggers, which may allow access to JavaScript context, sensitive data, and application internals. "
    "🛠️ Recommendation: Disable WebView debugging (`setWebContentsDebuggingEnabled(false)`) in production builds. "
    "Reference: https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean)"
)

class RemoteDebugging(CoroutinePlugin):
    """Detects if setWebContentsDebuggingEnabled(true) is used in WebView."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="Remote debugging enabled in WebView",
            description="Detects use of setWebContentsDebuggingEnabled(true) in WebView."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if valid_set_method_bool(method_invocation, str_bool="true", method_name="setWebContentsDebuggingEnabled"):
                webview_object = (getattr(method_invocation.qualifier, 'member', method_invocation.qualifier)
                                  if method_invocation.qualifier else "unknown")
                description = JAVASCRIPT_REMOTE_DEBUGGING_TEMPLATE.format(webview_object=webview_object)
                issue_name = f"Remote debugging enabled on '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description + "\n\n"
                        "📌 OWASP M10 - Extraneous Functionality\n"
                        "📌 MSTG-PLATFORM-6 - Do not allow WebView remote debugging in production.",
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="WebViews must not be remotely debuggable in production environments.",
                    owasp_refs=["M10"]
                ))

plugin = RemoteDebugging()

