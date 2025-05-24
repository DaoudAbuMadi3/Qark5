# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: Avoid enabling JavaScript in WebViews unless absolutely necessary.
# This plugin flags uses of setJavaScriptEnabled(true) which may expose the app to XSS or code injection attacks.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.plugins.webview.helpers import valid_set_method_bool
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

JAVASCRIPT_ENABLED_DESCRIPTION_TEMPLATE = (
    "WebView '{webview_object}' has JavaScript enabled (setJavaScriptEnabled(true)). "
    "If not explicitly required, consider disabling it to mitigate XSS or code injection risks. "
    "More info: http://developer.android.com/guide/practices/security.html. "
    "🛠️ Recommendation: Disable JavaScript unless rendering controlled content. "
    "If enabled, avoid loading remote URLs or user-influenced content."
)

class JavascriptEnabled(CoroutinePlugin):
    """Checks if setJavaScriptEnabled(true) is called on a WebView."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="JavaScript enabled in WebView",
            description="Detects WebViews with setJavaScriptEnabled(true)"
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if valid_set_method_bool(method_invocation, str_bool="true", method_name="setJavaScriptEnabled"):
                webview_object = (getattr(method_invocation.qualifier, 'member', method_invocation.qualifier)
                                  if method_invocation.qualifier else "unknown")
                description = JAVASCRIPT_ENABLED_DESCRIPTION_TEMPLATE.format(webview_object=webview_object)
                issue_name = f"JavaScript enabled in '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description + "\n\n"
                        "📌 OWASP M10 - Extraneous Functionality\n"
                        "📌 MSTG-PLATFORM-6 - JavaScript must not be enabled in WebViews unless strictly required and content is controlled.",
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="JavaScript must not be enabled in WebViews unless strictly required and content is controlled.",
                    owasp_refs=["M10"]
                ))

plugin = JavascriptEnabled()

