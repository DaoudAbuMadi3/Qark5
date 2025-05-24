# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: Avoid enabling DOM storage in WebViews unless necessary.
# This plugin detects uses of setDomStorageEnabled(true), which may cache sensitive data locally.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Issue, Severity
from qark.plugins.webview.helpers import valid_set_method_bool
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

SET_DOM_STORAGE_ENABLED_TEMPLATE = (
    "WebView '{webview_object}' enables DOM Storage (setDomStorageEnabled(true)). "
    "Enabling DOM Storage can lead to caching sensitive data locally, potentially accessible by other code or apps. "
    "Review its necessity and ensure appropriate controls are in place.\n\n"
    "📌 OWASP M10 - Extraneous Functionality\n"
    "📌 MSTG-PLATFORM-6 - Avoid enabling DOM Storage unless required.\n"
    "🛠️ Recommendation: Only enable DOM storage if absolutely needed and ensure local data is cleared and protected."
)

class SetDomStorageEnabled(CoroutinePlugin):
    """Checks if setDomStorageEnabled(true) is called on a WebView."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="WebView enables DOM Storage",
            description="Detects use of setDomStorageEnabled(true) in WebView."
        )
        self.severity = Severity.WARNING
        self.java_method_name = "setDomStorageEnabled"

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if valid_set_method_bool(method_invocation, str_bool="true", method_name=self.java_method_name):
                webview_object = (getattr(method_invocation.qualifier, 'member', method_invocation.qualifier)
                                  if method_invocation.qualifier else "unknown")
                description = SET_DOM_STORAGE_ENABLED_TEMPLATE.format(webview_object=webview_object)
                issue_name = f"DOM Storage enabled on '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description,
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="Enabling DOM storage in WebViews may expose cached sensitive data to attacks or unauthorized access.",
                    owasp_refs=["M10"]
                ))

plugin = SetDomStorageEnabled()

