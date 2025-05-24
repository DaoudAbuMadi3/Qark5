# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: WebViews must disable universal file access to prevent cross-origin attacks.
# This plugin detects unsafe use of setAllowUniversalAccessFromFileURLs(true), which allows file:// pages to access network resources.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Issue, Severity
from qark.plugins.webview.helpers import webview_default_vulnerable, valid_set_method_bool
from qark.scanner.plugin import CoroutinePlugin, ManifestPlugin
 
log = logging.getLogger(__name__)

SET_ALLOW_UNIVERSAL_ACCESS_FROM_FILE_URLS_TEMPLATE = (
    "WebView '{webview_object}' allows universal access from file URLs "
    "(setAllowUniversalAccessFromFileURLs(true)). This exposes the app to JavaScript from file:// "
    "having access to all origins. Consider disabling or restricting this setting.\n\n"
    "🛠️ Recommendation: Avoid calling `setAllowUniversalAccessFromFileURLs(true)` unless absolutely required.\n"
    "📌 OWASP M10 - Extraneous Functionality\n"
    "📌 MSTG-PLATFORM-6 - WebViews must not allow universal access from file:// URLs.\n"
    "🔍 Manual Test: load file://qark/poc/html/UNIV_FILE_WARNING.html"
)

class SetAllowUniversalAccessFromFileURLs(CoroutinePlugin, ManifestPlugin):
    """Checks if setAllowUniversalAccessFromFileURLs(true) is called or defaults vulnerable for minSdk < 16."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="WebView enables universal access from file URLs",
            description="Detects enabling universal access from file URLs in WebView"
        )
        self.severity = Severity.VULNERABILITY
        self.java_method_name = "setAllowUniversalAccessFromFileURLs"

    def can_run_coroutine(self):
        if self.min_sdk <= 15:
            self.issues.extend(webview_default_vulnerable(
                self.java_ast,
                method_name=self.java_method_name,
                issue_name=self.name,
                description=SET_ALLOW_UNIVERSAL_ACCESS_FROM_FILE_URLS_TEMPLATE.format(webview_object="default WebView"),
                file_object=self.file_path,
                severity=self.severity
            ))
            return False
        return True

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if valid_set_method_bool(method_invocation, str_bool="true", method_name=self.java_method_name):
                webview_object = (getattr(method_invocation.qualifier, 'member', method_invocation.qualifier)
                                  if method_invocation.qualifier else "unknown")
                description = SET_ALLOW_UNIVERSAL_ACCESS_FROM_FILE_URLS_TEMPLATE.format(
                    webview_object=webview_object
                )
                issue_name = f"Universal access enabled on '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection
                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description,
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="Disabling setAllowUniversalAccessFromFileURLs prevents file:// pages from accessing remote URLs, mitigating XSS and SOP bypass attacks.",
                    owasp_refs=["M10"]
                ))

plugin = SetAllowUniversalAccessFromFileURLs()

