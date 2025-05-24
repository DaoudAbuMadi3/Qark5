# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: WebViews should disable setAllowContentAccess unless explicitly needed.
# This plugin flags WebViews that may expose content:// URIs due to default access settings.

import logging
from qark.issue import Severity, Issue
from qark.plugins.webview.helpers import webview_default_vulnerable
from qark.scanner.plugin import JavaASTPlugin

log = logging.getLogger(__name__)
 
SET_ALLOW_CONTENT_ACCESS_DESCRIPTION_TEMPLATE = (
    "WebView '{webview_object}' does not explicitly disable content provider access "
    "(setAllowContentAccess(false) was not called). If the WebView loads untrusted input, "
    "this may allow unauthorized access to content URIs, leading to data leakage. "
    "🛠️ Recommendation: Call `webView.getSettings().setAllowContentAccess(false)` unless strictly required.\n\n"
    "To validate manually, load: file://qark/poc/html/WV_CPA_WARNING.html"
)

class SetAllowContentAccess(JavaASTPlugin):
    """Checks if setAllowContentAccess(false) is called; otherwise, the WebView remains vulnerable (default true)."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="WebView enables content access",
            description="Detects WebViews not explicitly disabling content access via setAllowContentAccess(false)."
        )
        self.severity = Severity.VULNERABILITY

    def run(self):
        issues = webview_default_vulnerable(
            tree=self.java_ast,
            method_name="setAllowContentAccess",
            issue_name=self.name,
            description=self.description,
            file_object=self.file_path,
            severity=self.severity
        )

        for issue in issues:
            position_info = f"line {getattr(issue.line_number, 'line', issue.line_number)}"
            # log.warning removed to silence CLI output during vulnerability detection

            issue.description = SET_ALLOW_CONTENT_ACCESS_DESCRIPTION_TEMPLATE.format(
                webview_object="WebView at " + position_info
            )
            issue.standard_id = "MSTG-PLATFORM-6"
            issue.standard_description = (
                "WebViews should disable access to content URIs unless explicitly required. "
                "Leaving setAllowContentAccess enabled may expose internal content providers."
            )
            issue.owasp_refs = ["M10"]

        self.issues.extend(issues)

plugin = SetAllowContentAccess()

