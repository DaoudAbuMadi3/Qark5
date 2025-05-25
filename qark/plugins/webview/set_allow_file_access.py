# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: Avoid enabling file access in WebViews unless absolutely necessary.
# This plugin detects WebViews where setAllowFileAccess(false) was not called, leaving the app vulnerable to local file exposure.

import logging
from qark.issue import Severity, Issue
from qark.plugins.webview.helpers import webview_default_vulnerable
from qark.scanner.plugin import JavaASTPlugin

log = logging.getLogger(__name__)
 
SET_ALLOW_FILE_ACCESS_DESCRIPTION_TEMPLATE = (
    "WebView '{webview_object}' does not explicitly disable file access "
    "(setAllowFileAccess(false) was not called). If the WebView loads untrusted input, "
    "this may allow access to local files via `file://`, exposing sensitive data.\n\n"
    "🛠️ Recommendation: Call `webView.getSettings().setAllowFileAccess(false)` unless strictly required.\n"
    "📌 OWASP M10 - Extraneous Functionality\n"
    "📌 MSTG-PLATFORM-6 - Avoid file access in WebViews unless explicitly needed.\n"
    "🔍 Manual Test: load file:// paths and verify isolation from app-private files."
)

class SetAllowFileAccess(JavaASTPlugin):
    """Checks if setAllowFileAccess(false) is called; otherwise, the WebView may expose local file:// content."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="WebView enables file access",
            description="Detects WebViews not explicitly disabling file access via setAllowFileAccess(false)."
        )
        self.severity = Severity.VULNERABILITY

    def run(self):
        issues = webview_default_vulnerable(
            tree=self.java_ast,
            method_name="setAllowFileAccess",
            issue_name=self.name,
            description=self.description,
            file_object=self.file_path,
            severity=self.severity
        )

        for issue in issues:
            position_info = f"line {getattr(issue.line_number, 'line', issue.line_number)}"
            # log.warning removed to silence CLI output during vulnerability detection

            issue.description = SET_ALLOW_FILE_ACCESS_DESCRIPTION_TEMPLATE.format(
                webview_object="WebView at " + position_info
            )
            issue.standard_id = "MSTG-PLATFORM-6"
            issue.standard_description = (
                "WebViews should disable file access unless explicitly required. "
                "Enabling it may expose local files to malicious scripts."
            )
            issue.owasp_refs = ["M10"]

        self.issues.extend(issues)

plugin = SetAllowFileAccess()

