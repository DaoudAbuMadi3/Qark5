# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: Avoid exposing Java interfaces via WebView unless strictly controlled.
# This plugin detects usage of addJavascriptInterface() in apps targeting minSdkVersion < 17.

import logging
from qark.issue import Issue, Severity
from qark.plugins.helpers import valid_method_invocation
from qark.scanner.plugin import CoroutinePlugin, ManifestPlugin

log = logging.getLogger(__name__)
 
ADD_JAVASCRIPT_INTERFACE_DESCRIPTION_TEMPLATE = (
    "WebView '{webview_object}' uses addJavascriptInterface in an app targeting minSdkVersion={min_sdk} (API < 17). "
    "This exposes all public Java methods to JavaScript running in the WebView, which may lead to remote code execution "
    "if untrusted content is loaded. "
    "🛠️ Recommendation: Avoid using addJavascriptInterface below API 17, or validate loaded content and restrict Java interfaces. "
    "Reference: https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/"
)

class AddJavascriptInterface(CoroutinePlugin, ManifestPlugin):
    """Checks if addJavascriptInterface() is called in apps targeting API < 17."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="addJavascriptInterface used pre-API 17",
            description="Detects usage of addJavascriptInterface in apps targeting API < 17"
        )
        self.severity = Severity.VULNERABILITY
        self.java_method_name = "addJavascriptInterface"

    def can_run_coroutine(self):
        log.debug("minSdkVersion=%s; eligible for scanning: %s", self.min_sdk, self.min_sdk <= 16)
        return self.min_sdk <= 16

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if valid_method_invocation(method_invocation, method_name=self.java_method_name, num_arguments=2):
                webview_object = getattr(method_invocation.qualifier, 'member', method_invocation.qualifier) if method_invocation.qualifier else "unknown"
                description = ADD_JAVASCRIPT_INTERFACE_DESCRIPTION_TEMPLATE.format(
                    webview_object=webview_object,
                    min_sdk=self.min_sdk
                )
                issue_name = f"addJavascriptInterface on '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description + "\n\n"
                        "📌 OWASP M10 - Extraneous Functionality\n"
                        "📌 MSTG-PLATFORM-6 - Avoid exposing Java methods to JavaScript in insecure environments.",
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="Avoid using addJavascriptInterface on apps targeting API < 17, as it may expose Java methods to remote code execution.",
                    owasp_refs=["M10"]
                ))

plugin = AddJavascriptInterface()

