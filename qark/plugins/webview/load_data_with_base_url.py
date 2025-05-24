# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-6: Avoid unsafe use of loadDataWithBaseURL.
# This plugin detects use of WebView.loadDataWithBaseURL, which may allow cross-domain injection if the baseUrl is untrusted.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin
from qark.plugins.webview.helpers import valid_method_invocation

log = logging.getLogger(__name__)
 
LOAD_DATA_WITH_BASE_URL_DESCRIPTION_TEMPLATE = (
    "WebView '{webview_object}' calls loadDataWithBaseURL with base URL: {base_url}. "
    "This can be dangerous if the base URL is untrusted, because it allows JavaScript injection "
    "and cross-domain access within the WebView. Avoid using loadDataWithBaseURL with remote or user-influenced URLs. "
    "🛠️ Recommendation: Load only trusted content and avoid enabling JavaScript unless strictly necessary."
)

class LoadDataWithBaseURL(CoroutinePlugin):
    """Checks if loadDataWithBaseURL is called, which may introduce injection risks if not controlled."""
    def __init__(self):
        super().__init__(
            category="webview",
            name="loadDataWithBaseURL usage detected",
            description="Detects use of WebView.loadDataWithBaseURL, which may expose app to injection or XSS."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if not isinstance(method_invocation, MethodInvocation):
                continue

            if valid_method_invocation(method_invocation, "loadDataWithBaseURL", num_arguments=5):
                base_url_arg = getattr(method_invocation.arguments[0], "value", getattr(method_invocation.arguments[0], "member", "<unknown>"))
                webview_object = getattr(method_invocation.qualifier, 'member', method_invocation.qualifier) if method_invocation.qualifier else "unknown"

                description = LOAD_DATA_WITH_BASE_URL_DESCRIPTION_TEMPLATE.format(
                    webview_object=webview_object,
                    base_url=base_url_arg
                )
                issue_name = f"loadDataWithBaseURL on '{webview_object}'"

                # log.warning removed to silence CLI output during vulnerability detection

                self.issues.append(Issue(
                    category=self.category,
                    name=issue_name,
                    severity=self.severity,
                    description=description + "\n\n"
                        "📌 OWASP M10 - Extraneous Functionality\n"
                        "📌 MSTG-PLATFORM-6 - Avoid untrusted base URLs when using loadDataWithBaseURL().",
                    file_object=self.file_path,
                    line_number=method_invocation.position,
                    standard_id="MSTG-PLATFORM-6",
                    standard_description="Avoid using loadDataWithBaseURL unless the base URL and content are strictly controlled. This can allow injection attacks across domains.",
                    owasp_refs=["M10"]
                ))

plugin = LoadDataWithBaseURL()

