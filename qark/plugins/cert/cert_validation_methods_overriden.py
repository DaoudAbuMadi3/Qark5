# ✅ OWASP Mobile Top 10: M3 (Insecure Communication), M9
# ✅ MSTG-NETWORK-5: SSL certificate validation must not be bypassed.
# This plugin checks for unsafe overrides of checkServerTrusted and onReceivedSslError.

import logging
from javalang.tree import MethodDeclaration, MethodInvocation, ReturnStatement, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

CERT_METHODS = {"checkServerTrusted", "onReceivedSslError"}

DESC_CHECK_SERVER = "Instance of checkServerTrusted overridden insecurely. "
DESC_ON_RECEIVED_SSL = (
    "onReceivedSslError overridden insecurely, calls handler.proceed(). Vulnerable to MITM. "
    "https://developer.android.com/reference/android/webkit/WebViewClient.html"
)
MITM_DESCRIPTION = "Application vulnerable to Man-In-The-Middle attacks."

class CertValidation(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="network",  # updated from "cert"
            name="Certification Validation"
        )
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, method_declaration = (yield)
            if isinstance(method_declaration, MethodDeclaration) and method_declaration.name in CERT_METHODS:
                handler = getattr(self, f"_check_{method_declaration.name.lower()}", None)
                if handler:
                    handler(method_declaration)

    def _check_checkservertrusted(self, method, current_file=None):
        if not method.body:
            self._add_issue(
                "Empty checkServerTrusted",
                DESC_CHECK_SERVER + MITM_DESCRIPTION,
                method,
                override_severity=Severity.VULNERABILITY
            )
        elif len(method.body) == 1:
            stmt = method.body[0]
            if isinstance(stmt, ReturnStatement):
                if isinstance(stmt.expression, Literal) and stmt.expression.value in ("true", "null"):
                    self._add_issue(
                        "Insecure checkServerTrusted returning unsafe value",
                        DESC_CHECK_SERVER + "Returned: " + stmt.expression.value,
                        stmt,
                        override_severity=Severity.VULNERABILITY
                    )
                else:
                    self._add_issue(
                        "checkServerTrusted returns",
                        DESC_CHECK_SERVER + MITM_DESCRIPTION,
                        stmt
                    )

    def _check_onreceivedsslerror(self, method, current_file=None):
        for _, invocation in method.filter(MethodInvocation):
            if invocation.member == "proceed":
                self._add_issue(
                    "Insecure onReceivedSslError calls proceed()",
                    DESC_ON_RECEIVED_SSL,
                    invocation,
                    override_severity=Severity.VULNERABILITY
                )

    def _add_issue(self, name, desc, node, override_severity=None):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=name,
            severity=override_severity or self.severity,
            description=desc,
            file_object=self.file_path,
            line_number=node.position if hasattr(node, 'position') else None,
            standard_id="MSTG-NETWORK-5",
            standard_description="App does not properly validate SSL certificates, making it vulnerable to MITM attacks.",
            owasp_refs=["M3", "M9"]
        ))

plugin = CertValidation()

