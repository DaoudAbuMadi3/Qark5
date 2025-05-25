# ✅ OWASP Mobile Top 10: M3 (Insecure Communication)
# ✅ MSTG-NETWORK-5: HostnameVerifier must not bypass hostname validation.
# This plugin detects insecure HostnameVerifier usage that may expose the app to MITM attacks.

import logging
from javalang.tree import ClassCreator, MethodInvocation, MethodDeclaration, Literal, ReturnStatement
 
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

DESC_HOSTNAME = ("Insecure HostnameVerifier detected. Application may skip hostname validation. "
                 "Vulnerable to MITM attacks. See: "
                 "https://developer.android.com/training/articles/security-ssl.html")

DANGEROUS_CLASSES = {"AllowAllHostnameVerifier", "NullHostNameVerifier", "NullHostnameVerifier"}

STANDARD_ID = "MSTG-NETWORK-5"
STANDARD_DESCRIPTION = (
    "App must properly validate hostnames during SSL connections to prevent MITM attacks."
)

class HostnameVerifier(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="network", name="Hostname Verifier")
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, ClassCreator):
                if node.type.name in DANGEROUS_CLASSES:
                    self._add_issue("Insecure HostnameVerifier class", DESC_HOSTNAME, node, Severity.VULNERABILITY)
            elif isinstance(node, MethodInvocation):
                if (node.member == "setHostnameVerifier"
                        and len(node.arguments) == 1
                        and hasattr(node.arguments[0], 'member')
                        and node.arguments[0].member == "ALLOW_ALL_HOSTNAME_VERIFIER"):
                    self._add_issue("setHostnameVerifier(ALLOW_ALL)", DESC_HOSTNAME, node, Severity.VULNERABILITY)
            elif isinstance(node, MethodDeclaration) and node.name == "verify":
                if node.body and len(node.body) == 1 and isinstance(node.body[0], ReturnStatement):
                    ret = node.body[0]
                    if isinstance(ret.expression, Literal) and ret.expression.value == "true":
                        self._add_issue("Custom HostnameVerifier always returns true", DESC_HOSTNAME, ret, Severity.VULNERABILITY)

    def _add_issue(self, name, desc, node, severity=Severity.WARNING):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=name,
            severity=severity,
            description=desc,
            file_object=self.file_path,
            line_number=node.position if hasattr(node, 'position') else None,
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION,
            owasp_refs=["M3"]
        ))

plugin = HostnameVerifier()

