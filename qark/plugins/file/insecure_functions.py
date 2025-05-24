# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-9: The 'call' method of ContentProvider must have explicit permission checks.
# This plugin detects exposed 'call' methods that do not include enforceCallingPermission or similar protection.

import logging
from javalang.tree import MethodDeclaration, MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

INSECURE_FUNCTIONS_DESCRIPTION = (
    "The ContentProvider API exposes the 'call' method without enforced permission checks by default. "
    "Developers must manually enforce permissions inside this method. Failure to do so can lead to unauthorized access. "
    "Reference: https://developer.android.com/reference/android/content/ContentProvider#call(java.lang.String,%20java.lang.String,%20android.os.Bundle)"
)
 
INSECURE_FUNCTIONS_NAMES = {"call"}
SECURITY_CHECK_METHODS = {"checkCallingPermission", "enforceCallingPermission"}

STANDARD_ID = "MSTG-PLATFORM-9"
STANDARD_DESCRIPTION = (
    "ContentProvider methods like 'call' must enforce explicit permission checks."
)

class InsecureFunctions(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="ipc", name="Insecure ContentProvider function",
                         description=INSECURE_FUNCTIONS_DESCRIPTION)
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodDeclaration) and node.name in INSECURE_FUNCTIONS_NAMES:
                log.debug("Detected method '%s' at line %s in %s", node.name, getattr(node.position, 'line', '?'), self.file_path)
                if not self._has_permission_check(node):
                    # log.warning removed to silence CLI output during vulnerability detection
                    self.issues.append(Issue(
                        category=self.category,
                        severity=self.severity,
                        name=f"Insecure function: {node.name}",
                        description=self.description,
                        file_object=self.file_path,
                        line_number=node.position,
                        standard_id=STANDARD_ID,
                        standard_description=STANDARD_DESCRIPTION,
                        owasp_refs=["M1"]
                    ))

    def _has_permission_check(self, method_node):
        if not method_node.body:
            return False
        for _, invocation in method_node.filter(MethodInvocation):
            if invocation.member in SECURITY_CHECK_METHODS:
                log.debug("Permission check detected: %s at line %s", invocation.member, getattr(invocation.position, 'line', '?'))
                return True
        return False

plugin = InsecureFunctions()

