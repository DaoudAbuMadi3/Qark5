# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-10: Always enforce permissions strictly using enforceCallingPermission.
# This plugin detects use of relaxed permission-checking methods that may lead to unauthorized access.

import logging
import re
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import JavaASTPlugin

log = logging.getLogger(__name__)
 
CHECK_PERMISSIONS_DESCRIPTION = (
    "Use of {method_name} may expose app to Privilege Escalation or Confused Deputy attack. "
    "Consider replacing with {recommended_permission}CallingPermission for stricter security. "
    "Reference: https://developer.android.com/reference/android/content/Context.html"
)

CHECK_PERMISSION_METHODS = [
    "checkCallingOrSelfPermission",
    "checkCallingOrSelfUriPermission",
    "checkPermission",
    "enforceCallingOrSelfPermission",
    "enforceCallingOrSelfUriPermission",
    "enforcePermission"
]

STANDARD_ID = "MSTG-PLATFORM-10"
STANDARD_DESCRIPTION = (
    "Use strict permission-checking methods (e.g., enforceCallingPermission) to avoid privilege escalation."
)

class CheckPermissions(JavaASTPlugin):
    def __init__(self):
        super().__init__(category="generic",
                         name="Potentially insecure permission check",
                         description=CHECK_PERMISSIONS_DESCRIPTION)
        self.severity = Severity.WARNING
        self.permission_methods = set(CHECK_PERMISSION_METHODS)

    def run(self):
        for _, invocation in self.java_ast.filter(MethodInvocation):
            if invocation.member in self.permission_methods:
                recommended = invocation.member.replace("Self", "")
                desc = self.description.format(method_name=invocation.member,
                                               recommended_permission=recommended)
                self.issues.append(Issue(
                    category=self.category,
                    severity=self.severity,
                    name=f"Insecure permission method: {invocation.member}",
                    description=desc,
                    file_object=self.file_path,
                    line_number=invocation.position,
                    standard_id=STANDARD_ID,
                    standard_description=STANDARD_DESCRIPTION,
                    owasp_refs=["M1"]
                ))

plugin = CheckPermissions()

