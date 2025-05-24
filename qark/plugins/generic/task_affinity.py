# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-8: Misconfigured taskAffinity or misuse of intent flags can allow task hijacking.
# This plugin detects usage of FLAG_ACTIVITY_NEW_TASK or FLAG_ACTIVITY_MULTIPLE_TASK that may lead to task hijacking.

import logging
import re
from javalang.tree import MemberReference, MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import JavaASTPlugin

log = logging.getLogger(__name__)

TASK_AFFINITY_DESCRIPTION = (
    "Usage of {flag_name} may allow Task Hijacking vulnerability. "
    "Reference: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
) 

TASK_FLAGS = {
    "FLAG_ACTIVITY_NEW_TASK",
    "FLAG_ACTIVITY_MULTIPLE_TASK"
}

STANDARD_ID = "MSTG-PLATFORM-8"
STANDARD_DESCRIPTION = (
    "Misuse of intent flags like FLAG_ACTIVITY_NEW_TASK or incorrect taskAffinity settings can lead to task hijacking attacks."
)

class TaskAffinity(JavaASTPlugin):
    def __init__(self):
        super().__init__(category="generic",
                         name="Potential Task Hijacking",
                         description=TASK_AFFINITY_DESCRIPTION)
        self.severity = Severity.WARNING

    def run(self):
        for _, node in self.java_ast.filter((MemberReference, MethodInvocation)):
            flag_detected = None
            if isinstance(node, MemberReference) and node.member in TASK_FLAGS:
                flag_detected = node.member
            elif isinstance(node, MethodInvocation):
                for arg in node.arguments:
                    if hasattr(arg, 'member') and arg.member in TASK_FLAGS:
                        flag_detected = arg.member
            if flag_detected:
                desc = self.description.format(flag_name=flag_detected)
                # log.warning removed to silence CLI output during vulnerability detection
                self.issues.append(Issue(
                    category=self.category,
                    severity=self.severity,
                    name=f"Task flag used: {flag_detected}",
                    description=desc,
                    file_object=self.file_path,
                    line_number=node.position,
                    standard_id=STANDARD_ID,
                    standard_description=STANDARD_DESCRIPTION,
                    owasp_refs=["M1"]
                ))

plugin = TaskAffinity()

