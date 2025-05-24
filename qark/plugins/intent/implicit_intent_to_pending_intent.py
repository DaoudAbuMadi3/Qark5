# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-6: PendingIntents must use explicit Intents only.
# This plugin detects cases where implicit Intents are passed into PendingIntent methods, making them hijackable.

import logging
import re
from javalang.tree import MethodInvocation, ClassCreator, ReferenceType
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

PENDING_INTENT_METHODS = ("getActivity", "getActivities", "getService", "getBroadcast")
PENDING_INTENT_REGEX = re.compile(r'\b({})\b'.format('|'.join(PENDING_INTENT_METHODS)))
 
DESCRIPTION_TEMPLATE = (
    "Detected implicit Intent passed into PendingIntent.{method}. "
    "For security reasons, always use explicit Intent (with setClass or setComponent). "
    "Otherwise, malicious apps may intercept or hijack this Intent. "
    "Reference: https://developer.android.com/reference/android/app/PendingIntent.html"
)

STANDARD_ID = "MSTG-PLATFORM-6"
STANDARD_DESCRIPTION = "PendingIntent must only be created using explicit Intents to avoid hijacking by malicious apps."

class ImplicitIntentToPendingIntent(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="intent",
                         name="Implicit Intent passed to PendingIntent",
                         description="Detects implicit Intents passed into PendingIntent methods which are hijackable.")
        self.severity = Severity.VULNERABILITY

    def can_run_coroutine(self):
        if not re.search(r'new\s+Intent', self.file_contents):
            return False
        if not re.search(PENDING_INTENT_REGEX, self.file_contents):
            return False
        if not any("PendingIntent" in imp.path for imp in self.java_ast.imports):
            return False
        return True

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if isinstance(method_invocation, MethodInvocation) and method_invocation.member in PENDING_INTENT_METHODS:
                for arg in method_invocation.arguments:
                    for _, creator in arg.filter(ClassCreator):
                        if any(ref.name == "Intent" for _, ref in creator.filter(ReferenceType)):
                            if len(creator.arguments) in (0, 1):  # 0 or 1 args typically indicates implicit
                                desc = DESCRIPTION_TEMPLATE.format(method=method_invocation.member)
                                # log.warning removed to silence CLI output during vulnerability detection
                                self.issues.append(Issue(
                                    category=self.category,
                                    severity=self.severity,
                                    name=f"Implicit Intent in PendingIntent.{method_invocation.member}",
                                    description=desc,
                                    file_object=self.file_path,
                                    line_number=method_invocation.position,
                                    standard_id=STANDARD_ID,
                                    standard_description=STANDARD_DESCRIPTION,
                                    owasp_refs=["M1"]
                                ))

plugin = ImplicitIntentToPendingIntent()

