# ✅ OWASP Mobile Top 10: M8 (Code Tampering)
# ✅ MSTG-RESILIENCE-1/2/3: Root detection must be resilient and enforced, not bypassable.
# This plugin detects weak or ineffective root detection patterns in Java code.

import logging
import re
from javalang.tree import Literal, MethodInvocation
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)
 
# Weak root detection indicators
ROOT_PATTERNS = [
    r"/system/bin/su",
    r"/system/xbin/su",
    r"/system/app/Superuser.apk",
    r"test-keys",
    r"/sbin/su",
    r"/vendor/bin/su",
    r"magisk",
    r"rootcloak",
]

class RootDetectionBypassPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="generic",
            name="Weak or ineffective root detection",
            description="Detects presence of ineffective root detection logic that can be bypassed easily."
        )
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, Literal) and isinstance(node.value, str):
                val = node.value.strip('"').strip("'")
                if any(p in val.lower() for p in ROOT_PATTERNS):
                    self._report(node, val)

    def _report(self, node, value):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=self.name,
            severity=self.severity,
            description=f"Found weak root detection indicator: `{value}`. Root detection must include enforcement.\n\n"
                        "📌 OWASP M8\n📌 MSTG-RESILIENCE-1/2",
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-RESILIENCE-1",
            standard_description="Root detection must include mitigation. Detection-only logic is insufficient.",
            owasp_refs=["M8"]
        ))

plugin = RootDetectionBypassPlugin()

