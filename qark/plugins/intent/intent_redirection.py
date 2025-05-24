# ✅ OWASP Mobile Top 10: M9 (Insecure Communication)
# ✅ MSTG-PLATFORM-10: Intent redirection must be avoided by validating Intent targets.
# This plugin detects flows where received Intent is passed to startActivity/startService without validation.

import logging
from javalang.tree import MethodInvocation, MemberReference
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

REDIRECT_TARGETS = {"startActivity", "startService", "startForegroundService"}
 
class IntentRedirectionPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="intent",
            name="Intent redirection without validation",
            description="Detects usage of external Intent forwarded without validating its target."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in REDIRECT_TARGETS:
                    for arg in node.arguments:
                        if isinstance(arg, MemberReference) and "intent" in arg.member.lower():
                            self._add_issue(node)

    def _add_issue(self, node):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=self.name,
            severity=self.severity,
            description=(
                "An external Intent is passed to a sensitive method like `startActivity()` without verifying its target.\n"
                "This can allow an attacker to redirect execution to arbitrary components.\n\n"
                "📌 OWASP M9\n📌 MSTG-PLATFORM-10"
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-PLATFORM-10",
            standard_description="Application must validate all external Intents before use to prevent redirection.",
            owasp_refs=["M9"]
        ))

plugin = IntentRedirectionPlugin()

