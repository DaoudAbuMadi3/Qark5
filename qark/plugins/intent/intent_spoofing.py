# ✅ OWASP Mobile Top 10: M1, M9 (Improper Platform Usage, Insecure Communication)
# ✅ MSTG-PLATFORM-9: External Intents must be verified before use.
# This plugin detects usage of getXExtra() from Intents without validation, which may allow spoofing.

import logging
from javalang.tree import MethodInvocation, MemberReference
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin
 
log = logging.getLogger(__name__)

INTENT_EXTRA_GETTERS = {
    "getStringExtra", "getIntExtra", "getBooleanExtra", "getParcelableExtra",
    "getSerializableExtra", "getExtras", "getDoubleExtra", "getCharSequenceExtra"
}

SUSPICIOUS_SOURCES = {"getIntent", "intent", "incomingIntent"}

STANDARD_ID = "MSTG-PLATFORM-9"
STANDARD_DESCRIPTION = "The app must validate external Intents before trusting their content or origin."

class IntentSpoofingPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="intent",
            name="Intent spoofing",
            description="Detects use of getXExtra() methods from Intents without validating the origin, which may be spoofed."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in INTENT_EXTRA_GETTERS:
                    if isinstance(node.qualifier, MemberReference):
                        if node.qualifier.member in SUSPICIOUS_SOURCES:
                            # log.warning removed to silence CLI output during vulnerability detection
                            self.issues.append(Issue(
                                category=self.category,
                                name="Intent spoofing",
                                severity=self.severity,
                                description=(
                                    f"Method `{node.member}` called on `{node.qualifier.member}`. "
                                    "This may allow spoofed Intents to inject arbitrary data.\n\n"
                                    "📌 OWASP M1/M9 - Improper Platform Usage / Insecure Communication\n"
                                    "📌 MSTG-PLATFORM-9 - Validate Intent source or use explicit Intents only.\n"
                                    "🛠️ Check caller identity or use `getCallingPackage()` and clear restrictions."
                                ),
                                file_object=self.file_path,
                                line_number=node.position,
                                standard_id=STANDARD_ID,
                                standard_description=STANDARD_DESCRIPTION,
                                owasp_refs=["M1", "M9"]
                            ))

plugin = IntentSpoofingPlugin()

