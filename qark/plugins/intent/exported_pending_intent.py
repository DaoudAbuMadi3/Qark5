# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-6: PendingIntents should not point to exported components.
# This plugin checks for creation of PendingIntents targeting exported Activities, Services, or BroadcastReceivers.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin
from xml.etree import ElementTree as ET

log = logging.getLogger(__name__)

PENDING_INTENT_METHODS = {
    "getActivity",
    "getBroadcast",
    "getService",
    "getForegroundService"
}

class ExportedPendingIntentPlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="intent",
            name="PendingIntent targets exported component",
            description="Detects if PendingIntent may reference an exported component, which could be abused by external apps."
        )
        self.severity = Severity.VULNERABILITY
        self.exported_components = set()

    def run(self):
        self._load_exported_components()
        yield from self.run_coroutine()

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                if node.member in PENDING_INTENT_METHODS:
                    # ❗ Here the intent context is not checked directly.
                    self._add_issue(node)

    def _load_exported_components(self):
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            for tag in root.iter():
                name = tag.get("{http://schemas.android.com/apk/res/android}name")
                exported = tag.get("{http://schemas.android.com/apk/res/android}exported")
                if name and exported == "true":
                    self.exported_components.add(name.split('.')[-1])
        except Exception as e:
            log.error(f"[PendingIntent] Failed to parse manifest: {e}")

    def _add_issue(self, node):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=self.name,
            severity=self.severity,
            description="PendingIntent is created and might reference an exported component.\n"
                        "This can allow malicious apps to hijack the intent or invoke internal functionality.\n\n"
                        "📌 OWASP M1\n📌 MSTG-PLATFORM-6",
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-PLATFORM-6",
            standard_description="PendingIntent should never target exported or externally accessible components.",
            owasp_refs=["M1"]
        ))

plugin = ExportedPendingIntentPlugin()

