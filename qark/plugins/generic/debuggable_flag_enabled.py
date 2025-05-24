# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-7: Apps must not be debuggable in release builds.
# This plugin checks if the AndroidManifest contains android:debuggable="true"

import logging
from qark.issue import Issue, Severity
from qark.scanner.plugin import ManifestPlugin
from xml.etree import ElementTree as ET

log = logging.getLogger(__name__)

class DebuggableFlagPlugin(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="generic",
            name="Debuggable flag is set to true",
            description="Application is marked as debuggable in AndroidManifest.xml. This should be disabled in production."
        )
        self.severity = Severity.VULNERABILITY

    def run(self):
        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()

            for app in root.iter("application"):
                if app.get("{http://schemas.android.com/apk/res/android}debuggable") == "true":
                    # log.warning removed to silence CLI output during vulnerability detection
                    self.issues.append(Issue(
                        category=self.category,
                        name=self.name,
                        severity=self.severity,
                        description="Application is debuggable (android:debuggable=\"true\"). This should be false in production builds.\n\n"
                                    "📌 OWASP M10\n"
                                    "📌 MSTG-PLATFORM-7",
                        file_object=self.manifest_path,
                        line_number=None,
                        standard_id="MSTG-PLATFORM-7",
                        standard_description="Apps must not be debuggable in release builds.",
                        owasp_refs=["M10"]
                    ))

        except Exception as e:
            log.error(f"[debuggable_flag] Error parsing AndroidManifest: {e}")

plugin = DebuggableFlagPlugin()

