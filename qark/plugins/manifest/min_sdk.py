# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-1: Apps must avoid setting minSdkVersion below 9 to mitigate TapJacking risks.
# This plugin flags apps with minSdkVersion < 9 as vulnerable to interface overlay attacks.

import logging
from qark.issue import Issue, Severity
from qark.plugins.manifest_helpers import get_min_sdk
from qark.scanner.plugin import ManifestPlugin
 
log = logging.getLogger(__name__)

TAP_JACKING_TEMPLATE = (
    "MinSdkVersion is set to {min_sdk}, which is less than 9. "
    "This may leave the application vulnerable to TapJacking attacks. "
    "Consider setting minSdkVersion >= 9 or implementing custom protections. "
    "For more info: https://media.blackhat.com/ad-12/Niemietz/bh-ad-12-androidmarcus_niemietz-WP.pdf"
)

class MinSDK(ManifestPlugin):
    """
    This plugin checks if minSdkVersion is less than 9, which may leave the app vulnerable to TapJacking.
    It flags this configuration as a VULNERABILITY according to MSTG and OWASP guidelines.
    """
    def __init__(self):
        super().__init__(name="MinSDK checks", category="manifest")
        self.severity = Severity.WARNING

    def run(self):
        try:
            log.debug("Detected minSdkVersion=%s in %s", self.min_sdk, self.manifest_path)
            if self.min_sdk < 9:
                description = TAP_JACKING_TEMPLATE.format(min_sdk=self.min_sdk)
                self.issues.append(Issue(
                    category=self.category,
                    name="TapJacking possible (minSdkVersion < 9)",
                    severity=Severity.VULNERABILITY,
                    description=description,
                    file_object=self.manifest_path,
                    line_number=self._get_line_number(),
                    standard_id="MSTG-PLATFORM-1",
                    standard_description="Apps should not set minSdkVersion below 9 due to known vulnerabilities like TapJacking in earlier Android versions.",
                    owasp_refs=["M1"]
                ))
        except Exception as e:
            log.exception("Error while processing minSdkVersion check: %s", e)

    def _get_line_number(self):
        """Try to get line number from manifest parser (if supported)."""
        return None

plugin = MinSDK()

