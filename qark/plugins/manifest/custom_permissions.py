# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-5: Custom permissions must use secure protection levels and avoid 'signatureOrSystem' especially on Android < 10.
# This plugin detects insecure use of custom permissions with weak protection levels.

from qark.scanner.plugin import ManifestPlugin
import logging
from qark.issue import Severity, Issue

log = logging.getLogger(__name__)
 
SIGNATURE_OR_SYSTEM_DESCRIPTION = (
    "Permission uses 'signatureOrSystem', which is insecure on Android < 10 (API < 29). "
    "On older systems, apps signed by different keys but in /system can gain this permission. "
    "Consider replacing with 'signature'."
)

DANGEROUS_DESCRIPTION = (
    "Permission marked as 'dangerous'. Ensure it's used only when necessary and protected appropriately."
)

STANDARD_ID = "MSTG-PLATFORM-5"
STANDARD_DESCRIPTION = (
    "Custom permissions must use secure protection levels and be validated by signature, especially on older Android versions."
)

class CustomPermissions(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="Custom permissions defined in manifest",
            description="Detects custom permissions with potentially insecure protection levels depending on Android version."
        )
        self.severity = Severity.WARNING

    def run(self):
        try:
            permission_sections = self.manifest_xml.getElementsByTagName("permission")

            for permission in permission_sections:
                protection_level = permission.attributes.get("android:protectionLevel")
                protection_value = protection_level.value.strip() if protection_level else "normal"

                line_number = self._get_line_number(permission)

                # Only analyze versions from API 21 (Android 5.0) to API 34 (Android 14)
                if not (21 <= self.target_sdk <= 34):
                    log.debug(f"Skipping version {self.target_sdk} outside supported range")
                    continue

                log.debug("Found <permission> with protectionLevel='%s' in %s", protection_value, self.manifest_path)

                if protection_value == "signatureOrSystem":
                    severity = Severity.VULNERABILITY if self.target_sdk < 29 else Severity.INFO
                    self.issues.append(Issue(
                        category=self.category,
                        severity=severity,
                        name="Insecure custom permission: signatureOrSystem",
                        description=SIGNATURE_OR_SYSTEM_DESCRIPTION,
                        file_object=self.manifest_path,
                        line_number=line_number,
                        standard_id=STANDARD_ID,
                        standard_description=STANDARD_DESCRIPTION,
                        owasp_refs=["M1"]
                    ))

                elif protection_value == "dangerous":
                    severity = Severity.WARNING if self.target_sdk <= 28 else Severity.INFO
                    self.issues.append(Issue(
                        category=self.category,
                        severity=severity,
                        name="Custom permission with protectionLevel='dangerous'",
                        description=DANGEROUS_DESCRIPTION,
                        file_object=self.manifest_path,
                        line_number=line_number,
                        standard_id=STANDARD_ID,
                        standard_description=STANDARD_DESCRIPTION,
                        owasp_refs=["M1"]
                    ))
        except Exception as e:
            log.exception("Error while processing custom permissions: %s", e)

    def _get_line_number(self, node):
        return getattr(node, 'lineNumber', None)

plugin = CustomPermissions()

