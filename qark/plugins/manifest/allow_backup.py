# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage)
# ✅ MSTG-STORAGE-1: android:allowBackup should be false unless explicitly required and secured.
# This plugin detects if allowBackup is enabled, which may expose app data to adb or backup services.

from qark.scanner.plugin import ManifestPlugin
from qark.issue import Severity, Issue
import logging
 
log = logging.getLogger(__name__)

ALLOW_BACKUP_DESCRIPTION = (
    "Backups are enabled (android:allowBackup=\"true\"). This allows application data to be backed up via adb, "
    "which may lead to sensitive data leakage if USB debugging is enabled on a device. "
    "Consider setting android:allowBackup=\"false\" unless explicitly required. "
    "Reference: https://developer.android.com/reference/android/R.attr#allowBackup"
)

STANDARD_ID = "MSTG-STORAGE-1"
STANDARD_DESCRIPTION = "Do not allow backups unless required and secured."

class ManifestBackupAllowed(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="android:allowBackup enabled in manifest",
            description=ALLOW_BACKUP_DESCRIPTION
        )
        self.severity = Severity.VULNERABILITY  # upgraded from WARNING to VULNERABILITY

    def run(self):
        try:
            application_sections = self.manifest_xml.getElementsByTagName("application")

            for application in application_sections:
                if "android:allowBackup" in application.attributes.keys():
                    allow_backup_value = application.attributes["android:allowBackup"].value.strip().lower()
                    log.debug("Found android:allowBackup='%s' in %s", allow_backup_value, self.manifest_path)

                    if allow_backup_value == "true":
                        self.issues.append(Issue(
                            category=self.category,
                            severity=self.severity,
                            name=self.name,
                            description=self.description,
                            file_object=self.manifest_path,
                            line_number=self._get_line_number(application),
                            standard_id=STANDARD_ID,
                            standard_description=STANDARD_DESCRIPTION,
                            owasp_refs=["M2"]
                        ))
        except Exception as e:
            log.exception("[allow_backup] Failed to parse or process manifest: %s", e)

    def _get_line_number(self, node):
        """Helper method to extract line number if available."""
        return getattr(node, 'lineNumber', None)

plugin = ManifestBackupAllowed()

