# ✅ OWASP Mobile Top 10: M10 (Extraneous Functionality)
# ✅ MSTG-PLATFORM-7: android:debuggable should be false in release builds.
# This plugin detects if an app is marked as debuggable, which enables ADB access and runtime inspection.

from qark.scanner.plugin import ManifestPlugin
from qark.issue import Severity, Issue
import logging

log = logging.getLogger(__name__)
 
DEBUGGABLE_DESCRIPTION = (
    "The android:debuggable flag is manually set to 'true' in the AndroidManifest.xml. "
    "This will cause the application to be debuggable in production builds, exposing it to security risks such as "
    "data leakage and runtime code inspection. It is recommended to remove this attribute from the manifest and let "
    "the build tools set it automatically. "
    "Reference: https://developer.android.com/guide/topics/manifest/application-element#debug"
)

STANDARD_ID = "MSTG-PLATFORM-7"
STANDARD_DESCRIPTION = "android:debuggable must be false in production builds."

class DebuggableManifest(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="Manifest sets android:debuggable=\"true\"",
            description=DEBUGGABLE_DESCRIPTION
        )
        self.severity = Severity.VULNERABILITY

    def run(self):
        try:
            application_sections = self.manifest_xml.getElementsByTagName("application")
            for application in application_sections:
                debuggable_attr = application.attributes.get("android:debuggable")
                if debuggable_attr:
                    debuggable_value = debuggable_attr.value.strip().lower()
                    log.debug("android:debuggable found with value='%s' in %s", debuggable_value, self.manifest_path)
                    if debuggable_value == "true":
                        self.issues.append(Issue(
                            category=self.category,
                            severity=self.severity,
                            name=self.name,
                            description=self.description,
                            file_object=self.manifest_path,
                            line_number=self._get_line_number(application),
                            standard_id=STANDARD_ID,
                            standard_description=STANDARD_DESCRIPTION,
                            owasp_refs=["M10"]
                        ))
                else:
                    log.debug("No android:debuggable attribute found in <application> element")
        except Exception as e:
            log.exception("Error while parsing manifest in debuggable plugin: %s", e)

    def _get_line_number(self, node):
        """Extracts line number if available from the XML parser."""
        return getattr(node, 'lineNumber', None)

plugin = DebuggableManifest()

