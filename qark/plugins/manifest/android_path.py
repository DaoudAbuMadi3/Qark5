# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-5: When exposing ContentProviders, path matching should be precise.
# This plugin detects usage of android:path, pathPattern, or pathPrefix that may cause mismatches.
 
import logging
from qark.issue import Severity, Issue
from qark.scanner.plugin import ManifestPlugin

log = logging.getLogger(__name__)

PATH_USAGE_DESCRIPTION = (
    "android:path (or pathPattern/pathPrefix) limits permissions to the exact path defined, "
    "but **does not apply to subdirectories or other matching paths**. Ensure this is intentional. "
    "Reference: https://developer.android.com/reference/android/R.attr.html#path"
)

PATH_ATTRIBUTES = {"android:path", "android:pathPattern", "android:pathPrefix"}

STANDARD_ID = "MSTG-PLATFORM-5"
STANDARD_DESCRIPTION = (
    "Be explicit with path, pathPattern, and pathPrefix to avoid unintended ContentProvider access."
)

class AndroidPath(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="Usage of android:path, android:pathPattern, or android:pathPrefix",
            description=PATH_USAGE_DESCRIPTION
        )
        self.severity = Severity.WARNING

    def run(self):
        try:
            all_elements = self.manifest_xml.getElementsByTagName("*")
            for element in all_elements:
                for attr in PATH_ATTRIBUTES:
                    if attr in element.attributes.keys():
                        path_value = element.attributes[attr].value
                        log.debug("Found %s='%s' in element <%s> in %s", attr, path_value, element.tagName, self.manifest_path)
                        self.issues.append(Issue(
                            category=self.category,
                            severity=self.severity,
                            name=f"{self.name}: {attr}",
                            description=f"{self.description} Detected {attr}='{path_value}' in <{element.tagName}>.",
                            file_object=self.manifest_path,
                            line_number=self._get_line_number(element),
                            standard_id=STANDARD_ID,
                            standard_description=STANDARD_DESCRIPTION,
                            owasp_refs=["M1"]
                        ))
        except Exception as e:
            log.exception("Error while parsing manifest in android_path plugin: %s", e)

    def _get_line_number(self, node):
        """Helper to extract line number if available from XML parser."""
        return getattr(node, 'lineNumber', None)

plugin = AndroidPath()

