import logging
import xml.etree.ElementTree as ET
from qark.issue import Issue, Severity
from qark.scanner.plugin import ManifestPlugin

log = logging.getLogger(__name__)
 
STANDARD_ID = "MSTG-PLATFORM-10"
STANDARD_DESCRIPTION = (
    "Exported components without proper permissions allow unauthorized apps to interact with app internals."
)

class ExportedReceiversInManifest(ManifestPlugin):
    def __init__(self):
        super().__init__(category="broadcast", name="Exported receivers without permission",
                         description="Checks for exported broadcast receivers without permission in AndroidManifest.xml")

    def run(self):
        try:
            manifest = ET.parse(self.manifest_path).getroot()
            sdk_target = self._get_target_sdk(manifest)
            receivers = manifest.findall("application/receiver")

            for receiver in receivers:
                exported = receiver.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                permission = receiver.attrib.get("{http://schemas.android.com/apk/res/android}permission")
                name = receiver.attrib.get("{http://schemas.android.com/apk/res/android}name")

                # In SDK 31 and later, absence of "exported" means risk.
                if (exported == "true" or (exported is None and sdk_target >= 31)) and not permission:
                    self.issues.append(Issue(
                        category=self.category,
                        severity=Severity.VULNERABILITY,
                        name="Exported receiver without permission",
                        description=f"Receiver `{name}` is exported without specifying a permission. "
                                    f"This allows other apps to send malicious broadcasts to it.",
                        file_object=self.manifest_path,
                        line_number=None,  # No line_number is readily available with ElementTree.
                        standard_id=STANDARD_ID,
                        standard_description=STANDARD_DESCRIPTION
                    ))
        except Exception as e:
            log.exception("Failed to parse AndroidManifest.xml: %s", e)

    def _get_target_sdk(self, manifest_root):
        try:
            uses_sdk = manifest_root.find("uses-sdk")
            if uses_sdk is not None:
                target_sdk = uses_sdk.attrib.get("{http://schemas.android.com/apk/res/android}targetSdkVersion")
                return int(target_sdk)
        except Exception:
            pass
        return 1  # fallback

plugin = ExportedReceiversInManifest()

