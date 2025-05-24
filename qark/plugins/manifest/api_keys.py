# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage), M9 (Insecure Communication)
# ✅ MSTG-STORAGE-3: API keys and secrets must not be embedded in manifest files.
# This plugin scans the AndroidManifest for hardcoded API keys or secrets in <meta-data> or attribute values.

import logging
import re
from qark.issue import Severity, Issue
from qark.scanner.plugin import ManifestPlugin
 
log = logging.getLogger(__name__)

API_KEY_DESCRIPTION_TEMPLATE = (
    "Potential API key detected in manifest: {key_name}=\"{key_value}\". "
    "Please verify if this key should be publicly exposed. "
    "Avoid embedding sensitive tokens or credentials in AndroidManifest.xml."
)

API_KEY_ATTRIBUTE_NAMES = re.compile(r'(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)', re.IGNORECASE)
API_KEY_VALUE_PATTERN = re.compile(r'^[A-Za-z0-9_\-]{16,}$')

STANDARD_ID = "MSTG-STORAGE-3"
STANDARD_DESCRIPTION = "API keys and secrets must not be hardcoded in the manifest file."

class APIKeys(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="Potential API Key in manifest",
            description="Detects potential hardcoded API keys in manifest <meta-data> or attributes."
        )
        self.severity = Severity.WARNING

    def run(self):
        try:
            all_elements = self.manifest_xml.getElementsByTagName("*")
            for element in all_elements:
                for attr_name in element.attributes.keys():
                    attr_value = element.attributes[attr_name].value.strip()
                    if API_KEY_ATTRIBUTE_NAMES.search(attr_name) and API_KEY_VALUE_PATTERN.match(attr_value):
                        desc = API_KEY_DESCRIPTION_TEMPLATE.format(key_name=attr_name, key_value=attr_value)
                        # log.warning removed to silence CLI output during vulnerability detection
                        self.issues.append(Issue(
                            category=self.category,
                            severity=self.severity,
                            name=self.name,
                            description=desc,
                            file_object=self.manifest_path,
                            line_number=self._get_line_number(element),
                            standard_id=STANDARD_ID,
                            standard_description=STANDARD_DESCRIPTION,
                            owasp_refs=["M2", "M9"]
                        ))
        except Exception as e:
            log.exception("Error while parsing manifest in api_keys plugin: %s", e)

    def _get_line_number(self, node):
        return getattr(node, 'lineNumber', None)

plugin = APIKeys()

