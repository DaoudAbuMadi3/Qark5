# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-8: Use of allowTaskReparenting may lead to task hijacking or UI spoofing.
# This plugin flags activities where android:allowTaskReparenting is set to 'true'.

import logging
from qark.issue import Severity, Issue
from qark.scanner.plugin import ManifestPlugin

log = logging.getLogger(__name__)
 
TASK_REPARENTING_DESCRIPTION_TEMPLATE = (
    "Activity '{activity_name}' is configured with android:allowTaskReparenting='true'. "
    "This allows the activity to be reparented into another task with the same affinity, "
    "which may lead to UI spoofing or task hijacking attacks. "
    "Avoid setting this attribute to true unless absolutely necessary. "
    "More info: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
)

class TaskReparenting(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="android:allowTaskReparenting='true' found",
            description="Detects activities with android:allowTaskReparenting='true' which may be vulnerable to UI spoofing or task hijacking."
        )
        self.severity = Severity.WARNING

    def run(self):
        try:
            activity_tags = self.manifest_xml.getElementsByTagName("activity")
            for activity in activity_tags:
                attr = activity.attributes.get("android:allowTaskReparenting")
                if attr and attr.value.strip().lower() == "true":
                    activity_name = activity.attributes.get("android:name").value if "android:name" in activity.attributes else "unknown"
                    description = TASK_REPARENTING_DESCRIPTION_TEMPLATE.format(activity_name=activity_name)
                    log.debug("Found activity '%s' with allowTaskReparenting='true' in %s", activity_name, self.manifest_path)
                    self.issues.append(Issue(
                        category=self.category,
                        severity=self.severity,
                        name=f"allowTaskReparenting='true' in {activity_name}",
                        description=description + "\n\n"
                            "📌 OWASP M1 - Improper Platform Usage\n"
                            "📌 MSTG-PLATFORM-8 - Disabling allowTaskReparenting prevents hijacking by malicious tasks.\n"
                            "🛠️ Recommendation: Set android:allowTaskReparenting='false' unless absolutely required.",
                        file_object=self.manifest_path,
                        line_number=self._get_line_number(activity),
                        standard_id="MSTG-PLATFORM-8",
                        standard_description="Disabling allowTaskReparenting prevents activities from being reparented into malicious tasks, mitigating task hijacking.",
                        owasp_refs=["M1"]
                    ))
        except Exception as e:
            log.exception("Error while processing task reparenting plugin: %s", e)

    def _get_line_number(self, node):
        """Extracts line number if supported by XML parser."""
        return getattr(node, 'lineNumber', None)

plugin = TaskReparenting()

