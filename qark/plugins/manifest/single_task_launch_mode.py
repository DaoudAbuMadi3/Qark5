# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PLATFORM-8: Avoid using singleTask launchMode unless absolutely required.
# This plugin detects activities using launchMode='singleTask', which may introduce Task Hijacking vulnerabilities.

import logging
from qark.issue import Severity, Issue
from qark.scanner.plugin import ManifestPlugin

log = logging.getLogger(__name__)
 
TASK_LAUNCH_MODE_DESCRIPTION_TEMPLATE = (
    "Activity '{activity_name}' is configured with launchMode='singleTask'. "
    "This can lead to Task Poisoning if an attacker manipulates task affinity. "
    "Consider avoiding 'singleTask' unless explicitly required. "
    "More info: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
)

class SingleTaskLaunchMode(ManifestPlugin):
    def __init__(self):
        super().__init__(
            category="manifest",
            name="launchMode=singleTask found",
            description="Detects activities using launchMode='singleTask' which may be vulnerable to task poisoning."
        )
        self.severity = Severity.WARNING

    def run(self):
        try:
            activity_tags = self.manifest_xml.getElementsByTagName("activity")
            for activity in activity_tags:
                launch_mode_attr = activity.attributes.get("android:launchMode")
                if launch_mode_attr and launch_mode_attr.value.strip() == "singleTask":
                    activity_name = activity.attributes.get("android:name").value if "android:name" in activity.attributes else "unknown"
                    description = TASK_LAUNCH_MODE_DESCRIPTION_TEMPLATE.format(activity_name=activity_name)
                    log.debug("Found activity '%s' with launchMode='singleTask' in %s", activity_name, self.manifest_path)
                    self.issues.append(Issue(
                        category=self.category,
                        severity=Severity.WARNING,
                        name=f"launchMode=singleTask in {activity_name}",
                        description=description + "\n\n"
                                    "📌 OWASP M1 - Improper Platform Usage\n"
                                    "📌 MSTG-PLATFORM-8 - Avoid using launchMode='singleTask' unless absolutely required.\n"
                                    "🛠️ If needed, restrict it with taskAffinity, permissions, or intent filters.",
                        file_object=self.manifest_path,
                        line_number=self._get_line_number(activity),
                        standard_id="MSTG-PLATFORM-8",
                        standard_description="Avoid using launchMode='singleTask' unless explicitly required, as it may introduce task hijacking or UI spoofing vulnerabilities.",
                        owasp_refs=["M1"]
                    ))
        except Exception as e:
            log.exception("Error while processing singleTask launchMode: %s", e)

    def _get_line_number(self, node):
        """Extracts line number if parser provides it."""
        return getattr(node, 'lineNumber', None)

plugin = SingleTaskLaunchMode()

