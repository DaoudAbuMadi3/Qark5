# OWASP Reference:
# ⚠️ OWASP Mobile Top 10 - M1 (Improper Platform Usage), M9 (Insecure Communication)
# Description:
# Dynamically registered broadcast receivers without proper permissions can be abused by malicious apps to inject data,
# trigger actions, or escalate privileges. Always restrict dynamic receivers using strong permissions.
 
import logging
from javalang.tree import MethodInvocation
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin, ManifestPlugin

log = logging.getLogger(__name__)

STANDARD_ID = "MSTG-PLATFORM-10"
STANDARD_DESCRIPTION = (
    "The app does not restrict dynamic broadcast receivers using permissions, which may lead to unauthorized access."
)

DESCRIPTION_NO_PERMISSION = (
    "App uses `registerReceiver(...)` without specifying a `permission`. "
    "Any app can send broadcasts to this receiver. "
    "Use `registerReceiver(receiver, filter, permission, handler)` to restrict access."
)

DESCRIPTION_WEAK_PERMISSION = (
    "App uses `registerReceiver(...)` with a custom or weak permission. "
    "Ensure you use a strong, app-defined permission to protect this receiver."
)

class DynamicBroadcastReceiver(CoroutinePlugin, ManifestPlugin):
    def __init__(self):
        super().__init__(category="broadcast", name="Dynamic broadcast receiver found",
                         description="Detects dynamic registration of broadcast receivers")
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if not isinstance(node, MethodInvocation):
                continue

            if node.member == "registerReceiver":
                arg_count = len(node.arguments)

                if arg_count < 3:
                    self._add_issue(node, description=DESCRIPTION_NO_PERMISSION, severity=Severity.VULNERABILITY)
                elif arg_count >= 3:
                    permission_arg = node.arguments[2]
                    if hasattr(permission_arg, "value"):
                        perm_value = str(permission_arg.value)
                        # Basic classification of permission
                        if perm_value in ("null", "None"):
                            self._add_issue(node, description=DESCRIPTION_NO_PERMISSION, severity=Severity.VULNERABILITY)
                        elif perm_value.startswith("android.permission.") or "BROADCAST" in perm_value.upper():
                            self._add_issue(node, description=DESCRIPTION_WEAK_PERMISSION, severity=Severity.INFO)
                        else:
                            self._add_issue(node, description=DESCRIPTION_WEAK_PERMISSION, severity=Severity.WARNING)

    def _add_issue(self, node, description, severity):
        # log.warning removed to keep CLI clean from vulnerability notifications
        self.issues.append(Issue(
            category=self.category,
            severity=severity,
            name=self.name,
            description=description,
            file_object=self.file_path,
            line_number=node.position,
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION
        ))

plugin = DynamicBroadcastReceiver()

