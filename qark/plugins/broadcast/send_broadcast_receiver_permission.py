# OWASP Reference:
# ⚠️ OWASP Mobile Top 10 - M1 (Improper Platform Usage)
# Description: Sending broadcasts without proper permission exposes the app to unauthorized access, interception, or injection.
 
import logging
import re
import javalang
from javalang.tree import MethodInvocation

from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin, ManifestPlugin

log = logging.getLogger(__name__)

BROADCAST_METHODS = (
    "sendBroadcast",
    "sendBroadcastAsUser",
    "sendOrderedBroadcast",
    "sendOrderedBroadcastAsUser",
    "sendStickyBroadcast",
    "sendStickyBroadcastAsUser",
    "sendStickyOrderedBroadcast",
    "sendStickyOrderedBroadcastAsUser",
)

STICKY_BROADCAST_METHODS = BROADCAST_METHODS[-4:]
LOCAL_BROADCAST_IMPORTS = (
    "android.support.v4.content.LocalBroadcastManager",
    "android.support.v4.content.*",
    "android.support.v4.*",
    "android.support.*",
    "android.*",
)

STANDARD_ID = "MSTG-PLATFORM-10"
STANDARD_DESCRIPTION = (
    "The app does not use platform security features properly, exposing it to broadcast injection or interception."
)

DESCRIPTIONS = {
    "without_receiver": (
        "`{broadcast_type}()` used **without** `receiverPermission`. "
        "Any app can intercept this broadcast. "
        "➤ **Use** `sendBroadcast(intent, permission)` to restrict access."
    ),
    "with_receiver": (
        "`{broadcast_type}()` used **with** `receiverPermission`. "
        "Ensure the permission is strong and app-defined. "
        "➤ Consider verifying that no other apps can define the same permission."
    ),
    "with_receiver_under_21": (
        "`{broadcast_type}()` uses `receiverPermission`, but `minSdk < 21`. "
        "⚠️ **Risk of permission squatting** exists on older platforms. "
        "➤ Consider increasing minSdkVersion to >= 21 or enforce runtime permission checks."
    ),
    "sticky": (
        "Sticky broadcast `{broadcast_type}` detected. "
        "These are insecure and deprecated. "
        "➤ **Avoid using sticky broadcasts.** Consider using `LocalBroadcastManager` or other safe mechanisms."
    ),
    "intent_set_package_null": (
        "`Intent.setPackage(null)` detected, removing restrictions on the target package. "
        "This can allow any app to receive the broadcast. "
        "➤ **Avoid calling setPackage(null)** unless absolutely required."
    ),
}

class SendBroadcastReceiverPermission(CoroutinePlugin, ManifestPlugin):
    def __init__(self):
        super().__init__(category="broadcast", name="Send Broadcast Receiver Permission")
        self.severity = Severity.WARNING
        self.current_file = None
        self.below_min_sdk_21 = False
        self._local_broadcast_cached = None

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, MethodInvocation):
                self._check_method_invocation(node, self.java_ast.imports)

            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member == "setPackage" and any(
                    hasattr(arg, "value") and arg.value == "null" for arg in node.arguments
                ):
                    self._add_issue(
                        name="Intent.setPackage(null) detected",
                        description=DESCRIPTIONS["intent_set_package_null"],
                        broadcast_type="Intent.setPackage",
                        severity=Severity.WARNING,
                        line_number=node.position
                    )

    def can_run_coroutine(self):
        self.below_min_sdk_21 = self.min_sdk < 21
        self.current_file = self.file_path
        self._local_broadcast_cached = has_local_broadcast_imported_cached(self.java_ast.imports)
        return re.search(r"({})".format("|".join(BROADCAST_METHODS)), self.file_contents) is not None

    def _check_method_invocation(self, method_invocation, imports):
        method_name = method_invocation.member
        num_args = len(method_invocation.arguments)

        handler = BROADCAST_HANDLERS.get(method_name)
        if handler:
            handler(self, num_args, method_name, method_invocation)

    def _add_issue(self, name, description, broadcast_type, severity=Severity.WARNING, line_number=None):
        full_description = description.format(broadcast_type=broadcast_type)
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            severity=severity,
            name=name,
            description=full_description,
            file_object=self.current_file,
            line_number=line_number,
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION
        ))


def handler_send_broadcast(self, num_args, method_name, node):
    if self._local_broadcast_cached:
        return  # safe case

    if num_args == 1:
        self._add_issue(
            name="Broadcast without receiverPermission",
            description=DESCRIPTIONS["without_receiver"],
            broadcast_type=method_name,
            severity=Severity.VULNERABILITY,
            line_number=node.position
        )
    elif num_args >= 2:
        desc_key = "with_receiver_under_21" if self.below_min_sdk_21 else "with_receiver"
        self._add_issue(
            name="Broadcast with receiverPermission",
            description=DESCRIPTIONS[desc_key],
            broadcast_type=method_name,
            severity=Severity.WARNING,
            line_number=node.position
        )


def handler_sticky(self, num_args, method_name, node):
    self._add_issue(
        name="Sticky broadcast usage",
        description=DESCRIPTIONS["sticky"],
        broadcast_type=method_name,
        severity=Severity.VULNERABILITY,
        line_number=node.position
    )


BROADCAST_HANDLERS = {
    "sendBroadcast": handler_send_broadcast,
    "sendBroadcastAsUser": handler_send_broadcast,
    "sendOrderedBroadcast": handler_send_broadcast,
    "sendOrderedBroadcastAsUser": handler_send_broadcast,
    "sendStickyBroadcast": handler_sticky,
    "sendStickyBroadcastAsUser": handler_sticky,
    "sendStickyOrderedBroadcast": handler_sticky,
    "sendStickyOrderedBroadcastAsUser": handler_sticky,
}


def has_local_broadcast_imported_cached(import_tree):
    return any(import_decl.path in LOCAL_BROADCAST_IMPORTS for import_decl in import_tree)


plugin = SendBroadcastReceiverPermission()

