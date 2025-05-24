# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage)
# ✅ MSTG-STORAGE-5: Sensitive data must be encrypted when stored.
# This plugin detects storage of data using non-encrypted APIs such as FileOutputStream or SharedPreferences.

import logging
from javalang.tree import MethodInvocation, MemberReference, Literal
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)
 
UNENCRYPTED_APIS = {
    "FileOutputStream",
    "openFileOutput",
    "SharedPreferences.Editor.putString",
    "SharedPreferences.Editor.putInt",
    "SharedPreferences.Editor.putBoolean",
    "SharedPreferences.Editor.putLong",
}

ENCRYPTED_CLASSES = {
    "CipherOutputStream",
    "EncryptedSharedPreferences"
}

class EncryptedStoragePlugin(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="file",
            name="Sensitive data stored without encryption",
            description="Detects data written to storage without encryption (e.g., SharedPreferences or FileOutputStream)."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)

            if isinstance(node, MethodInvocation):
                full_method = self._get_full_method_name(node)
                if full_method in UNENCRYPTED_APIS:
                    if not self._is_encrypted_context(node):
                        self._add_issue(
                            "Unencrypted data storage detected",
                            f"Method `{full_method}` used without encryption. Use EncryptedSharedPreferences or CipherOutputStream.",
                            node
                        )

    def _get_full_method_name(self, node):
        # Compose method name with its qualifier if any
        qualifier = getattr(node, "qualifier", "")
        return f"{qualifier}.{node.member}" if qualifier else node.member

    def _is_encrypted_context(self, node):
        # Check if it's wrapped or used with encrypted classes
        if hasattr(node, "qualifier") and node.qualifier:
            if any(enc in node.qualifier for enc in ENCRYPTED_CLASSES):
                return True
        return False

    def _add_issue(self, name, description, node):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=name,
            severity=self.severity,
            description=(
                description + "\n\n"
                "📌 OWASP M2 - Insecure Data Storage\n"
                "📌 MSTG-STORAGE-5 - Sensitive data must be encrypted when stored.\n"
                "🛠️ Use EncryptedSharedPreferences or CipherOutputStream to securely store sensitive data."
            ),
            file_object=self.file_path,
            line_number=getattr(node, "position", None),
            standard_id="MSTG-STORAGE-5",
            standard_description="Sensitive data must be encrypted before writing to storage.",
            owasp_refs=["M2"]
        ))

plugin = EncryptedStoragePlugin()

