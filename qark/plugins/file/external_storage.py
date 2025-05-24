# ✅ OWASP Mobile Top 10: M2 (Insecure Data Storage)
# ✅ MSTG-STORAGE-2: Do not store sensitive data in external storage directories.
# This plugin detects usage of Android external storage APIs which may expose user data.

import logging
from javalang.tree import MethodInvocation
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)
 
EXTERNAL_STORAGE_DESCRIPTION = (
    "Reading/writing files in {storage_location} is potentially vulnerable to data injection attacks. "
    "Other apps with WRITE_EXTERNAL_STORAGE permission may write to these files. "
    "Reference: https://developer.android.com/reference/android/content/Context.html"
)

EXTERNAL_STORAGE_METHODS = {
    'getExternalFilesDir': "External Storage (App-specific)",
    'getExternalFilesDirs': "External Storage (Multiple directories)",
    'getExternalMediaDirs': "External Media Directory",
    'getExternalStoragePublicDirectory': "External Storage Public Directory",
    'getExternalStorageDirectory': "External Storage Directory (deprecated)",
}

class ExternalStorage(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="file", name="External storage API usage",
                         description=EXTERNAL_STORAGE_DESCRIPTION)
        self.severity = Severity.WARNING

    def run_coroutine(self):
        while True:
            _, method_invocation = (yield)

            if isinstance(method_invocation, MethodInvocation):
                method_name = method_invocation.member
                if method_name in EXTERNAL_STORAGE_METHODS:
                    storage_location = EXTERNAL_STORAGE_METHODS[method_name]
                    severity = Severity.VULNERABILITY if method_name in {
                        'getExternalStoragePublicDirectory', 'getExternalStorageDirectory'
                    } else self.severity
                    description = self.description.format(storage_location=storage_location)
                    # log.warning removed to silence CLI output during vulnerability detection
                    self.issues.append(Issue(
                        category=self.category,
                        severity=severity,
                        name=f"External storage method used: {method_name}",
                        description=description,
                        file_object=self.file_path,
                        line_number=method_invocation.position,
                        standard_id="MSTG-STORAGE-2",
                        standard_description="Sensitive data should not be stored on external storage due to lack of access controls.",
                        owasp_refs=["M2"]
                    ))

plugin = ExternalStorage()

