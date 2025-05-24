# ✅ OWASP Mobile Top 10: M1 (Improper Platform Usage)
# ✅ MSTG-PRIVACY-1: Avoid collecting device identifiers (IMEI, SIM, etc.) unless necessary and with informed consent.
# This plugin detects calls to sensitive TelephonyManager methods that expose hardware-level identifiers.

import logging
import re
from qark.issue import Severity, Issue
from qark.scanner.plugin import FileContentsPlugin

log = logging.getLogger(__name__)

PHONE_IDENTIFIER_DESCRIPTION = (
    "Access of phone number, IMEI, subscriber ID, or SIM serial number detected. "
    "Avoid storing or transmitting this data unless absolutely necessary and without informed user consent."
)

SENSITIVE_METHODS = ["getLine1Number", "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"]

TELEPHONY_MANAGER_VARIABLE_NAMES_REGEX = re.compile(
    r'(android\.telephony\.)?TelephonyManager\s+(\w+)\s*[=;)]'
)
 
INLINE_USAGE_REGEX = re.compile(
    r'\({2,}(android\.telephony\.)?TelephonyManager\)\w*\.getSystemService\(["\']phone["\']\){2,}\.(' + "|".join(SENSITIVE_METHODS) + r')'
)

STANDARD_ID = "MSTG-PRIVACY-1"
STANDARD_DESCRIPTION = "Avoid collecting hardware identifiers (IMEI, SIM Serial, etc.) unless strictly necessary and with user consent."

class PhoneIdentifier(FileContentsPlugin):
    def __init__(self):
        super().__init__(
            category="privacy",
            name="Phone identifier access detected",
            description=PHONE_IDENTIFIER_DESCRIPTION
        )
        self.severity = Severity.WARNING

    def run(self):
        detected = False

        if re.search(r'android\.telephony\.TelephonyManager', self.file_contents):
            for match in re.finditer(INLINE_USAGE_REGEX, self.file_contents):
                line = self._get_line_number(match.start())
                # log.warning removed to silence CLI output during vulnerability detection
                self._add_issue(line_number=line)
                detected = True

            for var_match in re.finditer(TELEPHONY_MANAGER_VARIABLE_NAMES_REGEX, self.file_contents):
                var_name = var_match.group(2)
                method_pattern = re.compile(rf'{re.escape(var_name)}\.({"|".join(SENSITIVE_METHODS)})\s*\(')
                for method_call in method_pattern.finditer(self.file_contents):
                    line = self._get_line_number(method_call.start())
                    # log.warning removed to silence CLI output during vulnerability detection
                    self._add_issue(line_number=line)
                    detected = True

        if not detected:
            log.debug("No sensitive TelephonyManager access found in %s", self.file_path)

    def _add_issue(self, line_number=None):
        self.issues.append(Issue(
            category=self.category,
            severity=self.severity,
            name=self.name,
            description=self.description,
            file_object=self.file_path,
            line_number=(line_number, 0) if line_number else None,
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION,
            owasp_refs=["M1"]
        ))

    def _get_line_number(self, index):
        return self.file_contents.count('\n', 0, index) + 1

plugin = PhoneIdentifier()

