# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography)
# ✅ MSTG-CRYPTO-2: Do not use ECB mode for encryption. Use CBC or GCM with IV instead.
# This plugin detects usage of insecure cipher modes such as AES/ECB or DES/ECB.
 
import logging
import re
import javalang
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

DANGEROUS_ECB_PATTERNS = [
    r'.*/ECB/.*',
    r'AES/ECB/.*',
    r'DES/ECB/.*'
]

STANDARD_ID = "MSTG-CRYPTO-2"
STANDARD_DESCRIPTION = (
    "Apps must use secure cipher modes (e.g., CBC with IVs or GCM). ECB must be avoided."
)

class ECBCipherCheck(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="crypto", name="ECB Cipher Usage",
                         description="ECB cipher mode is insecure; reveals patterns in plaintext.")
        self.severity = Severity.VULNERABILITY
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_ECB_PATTERNS]

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, javalang.tree.MethodInvocation):
                try:
                    if node.member == "getInstance" and node.qualifier == "Cipher":
                        arg_val = node.arguments[0].value if node.arguments else ""
                        for pattern in self.compiled_patterns:
                            if pattern.search(arg_val):
                                # log.warning removed to silence CLI output during vulnerability detection
                                desc = f"Cipher.getInstance uses insecure mode: {arg_val}"
                                self.issues.append(Issue(
                                    category=self.category,
                                    name=self.name,
                                    severity=self.severity,
                                    description=desc,
                                    file_object=self.file_path,
                                    standard_id=STANDARD_ID,
                                    standard_description=STANDARD_DESCRIPTION,
                                    owasp_refs=["M6"],
                                ))
                except Exception as e:
                    log.debug("Error in ECBCipherCheck: %s", e)

plugin = ECBCipherCheck()

