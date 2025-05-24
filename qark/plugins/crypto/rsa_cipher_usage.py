# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography)
# ✅ MSTG-CRYPTO-3: RSA must not be used without padding. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding instead.
# This plugin detects use of RSA with NoPadding, which is vulnerable to plaintext recovery attacks.
 
import logging
import re
import javalang
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

DANGEROUS_RSA_PATTERNS = [
    r'RSA/.+/NoPadding',
    r'RSA/NONE/NoPadding',
    r'RSA/ECB/NoPadding'
]

STANDARD_ID = "MSTG-CRYPTO-3"
STANDARD_DESCRIPTION = (
    "RSA encryption must always use padding (e.g., OAEP or PKCS1Padding). NoPadding is insecure."
)

class RSACipherCheck(CoroutinePlugin):
    def __init__(self):
        super().__init__(category="crypto", name="RSA Cipher Usage",
                         description="RSA without padding is insecure; prone to data leakage.")
        self.severity = Severity.VULNERABILITY
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_RSA_PATTERNS]

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, javalang.tree.MethodInvocation):
                try:
                    if node.member == "getInstance" and node.qualifier == "Cipher":
                        arg_val = node.arguments[0].value if node.arguments else ""
                        for pattern in self.compiled_patterns:
                            if pattern.search(arg_val):
                                desc = (
                                    f"Insecure RSA usage detected: {arg_val}. "
                                    f"Use RSA with OAEP or PKCS1Padding instead."
                                )
                                # log.warning removed to silence CLI output during vulnerability detection
                                self.issues.append(Issue(
                                    category=self.category,
                                    name=self.name,
                                    severity=self.severity,
                                    description=desc,
                                    file_object=self.file_path,
                                    line_number=node.position if hasattr(node, 'position') else None,
                                    standard_id=STANDARD_ID,
                                    standard_description=STANDARD_DESCRIPTION,
                                    owasp_refs=["M6"]
                                ))
                except Exception as e:
                    log.debug("Error in RSACipherCheck: %s", e)

plugin = RSACipherCheck()

