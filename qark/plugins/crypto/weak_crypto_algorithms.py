# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography)
# ✅ MSTG-CRYPTO-1: Use only strong cryptographic primitives (e.g., AES-GCM, SHA-256).
# This plugin detects weak algorithms, unsafe modes, and hardcoded secrets.

import logging
import re
import javalang
from javalang.tree import MethodInvocation, MemberReference, Literal, ClassCreator
from qark.issue import Issue, Severity
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

STANDARD_ID = "MSTG-CRYPTO-1"
STANDARD_DESCRIPTION = (
    "Apps must use strong, modern cryptographic primitives only. Weak algorithms must be avoided."
)

# Grouped weak patterns
WEAK_HASHES = [r"(?i)^MD5$", r"(?i)^SHA1$"]
WEAK_SIGNATURES = [r"(?i)^SHA1withRSA$", r"(?i)^MD5withRSA$"]
WEAK_MACS = [r"(?i)^HmacMD5$", r"(?i)^HmacSHA1$"]
WEAK_KEYGENS = [r"(?i)^DES$", r"(?i)^RC4$"]
WEAK_MODES = [r".*ECB.*", r".*/PKCS5Padding"]
HARDCODED_KEYWORDS = [r"(?i).*key.*", r"(?i).*secret.*"]

# Compile patterns
PATTERNS = {
    "hash": [re.compile(p) for p in WEAK_HASHES],
    "signature": [re.compile(p) for p in WEAK_SIGNATURES],
    "mac": [re.compile(p) for p in WEAK_MACS],
    "keygen": [re.compile(p) for p in WEAK_KEYGENS],
    "mode": [re.compile(p) for p in WEAK_MODES],
}

class WeakCryptoScanner(CoroutinePlugin):
    def __init__(self):
        super().__init__(
            category="crypto",
            name="Weak cryptographic primitive detected",
            description="Detects usage of weak algorithms, insecure cipher modes, or hardcoded keys."
        )
        self.severity = Severity.VULNERABILITY

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, MethodInvocation):
                self._check_insecure_usage(node)

            if isinstance(node, ClassCreator):
                self._check_hardcoded_keys(node)

    def _check_insecure_usage(self, node):
        target = node.qualifier or ""
        method = node.member
        args = node.arguments

        arg_val = self._get_literal_value(args[0]) if args else ""

        if not arg_val:
            return

        def matches(patterns): return any(p.match(arg_val) for p in patterns)

        if target == "MessageDigest" and method == "getInstance" and matches(PATTERNS["hash"]):
            self._report(node, f"Weak hash algorithm used: `{arg_val}`")

        elif target == "Signature" and method == "getInstance" and matches(PATTERNS["signature"]):
            self._report(node, f"Weak signature algorithm used: `{arg_val}`")

        elif target == "Mac" and method == "getInstance" and matches(PATTERNS["mac"]):
            self._report(node, f"Weak MAC algorithm used: `{arg_val}`")

        elif target == "KeyGenerator" and method == "getInstance" and matches(PATTERNS["keygen"]):
            self._report(node, f"Weak key generation algorithm used: `{arg_val}`")

        elif target == "Cipher" and method == "getInstance" and matches(PATTERNS["mode"]):
            self._report(node, f"Insecure cipher mode or padding used: `{arg_val}`")

    def _check_hardcoded_keys(self, node):
        for arg in node.arguments:
            if isinstance(arg, Literal):
                literal_val = arg.value.strip('"').strip("'")
                if any(re.match(p, literal_val) for p in HARDCODED_KEYWORDS):
                    self._report(node, f"Potential hardcoded secret: `{literal_val}`")

    def _get_literal_value(self, arg):
        if isinstance(arg, Literal):
            return arg.value.strip('"').strip("'")
        elif isinstance(arg, MemberReference) and hasattr(arg, "member"):
            return arg.member
        return ""

    def _report(self, node, message):
        # log.warning removed to silence CLI output during vulnerability detection
        self.issues.append(Issue(
            category=self.category,
            name=self.name,
            severity=self.severity,
            description=message,
            file_object=self.file_path,
            line_number=getattr(node, 'position', None),
            standard_id=STANDARD_ID,
            standard_description=STANDARD_DESCRIPTION,
            owasp_refs=["M6"]
        ))

plugin = WeakCryptoScanner()

