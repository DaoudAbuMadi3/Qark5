# ✅ OWASP Mobile Top 10: M6 (Insecure Cryptography)
# ✅ MSTG-CRYPTO-4: Do not use fixed seeds with SecureRandom. Always rely on system entropy.
# This plugin detects calls to setSeed() or constructor-based seeding of SecureRandom.
 
import logging
import javalang
from qark.issue import Severity, Issue
from qark.scanner.plugin import CoroutinePlugin

log = logging.getLogger(__name__)

STANDARD_ID = "MSTG-CRYPTO-4"
STANDARD_DESCRIPTION = (
    "SecureRandom must not be seeded with fixed values to ensure unpredictability."
)

class SeedWithSecureRandom(CoroutinePlugin):
    INSECURE_FUNCTIONS = {"setSeed", "generateSeed"}

    def __init__(self):
        super().__init__(category="crypto",
                         name="Insecure SecureRandom Seeding",
                         description="Fixed seed in SecureRandom causes predictable output.")
        self.severity = Severity.VULNERABILITY

    def can_run_coroutine(self):
        return any(imp.path == "java.security.SecureRandom" for imp in self.java_ast.imports)

    def run_coroutine(self):
        while True:
            _, node = (yield)
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member in self.INSECURE_FUNCTIONS:
                    self._add_issue(node, f"Method {node.member} called on SecureRandom")
            elif isinstance(node, javalang.tree.ClassCreator):
                if node.type.name == "SecureRandom" and node.arguments:
                    self._add_issue(node, "SecureRandom instantiated with fixed seed argument")

    def _add_issue(self, node, desc):
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

plugin = SeedWithSecureRandom()

