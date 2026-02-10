import ast
import re
import os

# ==============================
# Module 1: Code Loader
# ==============================

def load_python_file(file_path):
    """
    Safely reads a Python source file.
    No execution of code.
    """
    if not file_path.endswith(".py"):
        raise ValueError("Only Python (.py) files are allowed")

    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


# ==============================
# Module 2: Vulnerability Rules
# ==============================

VULNERABILITY_RULES = {
    "eval_usage": {
        "description": "Use of eval() detected",
        "severity": "High",
        "risk": "eval() executes arbitrary code and can allow attackers to run malicious commands.",
        "fix": "Avoid eval(). Use ast.literal_eval() or safer logic."
    },
    "exec_usage": {
        "description": "Use of exec() detected",
        "severity": "High",
        "risk": "exec() can execute malicious code dynamically.",
        "fix": "Avoid exec(). Use predefined functions or safer parsing."
    },
    "hardcoded_password": {
        "description": "Hardcoded password or secret detected",
        "severity": "High",
        "risk": "Hardcoded credentials can be leaked and abused.",
        "fix": "Store secrets in environment variables or secure vaults."
    },
    "os_system": {
        "description": "Use of os.system() detected",
        "severity": "Medium",
        "risk": "os.system() can lead to command injection vulnerabilities.",
        "fix": "Use subprocess.run() with proper argument handling."
    },
    "pickle_load": {
        "description": "Insecure pickle.load() usage",
        "severity": "High",
        "risk": "pickle.load() can execute arbitrary code from untrusted data.",
        "fix": "Avoid pickle for untrusted input. Use JSON or safer formats."
    },
    "weak_random": {
        "description": "Weak random number generator used for security",
        "severity": "Medium",
        "risk": "The random module is not suitable for cryptographic purposes.",
        "fix": "Use secrets module for secure random values."
    }
}


# ==============================
# Module 3: AST-based Detection
# ==============================

class SecurityVisitor(ast.NodeVisitor):
    """
    AST visitor that walks through Python code
    and detects insecure function usage.
    """

    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        # Detect eval()
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.issues.append("eval_usage")

        # Detect exec()
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self.issues.append("exec_usage")

        # Detect os.system()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                self.issues.append("os_system")

        # Detect pickle.load()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "load":
                self.issues.append("pickle_load")

        self.generic_visit(node)


# ==============================
# Module 4: Regex-based Detection
# ==============================

def detect_hardcoded_secrets(code_text):
    """
    Uses regex to detect hardcoded passwords or API keys.
    """
    patterns = [
        r"password\s*=\s*[\"'].*?[\"']",
        r"api_key\s*=\s*[\"'].*?[\"']",
        r"secret\s*=\s*[\"'].*?[\"']"
    ]

    for pattern in patterns:
        if re.search(pattern, code_text, re.IGNORECASE):
            return True
    return False


def detect_weak_random(code_text):
    """
    Detects use of random module for security-sensitive purposes.
    """
    return "import random" in code_text


# ==============================
# Module 5: Analysis Engine
# ==============================

def analyze_code(code_text):
    """
    Central analysis engine that applies
    rule-based + AST-based detection.
    """
    detected_issues = set()

    # AST Analysis
    tree = ast.parse(code_text)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    detected_issues.update(visitor.issues)

    # Regex Analysis
    if detect_hardcoded_secrets(code_text):
        detected_issues.add("hardcoded_password")

    if detect_weak_random(code_text):
        detected_issues.add("weak_random")

    return detected_issues


# ==============================
# Module 6: Report Generator
# ==============================

def generate_report(detected_issues):
    """
    Generates a human-readable security report.
    """
    print("\n🔐 AI Code Review & Security Report")
    print("=" * 40)

    if not detected_issues:
        print("✅ No major security issues detected.")
        return

    for issue_key in detected_issues:
        rule = VULNERABILITY_RULES.get(issue_key)
        if rule:
            print(f"\n⚠ Issue: {rule['description']}")
            print(f"Severity: {rule['severity']}")
            print(f"Why it's dangerous: {rule['risk']}")
            print(f"Suggested fix: {rule['fix']}")

    print("\n📌 Analysis completed.\n")


# ==============================
# Module 7: Main Controller
# ==============================

def main():
    """
    Entry point of the AI agent.
    """
    print("AI Code Review & Security Agent\n")

    file_path = input("Enter path to Python file for analysis: ").strip()

    if not os.path.exists(file_path):
        print("❌ File not found.")
        return

    try:
        code_text = load_python_file(file_path)
        issues = analyze_code(code_text)
        generate_report(issues)

    except Exception as e:
        print("❌ Error during analysis:", e)


# ==============================
# Run the Agent
# ==============================

if __name__ == "__main__":
    main()



