"""
AI Code Review & Security Agent (Streamlit App)
Educational prototype for AI Term Project
"""

import streamlit as st
import ast
import re

# ==============================
# Vulnerability Rules
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
        "fix": "Avoid exec(). Use predefined functions."
    },
    "hardcoded_password": {
        "description": "Hardcoded password or secret detected",
        "severity": "High",
        "risk": "Hardcoded credentials may be leaked.",
        "fix": "Use environment variables or secret managers."
    },
    "os_system": {
        "description": "Use of os.system() detected",
        "severity": "Medium",
        "risk": "May allow command injection attacks.",
        "fix": "Use subprocess.run() safely."
    },
    "weak_random": {
        "description": "Weak random module used",
        "severity": "Medium",
        "risk": "random is not cryptographically secure.",
        "fix": "Use secrets module for security purposes."
    }
}

# ==============================
# AST Visitor
# ==============================

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = set()

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.issues.add("eval_usage")
            if node.func.id == "exec":
                self.issues.add("exec_usage")

        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                self.issues.add("os_system")

        self.generic_visit(node)

# ==============================
# Detection Functions
# ==============================

def detect_hardcoded_secrets(code):
    patterns = [
        r"password\s*=\s*[\"']",
        r"api_key\s*=\s*[\"']",
        r"secret\s*=\s*[\"']"
    ]
    return any(re.search(p, code, re.IGNORECASE) for p in patterns)

def detect_weak_random(code):
    return "import random" in code

def analyze_code(code):
    issues = set()

    tree = ast.parse(code)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    issues.update(visitor.issues)

    if detect_hardcoded_secrets(code):
        issues.add("hardcoded_password")

    if detect_weak_random(code):
        issues.add("weak_random")

    return issues

# ==============================
# Streamlit UI
# ==============================

st.set_page_config(page_title="AI Code Review Agent", layout="centered")

st.title("🔐 AI Code Review & Security Agent")
st.write("Upload a Python file to detect security vulnerabilities.")

uploaded_file = st.file_uploader("Upload Python (.py) file", type=["py"])

if uploaded_file:
    code_text = uploaded_file.read().decode("utf-8")

    st.subheader("📄 Uploaded Code")
    st.code(code_text, language="python")

    issues = analyze_code(code_text)

    st.subheader("🛑 Security Analysis Report")

    if not issues:
        st.success("No major security issues detected.")
    else:
        for issue in issues:
            rule = VULNERABILITY_RULES[issue]
            st.error(f"**{rule['description']}**")
            st.write(f"**Severity:** {rule['severity']}")
            st.write(f"**Why dangerous:** {rule['risk']}")
            st.write(f"**Suggested fix:** {rule['fix']}")
            st.markdown("---")

