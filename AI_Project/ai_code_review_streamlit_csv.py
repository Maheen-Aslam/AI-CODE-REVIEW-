# ai_code_review_streamlit_colored.py

import streamlit as st
import ast
import re
import pandas as pd
import os

# ==============================
# Vulnerability Rules
# ==============================
VULNERABILITY_RULES = {
    "eval_usage": {
        "description": "Use of eval() detected",
        "severity": "High",
        "risk": "eval() executes arbitrary code and can allow attackers to run malicious commands.",
        "fix": "Avoid eval(). Use ast.literal_eval() or safer alternatives."
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
# AST-based Detection
# ==============================
class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.issues.append("eval_usage")
            if node.func.id == "exec":
                self.issues.append("exec_usage")
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                self.issues.append("os_system")
            if node.func.attr == "load":
                self.issues.append("pickle_load")
        self.generic_visit(node)

# ==============================
# Regex-based Detection
# ==============================
def detect_hardcoded_secrets(code_text):
    patterns = [
        r"password\s*=\s*[\"'].*?[\"']",
        r"api_key\s*=\s*[\"'].*?[\"']",
        r"secret\s*=\s*[\"'].*?[\"']"
    ]
    return any(re.search(p, code_text, re.IGNORECASE) for p in patterns)

def detect_weak_random(code_text):
    return "import random" in code_text

# ==============================
# Analysis Engine
# ==============================
def analyze_code(code_text):
    detected_issues = set()
    try:
        tree = ast.parse(code_text)
        visitor = SecurityVisitor()
        visitor.visit(tree)
        detected_issues.update(visitor.issues)
    except Exception:
        detected_issues.add("syntax_error")
    if detect_hardcoded_secrets(code_text):
        detected_issues.add("hardcoded_password")
    if detect_weak_random(code_text):
        detected_issues.add("weak_random")
    return detected_issues

# ==============================
# Folder Scan Function
# ==============================
def scan_folder(folder_path):
    report_data = []
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".py"):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        code_text = f.read()
                    issues = analyze_code(code_text)
                    for issue_key in issues:
                        rule = VULNERABILITY_RULES.get(issue_key)
                        if rule:
                            report_data.append({
                                "File": file_path,
                                "Issue": rule["description"],
                                "Severity": rule["severity"],
                                "Risk": rule["risk"],
                                "Suggested Fix": rule["fix"]
                            })
                except Exception as e:
                    report_data.append({
                        "File": file_path,
                        "Issue": "File Read Error",
                        "Severity": "High",
                        "Risk": str(e),
                        "Suggested Fix": "Check file encoding or permissions"
                    })
    return report_data

# ==============================
# Streamlit UI
# ==============================
st.title("🔐 AI Code Review & Security Agent")
st.markdown(
    "Scan Python files for common security vulnerabilities. Upload files or scan a folder. Severity is color-coded!"
)

# File upload
uploaded_files = st.file_uploader(
    "Upload Python files (.py)", type=["py"], accept_multiple_files=True
)

# Folder path input
folder_scan = st.text_input(
    "Or enter folder path to scan all Python files:"
)

report_data = []

# Analyze uploaded files
if uploaded_files:
    for uploaded_file in uploaded_files:
        code_text = uploaded_file.read().decode("utf-8")
        issues = analyze_code(code_text)
        for issue_key in issues:
            rule = VULNERABILITY_RULES.get(issue_key)
            if rule:
                report_data.append({
                    "File": uploaded_file.name,
                    "Issue": rule["description"],
                    "Severity": rule["severity"],
                    "Risk": rule["risk"],
                    "Suggested Fix": rule["fix"]
                })

# Analyze folder if provided
if folder_scan and folder_scan.strip() != "":
    if not os.path.exists(folder_scan):
        st.error("❌ Folder path not found.")
    else:
        report_data.extend(scan_folder(folder_scan))

# ==============================
# Display report with color coding
# ==============================
if report_data:
    df = pd.DataFrame(report_data)

    # Color-coding function
    def color_severity(val):
        if val == "High":
            color = "red"
        elif val == "Medium":
            color = "orange"
        else:
            color = "green"
        return f"color: {color}; font-weight: bold"

    st.subheader("Scan Report")
    st.dataframe(df.style.applymap(color_severity, subset=["Severity"]))

    # Download CSV
    csv = df.to_csv(index=False)
    st.download_button(
        label="📥 Download CSV Report",
        data=csv,
        file_name="ai_code_review_report.csv",
        mime="text/csv"
    )
elif uploaded_files or folder_scan:
    st.success("✅ No major security issues detected.")
