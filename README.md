Here is a **professional README.md description** for your Python project. You can directly paste this into your GitHub repository.

---

# 🔐 AI Code Review & Security Agent

## 📌 Project Overview

AI Code Review & Security Agent is a Python-based static code analysis tool that detects common security vulnerabilities in Python source files. The system uses Abstract Syntax Tree (AST) parsing and rule-based AI techniques to analyze code and generate explainable security reports.

This project was developed as part of the **Artificial Intelligence – Term Project (AI Solution Development & Prototyping)**.

---

## 🎯 Objective

The goal of this project is to build a functional AI prototype that:

* Automatically scans Python files
* Detects security vulnerabilities
* Provides risk explanations
* Suggests safer alternatives
* Displays results through a Streamlit web interface

This is a Proof-of-Concept (POC) for an AI-powered secure coding assistant.

---

## 🧠 AI Techniques Used

This project uses:

* ✅ Rule-Based AI (Expert System)
* ✅ Static Code Analysis
* ✅ Abstract Syntax Tree (AST) Parsing
* ✅ Pattern Recognition (Regex)
* ✅ Explainable AI (Risk + Suggested Fix)

⚠️ Note: This project does not use Machine Learning or Deep Learning models. It follows a symbolic AI approach.

---

## 🔍 Vulnerabilities Detected

The system currently detects:

* Use of `eval()`
* Use of `exec()`
* Hardcoded passwords or API keys
* Use of `os.system()`
* Insecure `pickle.load()` usage
* Weak random number generation (`random` module)

Each vulnerability includes:

* Severity Level (High / Medium)
* Risk Explanation
* Suggested Fix

---

## 🏗️ Tech Stack

* Python 3.x
* Streamlit
* AST (Python built-in module)
* Pandas
* Regex (re module)
* OS module

---

## 📂 Features

* Upload multiple Python files
* Scan entire folders recursively
* Color-coded severity display
* Downloadable CSV security report
* User-friendly web interface

---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/ai-code-review-agent.git
cd ai-code-review-agent
```

### 2️⃣ Install Dependencies

```bash
pip install streamlit pandas
```

### 3️⃣ Run the Application

```bash
streamlit run ai_code_review_streamlit_colored.py
```

---

## 🖥️ How to Use

1. Launch the Streamlit app.
2. Upload one or more `.py` files
   OR
   Enter a folder path to scan all Python files.
3. View the security report.
4. Download the CSV report if needed.

---

## 📊 Output Example

The system generates a report containing:

| File | Issue | Severity | Risk | Suggested Fix |
| ---- | ----- | -------- | ---- | ------------- |

Severity is color-coded:

* 🔴 High
* 🟠 Medium
* 🟢 Low

---

## 📈 Future Improvements

* Machine Learning-based vulnerability prediction
* NLP-based comment analysis
* Integration with CI/CD pipelines
* Multi-language support
* GitHub repository scanning

---

## 👩‍💻 Author

**Maheen Aslam**
Student ID: F2025436045
Course: Artificial Intelligence
Term Project: AI Solution Development & Prototyping

---

## 📜 License

This project is developed for academic purposes.

---

If you want, I can also generate:

* ⭐ A more advanced professional GitHub version
* 📄 A short academic version
* 🚀 A README with screenshots section
* 🎓 A polished final report introduction

Tell me what you need next 😊
