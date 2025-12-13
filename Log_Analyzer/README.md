# AI-Powered Log Security Agent (Context-Aware) 🤖

An intelligent security agent that analyzes server logs using **GenAI (OpenAI GPT-4o)**.
Unlike traditional regex-based parsers, this agent uses **Batch Processing** to understand context, allowing it to detect complex attack patterns that span multiple log lines.

## 🚀 Key Features
* **Context-Aware Batch Analysis:** Analyzes logs in chunks (windows) rather than single lines.
* **Pattern Detection:** Identifies attacks that rely on sequence, such as **Brute Force**, **Port Scanning**, and **Lateral Movement**.
* **Smart Classification:** Distinguishes between legitimate failures and malicious intent based on behavioral context.
* **Auto-Remediation:** Provides actionable mitigation steps for every detected threat.
* **Detailed Reporting:** Generates a structured `security_summary.txt` with evidence and analysis.

## 🛠️ Prerequisites
* Python 3.8+
* OpenAI API Key

## 📦 Installation

1. **Clone or Download the repository**
2. **Set up a Virtual Environment (Recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # venv\Scripts\activate   # On Windows