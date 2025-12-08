# AI-Powered Log Security Agent 🤖

An intelligent agent that parses server logs and uses LLMs (OpenAI GPT-4) to classify threats.

## Features
* **Semantic Analysis:** Detects attacks like SQL Injection and Path Traversal without static signatures.
* **Auto-Remediation:** Suggests specific mitigation steps for every detected threat.
* **Reporting:** Generates a clean `security_summary.txt` report.

## Setup
1. Create a `.env` file with `OPENAI_API_KEY=sk-...`
2. Run the scanner:
   ```bash
   python ai_agent.py