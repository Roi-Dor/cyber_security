# 🛡️ Mini-CWPP: Container Security Scanner

A Python-based **Cloud Workload Protection Platform (CWPP)** agent prototype.
This tool performs runtime security assessments on Docker containers, combining configuration analysis with vulnerability scanning to detect security risks in real-time.

## 🚀 Key Features

* **Runtime Configuration Analysis:**
    * Detects containers running as **Root User** (Least Privilege violation).
    * Identifies **Privileged Mode** containers (High risk of host takeover).
    * Alerts on insecure mounts, specifically **Docker Socket exposure** (`/var/run/docker.sock`).
    * Checks for exposed sensitive ports (e.g., SSH port 22).
* **Vulnerability Scanning:**
    * Orchestrates **Trivy** to scan running images for CVEs (Common Vulnerabilities and Exposures).
    * Aggregates Critical and High severity vulnerabilities.
* **Reporting & Integration:**
    * Generates a structured `report.json` artifact for SIEM/Dashboard integration.
    * Calculates a `RISK` vs `SECURE` status for each workload.

## 🛠️ Architecture

The scanner operates as a host-based agent:
1.  **Discovery:** Uses the **Docker SDK for Python** to query the Docker Daemon API.
2.  **Inspection:** Deep dives into `Container.Config` and `HostConfig` for misconfigurations.
3.  **Scanning:** Triggers a sub-process to run Trivy on the specific image tags.
4.  **Reporting:** Consolidates findings into a standardized JSON format.

## 📋 Prerequisites

* Python 3.8+
* Docker Desktop / Docker Daemon running
* [Trivy Scanner](https://github.com/aquasecurity/trivy) installed and in system PATH

## ⚙️ Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-folder>
    ```

2.  **Set up a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install docker
    ```

## 🏃 Usage

1.  Ensure Docker is running.
2.  Run the scanner:
    ```bash
    python scanner.py
    ```
3.  View the results in the terminal or check the generated artifact:
    ```bash
    cat report.json
    ```

## 📊 Sample Output (report.json)

```json
{
    "container_name": "risky-hacker",
    "security_status": "RISK",
    "findings": {
        "configuration": [
            "Running as ROOT user",
            "Running in PRIVILEGED mode",
            "Docker Socket mounted inside container"
        ],
        "vulnerabilities": {
            "critical": 2,
            "high": 14
        }
    }
}