# Cloud Context Scanner ☁️
### Detects "Toxic Combinations" in AWS Environments

A specialized Cloud Security Posture Management (CSPM) tool designed to identify **Toxic Combinations**—critical risks created by the intersection of network exposure and high-privileged identities.

Unlike standard scanners that check configurations in silos, this tool analyzes the **Context** to determine effective exposure.

---

## 🚀 Key Features

### 1. Effective Network Reachability (Network Analysis)
Instead of relying solely on Security Groups (which creates False Positives), this tool verifies the full path from the internet to the instance:
* **Public IP Check:** Verifies the instance has a public IP.
* **Security Group Analysis:** Checks for `0.0.0.0/0` ingress rules.
* **Route Table Verification:** **(New)** Validates that the subnet is actually connected to an Internet Gateway (IGW). If the Security Group is open but there is no route to the IGW, the risk is downgraded to "Warning".

### 2. Deep IAM Policy Analysis (Identity Analysis)
Instead of relying on Role names (which can be misleading), this tool performs deep JSON parsing of attached policies:
* **Document Parsing:** Downloads and analyzes the actual Policy Document (JSON).
* **Effective Permission Check:** Looks for `Effect: Allow` combined with `Action: *` (or `*:*`) and `Resource: *`.
* **Bypasses Naming Conventions:** Detects Admin privileges even if the policy is named "ReadOnly" or "CustomPolicy".

### 3. Contextual Risk Assessment
The tool only flags a **CRITICAL** alert if *both* vectors overlap:
* The instance is effectively exposed to the internet.
* The instance holds Admin keys.

### 4. Machine-Readable Output
* **Console UI:** Clear, human-readable summary for quick assessment.
* **JSON Export:** Automatically exports all findings to `scan_results.json` for integration with SIEM/SOAR pipelines or dashboards.

---

## 🛠️ The Logic: How it Works

The scanner builds a mini "Security Graph" for each instance:

```mermaid
graph LR
    Internet((Internet)) --> IGW[Internet Gateway]
    IGW --> RT[Route Table]
    RT --> SG[Security Group 0.0.0.0/0]
    SG --> EC2[EC2 Instance]
    EC2 --> IAM[IAM Admin Role]
    IAM --> Account[Account Takeover]
    
    style Account fill:#f9f,stroke:#333,stroke-width:2px,color:red