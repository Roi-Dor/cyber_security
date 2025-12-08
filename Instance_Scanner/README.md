# Cloud "Toxic Combination" Scanner ☁️

A Python tool that emulates a Cloud Security Posture Management (CSPM) check.

## The Logic
It detects a specific "Toxic Combination" of risks:
1. **Network Exposure:** Is the EC2 instance open to `0.0.0.0/0`?
2. **Identity Risk:** Does the instance have `AdministratorAccess` IAM permissions?

If both are true, it flags a **CRITICAL** alert, as an attacker could use this instance to take over the entire cloud account.

## Dependencies
* `boto3`
* AWS Credentials configured