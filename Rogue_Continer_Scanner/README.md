# Mini-Wiz Container Scanner 🐳

A Bash-based runtime security tool that audits running Docker containers for "Root User" violations.

## How it Works
It uses `docker inspect` to extract metadata from all running containers and alerts if any container is running as `User 0` (Root), which breaks the Principle of Least Privilege.

## Usage
```bash
chmod +x scanner.sh
./scanner.sh