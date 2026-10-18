# Security Policy

## Supported Versions

Adversum is under active release development. Critical security fixes and invariant patches are prioritized on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The Adversum team takes the security of smart contracts, autonomous defense agents, and underlying infrastructure seriously.

If you believe you have discovered a vulnerability, security flaw, or bug that affects Adversum or any of its subcomponents (Rust Core SAST, Python Reasoning Engine, Autonomous Threat Hunter, or WebSocket Event Bus):

1. **Do not open a public issue.**
2. Send a report with technical details and reproduction steps to the repository maintainer or security contact at:
   - **Email:** `security@adversum.ai` (or via GitHub Private Vulnerability Reporting on this repository)
3. Please include:
   - A description of the vulnerability and its potential impact.
   - Affected components (`core/`, `api/`, `orchestrator/`, `modules/`).
   - Proof of Concept (PoC) or reproduction steps.
   - Any proposed remediation or mitigation.

## Response Commitment

- **Acknowledgment:** Within 24 hours of receipt.
- **Initial Triage:** Within 48 hours.
- **Remediation & Advisory:** Coordinate with reporter prior to any public disclosure or release note.
