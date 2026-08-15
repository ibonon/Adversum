# Adversum Solidity Scanner

Standalone SAST scanner for Solidity/Vyper smart contracts, designed specifically for auditing CEX platforms like AlphaNex Exchange.

## Architecture

* **scanner.py**: Main execution engine loading rules dynamically.
* **rules/**: Detection modules mapping to SWC and CWE.
* **kb/**: Comprehensive knowledge base containing real-world examples and CVSS scores.
* **output/**: Export pipelines (e.g., SARIF for CI/CD integration).

## Usage

Run the scanner locally over your smart contract repository:

```bash
python scanner.py --target tests/test_contracts/ --format sarif
```

## Features
- **Reentrancy (SWC-107)**
- **tx.origin Auth Bypass (SWC-115)**
- **Integer Overflow (SWC-101)**
- ... and more, backed by the 15+ checks in `kb/vulnerabilities.json`.
