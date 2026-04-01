# Axios Supply Chain Attack Scanner

A shell script to check your npm project for indicators of compromise related to the **Axios npm supply chain attack** (March 30, 2026).

An attacker hijacked the lead maintainer's npm account and published two malicious versions (`axios@1.14.1` and `axios@0.30.4`) containing a phantom dependency (`plain-crypto-js@4.2.1`) that deploys a cross-platform RAT (Remote Access Trojan) during `npm install`.

Reference: [Trend Micro - Axios NPM Package Compromised](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html)

---

## What it checks

| Check | Description |
|-------|-------------|
| **1. Compromised packages** | Scans `package-lock.json` for `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js`, `@shadanai/openclaw`, `@qqbrowser/openclaw-qbot` |
| **2. Phantom dependency** | Searches `node_modules/` for `plain-crypto-js` directory (primary IOC) |
| **3. RAT artifacts** | Checks for malware files: `/Library/Caches/com.apple.act.mond` (macOS), `/tmp/ld.py` (Linux), `/tmp/6202033*` (dropper) |
| **4. C&C indicators** | Scans codebase for C&C domains (`sfrclak.com`, `callnrwise.com`), IP (`142.11.206.73`), attacker emails, and obfuscation keys |
| **5. Axios metadata** | Verifies installed axios version is not a compromised release |

## Usage

1. Copy the script into your repository (or run from any directory).
2. Run the scanner:

```bash
./scanner.sh
```

Or scan a specific project:

```bash
cd /path/to/your/project && /path/to/scanner.sh
```

## Requirements

- `bash`
- `jq` (for JSON parsing)
- `grep`, `find` (standard unix tools)

## Safe versions

- **1.x branch:** `axios@1.14.0` or latest
- **0.x branch:** `axios@0.30.3` or earlier

## Compromised versions (DO NOT INSTALL)

- `axios@1.14.1` (SHA-1: `2553649f2322049666871cea80a5d0d6adc700ca`)
- `axios@0.30.4` (SHA-1: `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`)
- `plain-crypto-js@4.2.1` (SHA-1: `07d889e2dadce6f3910dcbc253317d28ca61c766`)

## Sources

- [Trend Micro](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html)
- [Snyk](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- [Elastic Security Labs](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)
