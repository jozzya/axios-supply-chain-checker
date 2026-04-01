# Axios Supply Chain Attack Scanner

A shell script to check your npm project for indicators of compromise related to the **Axios npm supply chain attack** (March 30, 2026).

An attacker hijacked the lead maintainer's npm account and published two malicious versions (`axios@1.14.1` and `axios@0.30.4`) containing a phantom dependency (`plain-crypto-js@4.2.1`) that deploys a cross-platform RAT (Remote Access Trojan) during `npm install`.

Reference: [Trend Micro - Axios NPM Package Compromised](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html)

---

## What it checks

| Check | Description |
|-------|-------------|
| **1. Compromised packages** | Scans `package-lock.json` for known-bad packages defined in `import.json`: `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`, `plain-crypto-js@4.2.0` (clean decoy), `@shadanai/openclaw@*`, `@qqbrowser/openclaw-qbot@0.0.130` |
| **2. Phantom dependency** | Searches `node_modules/` for `plain-crypto-js` directory (primary IOC) |
| **3. RAT artifacts** | Checks for malware files: `/Library/Caches/com.apple.act.mond` (macOS), `/tmp/ld.py` (Linux), `/tmp/6202033*` (dropper artifacts), `/mnt/c/ProgramData/wt.exe` (Windows/WSL) |
| **4. C&C indicators** | Scans project files (`.json`, `.js`, `.ts`, `.sh`, `.ps1`, `.py`, `.vbs`) for C&C domains (`sfrclak.com`, `callnrwise.com`), IP (`142.11.206.73`), attacker emails (`nrwise@proton.me`, `ifstap@proton.me`), and obfuscation key (`OrDeR_7077`) |
| **5. Installed axios version** | Checks `node_modules/axios/package.json` to verify the installed version is not `1.14.1` or `0.30.4` |
| **6. Risky version ranges** | Scans all `package.json` files for axios semver ranges that could have resolved to a compromised version during the attack window (2026-03-31 00:21–03:30 UTC): `^1.x`, `^0.30.x`, `~1.14.x`, `~0.30.x`, `*`, `latest` |

## Usage

```
./scanner.sh                    Scan current directory
./scanner.sh /path/to/project   Scan a specific project
./scanner.sh --scan-dir /path   Scan ALL subdirectories inside /path
./scanner.sh --help | -h        Show usage information
```

### Scan current directory

```bash
./scanner.sh
```

### Scan a specific project

```bash
./scanner.sh /path/to/your/project
```

### Scan all repos in a directory

```bash
./scanner.sh --scan-dir /path/to/repos
```

This scans every subdirectory inside the given path and produces a summary of clean vs flagged repositories.

## Requirements

- `bash`
- `jq` (for JSON parsing)
- `grep`, `find` (standard unix tools)

## Attack window

The compromised versions were live on npm between **2026-03-31 00:21 UTC** and **2026-03-31 03:30 UTC**. If `npm install` ran during this window with a matching semver range, a compromised version may have been pulled.

## Safe versions

- **1.x branch:** `axios@1.14.0` or `axios@1.14.2+`
- **0.x branch:** `axios@0.30.3` or earlier

## Compromised versions (DO NOT INSTALL)

- `axios@1.14.1` (SHA-1: `2553649f2322049666871cea80a5d0d6adc700ca`)
- `axios@0.30.4` (SHA-1: `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`)
- `plain-crypto-js@4.2.1` (SHA-1: `07d889e2dadce6f3910dcbc253317d28ca61c766`)
- `plain-crypto-js@4.2.0` (clean decoy published to build registry history before attack)

## Sources

- [Trend Micro](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html)
- [Snyk](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- [Elastic Security Labs](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)
