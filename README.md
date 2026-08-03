# Blockchain Auditor ⛓️🔐

**6-stage automated audit pipeline for blockchain and cryptocurrency repositories.**
**Now with V2 optimized scanner + 11 new detection rules from DeFiHackLabs cross-analysis.**

## Pipeline
```
Discover → Audit → Optimize → Contribute → Track → Case Study → Daily Report
 (weekly)   (label)   (V2)      (label)     (every 4h)  (label)      (daily)
```

## 70 Audit Rules (33 original + 37 language-specific + 11 new)

### New Rules (BLK-SOL-023 to BLK-SOL-033)
Derived from cross-analyzing 837 DeFiHackLabs PoCs against 50 attack patterns.
These 11 patterns had **zero hits** in the PoC database, representing under-explored attack surfaces:

| ID | Rule | Severity | Description |
|:---|:-----|:--------:|:-----------|
| 023 | Timing Attack | medium | block.timestamp manipulation |
| 024 | Storage Collision | critical | Proxy storage layout conflicts |
| 025 | Uninitialized Implementation | critical | Implementation contract takeover |
| 026 | Cross-protocol Composability | critical | Flash loan + cross-protocol attacks |
| 027 | Token Non-Standard | high | Fee-on-transfer, rebasing tokens |
| 028 | Pool Init & Migration | high | Uninitialized pool takeovers |
| 029 | Social Engineering | high | Single-step ownership transfer |
| 030 | Incentive Misalignment | medium | Reward manipulation via flash loans |
| 031 | Wormhole Bridge | critical | Cross-chain message verification |
| 032 | Callback Injection | high | ERC777-style callback attacks |
| 033 | Ponzi Scheme | low | Pyramid scheme detection |

### False-Positive Filtering (V2 Optimized Mode)
The V2 scanner adds intelligent exclusion logic:
- `initializer`/`onlyInitializing` modifier detection
- `AlreadyInitialized` custom check recognition
- `__gap` array and Unstructured Storage (EIP-1967) detection
- `forceApprove`/`SafeERC20` pattern recognition
- `checkAccess`/`onlyOwner`/`onlyRole` access control detection
- `block.timestamp` expiration check exclusion
- Interface/comment/library code filtering

**Results: 82-93% false positive reduction** on real-world protocols.

## Quick Start
```bash
# Standard mode
python auditor/scripts/audit.py --target /path/to/contracts/ --rules auditor/rules/blockchain-audit-rules.txt

# V2 Optimized mode (with false-positive filtering)
python auditor/scripts/audit_v2.py --target /path/to/contracts/ --rules auditor/rules/blockchain-audit-rules.txt --optimized

# Discover new repos
python auditor/scripts/discover.py --min-stars 50 --output discovered.jsonl
```

## Validation
Scanner validated against:
- **cap-contracts** ($254M TVL, 185 contracts): 57→4 findings (93% FP reduction)
- **Frankencoin** ($68M TVL, 202 contracts): 58→10 findings (83% FP reduction)

## Architecture
- `auditor/scripts/audit.py` — Core scan engine (original)
- `auditor/scripts/audit_v2.py` — V2 optimized scanner with FP filtering
- `auditor/scripts/discover.py` — GitHub repo discovery
- `auditor/rules/blockchain-audit-rules.txt` — 70 detection rules
- `auditor/findings/` — Output directory for scan results

## References
- DeFiHackLabs: 837 PoCs cross-analyzed
- SWC Registry: Smart Contract Weakness Classification
- OpenZeppelin Contracts: Security best practices

Star ⭐ to support blockchain security research.