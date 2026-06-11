# Blockchain Auditor

Automated 6-stage audit pipeline for blockchain and cryptocurrency repositories.

Inspired by [xiaolai/nlpm](https://github.com/xiaolai/nlpm) auditor bot architecture.

## Architecture

`
Discover -> Audit -> Contribute -> Track -> Case Study -> Daily Report
 (weekly)   (label)   (label)     (every 4h)    (label)       (daily)
`

## Audit Rules

20 rules covering:
- **Solidity/EVM:** Reentrancy, overflow, access control, oracle manipulation, flash loans, frontrunning, weak randomness, delegatecall, signature replay, timestamp dependence
- **Rust/Solana:** Account validation, CPI return checks, bump seed mismatch, arithmetic overflow
- **Go/Cosmos:** Consensus testing, insecure randomness, race conditions
- **Universal:** Hardcoded secrets, vulnerable dependencies, non-standard token implementations

See uditor/rules/blockchain-audit-rules.txt for full rule definitions.

## Usage

1. Push this repo to GitHub
2. Set up secrets: GITHUB_TOKEN (auto), OPENAI_API_KEY (optional, for case study polish)
3. Enable GitHub Actions

### Manual Triggers

| Workflow | Trigger |
|----------|---------|
| Discover | workflow_dispatch or weekly cron |
| Audit | Add udit-ready label to issue |
| Contribute | Add contribute-approved label to issue |
| Track | Every 4 hours automatically |
| Case Study | Add case-study-ready label to issue |
| Daily Report | Daily 22:00 UTC automatically |

## Directory Structure

`
blockchain-auditor/
  .github/workflows/    # 6 GitHub Actions workflows
  auditor/
    rules/              # Audit rule definitions
    scripts/            # Python automation scripts
    logs/               # Event logs, tracking data, reports
    findings/           # Audit finding results
    case-studies/       # Generated case studies
