"""Draft a case study from audit evidence."""
import json
import os
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", default="auditor/case-studies/")
    parser.add_argument("--rules", default="auditor/rules/blockchain-audit-rules.txt")
    parser.add_argument("--output", default="auditor/case-studies/draft.md")
    args = parser.parse_args()
    
    evidence_file = os.path.join(args.evidence, "evidence.json")
    if not os.path.exists(evidence_file):
        print("No evidence found")
        return
    
    with open(evidence_file, "r") as f:
        evidence = json.load(f)
    
    findings = evidence.get("findings", [])
    
    lines = []
    lines.append(f"# Case Study: Blockchain Security Audit")
    lines.append(f"\n**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    lines.append(f"**Findings analyzed:** {len(findings)}")
    lines.append("")
    
    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        sev = f.get("severity", "low")
        by_severity.setdefault(sev, []).append(f)
    
    lines.append("## Summary")
    lines.append("")
    for sev in ["critical", "high", "medium", "low"]:
        count = len(by_severity[sev])
        if count > 0:
            lines.append(f"- **{sev.capitalize()}:** {count} findings")
    lines.append("")
    
    # Top findings detail
    lines.append("## Key Findings")
    lines.append("")
    
    # Show critical and high first
    for severity in ["critical", "high", "medium"]:
        for finding in by_severity[severity][:3]:
            lines.append(f"### {finding['rule_id']}: {finding.get('rule_name', '')}")
            lines.append(f"- **Severity:** {finding.get('severity', 'N/A')}")
            lines.append(f"- **Confidence:** {finding.get('confidence', 'N/A')}")
            lines.append(f"- **File:** `{finding.get('file', 'N/A')}`")
            lines.append(f"- **Fix:** {finding.get('fix_guidance', 'N/A')}")
            lines.append("")
    
    lines.append("## Lessons Learned")
    lines.append("")
    lines.append("1. Regular automated security auditing catches vulnerabilities early")
    lines.append("2. High-severity findings should be addressed before deployment")
    lines.append("3. Use established security patterns (OpenZeppelin, Chainlink, etc.)")
    lines.append("")
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Draft written to {args.output}")

if __name__ == "__main__":
    main()
