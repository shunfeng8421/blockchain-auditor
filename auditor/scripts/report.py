"""Generate human-readable audit report from findings."""
import json
import os
import argparse
from datetime import datetime
from collections import Counter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", default="auditor/findings/")
    parser.add_argument("--output", default="auditor/logs/audit_report.md")
    args = parser.parse_args()
    
    findings_file = os.path.join(args.findings, "findings.jsonl")
    summary_file = os.path.join(args.findings, "findings_summary.json")
    
    if not os.path.exists(summary_file):
        print("No findings to report")
        return
    
    with open(summary_file, "r") as f:
        summary = json.load(f)
    
    lines = []
    lines.append("# Blockchain Security Audit Report")
    lines.append(f"\n**Generated:** {datetime.utcnow().isoformat()}Z")
    lines.append(f"**Target:** {summary.get('target', 'N/A')}")
    lines.append(f"**Files scanned:** {summary['total_files_scanned']}")
    lines.append(f"**Total findings:** {summary['total_findings']}")
    lines.append("")
    
    # Severity breakdown
    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    sev_emoji = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f7e2"}
    for sev in ["critical", "high", "medium", "low"]:
        count = summary["by_severity"].get(sev, 0)
        emoji = sev_emoji.get(sev, "")
        lines.append(f"| {emoji} {sev.capitalize()} | {count} |")
    lines.append("")
    
    # Language breakdown
    lines.append("## Findings by Language")
    lines.append("")
    lines.append("| Language | Findings |")
    lines.append("|----------|----------|")
    for lang, count in summary.get("by_language", {}).items():
        lines.append(f"| {lang.capitalize()} | {count} |")
    lines.append("")
    
    # Top findings
    if os.path.exists(findings_file):
        lines.append("## Detailed Findings")
        lines.append("")
        with open(findings_file, "r", encoding="utf-8") as f:
            all_findings = []
            for line in f:
                if line.strip():
                    all_findings.append(json.loads(line))
        
        # Group by rule
        by_rule = {}
        for finding in all_findings:
            rid = finding["rule_id"]
            if rid not in by_rule:
                by_rule[rid] = []
            by_rule[rid].append(finding)
        
        for rid, findings in sorted(by_rule.items()):
            lines.append(f"### {rid}: {findings[0].get('rule_name', rid)}")
            lines.append(f"**Severity:** {findings[0].get('severity', 'N/A')} | **Count:** {len(findings)}")
            lines.append("")
            lines.append("**Affected files:**")
            for f in findings[:5]:
                lines.append(f"- `{f['file']}`")
            if len(findings) > 5:
                lines.append(f"- ... and {len(findings) - 5} more")
            lines.append("")
            
            fix = findings[0].get("fix_guidance", "")
            if fix:
                lines.append(f"**Fix guidance:** {fix}")
                lines.append("")
            
            exploits = findings[0].get("known_exploits", "")
            if exploits:
                lines.append(f"**Known exploits:** {exploits}")
                lines.append("")
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Report written to {args.output}")

if __name__ == "__main__":
    main()
