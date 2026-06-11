"""Load a specific finding for contribution."""
import json
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", help="Issue label")
    parser.add_argument("--output", default="finding.json")
    args = parser.parse_args()
    
    findings_file = "auditor/findings/findings.jsonl"
    if not os.path.exists(findings_file):
        print("No findings available")
        sys.exit(1)
    
    # Load latest finding with highest severity
    findings = []
    with open(findings_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    
    if not findings:
        print("No findings to load")
        sys.exit(1)
    
    findings.sort(key=lambda x: x.get("severity_weight", 0), reverse=True)
    finding = findings[0]
    
    # Construct finding object with repo info
    target = os.environ.get("TARGET_REPO", "unknown/unknown")
    result = {
        "finding_id": finding["id"],
        "rule_id": finding["rule_id"],
        "rule_name": finding.get("rule_name", ""),
        "severity": finding["severity"],
        "file": finding["file"],
        "fix_guidance": finding.get("fix_guidance", ""),
        "repo_url": f"https://github.com/{target}",
        "repo_name": target.split("/")[-1] if "/" in target else target,
    }
    
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()
