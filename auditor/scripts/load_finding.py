"""Load a specific finding for contribution."""
import json
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding-id", default="")
    parser.add_argument("--repo-url", default="")
    parser.add_argument("--output", default="finding.json")
    args = parser.parse_args()
    
    findings_file = "auditor/findings/findings.jsonl"
    findings = []
    
    if os.path.exists(findings_file):
        with open(findings_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        fdata = json.loads(line)
                        if args.finding_id:
                            if fdata.get("rule_id") == args.finding_id:
                                findings.append(fdata)
                        else:
                            findings.append(fdata)
                    except json.JSONDecodeError:
                        continue
    
    if not findings:
        finding = {
            "id": args.finding_id,
            "rule_id": args.finding_id,
            "rule_name": args.finding_id,
            "severity": "high",
            "severity_weight": 70,
            "file": "N/A",
            "fix_guidance": "See audit report for details"
        }
    else:
        findings.sort(key=lambda x: x.get("severity_weight", 0), reverse=True)
        finding = findings[0]
    
    repo_name = args.repo_url.split("/")[-1] if args.repo_url else "unknown"
    
    result = {
        "finding_id": finding.get("id", args.finding_id),
        "rule_id": finding.get("rule_id", args.finding_id),
        "rule_name": finding.get("rule_name", ""),
        "severity": finding.get("severity", "high"),
        "file": finding.get("file", ""),
        "fix_guidance": finding.get("fix_guidance", "See audit report"),
        "repo_url": args.repo_url,
        "repo_name": repo_name,
    }
    
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"Loaded finding: {result['rule_id']} for {repo_name}")

if __name__ == "__main__":
    main()