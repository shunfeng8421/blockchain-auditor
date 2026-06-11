"""Gather evidence for case study from findings and PR tracking."""
import json
import os
import argparse
from datetime import datetime
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding", default="auditor/findings/")
    parser.add_argument("--output", default="auditor/case-studies/")
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    evidence = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": [],
        "pr_tracking": []
    }
    
    # Load findings
    findings_file = os.path.join(args.finding, "findings.jsonl")
    if os.path.exists(findings_file):
        with open(findings_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    evidence["findings"].append(json.loads(line))
    
    # Load PR tracking
    tracking_file = "auditor/logs/pr_tracking.jsonl"
    if os.path.exists(tracking_file):
        with open(tracking_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    evidence["pr_tracking"].append(json.loads(line))
    
    # Load PR status
    status_file = "auditor/logs/pr_status.jsonl"
    if os.path.exists(status_file):
        evidence["pr_statuses"] = []
        with open(status_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    evidence["pr_statuses"].append(json.loads(line))
    
    output_file = os.path.join(args.output, "evidence.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, default=str)
    
    print(f"Evidence gathered: {len(evidence['findings'])} findings, {len(evidence.get('pr_tracking', []))} PRs")

if __name__ == "__main__":
    main()
