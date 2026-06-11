"""Update PR tracking records after submission."""
import json
import os
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding", default="finding.json")
    parser.add_argument("--status", default="submitted")
    parser.add_argument("--log", default="auditor/logs/events.jsonl")
    args = parser.parse_args()
    
    if not os.path.exists(args.finding):
        print("Finding file not found")
        return
    
    with open(args.finding, "r") as f:
        finding = json.load(f)
    
    repo = finding.get("repo_name", "unknown")
    repo_full = f"{os.environ.get('GITHUB_REPOSITORY_OWNER', 'unknown')}/{repo}"
    
    tracking_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repo_full_name": repo_full,
        "pr_number": int(os.environ.get("GITHUB_RUN_NUMBER", "0")),
        "finding_id": finding["finding_id"],
        "rule_id": finding["rule_id"],
        "status": args.status,
    }
    
    tracking_path = "auditor/logs/pr_tracking.jsonl"
    os.makedirs(os.path.dirname(tracking_path), exist_ok=True)
    
    with open(tracking_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(tracking_entry, ensure_ascii=False) + "\n")
    
    print(f"Tracking updated: {repo_full}#{tracking_entry['pr_number']} [{args.status}]")

if __name__ == "__main__":
    main()
