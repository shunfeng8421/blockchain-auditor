"""Generate summary statistics from events log."""
import json
import os
import argparse
from collections import Counter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default="auditor/logs/events.jsonl")
    parser.add_argument("--output", default="auditor/logs/summary.json")
    args = parser.parse_args()
    
    stats = {
        "total_repos_audited": 0,
        "total_findings": 0,
        "prs_submitted": 0,
        "prs_merged": 0,
        "prs_closed": 0,
        "prs_tracked": 0,
        "rules_adopted": 0,
        "total_workflow_runs": 0,
    }
    
    if os.path.exists(args.events):
        with open(args.events, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        evt = json.loads(line)
                        stats["total_workflow_runs"] += 1
                        
                        data = evt.get("data", {})
                        wf = evt.get("workflow", "")
                        
                        if wf == "track" and evt.get("event") == "status_check":
                            stats["prs_merged"] = max(stats["prs_merged"], data.get("merged", 0))
                            stats["prs_tracked"] = max(stats["prs_tracked"], data.get("tracked", 0))
                        
                        if wf == "audit" and evt.get("event") == "audit_complete":
                            stats["total_repos_audited"] += 1
                            stats["total_findings"] += data.get("total_findings", 0)
                    except json.JSONDecodeError:
                        continue
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(stats, f, indent=2)
    
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
