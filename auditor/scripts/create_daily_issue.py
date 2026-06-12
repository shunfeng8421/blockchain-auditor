import json, os, subprocess, argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    
    with open(args.summary, "r") as f:
        d = json.load(f)
    
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    body = f"""## Daily Audit Report - {today}

| Metric | Count |
|--------|-------|
| Repos Audited | {d.get("total_repos_audited", 0)} |
| Total Findings | {d.get("total_findings", 0)} |
| PRs Merged | {d.get("prs_merged", 0)} |
| PRs Tracked | {d.get("prs_tracked", 0)} |
| Rules Adopted | {d.get("rules_adopted", 0)} |
| Total Workflow Runs | {d.get("total_workflow_runs", 0)} |

See full report: `{args.report}`
"""
    
    result = subprocess.run(
        ["gh", "issue", "create",
         "--title", f"[Daily Report] {today}",
         "--body", body,
         "--label", "daily-report"],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print(f"Issue created: {result.stdout.strip()}")
    else:
        print(f"ERROR: {result.stderr}")
        exit(1)

if __name__ == "__main__":
    main()
