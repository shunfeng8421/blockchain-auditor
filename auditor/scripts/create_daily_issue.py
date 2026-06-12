import json, os, requests, argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    
    with open(args.summary, "r") as f:
        d = json.load(f)
    
    today = datetime.utcnow().strftime("%Y-%m-%d")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GH_TOKEN not set")
        exit(1)
    
    repo = os.environ.get("GITHUB_REPOSITORY", "shunfeng8421/blockchain-auditor")
    
    body = (
        f"## Daily Audit Report - {today}\n\n"
        f"| Metric | Count |\n|--------|-------|\n"
        f"| Repos Audited | {d.get('total_repos_audited', 0)} |\n"
        f"| Total Findings | {d.get('total_findings', 0)} |\n"
        f"| PRs Merged | {d.get('prs_merged', 0)} |\n"
        f"| PRs Tracked | {d.get('prs_tracked', 0)} |\n"
        f"| Rules Adopted | {d.get('rules_adopted', 0)} |\n"
        f"| Total Workflow Runs | {d.get('total_workflow_runs', 0)} |\n\n"
        f"See full report: `{args.report}`"
    )
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    
    resp = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers=headers,
        json={"title": f"[Daily Report] {today}", "body": body, "labels": ["daily-report"]},
        timeout=15
    )
    
    if resp.status_code == 201:
        print(f"Issue created: {resp.json()['html_url']}")
    else:
        print(f"ERROR {resp.status_code}: {resp.text[:300]}")
        exit(1)

if __name__ == "__main__":
    main()
