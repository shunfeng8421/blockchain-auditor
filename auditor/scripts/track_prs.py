"""Track PR Status - Check all submitted PRs and update their status.
Core of the Track bot that runs every 4 hours.
"""
import json
import os
import sys
import time
import argparse
import requests
from datetime import datetime

GITHUB_API = "https://api.github.com"

PR_STATUSES = ["open", "merged", "closed", "unknown"]

def get_pr_status(token, repo_full_name, pr_number):
    """Query GitHub API for a PR's current status."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}"
    
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 404:
            return {"status": "unknown", "merged": False, "closed_at": None}
        
        resp.raise_for_status()
        data = resp.json()
        
        status = data.get("state", "unknown")
        merged = data.get("merged", False)
        
        if status == "closed" and merged:
            status = "merged"
        
        return {
            "status": status,
            "merged": merged,
            "closed_at": data.get("closed_at"),
            "merged_at": data.get("merged_at"),
            "updated_at": data.get("updated_at"),
            "title": data.get("title", ""),
            "html_url": data.get("html_url", ""),
        }
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching PR {repo_full_name}#{pr_number}: {e}", file=sys.stderr)
        return {"status": "error", "error": str(e)}

def load_tracking(tracking_path):
    """Load PR tracking data from JSONL file."""
    tracked = {}
    if os.path.exists(tracking_path):
        with open(tracking_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        key = f"{entry['repo_full_name']}#{entry['pr_number']}"
                        tracked[key] = entry
                    except json.JSONDecodeError:
                        continue
    return tracked

def track_all(token, tracking_path, output_path, log_path):
    """Check all tracked PRs and update statuses."""
    tracked = load_tracking(tracking_path)
    
    if not tracked:
        print("No PRs to track")
        stats = {
            "contributed": 0, "tracked": 0, "open": 0,
            "merged": 0, "closed": 0, "unknown": 0
        }
        return stats
    
    stats = {
        "contributed": len(tracked),
        "tracked": len(tracked),
        "open": 0, "merged": 0, "closed": 0, "unknown": 0
    }
    
    updates = []
    status_changes = []
    
    for key, entry in tracked.items():
        repo = entry["repo_full_name"]
        pr_num = entry["pr_number"]
        old_status = entry.get("status", "unknown")
        
        # Check current status
        result = get_pr_status(token, repo, pr_num)
        new_status = result["status"]
        
        # Update stats
        stats[new_status] = stats.get(new_status, 0) + 1
        
        # Record update
        update = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "repo_full_name": repo,
            "pr_number": pr_num,
            "old_status": old_status,
            "new_status": new_status,
            "html_url": result.get("html_url", ""),
            "title": result.get("title", ""),
        }
        
        if "merged_at" in result and result["merged_at"]:
            update["merged_at"] = result["merged_at"]
        if "closed_at" in result and result["closed_at"]:
            update["closed_at"] = result["closed_at"]
        
        updates.append(update)
        
        # Track status changes
        if old_status != new_status:
            status_changes.append(update)
            print(f"  [{old_status} -> {new_status}] {repo}#{pr_num}: {result.get('title', 'N/A')}")
        
        # Rate limit courtesy
        time.sleep(1)
    
    # Write updates
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for update in updates:
            f.write(json.dumps(update, ensure_ascii=False) + "\n")
    
    # Log event
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workflow": "track",
        "event": "status_check",
        "data": {
            "contributed": stats["contributed"],
            "tracked": stats["tracked"],
            "open": stats["open"],
            "merged": stats["merged"],
            "closed": stats["closed"],
            "status_changes": len(status_changes)
        }
    }
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    
    return stats

def main():
    parser = argparse.ArgumentParser(description="Track PR statuses")
    parser.add_argument("--tracking", default="auditor/logs/pr_tracking.jsonl")
    parser.add_argument("--output", default="auditor/logs/pr_status.jsonl")
    parser.add_argument("--log", default="auditor/logs/events.jsonl")
    args = parser.parse_args()
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    
    print(f"Tracking PRs at {datetime.utcnow().isoformat()}Z")
    stats = track_all(token, args.tracking, args.output, args.log)
    
    print(f"\nTrack Summary:")
    print(f"  Total contributed: {stats['contributed']}")
    print(f"  Open:  {stats.get('open', 0)}")
    print(f"  Merged: {stats.get('merged', 0)}")
    print(f"  Closed: {stats.get('closed', 0)}")
    
    # Write summary for GitHub Actions output
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"merged={stats.get('merged', 0)}\n")
            f.write(f"open={stats.get('open', 0)}\n")
            f.write(f"tracked={stats['tracked']}\n")

if __name__ == "__main__":
    main()
