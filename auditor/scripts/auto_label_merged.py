"""Auto-label merged PRs as case-study-ready."""
import json
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracking", default="auditor/logs/pr_status.jsonl")
    parser.add_argument("--label", default="case-study-ready")
    args = parser.parse_args()
    
    if not os.path.exists(args.tracking):
        print("No tracking data")
        return
    
    merged = []
    with open(args.tracking, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    entry = json.loads(line)
                    if entry.get("new_status") == "merged":
                        merged.append(entry)
                except json.JSONDecodeError:
                    continue
    
    if merged:
        print(f"Found {len(merged)} merged PRs ready for case study")
        # In a real setup, would call gh CLI to label issues
        for m in merged:
            print(f"  - {m.get('repo_full_name', 'N/A')}#{m.get('pr_number', '?')}: {m.get('title', 'N/A')}")
    else:
        print("No merged PRs found")

if __name__ == "__main__":
    main()
