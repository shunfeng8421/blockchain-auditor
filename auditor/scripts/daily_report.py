"""Generate daily audit report."""
import json
import os
import argparse
from datetime import datetime, timedelta

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default="auditor/logs/events.jsonl")
    parser.add_argument("--findings", default="auditor/findings/")
    parser.add_argument("--tracking", default="auditor/logs/pr_status.jsonl")
    parser.add_argument("--output", default="auditor/logs/daily_report.md")
    args = parser.parse_args()
    
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)
    
    lines = []
    lines.append(f"# Daily Audit Report - {today.strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## Pipeline Status")
    lines.append("")
    
    # Count today's events
    events_today = []
    if os.path.exists(args.events):
        with open(args.events, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        evt = json.loads(line)
                        ts = evt.get("timestamp", "")
                        if yesterday.strftime("%Y-%m-%d") in ts or today.strftime("%Y-%m-%d") in ts:
                            events_today.append(evt)
                    except json.JSONDecodeError:
                        continue
    
    # Counting
    audit_count = sum(1 for e in events_today if e.get("workflow") == "audit")
    track_count = sum(1 for e in events_today if e.get("workflow") == "track")
    contribute_count = sum(1 for e in events_today if e.get("workflow") == "contribute")
    
    lines.append(f"| Workflow | Runs Today |")
    lines.append(f"|----------|------------|")
    lines.append(f"| Discover | - (weekly) |")
    lines.append(f"| Audit | {audit_count} |")
    lines.append(f"| Contribute | {contribute_count} |")
    lines.append(f"| Track | {track_count} |")
    lines.append("")
    
    # Latest track data
    for evt in reversed(events_today):
        if evt.get("workflow") == "track" and evt.get("event") == "status_check":
            data = evt.get("data", {})
            lines.append("## PR Scorecard")
            lines.append("")
            lines.append(f"| Metric | Count |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Contributed | {data.get('contributed', 0)} |")
            lines.append(f"| Tracked | {data.get('tracked', 0)} |")
            lines.append(f"| Merged | {data.get('merged', 0)} |")
            lines.append(f"| Open | {data.get('open', 0)} |")
            break
    
    lines.append("")
    lines.append(f"_Report generated at {today.isoformat()}Z_")
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Daily report written to {args.output}")

if __name__ == "__main__":
    main()
