"""Apply automated fix based on finding and rules."""
import json
import os
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding", default="finding.json")
    parser.add_argument("--rules", default="auditor/rules/blockchain-audit-rules.txt")
    args = parser.parse_args()
    
    if not os.path.exists(args.finding):
        print(f"Finding file not found: {args.finding}")
        return
    
    with open(args.finding, "r") as f:
        finding = json.load(f)
    
    rule_id = finding["rule_id"]
    file_path = finding.get("file", "")
    
    print(f"Applying fix for {rule_id} in {file_path}")
    print(f"Guidance: {finding.get('fix_guidance', 'N/A')}")
    
    # For now, create a fix suggestion file
    suggestion = f"""# Automated Fix Suggestion
# Rule: {rule_id} - {finding.get('rule_name', '')}
# File: {file_path}
# Severity: {finding.get('severity', 'unknown')}
#
# Fix Guidance:
{finding.get('fix_guidance', 'No guidance available')}
#
# Note: This is an automated suggestion. Please review before applying.
"""
    
    with open("FIX_SUGGESTION.md", "w") as f:
        f.write(suggestion)
    
    print("Fix suggestion written to FIX_SUGGESTION.md")

if __name__ == "__main__":
    main()
