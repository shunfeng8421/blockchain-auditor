"""Core audit engine: scan target repo against blockchain rules."""
import json
import os
import re
import sys
import hashlib
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

def parse_rules(rules_path):
    """Parse the blockchain-audit-rules.txt into structured rules."""
    rules = []
    current = None
    
    with open(rules_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            
            # Skip comments and separators
            if line.startswith("#") or line.startswith("==") or line.startswith("---") or not line.strip():
                continue
            
            if line.startswith("rule_id:"):
                if current:
                    rules.append(current)
                current = {"rule_id": line.split(":", 1)[1].strip()}
            elif current is not None:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip().strip('"')
                    if key == "tags":
                        current[key] = [t.strip() for t in val.strip("[]").split(",")]
                    elif key == "detection":
                        current[key] = {"methods": [], "patterns": []}
                    elif key in ("methods", "patterns"):
                        pass  # Handled below
                    else:
                        current[key] = val
                elif line.strip().startswith("-"):
                    item = line.strip()[1:].strip().strip('"')
                    if "methods" not in current.setdefault("detection", {}):
                        current.setdefault("detection", {})["methods"] = []
                    if "patterns" not in current["detection"]:
                        current["detection"]["patterns"] = []
                    # Simple heuristic: if it looks like a regex, add to patterns
                    if any(c in item for c in "\\*+?[](){}^$"):
                        current["detection"]["patterns"].append(item)
                    else:
                        current["detection"]["methods"].append(item)
    
    if current:
        rules.append(current)
    
    return rules

def find_files(target_dir, extensions):
    """Find files with given extensions in target directory."""
    files = []
    for ext in extensions:
        for f in Path(target_dir).rglob(f"*{ext}"):
            if f.is_file() and ".git" not in str(f):
                files.append(str(f))
    return files

def scan_file(filepath, rules):
    """Scan a single file against all applicable rules."""
    findings = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings
    
    ext = Path(filepath).suffix
    filename = Path(filepath).name
    
    for rule in rules:
        # Check if rule applies to this file type
        tags = rule.get("tags", [])
        lang_match = False
        
        if ext == ".sol" and "solidity" in tags:
            lang_match = True
        elif ext == ".rs" and "rust" in tags:
            lang_match = True
        elif ext == ".go" and "go" in tags:
            lang_match = True
        elif "all" in tags:
            lang_match = True
        
        if not lang_match:
            continue
        
        # Check patterns
        patterns = rule.get("detection", {}).get("patterns", [])
        matched = False
        
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    matched = True
                    break
            except re.error:
                continue
        
        if matched:
            finding = {
                "id": hashlib.md5(f"{rule['rule_id']}:{filepath}".encode()).hexdigest()[:12],
                "rule_id": rule["rule_id"],
                "rule_name": rule.get("name", ""),
                "severity": rule.get("severity", "unknown"),
                "severity_weight": int(rule.get("severity_weight", 0)),
                "file": filepath,
                "confidence": rule.get("confidence", "low"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "fix_guidance": rule.get("fix", ""),
                "known_exploits": rule.get("known_exploits", ""),
            }
            findings.append(finding)
    
    return findings

def scan_hardcoded_secrets(filepath):
    """Specialized scan for hardcoded private keys and secrets."""
    findings = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings
    
    # Private key patterns (focused - avoid false positives in blockchain repos)
    pk_patterns = [
        # Explicit key assignment with hex value (most reliable)
        r"(?:private[_\s]*key|secret[_\s]*key)\s*[:=]\s*[\"\x27]?\s*(0x[a-fA-F0-9]{64})",
        # Env-style secrets with non-empty values
        r"(?:PRIVATE_KEY|SECRET_KEY|MNEMONIC|INFURA_KEY|ALCHEMY_KEY)\s*=\s*[\"\x27]([^\"\x27\s]{32,})[\"\x27]",
        # Mnemonic phrases (12+ words in quotes)
        r"(?:mnemonic|seed[_\s]*phrase)\s*[:=]\s*[\"\x27]([a-z]+\s+){11,}[a-z]+[\"\x27]",
        # .env files with non-placeholder values (not "your_key_here")
        r"(?:KEY|SECRET|PASSWORD|TOKEN)\s*=\s*[\"\x27](?!your_|example_|test_|change_|placeholder)([^\"\x27]{8,})[\"\x27]",
    ]
    
    for pattern in pk_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            finding = {
                "id": hashlib.md5(f"BLK-CRYPTO-001:{filepath}:{match.start()}".encode()).hexdigest()[:12],
                "rule_id": "BLK-CRYPTO-001",
                "rule_name": "Hardcoded Private Keys / Secrets",
                "severity": "critical",
                "severity_weight": 100,
                "file": filepath,
                "line_hint": content[:match.start()].count("\n") + 1,
                "confidence": "critical",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "fix_guidance": "Use environment variables or key management service. Never hardcode secrets.",
            }
            findings.append(finding)
    
    return findings

def main():
    parser = argparse.ArgumentParser(description="Blockchain code auditor")
    parser.add_argument("--target", required=True, help="Target repo directory")
    parser.add_argument("--rules", required=True, help="Rules file path")
    parser.add_argument("--output", default="auditor/findings/", help="Output directory for findings")
    parser.add_argument("--log", default="auditor/logs/events.jsonl", help="Event log path")
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"ERROR: Target directory not found: {args.target}", file=sys.stderr)
        sys.exit(1)
    
    # Parse rules
    rules = parse_rules(args.rules)
    print(f"Loaded {len(rules)} audit rules")
    
    # Find files to scan
    sol_files = find_files(args.target, [".sol"])
    rs_files = find_files(args.target, [".rs"])
    go_files = find_files(args.target, [".go"])
    config_files = find_files(args.target, [".env", ".env.example", ".yml", ".yaml", ".toml", ".json"])
    
    all_files = sol_files + rs_files + go_files + config_files
    print(f"Found {len(sol_files)} Solidity, {len(rs_files)} Rust, {len(go_files)} Go, {len(config_files)} config files")
    
    # Scan all files
    all_findings = []
    
    for filepath in all_files:
        # Rule-based scan
        findings = scan_file(filepath, rules)
        all_findings.extend(findings)
        
        # Special scans
        if any(filepath.endswith(ext) for ext in [".env", ".env.example", ".yml", ".yaml", ".toml", ".json", ".py", ".js", ".ts", ".go", ".rs", ".sol"]):
            secrets = scan_hardcoded_secrets(filepath)
            all_findings.extend(secrets)
    
    # Limit total findings to prevent overflow
    MAX_FINDINGS = 500
    if len(all_findings) > MAX_FINDINGS * 2:
        all_findings = all_findings[:MAX_FINDINGS * 2]
    
    # Deduplicate and sort
    seen = set()
    unique = []
    for f in all_findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    
    unique.sort(key=lambda x: x.get("severity_weight", 0), reverse=True)
    
    # Write findings
    os.makedirs(args.output, exist_ok=True)
        repo_name = os.path.basename(args.target.rstrip("/"))
    findings_file = os.path.join(args.output, f"{repo_name}_findings.jsonl")
    summary_file = os.path.join(args.output, f"{repo_name}_summary.json")
    
    
    with open(findings_file, "w", encoding="utf-8") as f:
        for finding in unique:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")
    
    # Summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in unique:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    summary = {
        "target": args.target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_files_scanned": len(all_files),
        "total_findings": len(unique),
        "by_severity": severity_counts,
        "by_language": {
            "solidity": len([f for f in unique if f["file"].endswith(".sol")]),
            "rust": len([f for f in unique if f["file"].endswith(".rs")]),
            "go": len([f for f in unique if f["file"].endswith(".go")]),
            "config": len([f for f in unique if any(f["file"].endswith(e) for e in [".env", ".yml", ".yaml", ".toml", ".json"])]),
        }
    }
    
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    # Log event
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workflow": "audit",
        "event": "audit_complete",
        "data": summary
    }
    with open(args.log, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    
    print(f"Audit complete: {len(unique)} findings ({severity_counts})")

if __name__ == "__main__":
    main()
