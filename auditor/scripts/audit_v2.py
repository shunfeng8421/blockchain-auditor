#!/usr/bin/env python3
"""
V2 Optimized Scanner — integrated into blockchain-auditor as --optimized mode
Adds false-positive filtering to reduce noise from new rules.
"""
import re, os, sys, json, hashlib, argparse, subprocess
from datetime import datetime
from pathlib import Path

# ===== FALSE POSITIVE EXCLUSION FUNCTIONS =====

FP_EXCLUSIONS = {
    "BLK-SOL-023": lambda c: bool(re.search(
        r'block\.timestamp\s*[<>]=\s*\w+\s*\+\s*\w+|'
        r'block\.timestamp\s*<<\s*TIME_RESOLUTION|'
        r'block\.timestamp\s*[<>]\s*minters\[|'
        r'block\.timestamp\s*[<>]\s*MATURITY|'
        r'block\.timestamp\s*[<>]\s*EXPIRATION|'
        r'block\.timestamp\s*[<>]\s*horizon|'
        r'block\.timestamp\s*[<>]=\s*validAfter|'
        r'block\.timestamp\s*>=\s*executableAt|'
        r'block\.timestamp\s*[<>]=\s*\w+\)\s*revert\s+Expired|'
        r'block\.timestamp\s*[<>]=\s*\w+\)\s*revert\s+TooLat',
        c, re.IGNORECASE)),
    "BLK-SOL-024": lambda c: bool(re.search(r'__gap\s*\[', c)) or bool(re.search(r'bytes32\s+(private|internal|constant)\s+\w+StorageLocation\s*=', c)),
    "BLK-SOL-025": lambda c: bool(re.search(r'initializer\b|onlyInitializing\b|AlreadyInitialized|alreadyInitialized|totalSupply\s*\(\s*\)\s*==\s*0|owner\s*!=\s*address\s*\(\s*0\s*\)', c)),
    "BLK-SOL-026": lambda c: bool(re.search(r'forceApprove\b|SafeERC20\b', c)),
    "BLK-SOL-027": lambda c: bool(re.search(r'@openzeppelin|OpenZeppelin', c, re.IGNORECASE)) or (not bool(re.search(r'taxAmount|feeAmount|reflectFee', c))),
    "BLK-SOL-029": lambda c: bool(re.search(r'checkAccess\b|onlyOwner\b|onlyRole\b|Ownable2Step\b', c)),
    "BLK-SOL-032": lambda c: bool(re.search(r'forceApprove\b|SafeERC20\b|ReentrancyGuard|nonReentrant', c)),
    "BLK-SOL-033": lambda c: bool(re.search(r'///\s*@notice|interface\s+\w+|@title|@dev\s', c)),
}

def scan_file_optimized(filepath, rules):
    """Scan file with false-positive filtering for new rules."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []
    
    ext = Path(filepath).suffix
    filename = Path(filepath).name
    findings = []
    
    for rule in rules:
        # Check if rule applies to this file type
        tags = rule.get("tags", [])
        lang_match = False
        if ext == ".sol" and "solidity" in tags: lang_match = True
        elif ext == ".rs" and "rust" in tags: lang_match = True
        elif ext == ".go" and "go" in tags: lang_match = True
        elif ext in (".cpp", ".cc", ".cxx", ".h", ".hpp") and "cpp" in tags: lang_match = True
        elif ext == ".py" and "python" in tags: lang_match = True
        elif ext in (".ts", ".tsx", ".js", ".jsx", ".mjs") and ("typescript" in tags or "javascript" in tags): lang_match = True
        elif ext == ".java" and "java" in tags: lang_match = True
        elif ext == ".cs" and "csharp" in tags: lang_match = True
        elif ext == ".move" and "move" in tags: lang_match = True
        elif "all" in tags: lang_match = True
        
        if not lang_match:
            continue
        
        rule_id = rule["rule_id"]
        
        # False-positive filter for new rules
        if rule_id in FP_EXCLUSIONS:
            try:
                if FP_EXCLUSIONS[rule_id](content):
                    continue
            except Exception:
                pass
        
        # Check patterns
        patterns = rule.get("detection", {}).get("patterns", [])
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    findings.append({
                        "id": hashlib.md5(f"{rule_id}:{filepath}".encode()).hexdigest()[:12],
                        "rule_id": rule_id,
                        "rule_name": rule.get("name", ""),
                        "severity": rule.get("severity", "unknown"),
                        "severity_weight": int(rule.get("severity_weight", 0)),
                        "file": filepath,
                        "confidence": rule.get("confidence", "low"),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "fix_guidance": rule.get("fix", ""),
                        "known_exploits": rule.get("known_exploits", ""),
                        "filtered": False,
                    })
                    break
            except re.error:
                continue
    
    return findings


def main():
    parser = argparse.ArgumentParser(description="Blockchain code auditor (V2 optimized)")
    parser.add_argument("--target", required=True, help="Target repo directory")
    parser.add_argument("--repo-url", default="", help="Repository URL for output file naming")
    parser.add_argument("--rules", required=True, help="Rules file path")
    parser.add_argument("--output", default="auditor/findings/", help="Output directory for findings")
    parser.add_argument("--log", default="auditor/logs/events.jsonl", help="Event log path")
    parser.add_argument("--optimized", action="store_true", help="Enable false-positive filtering for new rules")
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"ERROR: Target directory not found: {args.target}", file=sys.stderr)
        sys.exit(1)
    
    # Import original audit module for shared functions
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from audit import parse_rules, find_files, scan_hardcoded_secrets
    
    # Parse rules
    rules = parse_rules(args.rules)
    print(f"Loaded {len(rules)} audit rules")
    
    # Find files
    sol_files = find_files(args.target, [".sol"])
    rs_files = find_files(args.target, [".rs"])
    go_files = find_files(args.target, [".go"])
    cpp_files = find_files(args.target, [".cpp", ".cc", ".cxx", ".h", ".hpp"])
    py_files = find_files(args.target, [".py"])
    ts_files = find_files(args.target, [".ts", ".tsx", ".js", ".jsx", ".mjs"])
    java_files = find_files(args.target, [".java"])
    cs_files = find_files(args.target, [".cs"])
    move_files = find_files(args.target, [".move"])
    config_files = find_files(args.target, [".env", ".env.example", ".yml", ".yaml", ".toml", ".json"])
    
    all_files = sol_files + rs_files + go_files + cpp_files + py_files + ts_files + java_files + cs_files + move_files + config_files
    print(f"Found {len(sol_files)} Solidity, {len(rs_files)} Rust, {len(go_files)} Go, {len(cpp_files)} C/C++, {len(py_files)} Python, {len(ts_files)} TS/JS, {len(java_files)} Java, {len(cs_files)} C#, {len(move_files)} Move, {len(config_files)} config files")
    
    # Scan
    all_findings = []
    for filepath in all_files:
        if args.optimized:
            findings = scan_file_optimized(filepath, rules)
        else:
            from audit import scan_file
            findings = scan_file(filepath, rules)
        all_findings.extend(findings)
        
        # Always scan for secrets
        if any(filepath.endswith(ext) for ext in [".env", ".env.example", ".yml", ".yaml", ".toml", ".json", ".py", ".js", ".ts", ".go", ".rs", ".sol"]):
            secrets = scan_hardcoded_secrets(filepath)
            all_findings.extend(secrets)
    
    # Dedup and sort
    MAX_FINDINGS = 500
    if len(all_findings) > MAX_FINDINGS * 2:
        all_findings = all_findings[:MAX_FINDINGS * 2]
    
    seen = set()
    unique = []
    for f in all_findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    
    unique.sort(key=lambda x: x.get("severity_weight", 0), reverse=True)
    
    # Write findings
    os.makedirs(args.output, exist_ok=True)
    if args.repo_url:
        parts = args.repo_url.rstrip("/").split("/")
        repo_name = parts[-2] + "_" + parts[-1] if len(parts) >= 2 else parts[-1]
    else:
        repo_name = os.path.basename(args.target.rstrip("/"))
    
    findings_file = os.path.join(args.output, repo_name + "_findings.jsonl")
    summary_file = os.path.join(args.output, repo_name + "_summary.json")
    
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
        "mode": "optimized" if args.optimized else "standard",
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
    
    # Log
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workflow": "audit_v2",
        "event": "audit_complete",
        "data": summary
    }
    with open(args.log, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    
    print(f"Audit complete ({summary['mode']}): {len(unique)} findings ({severity_counts})")


if __name__ == "__main__":
    main()