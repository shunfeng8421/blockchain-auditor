"""Blockchain Auditor v2 - Multi-Engine: Slither + Custom Detectors + Taint + Secrets"""
import json, os, sys, hashlib, argparse, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {"node_modules", "Migrations"}

def _skip(p):
    parts = set(p.replace(chr(92), chr(47)).split(chr(47)))
    return bool(parts & SKIP_DIRS)

def run_slither(td):
    findings = []
    try:
        r = subprocess.run(["slither",td,"--json","-","--filter-paths","node_modules|test|mock|Migrations"],capture_output=True,text=True,timeout=300,cwd=td)
        if r.returncode not in (0,1) or not r.stdout.strip(): return findings
        data = json.loads(r.stdout)
        for det in data.get("results",{}).get("detectors",[]):
            for el in det.get("elements",[]):
                sm = el.get("source_mapping",{})
                fn = str(Path(td) / sm.get("filename_relative",""))
                findings.append({"id":hashlib.md5(f"slither:{det.get('check','')}:{fn}:{sm.get('lines',[0])[0]}".encode()).hexdigest()[:12],"rule_id":f"SLITHER-{det.get('check','').upper()}","rule_name":det.get("check",""),"severity":{"High":"critical","Medium":"high","Low":"medium","Informational":"low"}.get(det.get("impact",""),"medium"),"severity_weight":{"High":100,"Medium":65,"Low":35}.get(det.get("impact",""),35),"category":"security","file":fn,"line":sm.get("lines",[0])[0],"match":det.get("description","")[:200],"confidence":{"High":"high","Medium":"medium","Low":"low"}.get(det.get("confidence",""),"medium"),"timestamp":datetime.now(timezone.utc).isoformat(),"source":"slither","advisory_score":0})
    except Exception as e:
        print(f"Slither: {e}", file=sys.stderr)
    return findings

def _mk(sol_file, rid, name, sev, line, match, fix, exploits="", cat="security"):
    return {"id":hashlib.md5(f"{rid}:{str(sol_file)}:{line}".encode()).hexdigest()[:12],"rule_id":rid,"rule_name":name,"severity":sev,"severity_weight":{"critical":100,"high":70,"medium":40,"low":15}.get(sev,30),"category":cat,"file":str(sol_file),"line":line,"match":match[:200],"confidence":"medium","timestamp":datetime.now(timezone.utc).isoformat(),"fix_guidance":fix,"known_exploits":exploits,"source":"custom-detector","advisory_score":0}

def run_custom_detectors(td):
    findings = []
    for sol_file in Path(td).rglob("*.sol"):
        sp = str(sol_file)
        if _skip(sp): continue
        try:
            with open(sol_file,"r",encoding="utf-8",errors="ignore") as f: src = f.read()
        except: continue
        lines = src.split("\n")
        # Flash loan surface
        for i, line in enumerate(lines, 1):
            for kw in ["flashLoan","flashSwap","onFlashLoan","executeOperation"]:
                if kw in line and "function" in line:
                    findings.append(_mk(sol_file,"CUSTOM-FLSH-001","Flash Loan Attack Surface","critical",i,line[:80],"Add TWAP oracle and minDelay timelock","bZx $1M, PancakeBunny $200M, Beanstalk $182M"))
                    break
        # Oracle: spot price via getReserves without TWAP
        if "getReserves()" in src and "TWAP" not in src and "cumulative" not in src.lower():
            idx = src.find("getReserves()")
            if "library" not in src[max(0,idx-500):idx]:
                for i, line in enumerate(lines, 1):
                    if "getReserves()" in line:
                        findings.append(_mk(sol_file,"CUSTOM-ORCL-001","Spot Price Oracle (no TWAP)","high",i,line[:80],"Use Chainlink or TWAP","Cream $130M, Inverse $15M"))
                        break
        # Missing slippage
        for m in re.finditer(r"function\s+(swap|exchange|trade|convert)\s*\(", src, re.I):
            ln = src[:m.start()].count("\n")+1
            rest = src[m.end():]; bc, body, started = 0, "", False
            for ch in rest:
                if ch == "{": bc += 1; started = True
                elif ch == "}": bc -= 1
                if started and bc == 0: break
                if started: body += ch
            if not re.search(r"(amountOutMin|amountMin|minReturn|minAmount|slippage)", body, re.I):
                findings.append(_mk(sol_file,"CUSTOM-SLIP-001","Missing Slippage Protection","high",ln,m.group(0)[:80],"Add amountOutMin parameter","Universal sandwich attacks"))
        # Missing access control
        for pat, name in [(r"function\s+setFee\s*\(.*\)\s*(?:external|public)","setFee"),(r"function\s+setAdmin\s*\(.*\)\s*(?:external|public)","setAdmin"),(r"function\s+setOwner\s*\(.*\)\s*(?:external|public)","setOwner"),(r"function\s+mint\s*\(.*\)\s*(?:external|public)","mint")]:
            for m in re.finditer(pat, src, re.I):
                ln = src[:m.start()].count("\n")+1
                ctx = src[max(0,m.start()-500):m.end()+500]
                if "onlyOwner" not in ctx and "onlyRole" not in ctx:
                    findings.append(_mk(sol_file,"CUSTOM-TMLK-001",f"Privileged Function Without Access Control: {name}","critical",ln,m.group(0)[:80],"Add onlyOwner/onlyRole modifier","Multiple DeFi rug pulls"))
        # Unprotected initializer
        for m in re.finditer(r"function\s+initialize\s*\([^)]*\)\s*(?:external|public)", src, re.I):
            ln = src[:m.start()].count("\n")+1
            if "initializer" not in src[max(0,m.start()-300):m.start()].lower():
                findings.append(_mk(sol_file,"CUSTOM-INIT-001","Unprotected Initializer","critical",ln,m.group(0)[:80],"Add initializer modifier","Wormhole $326M"))
        # Unbounded approval
        for m in re.finditer(r"approve\s*\([^,]+,\s*type\s*\(\s*uint256\s*\)\s*\.\s*max", src, re.I):
            ln = src[:m.start()].count("\n")+1
            findings.append(_mk(sol_file,"CUSTOM-APRV-001","Unbounded Token Approval","medium",ln,m.group(0)[:80],"Approve exact amount; reset to 0 first","ERC20 approval race condition"))
    return findings

def run_taint_analysis(td):
    findings = []
    for sol_file in Path(td).rglob("*.sol"):
        sp = str(sol_file)
        if _skip(sp): continue
        try:
            with open(sol_file,"r",encoding="utf-8",errors="ignore") as f: src = f.read()
        except: continue
        for fm in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:external|public)\s*(?:view\s+|pure\s+)*(?:override\s+)*(?:returns\s*\([^)]*\)\s*)?\{", src):
            pnames = [p.strip().split()[-1].lstrip("_") for p in fm.group(2).split(",") if p.strip() and p.strip().split()[-1].lstrip("_") not in ("memory","calldata","storage")]
            if not pnames: continue
            pos = fm.end()-1; rest = src[pos:]; bc, body, started = 0, "", False
            for ch in rest:
                if ch == "{": bc += 1; started = True
                elif ch == "}": bc -= 1
                if started and bc == 0: break
                if started: body += ch
            for sp_pat, sp_desc in [(r"\.call\s*\{",".call{}"),(r"\.delegatecall\s*\(",".delegatecall()"),(r"\bassembly\s*\{","inline assembly")]:
                for sm in re.finditer(sp_pat, body):
                    ctx = body[max(0,sm.start()-300):sm.start()+100]
                    for pn in pnames:
                        if re.search(r"\b"+re.escape(pn)+r"\b", ctx):
                            ln = src[:pos+sm.start()].count("\n")+1
                            findings.append(_mk(sol_file,"TAINT-CALL-001",f"User Input ({pn}) Reaches {sp_desc}","critical",ln,f"Parameter {pn} from {fm.group(1)} flows to {sp_desc}","Validate/restrict {pn} before it reaches the sink",""))
                            break
    return findings

def run_secret_scan(td):
    findings = []
    patterns = [
        (r"(?i)(?:private_key|secret_key)\s*=\s*['\"]?(0x[a-fA-F0-9]{64})['\"]?","critical","Ethereum Private Key"),
        (r"(?:secret_key|SECRET_KEY)\s*=\s*\[\s*\d+(?:\s*,\s*\d+){31,}\s*\]","critical","Solana Private Key"),
        (r"(?:mnemonic|seed_phrase)\s*=\s*['\"]([a-z]{2,}\s+){11,23}[a-z]{2,}['\"]","critical","BIP39 Mnemonic"),
        (r"(?i)AWS_ACCESS_KEY_ID\s*=\s*['\"](AKIA[0-9A-Z]{16})['\"]","critical","AWS Access Key"),
        (r"ghp_[A-Za-z0-9]{36}","critical","GitHub Token"),
        (r"(?:INFURA_API_KEY|ALCHEMY_API_KEY)\s*=\s*['\"]([a-zA-Z0-9]{32,})['\"]","high","RPC API Key"),
    ]
    exts = [".sol",".js",".ts",".py",".rs",".go",".env",".yml",".yaml",".json",".toml",".txt",".md"]
    all_files = []
    for ext in exts:
        for f in Path(td).rglob(f"*{ext}"):
            if not _skip(str(f)): all_files.append(f)
    for fp in all_files:
        try:
            with open(fp,"r",encoding="utf-8",errors="ignore") as f: content = f.read()
        except: continue
        for pattern, sev, name in patterns:
            for m in re.finditer(pattern, content, re.M):
                ln = content[:m.start()].count("\n")+1
                lc = content.split("\n")[ln-1] if ln <= len(content.split("\n")) else ""
                if any(w in lc.lower() for w in ["example","placeholder","test","mock","dummy","your_","changeme","xxxx"]): continue
                findings.append({"id":hashlib.md5(f"secret:{str(fp)}:{m.start()}".encode()).hexdigest()[:12],"rule_id":"SECRET-001","rule_name":f"Hardcoded {name}","severity":sev,"severity_weight":100 if sev=="critical" else 70,"category":"secret-leak","file":str(fp),"line":ln,"match":f"[REDACTED {name}]" if sev=="critical" else m.group(0)[:100],"confidence":"high" if sev=="critical" else "medium","timestamp":datetime.now(timezone.utc).isoformat(),"fix_guidance":"Rotate immediately. Use env vars or secrets manager.","known_exploits":"Direct theft of funds or account takeover.","source":"secret-scanner","advisory_score":100 if sev=="critical" else 60})
    return findings

def score_finding(f):
    s = {"critical":40,"high":25,"medium":10,"low":0}.get(f.get("severity","low"),0)
    s += {"high":25,"medium":15,"low":5}.get(f.get("confidence","low"),0)
    s += {"slither":15,"custom-detector":20,"taint-tracker":25,"secret-scanner":20}.get(f.get("source",""),0)
    s += {"secret-leak":15,"security":5}.get(f.get("category",""),0)
    return s

def main():
    p = argparse.ArgumentParser(description="Blockchain Auditor v2")
    p.add_argument("--target", required=True)
    p.add_argument("--output", default="auditor/findings/")
    p.add_argument("--log", default="auditor/logs/events.jsonl")
    p.add_argument("--max-findings", type=int, default=500)
    p.add_argument("--skip-slither", action="store_true")
    p.add_argument("--only-secrets", action="store_true")
    args = p.parse_args()
    if not os.path.isdir(args.target): print(f"ERROR: {args.target} not found", file=sys.stderr); sys.exit(1)
    all_findings = []

    if not args.skip_slither and not args.only_secrets:
        print("[1/4] Slither...")
        sf = run_slither(args.target); all_findings.extend(sf); print(f"  Slither: {len(sf)}")
    if not args.only_secrets:
        print("[2/4] Custom detectors...")
        cf = run_custom_detectors(args.target); all_findings.extend(cf); print(f"  Custom: {len(cf)}")
        print("[3/4] Taint analysis...")
        tf = run_taint_analysis(args.target); all_findings.extend(tf); print(f"  Taint: {len(tf)}")
    print("[4/4] Secret scanner...")
    secf = run_secret_scan(args.target); all_findings.extend(secf); print(f"  Secrets: {len(secf)}")

    seen = set(); unique = []
    for f in all_findings:
        if f["id"] not in seen: seen.add(f["id"]); unique.append(f)
    for f in unique: f["advisory_score"] = score_finding(f)
    unique.sort(key=lambda x: x.get("advisory_score",0), reverse=True)
    unique = unique[:args.max_findings]

    os.makedirs(args.output, exist_ok=True)
    with open(os.path.join(args.output, "findings.jsonl"), "w", encoding="utf-8") as f:
        for x in unique: f.write(json.dumps(x, ensure_ascii=False)+"\n")
    advisory = [x for x in unique if x["advisory_score"]>=40]
    with open(os.path.join(args.output, "advisory_ready.jsonl"), "w", encoding="utf-8") as f:
        for x in advisory: f.write(json.dumps(x, ensure_ascii=False)+"\n")

    sev = {"critical":0,"high":0,"medium":0,"low":0}; srcs = {}
    for x in unique:
        sev[x.get("severity","low")] = sev.get(x.get("severity","low"),0)+1
        s = x.get("source","?"); srcs[s] = srcs.get(s,0)+1

    summary = {"target":args.target,"repo":Path(args.target).name,"timestamp":datetime.now(timezone.utc).isoformat(),"total_findings":len(unique),"advisory_ready":len(advisory),"by_severity":sev,"by_source":srcs}
    with open(os.path.join(args.output, "findings_summary.json"), "w") as f: json.dump(summary, f, indent=2)
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    with open(args.log, "a") as f: f.write(json.dumps({"timestamp":datetime.now(timezone.utc).isoformat(),"event":"audit_complete_v2","data":summary})+"\n")

    print(f"\n===== AUDIT COMPLETE (v2) =====")
    print(f"  Target: {Path(args.target).name}")
    print(f"  Total: {len(unique)} | Advisory-ready: {len(advisory)}")
    print(f"  Critical: {sev.get('critical',0)} | High: {sev.get('high',0)} | Medium: {sev.get('medium',0)} | Low: {sev.get('low',0)}")
    for s,c in srcs.items(): print(f"  [{s}]: {c}")
    if advisory:
        print(f"\n  Top Advisory Targets:")
        for x in advisory[:5]:
            print(f"    [{x['severity'].upper():8s}] [{x.get('source',''):16s}] Score:{x['advisory_score']:3d}  {x['rule_name']}")

if __name__ == "__main__": main()