#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ORFX - Offensive Recon Framework CLI."""
from __future__ import annotations
import argparse
import compileall
import datetime as dt
import importlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

TOOL = "ORFX"
TAGLINE = "Offensive Recon Framework"
VERSION = "3.1.0"
USE_COLOR = True

COMMANDS = {
    "subdomains": ("modules.subdomain_enum", "SubdomainEnumerator", "Discover subdomains using passive and DNS methods."),
    "dns": ("modules.dns_recon", "DNSRecon", "Enumerate DNS records."),
    "http": ("modules.http_probe", "HTTPProbe", "Probe HTTP services, headers, technologies and security headers."),
    "ports": ("modules.port_scanner", "PortScanner", "Perform light TCP port discovery."),
    "whois": ("modules.whois_lookup", "WhoisLookup", "Query WHOIS information."),
}

ANSI = {"reset":"\033[0m","bold":"\033[1m","dim":"\033[90m","red":"\033[91m","green":"\033[92m","yellow":"\033[93m","cyan":"\033[96m","white":"\033[97m"}
def c(name: str, text: str) -> str:
    return text if not USE_COLOR else ANSI.get(name, "") + text + ANSI["reset"]

def banner():
    print(c("bold", r"""
   ____  ____  _______  __
  / __ \/ __ \/ ____/ |/ /
 / / / / /_/ / /_   |   /
/ /_/ / _, _/ __/  /   |
\____/_/ |_/_/    /_/|_|
"""))
    print(f"  {c('white', TOOL)}  {c('dim', TAGLINE)}  {c('white', 'v'+VERSION)}")
    print(c("dim", "  Authorized security testing only."))
    print()

def print_commands():
    print(c("bold", "Available commands")); print("-"*86)
    for name, (_, _, desc) in COMMANDS.items(): print(f"  {name:<14} {desc}")
    print("  full           Run the documented end-to-end reconnaissance flow")
    print("\nGlobal options: --json --txt --html --out PATH --silent --no-color")
    print("\nExamples:")
    for x in [
        "./orfx.sh subdomains -d example.com --resolve",
        "./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA",
        "./orfx.sh http -u https://example.com",
        "./orfx.sh http -i reports/example_subdomains.txt",
        "./orfx.sh ports -t 192.168.1.10 --ports 21,22,80,443,445",
        "./orfx.sh whois -d example.com",
        "./orfx.sh full -d example.com --resolve --http --json --txt --out reports/example_full",
    ]: print("  "+x)

def load_module(command):
    mod_name, cls_name, _ = COMMANDS[command]
    mod = importlib.import_module(mod_name); return getattr(mod, cls_name)()

def parse_common(argv):
    common = {"json":False,"txt":False,"html":False,"out":"","silent":False,"no_color":False}
    cleaned=[]; i=0
    while i < len(argv):
        a=argv[i]
        if a in ("--json","--txt","--html","--silent","--no-color"):
            common[a[2:].replace("-","_")]=True; i+=1; continue
        if a=="--out":
            if i+1>=len(argv): raise ValueError("--out requires a path")
            common["out"]=argv[i+1]; i+=2; continue
        if a.startswith("--out="):
            common["out"]=a.split("=",1)[1]; i+=1; continue
        cleaned.append(a); i+=1
    return cleaned, common

def set_options(obj, args):
    opts=obj.options
    # aliases used by README and old CLI
    aliases={"-d":"TARGET","-u":"TARGET","-t":"TARGET","-i":"INPUT","--records":"TYPES","--wordlist":"WORDLIST","--threads":"THREADS","--timeout":"TIMEOUT","--resolve":"RESOLVE","--http":"HTTP","--passive":"PASSIVE","--active":"ACTIVE","--follow":"FOLLOW","--scheme":"SCHEME","--fallback":"FALLBACK","--banners":"BANNERS","--ports":"PORTS"}
    i=0
    while i<len(args):
        a=args[i]
        if a in ("--help","-h"): return "help"
        if a in ("--verbose","--authorized"): i+=1; continue
        key=aliases.get(a)
        if key:
            if key in ("RESOLVE","HTTP","PASSIVE","ACTIVE"):
                val="true"
            else:
                if i+1>=len(args): raise ValueError(f"{a} requires a value")
                val=args[i+1]; i+=1
            if key in opts: obj.set_option(key,val)
            else: raise ValueError(f"Option {a} is not supported by this command")
            i+=1; continue
        if a.startswith("--"):
            raw=a[2:]; key=raw.replace("-","_").upper()
            if key not in opts:
                raise ValueError(f"Unknown option: {a}")
            if i+1>=len(args) or args[i+1].startswith("-"): raise ValueError(f"{a} requires a value")
            obj.set_option(key,args[i+1]); i+=2; continue
        if a.startswith("-"):
            raise ValueError(f"Unknown option: {a}")
        raise ValueError(f"Unexpected argument: {a}")
    return None

def show_module_help(command,obj):
    print(c("bold", f"Command: {command}")); print(COMMANDS[command][2]); print()
    for k,m in obj.options.items():
        req="required" if m.get("required") else "optional"
        print(f"  --{k.lower().replace('_','-'):<16} {req:<9} {m.get('desc','')}")
    print("\nAliases: -d/-u/-t for TARGET where applicable; --json --txt --html --out --silent")

def scalar(v):
    if v is None: return ""
    if isinstance(v,(dict,list)): return json.dumps(v, ensure_ascii=False)
    return str(v)

def findings(command, result):
    rows=[]
    if not isinstance(result,dict): return [{"severity":"INFO","target":"","check":command,"detail":scalar(result)}]
    target=result.get("target","")
    if command=="subdomains":
        for x in result.get("subdomains",[]): rows.append({"severity":"INFO","target":x.get("subdomain",""),"check":"DNS A","detail":", ".join(x.get("ips",[]))})
        if result.get("passive_subdomains") is not None: rows.append({"severity":"INFO","target":target,"check":"Passive source","detail":f"{len(result.get('passive_subdomains',[]))} names"})
        rows.append({"severity":"INFO","target":target,"check":"Subdomains","detail":f"{len(result.get('subdomains',[]))} resolved names"})
    elif command=="dns":
        for typ,vals in result.get("records",{}).items():
            for x in vals: rows.append({"severity":"INFO","target":x.get("name",target),"check":typ,"detail":x.get("data","")})
        if not result.get("records"): rows.append({"severity":"WARN","target":target,"check":"DNS","detail":result.get("error","No records returned")})
    elif command=="http":
        if result.get("error"): rows.append({"severity":"ERROR","target":target,"check":"HTTP","detail":result["error"]})
        else:
            rows.append({"severity":"INFO","target":result.get("final_url",target),"check":"HTTP status","detail":result.get("status_code","")})
            for t in result.get("technologies",[]): rows.append({"severity":"INFO","target":target,"check":"Technology","detail":t})
            for h,present in result.get("security_headers",{}).items(): rows.append({"severity":"INFO" if present else "LOW","target":target,"check":"Security header","detail":f"{h}: {'PRESENT' if present else 'MISSING'}"})
    elif command=="ports":
        for p in result.get("open_ports",[]): rows.append({"severity":"INFO","target":target,"check":f"TCP/{p.get('port')}","detail":f"{p.get('service','unknown')} OPEN {p.get('banner','')}"})
        rows.append({"severity":"INFO","target":target,"check":"Port scan","detail":f"{len(result.get('open_ports',[]))} open port(s)"})
    elif command=="whois":
        for k,v in result.items():
            if k not in ("target",) and v not in (None,""): rows.append({"severity":"INFO","target":target,"check":k,"detail":scalar(v)})
    return rows

def print_rows(rows):
    print(c("bold","Results")); print("-"*110)
    if not rows: print(c("yellow","No structured findings returned.")); return
    print(f"{'Severity':<10} {'Target':<36} {'Check':<22} Detail")
    print("-"*110)
    for r in rows[:300]:
        sev=str(r.get("severity","INFO")).upper(); color="red" if sev in ("ERROR","HIGH") else "yellow" if sev=="LOW" else "cyan"
        print(f"{c(color,sev):<18} {str(r.get('target',''))[:36]:<36} {str(r.get('check',''))[:22]:<22} {str(r.get('detail',''))[:120]}")
    if len(rows)>300: print(c("dim",f"... {len(rows)-300} more findings; use --json/--txt/--html."))

def save_reports(command,result,rows,common):
    if not (common["json"] or common["txt"] or common["html"] or common["out"]): return []
    base=Path(common["out"] or f"reports/{command}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    if base.suffix: base=base.with_suffix("")
    base.parent.mkdir(parents=True,exist_ok=True)
    payload={"tool":TOOL,"version":VERSION,"command":command,"timestamp":dt.datetime.now().isoformat(timespec="seconds"),"results":result,"findings":rows}
    saved=[]
    if common["json"] or common["out"]:
        p=Path(str(base)+".json"); p.write_text(json.dumps(payload,indent=2,ensure_ascii=False,default=str),encoding="utf-8"); saved.append(str(p))
    if common["txt"]:
        p=Path(str(base)+".txt"); lines=[f"{TOOL} {VERSION} - {command}","="*80,""]+[f"{r['severity']} | {r['target']} | {r['check']} | {r['detail']}" for r in rows]; p.write_text("\n".join(lines)+"\n",encoding="utf-8"); saved.append(str(p))
    if common["html"]:
        import html
        trs="".join(f"<tr><td>{html.escape(str(r['severity']))}</td><td>{html.escape(str(r['target']))}</td><td>{html.escape(str(r['check']))}</td><td>{html.escape(str(r['detail']))}</td></tr>" for r in rows)
        p=Path(str(base)+".html"); p.write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>ORFX {command}</title><style>body{{font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:2rem}}table{{width:100%;border-collapse:collapse}}td,th{{padding:.6rem;border:1px solid #30363d;text-align:left}}</style></head><body><h1>ORFX — {html.escape(command)}</h1><table><tr><th>Severity</th><th>Target</th><th>Check</th><th>Detail</th></tr>{trs}</table></body></html>",encoding="utf-8"); saved.append(str(p))
    return saved

def run_check():
    ok=True
    print(c("bold","ORFX Environment Check")); print("-"*70)
    py=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"; print(f"[+] Python detected: {py}")
    if sys.version_info < (3,10): ok=False; print(c("red","[-] Python 3.10+ required"))
    for cmd in ("dig","whois","nmap"):
        print(("[+]" if shutil.which(cmd) else "[!]"), f"{cmd}: {'available' if shutil.which(cmd) else 'not installed (optional)'}")
    compiled=compileall.compile_dir(".",quiet=1)
    print(("[+]" if compiled else "[-]"),"Python syntax check:","PASS" if compiled else "FAIL"); ok &= compiled
    for command in COMMANDS:
        try: load_module(command); print(f"[+] Module loaded: {command}")
        except Exception as e: ok=False; print(c("red",f"[-] Module failed: {command}: {e}"))
    print("\n"+c("green" if ok else "red", "[+] ORFX is ready" if ok else "[-] ORFX check failed"))
    return 0 if ok else 1

def run_command(command,args,common):
    obj=load_module(command)
    try: status=set_options(obj,args)
    except ValueError as e: print(c("red",str(e))); return 2
    if status=="help": show_module_help(command,obj); return 0
    if not obj._validate(): return 2
    if not common["silent"]: banner(); print(f"Command: {command}\n")
    try: result=obj.run()
    except KeyboardInterrupt: print(c("yellow","Interrupted.")); return 130
    except Exception as e:
        print(c("red",f"Module execution failed: {e}")); return 1
    rows=findings(command,result)
    if not common["silent"]:
        print(); print_rows(rows)
    else:
        for r in rows: print(json.dumps(r,ensure_ascii=False))
    saved=save_reports(command,result,rows,common)
    if saved and not common["silent"]:
        print("\n"+c("green","Saved reports")); [print("  "+x) for x in saved]
    return 0

def run_full(args,common):
    # The documented flow: subdomains -> DNS -> optional HTTP.
    # It deliberately does not run port scanning automatically.
    obj=load_module("subdomains")
    try: set_options(obj,args)
    except ValueError as e: print(c("red",str(e))); return 2
    if not obj._validate(): return 2
    if not common["silent"]: banner(); print(c("bold","Full Recon Flow")); print()
    aggregate={"target":obj.get_option("TARGET"),"subdomains":None,"dns":None,"http":[]}
    aggregate["subdomains"]=obj.run()
    dns=load_module("dns"); dns.set_option("TARGET",obj.get_option("TARGET")); aggregate["dns"]=dns.run()
    do_http=str(obj.get_option("HTTP") or "false").lower() in ("1","true","yes","on")
    if do_http:
        hosts=[]
        for item in aggregate["subdomains"].get("subdomains",[]): hosts.append(item.get("subdomain"))
        if not hosts: hosts=[obj.get_option("TARGET")]
        # Keep full flow predictable; probe each discovered host, with a safe cap.
        for host in hosts[:100]:
            h=load_module("http"); h.set_option("TARGET",host); aggregate["http"].append(h.run())
    rows=[]
    for name,data in (("subdomains",aggregate["subdomains"]),("dns",aggregate["dns"]),("http",aggregate["http"])):
        if isinstance(data,list):
            for d in data: rows.extend(findings("http",d))
        else: rows.extend(findings(name,data))
    if not common["silent"]: print(); print_rows(rows)
    saved=save_reports("full",aggregate,rows,common)
    if saved and not common["silent"]:
        print("\n"+c("green","Saved reports")); [print("  "+x) for x in saved]
    return 0

def main(argv=None):
    global USE_COLOR
    argv=sys.argv[1:] if argv is None else argv
    if "--no-color" in argv: USE_COLOR=False
    if not argv or argv[0] in ("-h","--help","help"): banner(); print_commands(); return 0
    if argv[0]=="--check": return run_check()
    command=argv[0]
    if command in ("commands","list"): banner(); print_commands(); return 0
    args,common=parse_common(argv[1:])
    if command=="full": return run_full(args,common)
    if command not in COMMANDS: print(c("red",f"Unknown command: {command}")); print_commands(); return 2
    return run_command(command,args,common)

if __name__=="__main__": raise SystemExit(main())
