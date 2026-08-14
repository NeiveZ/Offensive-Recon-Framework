#!/usr/bin/env python3
import concurrent.futures, json, os, re, socket, urllib.request, urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section, loading_bar

DEFAULT_WORDLIST=["www","mail","ftp","api","dev","staging","test","app","portal","vpn","remote","blog","shop","cdn","static","media","images","login","auth","dashboard","internal","corp","intranet","secure","help","support","docs","wiki","git","gitlab","jenkins","ci","prometheus","grafana","jira","confluence","ldap","smtp","webmail","exchange","backup","monitor","status","beta","alpha","demo","sandbox","db","database","mysql","postgres","redis","elastic","kibana","ns1","ns2","mx","mx1","mx2","proxy"]

class SubdomainEnumerator(BaseModule):
    NAME="subdomain/enum"; DESCRIPTION="Passive certificate discovery + active DNS enumeration"; AUTHOR="NeiveZ"; REFERENCES=["https://crt.sh","https://github.com/danielmiessler/SecLists"]
    def _define_options(self):
        self._add_option("TARGET","",True,"Target domain")
        self._add_option("THREADS","50",False,"Concurrent DNS lookups")
        self._add_option("WORDLIST","",False,"Custom subdomain wordlist")
        self._add_option("TIMEOUT","3",False,"DNS timeout in seconds")
        self._add_option("RESOLVE","false",False,"Resolve discovered passive names")
        self._add_option("PASSIVE","true",False,"Query crt.sh certificate transparency data")
        self._add_option("ACTIVE","true",False,"Run DNS wordlist enumeration")
        self._add_option("HTTP","false",False,"Probe discovered HTTP services during full flow")
    @staticmethod
    def _bool(v): return str(v).lower() in ("1","true","yes","on")
    def run(self):
        if not self._validate(): return {}
        target=self._normalize_target(self.get_option("TARGET")); timeout=max(.2,min(30,float(self.get_option("TIMEOUT") or 3))); threads=max(1,min(200,int(self.get_option("THREADS") or 50)))
        if not self._valid_domain(target): print_status(f"Invalid target domain: {target}","error"); return {}
        print_section(f"Subdomain Enumeration → {Colors.CYAN}{target}{Colors.RESET}")
        passive=[]
        if self._bool(self.get_option("PASSIVE")):
            passive=self._crtsh(target,timeout)
            print_status(f"Passive discovery: {len(passive)} names from crt.sh","info")
        candidates=set(passive)
        if self._bool(self.get_option("ACTIVE")):
            words=self._load_wordlist(self.get_option("WORDLIST") or "")
            print_status(f"Active wordlist: {len(words)} candidates","info")
            for w in words: candidates.add(f"{w}.{target}")
        resolved=[]; resolve_all=self._bool(self.get_option("RESOLVE"))
        # Active candidates are always resolved; passive candidates only with --resolve.
        to_resolve=[x for x in sorted(candidates) if self._is_active_candidate(x,target) or resolve_all]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futs={ex.submit(self._resolve,x,timeout):x for x in to_resolve}
            total=len(futs); done=0
            for f in concurrent.futures.as_completed(futs):
                done+=1; loading_bar("Resolving",total,done)
                r=f.result()
                if r: resolved.append(r)
        if total: print()
        resolved.sort(key=lambda x:x["subdomain"])
        print_status(f"Enumeration complete. Found {len(resolved)} resolved subdomains.","ok")
        return {"target":target,"passive_subdomains":sorted(passive),"subdomains":resolved,"total":len(resolved)}
    def _crtsh(self,target,timeout):
        url="https://crt.sh/?q=%25."+urllib.parse.quote(target,safe="")+"&output=json"
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"ORFX/3.1"})
            with urllib.request.urlopen(req,timeout=timeout) as r: data=json.loads(r.read().decode("utf-8",errors="replace"))
            names=set()
            for row in data if isinstance(data,list) else []:
                for name in str(row.get("name_value","")).splitlines():
                    name=name.strip().lower().lstrip("*.")
                    if name==target or name.endswith("."+target): names.add(name)
            return sorted(names)
        except Exception as e:
            print_status(f"crt.sh unavailable: {e}","warn"); return []
    def _resolve(self,fqdn,timeout):
        try:
            old=socket.getdefaulttimeout(); socket.setdefaulttimeout(timeout)
            ips=sorted(set(socket.gethostbyname_ex(fqdn)[2])); socket.setdefaulttimeout(old)
            return {"subdomain":fqdn,"ips":ips,"ip":ips[0]} if ips else None
        except Exception: return None
    def _is_active_candidate(self,name,target):
        return name.count(".")==target.count(".")+1
    def _load_wordlist(self,path):
        candidates=[path] if path else []
        candidates.append(os.path.join(os.path.dirname(__file__),"..","wordlists","subdomains.txt"))
        for f in candidates:
            if f and os.path.isfile(f):
                return self._clean(open(f,encoding="utf-8",errors="ignore").read().splitlines())
        return DEFAULT_WORDLIST
    def _clean(self,lines):
        out=[]; seen=set()
        for line in lines:
            w=str(line).strip().lower().split()[0] if str(line).strip() else ""
            w=w.strip(".")
            if "." in w: w=w.split(".")[0]
            if w and re.match(r"^[a-z0-9][a-z0-9-]{0,62}$",w) and w not in seen: seen.add(w); out.append(w)
        return out
    def _normalize_target(self,v):
        raw=(v or "").strip().lower()
        if "://" in raw:
            p=urllib.parse.urlsplit(raw); raw=p.netloc or p.path
        return raw.split("/")[0].split(":")[0].strip(".")
    def _valid_domain(self,d):
        if len(d)>253 or "." not in d: return False
        return all(re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",x) for x in d.split("."))
