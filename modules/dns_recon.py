#!/usr/bin/env python3
import shutil, socket, subprocess
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section, print_table
RECORD_TYPES=["A","AAAA","CNAME","MX","NS","TXT","SOA","PTR","SRV"]
class DNSRecon(BaseModule):
    NAME="recon/dns"; DESCRIPTION="DNS record enumeration"; AUTHOR="NeiveZ"; REFERENCES=["https://www.rfc-editor.org/rfc/rfc1035"]
    def _define_options(self):
        self._add_option("TARGET","",True,"Target domain"); self._add_option("TYPES","all",False,"all or comma-separated record types"); self._add_option("SERVER","",False,"DNS server"); self._add_option("TIMEOUT","5",False,"Query timeout")
    def run(self):
        if not self._validate(): return {}
        target=self.get_option("TARGET").strip(); types=self._parse_types(self.get_option("TYPES")); server=self.get_option("SERVER") or ""; timeout=max(1,min(30,int(self.get_option("TIMEOUT") or 5)))
        print_section(f"DNS Recon → {Colors.CYAN}{target}{Colors.RESET}"); print_status("Record types: "+", ".join(types),"info")
        records={}
        for typ in types:
            vals=self._query(target,typ,server,timeout)
            if vals: records[typ]=vals
        total=sum(map(len,records.values()))
        if total:
            print_table(["Type","Name","Data"],[(t,x.get("name",target),x.get("data","")) for t,vals in records.items() for x in vals])
            print_status(f"DNS enumeration complete. Found {total} records.","ok")
        else: print_status("No DNS records returned.","warn")
        return {"target":target,"records":records,"total_records":total}
    def _parse_types(self,v):
        if not v or v.lower()=="all": return RECORD_TYPES
        return [x.strip().upper() for x in v.split(",") if x.strip().upper() in RECORD_TYPES]
    def _query(self,domain,rtype,server,timeout):
        if shutil.which("dig"):
            cmd=["dig","+noall","+answer",f"+time={timeout}"]+([f"@{server}"] if server else [])+[domain,rtype]
            try:
                out=subprocess.check_output(cmd,stderr=subprocess.DEVNULL,timeout=timeout+2).decode(errors="replace"); vals=[]
                for line in out.splitlines():
                    p=line.split()
                    if len(p)>=5: vals.append({"name":p[0],"ttl":p[1],"type":p[3],"data":" ".join(p[4:])})
                return vals
            except Exception: return []
        if rtype=="A":
            try: return [{"name":domain,"ttl":"","type":"A","data":ip} for ip in socket.gethostbyname_ex(domain)[2]]
            except Exception:return []
        return []
