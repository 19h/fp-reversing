#!/usr/bin/env python3
"""Read original libsystem_notify cache bytes,functions,veneer bindings.

No target/loader/API execution. Original v5 chains independently walked and
cross-checked. Nlist strings read in bounded512-byte ranges;cache-wide string
pool is not copied. O(B+F+I+E) source extraction time/space.
"""
import bisect
import json
from pathlib import Path
import struct
from bootpolicy_cache_reader import Cache,Dylib,CS
from ams_core_reader import Core
from appstore_agent_reader import ROOT,sha

LIBRARY='/usr/lib/system/libsystem_notify.dylib'
UUID='266b92ef-8350-347c-9086-b53ba04523cf'


class Notify:
    page_chains=Core.page_chains
    section_chains=Core.section_chains
    pointer=Core.pointer
    def __init__(self):
        self.cache=Cache();assert self.cache.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';self.lib=Dylib(self.cache,LIBRARY);assert self.lib.uuid==UUID;self.page_cache={};self.headers={};self.libs={LIBRARY:self.lib};self.images=sorted((r['address'],r['path']) for r in self.cache.images);self.image_starts=[r[0] for r in self.images];self.external={};self.veneers={}
        self.text=next(x for x in self.lib.sections if x['name']=='__text');self.starts=self.lib.functions
    def read(self,a,n):return self.cache.read(a,n)
    def bounds(self,a):
        ix=bisect.bisect_right(self.starts,a)-1;assert ix>=0;z=self.starts[ix+1] if ix+1<len(self.starts) else self.text['address']+self.text['size'];assert self.starts[ix]<=a<z;return self.starts[ix],z
    def function(self,a):
        start,end=self.bounds(a);assert start==a;raw=self.read(a,end-a);return {'start':hex(a),'end':hex(end),'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]}
    def nlists(self):
        raw=next(raw for cmd,raw in self.lib.commands if cmd==2);off,count,stroff,strsize=struct.unpack_from('<4I',raw,8);rows=self.lib.read_offset(off,count*16);out=[]
        for j in range(count):
            ix,typ,sect,desc,value=struct.unpack_from('<IBBHQ',rows,j*16);name=''
            if ix:
                assert ix<strsize;raw=self.lib.read_offset(stroff+ix,min(512,strsize-ix));assert b'\0' in raw;name=raw.split(b'\0')[0].decode()
            out.append({'name':name,'address':hex(value),'n_type':typ,'n_sect':sect,'n_desc':desc,'nlist_index':j})
        return out
    def target(self,a):
        if a in self.external:return self.external[a]
        ix=bisect.bisect_right(self.image_starts,a)-1;assert ix>=0;path=self.images[ix][1]
        if path not in self.libs:self.libs[path]=Dylib(self.cache,path)
        d=self.libs[path];sections=[{'segment':s['segment'],'section':s['name']} for s in d.sections if s['address']<=a<s['address']+s['size']];assert sections,(hex(a),path)
        out={'address':hex(a),'library':path,'uuid':d.uuid,'exact_exports':[n for n,r in d.exports.items() if r['address']==a],'compiler_function_start':a in d.functions,'sections':sections};self.external[a]=out;return out
    def veneer(self,a):
        if a in self.veneers:return self.veneers[a]
        raw=self.read(a,16);ins=list(CS.disasm(raw,a));assert len(ins)==4 and [i.mnemonic for i in ins]==['adrp','add','ldr','braa'];assert ins[0].op_str.startswith('x17, #') and ins[1].op_str.startswith('x17, x17, #') and ins[2].op_str=='x16, [x17]' and ins[3].op_str=='x16, x17';slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],0);p=self.pointer(slot);target=self.target(int(p['target'],16));out={'address':hex(a),'bytes':raw.hex(),'slot':hex(slot),'pointer':p,'resolved_target':target};self.veneers[a]=out;return out


def main():
    s=Notify();chains={}
    for sec in s.lib.sections:
        if sec['segment'] in ['__DATA_CONST','__AUTH_CONST'] and sec['size']:chains.update(s.section_chains(sec))
    functions=[s.function(a) for a in s.starts];calls=[]
    for f in functions:
        for i in f['instructions']:
            if i['mnemonic'] not in ['bl','b'] or not i['operands'].startswith('#'):continue
            target=int(i['operands'][1:],16);row={'source_function':f['start'],'site':i['ea'],'branch':i['mnemonic'],'target':hex(target)}
            if not s.text['address']<=target<s.text['address']+s.text['size']:row['veneer']=s.veneer(target)
            calls.append(row)
    csec=next(x for x in s.lib.sections if x['name']=='__cstring');raw=s.read(csec['address'],csec['size']);strings=[];off=0
    while off<len(raw):
        end=raw.find(b'\0',off)
        if end<0:break
        if end>off:strings.append({'address':hex(csec['address']+off),'text':raw[off:end].decode()})
        off=end+1
    out={'scope':__doc__,'cache_uuid':s.cache.uuid,'library_path':LIBRARY,'library_uuid':UUID,'base':hex(s.lib.base),'sections':s.lib.sections,'exports':s.lib.exports,'function_starts':[hex(a) for a in s.starts],'complete_original_functions':functions,'original_nlists':s.nlists(),'original_chain_members':list(chains.values()),'original_direct_edges':calls,'original_bound_veneers':list(s.veneers.values()),'original_strings':strings,'external_bound_targets':list(s.external.values()),'cache_file_catalog':list(s.cache.files.values()),'reader_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['bootpolicy_cache_reader.py','ams_core_reader.py','appstore_agent_reader.py']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notify_ipc_inventory.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(functions),'exports':len(s.lib.exports),'nlists':len(out['original_nlists']),'chains':len(chains),'direct_edges':len(calls),'bound_veneers':len(s.veneers),'external_targets':len(s.external),'selected_strings':[r for r in strings if any(k in r['text'] for k in ['notifyd','shm.','notification_center'])]}),flush=True)


if __name__=='__main__':main()
