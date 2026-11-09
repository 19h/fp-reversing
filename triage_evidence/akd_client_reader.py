#!/usr/bin/env python3
"""Original co-installed akd arm64e identity, chains and ObjC metadata reader.

Read-only original universal bytes and dyld_info reference; independently walk
format12 chains. No target/loader/IPC/native API. O(B+F+I+C+M) time/space.
"""
import bisect
import json
import plistlib
from pathlib import Path
import re
import struct
import subprocess
from adid_reader import ROOT,CS,sha
from resolve_kernel_collection_interfaces import macho,commands,string
from bootpolicy_cache_reader import uleb
from appstore_agent_reader import Agent
from recover_appstore_agent import methods
from arcade_service_reader import code_signature

SOURCE=Path('/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd')
SOURCE_SHA='b672326beefc8cce30c2f6f2e071bdc965ca9538a728ab3d5376e0db0f73c5f6'
THIN_SHA='097f11648c43cb0e360dcee4be9aa87d46153779f0ae21ea318883310a5a552a'
FIXUPS=ROOT/'akd_client_fixups.txt'


class Akd:
    class_inventory=Agent.class_inventory
    cstring=Agent.cstring
    def __init__(self):
        raw=SOURCE.read_bytes();assert sha(raw)==SOURCE_SHA and raw[:4]==bytes.fromhex('cafebabe');self.slices=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,align=struct.unpack_from('>5I',raw,8+20*j);self.slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'alignment_power':align,'sha256':sha(raw[off:off+n])})
        selected=next(x for x in self.slices if x['cpu']=='0x100000c' and x['subtype']=='0x80000002');self.data=raw[selected['offset']:selected['offset']+selected['size_bytes']];assert sha(self.data)==THIN_SHA
        self.meta=macho(self.data,0,'akd arm64e client source');self.base=next(x['address'] for x in self.meta['segments'] if x['name']=='__TEXT');self.sections=self.meta['sections'];self.loads=[];self.starts=[];self.entry=None
        for at,cmd,n in commands(self.data,0):
            if cmd in (0xc,0x80000018,0x8000001f,0x80000023,0x20):self.loads.append(string(self.data,at+struct.unpack_from('<I',self.data,at+8)[0]))
            if cmd==0x80000028:self.entry=self.base+struct.unpack_from('<Q',self.data,at+8)[0]
            if cmd==0x26:
                off,z=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+z];p=0;a=self.base
                while p<len(buf):
                    delta,p=uleb(buf,p)
                    if not delta:break
                    a+=delta;self.starts.append(a)
        reference={}
        for line in FIXUPS.read_text().splitlines():
            m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
            if m:reference[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],'annotation':m[4].strip(),'line':line.strip()}
        at=next(a for a,c,n in commands(self.data,0) if c==0x80000034);fo,sz=struct.unpack_from('<II',self.data,at+8);version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',self.data,fo);assert (version,fmt,symfmt)==(0,1,0)
        self.imports=[]
        for j in range(count):
            word=struct.unpack_from('<I',self.data,fo+imports+4*j)[0];lib=word&255;lib=lib-256 if lib&128 else lib;self.imports.append({'ordinal':j,'name':string(self.data,fo+symbols+(word>>9)),'library_ordinal':lib,'library_path':self.loads[lib-1] if 0<lib<=len(self.loads) else 'special ordinal','import_addend':0,'weak':bool(word&256)})
        self.decoded_fixups={};st=fo+starts;ns=struct.unpack_from('<I',self.data,st)[0];self.chain_headers=[]
        for j in range(ns):
            delta=struct.unpack_from('<I',self.data,st+4+j*4)[0]
            if not delta:continue
            info=st+delta;size,page_size,pf,vmoff,maxptr,pages=struct.unpack_from('<IHHQIH',self.data,info);assert pf==12;self.chain_headers.append({'segment_index':j,'pointer_format':pf,'page_size_bytes':page_size,'page_count':pages,'vm_offset':hex(vmoff)})
            for page in range(pages):
                start=struct.unpack_from('<H',self.data,info+22+page*2)[0]
                if start==0xffff:continue
                offsets=[]
                if start&0x8000:
                    ix=start&0x7fff
                    while True:
                        value=struct.unpack_from('<H',self.data,info+22+ix*2)[0];offsets.append(value&0x7fff);ix+=1
                        if value&0x8000:break
                else:offsets=[start]
                for off in offsets:
                    a=self.base+vmoff+page*page_size+off
                    while True:
                        assert a not in self.decoded_fixups;word=struct.unpack('<Q',self.read(a,8))[0];auth=bool(word>>63);bind=bool(word>>62&1);r={'address':hex(a),'word':hex(word),'authenticated':auth,'bind':bind,'pointer_format':12,'chain_membership_verified':True}
                        if bind:
                            ordinal=word&0xffffff;im=self.imports[ordinal];add=0 if auth else word>>32&0x7ffff
                            if add&0x40000:add-=0x80000
                            r.update({'import':im,'symbol':im['name'],'target':reference[a]['target'],'pointer_addend':add,'total_addend':add})
                            assert reference[a]['target'].split('/',1)[1]==im['name']
                            tool=re.search(r'\+ (0x[0-9A-Fa-f]+)',reference[a]['annotation']);assert (int(tool[1],16) if tool else 0)==add
                        else:
                            target=self.base+(word&0xffffffff) if auth else self.base+(word&((1<<43)-1))+(((word>>43)&255)<<56);r['target']=hex(target);assert target==reference[a]['target']
                        assert auth==reference[a]['kind'].startswith('auth-') and bind==reference[a]['kind'].endswith('bind')
                        if auth:r.update({'diversity':hex(word>>32&65535),'address_diversity':word>>48&1,'key':('IA','IB','DA','DB')[word>>49&3]})
                        self.decoded_fixups[a]=r;nxt=word>>51&0x7ff
                        if not nxt:break
                        a+=nxt*8
        assert set(self.decoded_fixups)==set(reference);self.fixups=reference;self.decoded=self.decoded_fixups
    def read(self,a,n):
        for seg in self.meta['segments']:
            if seg['address']<=a and a+n<=seg['address']+seg['file_size']:
                off=seg['file_offset']+a-seg['address'];return self.data[off:off+n]
        raise ValueError('unbacked original akd extent '+hex(a)+'+'+str(n))
    def qword(self,a):
        if a in self.decoded_fixups:
            r=self.decoded_fixups[a];return r['target'] if r['bind'] else int(r['target'],16)
        return struct.unpack('<Q',self.read(a,8))[0]
    def bounds(self,a):
        ix=bisect.bisect_right(self.starts,a)-1;assert ix>=0;end=self.starts[ix+1] if ix+1<len(self.starts) else next(x['address']+x['size'] for x in self.sections if x['section']=='__text');assert self.starts[ix]<=a<end;return self.starts[ix],end
    def function(self,a):
        start,end=self.bounds(a);assert a==start;raw=self.read(a,end-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
        return {'start':hex(a),'end':hex(end),'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}


def main():
    s=Akd();classes=s.class_inventory();ms=[]
    for cls in classes:
        for kind,field in [('instance','instance_method_list'),('class','class_method_list')]:ms+=methods(s,int(cls[field],16),cls['name'],kind)
    signature=code_signature(s.data);embedded=next(b['xml_entitlements'] for b in signature['blobs'] if 'xml_entitlements' in b);cmd=['/usr/bin/codesign','-d','--arch','arm64e','--entitlements',':-',str(SOURCE)];run=subprocess.run(cmd,capture_output=True,check=True);assert plistlib.loads(run.stdout)==embedded and embedded['adi-client']=='347420559';(ROOT/'akd_client_entitlements.xml').write_bytes(run.stdout);declarations={'scope':'Original selected-slice embedded declarations and independent codesign display;signature trust,effective entitlements and runtime enforcement unknown.','source_sha256':SOURCE_SHA,'thin_sha256':THIN_SHA,'signature':signature,'independent_command':cmd,'display_stdout_sha256':sha(run.stdout),'display_stderr':run.stderr.decode(),'effective_entitlements_established':False,'signature_authentication_executed':False};(ROOT/'akd_client_entitlements.json').write_text(json.dumps(declarations,indent=2)+'\n')
    selected=[m for m in ms if any(q.lower() in (m['class']+' '+m['selector']).lower() for q in ['anisette','provision','ADI','absinthe'])];out={'scope':__doc__,'source_path':str(SOURCE),'source_sha256':SOURCE_SHA,'thin_sha256':THIN_SHA,'slices':s.slices,'uuid':s.meta['uuid'],'entry':hex(s.entry),'base':hex(s.base),'loads':s.loads,'segments':s.meta['segments'],'sections':s.sections,'function_starts':[hex(a) for a in s.starts],'imports':s.imports,'fixups':list(s.decoded_fixups.values()),'chain_headers':s.chain_headers,'fixups_reference_sha256':sha(FIXUPS.read_bytes()),'classes':classes,'methods':ms,'selected_methods':selected,'embedded_entitlements':embedded,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','appstore_agent_reader.py','recover_appstore_agent.py','arcade_service_reader.py','bootpolicy_cache_reader.py','akd_client_fixups.txt','akd_client_entitlements.xml','akd_client_entitlements.json']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'akd_client_inventory.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'classes':len(classes),'methods':len(ms),'functions':len(s.starts),'fixups':len(s.decoded_fixups),'imports':len(s.imports),'selected_methods':len(selected),'adi_client_declared':embedded['adi-client']}));print(json.dumps(selected))


if __name__=='__main__':main()
