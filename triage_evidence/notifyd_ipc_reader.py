#!/usr/bin/env python3
"""Original notifyd universal identity,format12 chains and function reader.

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
from arcade_service_reader import code_signature

SOURCE=Path('/usr/sbin/notifyd')
SOURCE_SHA='79105a37b75d37f43ea0190ae1f5307f775446730774ee76b62a3484b8166c15'
THIN_SHA='aeeae7016d04af9b2a08f0491559ac0291ec3954fd93bdf167c30607d44fae23'
FIXUPS=ROOT/'notifyd_ipc_fixups.txt'


class Notifyd:
    def __init__(self):
        raw=SOURCE.read_bytes();assert sha(raw)==SOURCE_SHA and raw[:4]==bytes.fromhex('cafebabe');self.slices=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,align=struct.unpack_from('>5I',raw,8+20*j);self.slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'alignment_power':align,'sha256':sha(raw[off:off+n])})
        selected=next(x for x in self.slices if x['cpu']=='0x100000c' and x['subtype']=='0x80000002');self.data=raw[selected['offset']:selected['offset']+selected['size_bytes']];assert sha(self.data)==THIN_SHA
        self.meta=macho(self.data,0,'notifyd arm64e source');self.base=next(x['address'] for x in self.meta['segments'] if x['name']=='__TEXT');self.sections=self.meta['sections'];self.loads=[];self.starts=[];self.entry=None
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
        raise ValueError('unbacked original notifyd extent '+hex(a)+'+'+str(n))
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
    s=Notifyd();nlists=[]
    for at,cmd,n in commands(s.data,0):
        if cmd!=2:continue
        off,count,stroff,strsize=struct.unpack_from('<4I',s.data,at+8)
        for j in range(count):
            ix,typ,sect,desc,value=struct.unpack_from('<IBBHQ',s.data,off+16*j);name=string(s.data,stroff+ix) if ix else ''
            nlists.append({'name':name,'address':hex(value),'n_type':typ,'n_sect':sect,'n_desc':desc,'nlist_index':j})
    strings=[]
    for sec in s.sections:
        if sec['section']!='__cstring':continue
        raw=s.read(sec['address'],sec['size']);off=0
        while off<len(raw):
            end=raw.find(b'\0',off)
            if end<0:break
            if end>off:strings.append({'address':hex(sec['address']+off),'text':raw[off:end].decode()})
            off=end+1
    launch=Path('/System/Library/LaunchDaemons/com.apple.notifyd.plist');declaration=plistlib.loads(launch.read_bytes());signature=code_signature(s.data)
    out={'scope':__doc__,'source_path':str(SOURCE),'source_sha256':SOURCE_SHA,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'slices':s.slices,'base':hex(s.base),'entry':hex(s.entry),'loads':s.loads,'sections':s.sections,'segments':s.meta['segments'],'imports':s.imports,'fixups':list(s.decoded.values()),'original_nlists':nlists,'function_starts':[hex(a) for a in s.starts],'complete_original_functions':[s.function(a) for a in s.starts],'original_strings':strings,'embedded_code_signature':signature,'signature_authentication_executed':False,'launchd_declaration':{'path':str(launch),'sha256':sha(launch.read_bytes()),'parsed':declaration,'native_publication_established':False},'reader_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','arcade_service_reader.py','notifyd_ipc_fixups.txt']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notifyd_ipc_inventory.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(s.starts),'imports':len(s.imports),'fixups':len(s.decoded),'entry':hex(s.entry),'selected_strings':[r for r in strings if any(q in r['text'] for q in ['checkin','register_check','notification_center','notify_server'])]}),flush=True)


if __name__=='__main__':main()
