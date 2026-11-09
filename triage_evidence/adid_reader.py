#!/usr/bin/env python3
"""Read original CoreADI adid: arm64e, function starts and format1 chains.

Independent chain membership and pointer decoding must match the retained
dyld_info text. No target, loader, IPC, framework or native service executes.
Time O(B+F+I); space O(B+F+I), image bytes B, fixups F and imports I.
"""
import bisect
import json
from pathlib import Path
import re
import struct
from appstore_agent_reader import CS,ROOT,sha
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import uleb

SOURCE=Path('/System/Library/PrivateFrameworks/CoreADI.framework/adid')
SOURCE_SHA='58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929'
THIN_SHA='ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf'
FIXUPS=ROOT/'adid_fixups.txt'


class Adid:
    def __init__(self):
        raw=SOURCE.read_bytes();assert sha(raw)==SOURCE_SHA and raw[:4]==bytes.fromhex('cafebabe')
        self.slices=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,align=struct.unpack_from('>5I',raw,8+20*j)
            self.slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'sha256':sha(raw[off:off+n])})
        sel=next(x for x in self.slices if x['cpu']=='0x100000c' and x['subtype']=='0x80000002')
        self.data=raw[sel['offset']:sel['offset']+sel['size_bytes']];assert sha(self.data)==THIN_SHA
        self.meta=macho(self.data,0,'CoreADI adid original arm64e');self.base=next(x['address'] for x in self.meta['segments'] if x['name']=='__TEXT')
        self.starts=[];self.loads=[];self.entry=None
        for at,c,n in commands(self.data,0):
            if c in (0xc,0x80000018,0x8000001f,0x80000023,0x20):self.loads.append(string(self.data,at+struct.unpack_from('<I',self.data,at+8)[0]))
            if c==0x80000028:self.entry=self.base+struct.unpack_from('<Q',self.data,at+8)[0]
            if c==0x26:
                off,size=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+size];p=0;a=self.base
                while p<len(buf):
                    d,p=uleb(buf,p)
                    if not d:break
                    a+=d;self.starts.append(a)
        self.fixups={}
        for line in FIXUPS.read_text().splitlines():
            m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
            if m:self.fixups[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],'annotation':m[4].strip(),'line':line.strip()}
        at=next(a for a,c,n in commands(self.data,0) if c==0x80000034);fo,size=struct.unpack_from('<II',self.data,at+8)
        ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',self.data,fo);assert ver==symfmt==0 and fmt in (1,2)
        self.imports=[];self.import_format=fmt
        for j in range(count):
            word=struct.unpack_from('<I',self.data,fo+imports+j*(4 if fmt==1 else 8))[0]
            add=0 if fmt==1 else struct.unpack_from('<i',self.data,fo+imports+j*8+4)[0]
            lib=word&255;lib=lib-256 if lib&128 else lib
            self.imports.append({'ordinal':j,'name':string(self.data,fo+symbols+(word>>9)),'import_addend':add,'weak':bool(word&256),
                'library_ordinal':lib,'library_path':self.loads[lib-1] if 0<lib<=len(self.loads) else 'special ordinal'})
        st=fo+starts;ns=struct.unpack_from('<I',self.data,st)[0];members=set();self.pointer_format=None
        for j in range(ns):
            delta=struct.unpack_from('<I',self.data,st+4+j*4)[0]
            if not delta:continue
            info=st+delta;size,page_size,pf,vmoff,maxptr,pages=struct.unpack_from('<IHHQIH',self.data,info);assert pf==1
            self.pointer_format=pf
            for p in range(pages):
                start=struct.unpack_from('<H',self.data,info+22+p*2)[0]
                if start==0xffff:continue
                positions=[]
                if start&0x8000:
                    ix=start&0x7fff
                    while True:
                        v=struct.unpack_from('<H',self.data,info+22+ix*2)[0];positions.append(v&0x7fff);ix+=1
                        if v&0x8000:break
                else:positions=[start]
                for pos in positions:
                    a=self.base+vmoff+p*page_size+pos
                    while True:
                        assert a not in members;members.add(a);word=struct.unpack('<Q',self.read(a,8))[0];nxt=(word>>51)&0x7ff
                        if not nxt:break
                        a+=nxt*8
        assert members==set(self.fixups),(len(members),len(self.fixups));self.decoded={}
        for a,old in self.fixups.items():
            word=struct.unpack('<Q',self.read(a,8))[0];auth=bool(word>>63);bind=bool(word>>62&1)
            assert auth==old['kind'].startswith('auth-') and bind==old['kind'].endswith('bind')
            row={'address':hex(a),'word':hex(word),'authenticated':auth,'bind':bind,'pointer_format':1,'chain_membership_verified':True}
            if bind:
                assert word>>16&65535==0
                im=self.imports[word&0xffff];assert old['target'].split('/',1)[1]==im['name']
                add=0 if auth else word>>32&0x7ffff
                if add&0x40000:add-=0x80000
                row.update({'import':im,'pointer_addend':add,'total_addend':im['import_addend']+add,'target':old['target']})
                tool_add=re.search(r'\+ (0x[0-9A-Fa-f]+)',old['annotation'])
                assert (int(tool_add[1],16) if tool_add else 0)==row['total_addend'],(row,old)
            else:
                target=self.base+(word&0xffffffff) if auth else (word&((1<<43)-1))+(((word>>43)&255)<<56)
                assert target==old['target'];row['target']=hex(target)
            if auth:row.update({'diversity':hex(word>>32&65535),'address_diversity':word>>48&1,'key':('IA','IB','DA','DB')[word>>49&3]})
            self.decoded[a]=row
    def read(self,a,n):
        for seg in self.meta['segments']:
            if seg['address']<=a and a+n<=seg['address']+seg['file_size']:
                off=seg['file_offset']+a-seg['address'];return self.data[off:off+n]
        raise ValueError('unbacked original adid extent:'+hex(a))
    def qword(self,a):
        if a in self.fixups:return self.fixups[a]['target']
        return struct.unpack('<Q',self.read(a,8))[0]
    def cstring(self,a,limit=4096):
        b=self.read(a,limit);return b[:b.index(0)].decode()
    def bounds(self,a):
        ix=bisect.bisect_right(self.starts,a)-1;assert ix>=0
        start=self.starts[ix];end=self.starts[ix+1] if ix+1<len(self.starts) else next(x['address']+x['size'] for x in self.meta['sections'] if x['section']=='__text')
        assert start<=a<end;return start,end
    def function(self,a):
        start,end=self.bounds(a);assert start==a;raw=self.read(start,end-start);ins=list(CS.disasm(raw,start));assert len(ins)*4==len(raw)
        return {'start':hex(start),'end':hex(end),'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}


def main():
    s=Adid();stubs={};edges=[];ranges={}
    sec=next(x for x in s.meta['sections'] if x['section']=='__auth_stubs')
    for at in range(sec['address'],sec['address']+sec['size'],16):
        raw=s.read(at,16);ins=list(CS.disasm(raw,at));assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa']
        cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=s.decoded[cell]
        assert ptr['bind'] and ptr['address_diversity']==1 and ptr['key']=='IA'
        stubs[at]={'address':hex(at),'bytes':raw.hex(),'pointer':ptr}
    sec=next(x for x in s.meta['sections'] if x['section']=='__text')
    for ix,(word,) in enumerate(struct.iter_unpack('<I',s.read(sec['address'],sec['size']))):
        if word&0x7c000000!=0x14000000:continue
        pc=sec['address']+ix*4;delta=word&0x3ffffff
        if delta&0x2000000:delta-=0x4000000
        target=pc+delta*4
        if target not in stubs:continue
        a,z=s.bounds(pc);im=stubs[target]['pointer']['import']
        edges.append({'callsite':hex(pc),'branch':'bl' if word>>31 else 'b','stub':hex(target),'import':im,'compiler_function_start':hex(a)})
        if im['name']!='___stack_chk_fail' and a not in ranges:
            raw=s.read(a,z-a);ranges[a]={'start':hex(a),'end':hex(z),'sha256':sha(raw),'size_bytes':len(raw)}
            if len(raw)<=0x8000:ranges[a]['original_function']=s.function(a)
    out={'scope':__doc__,'source_path':str(SOURCE),'source_sha256':SOURCE_SHA,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],
        'entry':hex(s.entry),'base':hex(s.base),'segments':s.meta['segments'],'sections':s.meta['sections'],'loads':s.loads,
        'function_starts':[hex(a) for a in s.starts],'imports':s.imports,'import_format':s.import_format,'fixups':list(s.decoded.values()),
        'all_chain_members_match_dyld_info':True,'fixup_text_sha256':sha(FIXUPS.read_bytes()),'stubs':list(stubs.values()),
        'direct_import_branch_candidates':edges,'caller_ranges':list(ranges.values()),'reader_sha256':sha(Path(__file__).read_bytes()),
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_inventory.json').write_text(json.dumps(out,indent=2)+'\n')
    from collections import Counter
    print(json.dumps({'entry':hex(s.entry),'functions':len(s.starts),'fixups':len(s.decoded),'imports':len(s.imports),'stubs':len(stubs),'direct_branches':len(edges),
        'calls':dict(Counter(e['import']['name'] for e in edges))}))


if __name__=='__main__':main()
