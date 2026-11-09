#!/usr/bin/env python3
"""Original CoreFP format12 pointers with independent dyld_info correspondence.

No target loader/code/API executes. O(B+P+I) for bytes, chain members and imports.
The frozen file/export reader is extended without changing prior artifacts.
"""
import json
from pathlib import Path
import re
import struct
from corefp_library_reader import Library,ROOT,THIN_SHA,SHA
from resolve_kernel_collection_interfaces import commands
from appstore_agent_reader import sha

FIXUPS=ROOT/'corefp_library_fixups.txt'


class Pointers(Library):
    def __init__(self):
        super().__init__();self.fixups={};self.imports=[]
        for line in FIXUPS.read_text().splitlines():
            m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
            if m:self.fixups[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],'line':line.strip()}
        at=next(a for a,c,n in commands(self.data,0) if c==0x80000034);fo,size=struct.unpack_from('<II',self.data,at+8)
        ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',self.data,fo);assert ver==symfmt==0 and fmt==1
        for j in range(count):
            word=struct.unpack_from('<I',self.data,fo+imports+j*4)[0];li=word&255;li=li-256 if li&128 else li
            no=fo+symbols+(word>>9);name=self.data[no:self.data.index(0,no)].decode()
            self.imports.append({'ordinal':j,'name':name,'library_ordinal':li,'library_path':self.loads[li-1] if 0<li<=len(self.loads) else 'special ordinal','weak':bool(word&256)})
        st=fo+starts;ns=struct.unpack_from('<I',self.data,st)[0];members=set();formats=[]
        for j in range(ns):
            delta=struct.unpack_from('<I',self.data,st+4+j*4)[0]
            if not delta:continue
            info=st+delta;size,page_size,pf,vmoff,maxptr,pages=struct.unpack_from('<IHHQIH',self.data,info);assert pf==12;formats.append(pf)
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
            word=struct.unpack('<Q',self.read(a,8))[0];auth=bool(word>>63);bind=bool((word>>62)&1)
            assert auth==old['kind'].startswith('auth-') and bind==old['kind'].endswith('bind')
            out={'address':hex(a),'word':hex(word),'pointer_format':12,'authenticated':auth,'bind':bind,'chain_membership_verified':True}
            if bind:
                ordinal=word&0xffffff;imp=self.imports[ordinal];assert old['target'].split('/',1)[1]==imp['name']
                add=0 if auth else (word>>32)&0x7ffff
                if add&0x40000:add-=0x80000
                out.update({'import':imp,'pointer_addend':add,'target':old['target']})
            else:
                target=self.base+(word&0xffffffff) if auth else self.base+(word&((1<<43)-1))+(((word>>43)&255)<<56)
                assert target==old['target'];out['target']=hex(target)
            if auth:out.update({'diversity':hex((word>>32)&65535),'address_diversity':(word>>48)&1,'key':('IA','IB','DA','DB')[(word>>49)&3]})
            self.decoded[a]=out
    def qword(self,a):
        if a in self.fixups:return self.fixups[a]['target']
        return struct.unpack('<Q',self.read(a,8))[0]


def main():
    p=Pointers();out={'scope':__doc__,'source_sha256':SHA,'thin_sha256':THIN_SHA,'uuid':p.meta['uuid'],'imports':p.imports,
        'fixups':list(p.decoded.values()),'dyld_info_text_sha256':sha(FIXUPS.read_bytes()),'all_chain_members_match_dyld_info':True,
        'reader_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_fixups_inventory.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'imports':len(p.imports),'fixups':len(p.fixups),'source_uuid':p.meta['uuid']}))


if __name__=='__main__':main()
