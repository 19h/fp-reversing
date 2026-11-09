#!/usr/bin/env python3
"""Original co-installed appstoreagent identity, fixups and class inventory.

Read-only source access and analyst dyld_info parser; no target code, launchd,
framework, Mach/NSXPC or notification call runs. O(B+F+C) bytes/fixups/classes.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
from arcade_service_reader import ROOT,sha,code_signature,CS
from verify_interface_contracts import Image
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import uleb

SOURCE=Path('/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support/appstoreagent')
SHA='7c05d92bfb7281bea6ce612cc01db143952c8691a6de8c93b325b6b6091c1a9c'
THIN_SHA='acd4f4a37478bb584aa58cfef9f5461c834b90a5fc578487702d74dad137a536'
THIN=ROOT/'appstore_agent.arm64e'
FIXUP_TEXT=ROOT/'appstore_agent_fixups.txt'
PLIST=Path('/System/Library/LaunchAgents/com.apple.appstoreagent.plist')


class Agent:
    def __init__(self,prepare=False):
        raw=SOURCE.read_bytes();assert sha(raw)==SHA and raw[:4]==bytes.fromhex('cafebabe')
        self.slices=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,al=struct.unpack_from('>5I',raw,8+20*j)
            self.slices.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'alignment_power':al,'sha256':sha(raw[off:off+n])})
        a=next(a for a in self.slices if a['cpu']=='0x100000c' and a['subtype']=='0x80000002')
        self.data=raw[a['offset']:a['offset']+a['size_bytes']];assert sha(self.data)==THIN_SHA
        if prepare:
            THIN.write_bytes(self.data)
            p=subprocess.run(['/usr/bin/dyld_info','-fixups',str(THIN)],capture_output=True,text=True,check=True)
            assert not p.stderr;FIXUP_TEXT.write_text(p.stdout)
        assert sha(THIN.read_bytes())==THIN_SHA
        self.image=Image(THIN);self.meta=macho(self.data,0,'appstoreagent arm64e');self.sections=self.meta['sections']
        self.base=next(s['address'] for s in self.meta['segments'] if s['name']=='__TEXT');self.starts=[];self.loads=[];self.entry=None;self.encryption=[]
        for at,c,n in commands(self.data,0):
            if c in (0xc,0x80000018,0x8000001f,0x80000023,0x20):self.loads.append(string(self.data,at+struct.unpack_from('<I',self.data,at+8)[0]))
            if c==0x80000028:self.entry=self.base+struct.unpack_from('<Q',self.data,at+8)[0]
            if c==0x2c:self.encryption.append(struct.unpack_from('<3I',self.data,at+8))
            if c==0x26:
                off,n=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+n];p=0;a=self.base
                while p<len(buf):
                    d,p=uleb(buf,p)
                    if not d:break
                    a+=d;self.starts.append(a)
        self.fixups={}
        for line in FIXUP_TEXT.read_text().splitlines():
            m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)(.*)',line)
            if m:self.fixups[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],
                'annotation':m[4].strip(),'line':line.strip()}
        at=next(a for a,c,n in commands(self.data,0) if c==0x80000034);fo,sz=struct.unpack_from('<II',self.data,at+8)
        ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',self.data,fo)
        assert ver==symfmt==0 and fmt in (1,2)
        self.import_format=fmt;self.imports_count=count;self.decoded_fixups={}
        st=fo+starts;nseg=struct.unpack_from('<I',self.data,st)[0];members=set();formats=[]
        for j in range(nseg):
            delta=struct.unpack_from('<I',self.data,st+4+j*4)[0]
            if not delta:continue
            info=st+delta;size,page_size,pf,vmoff,maxptr,pages=struct.unpack_from('<IHHQIH',self.data,info);assert pf==12;formats.append(pf)
            for p in range(pages):
                start=struct.unpack_from('<H',self.data,info+22+p*2)[0]
                if start==0xffff:continue
                chain_starts=[]
                if start&0x8000:
                    ix=start&0x7fff
                    while True:
                        v=struct.unpack_from('<H',self.data,info+22+2*ix)[0];chain_starts.append(v&0x7fff);ix+=1
                        if v&0x8000:break
                else:chain_starts=[start]
                for pos in chain_starts:
                    a=self.base+vmoff+p*page_size+pos
                    while True:
                        assert a not in members;members.add(a);word=struct.unpack('<Q',self.read(a,8))[0];nxt=(word>>51)&0x7ff
                        if not nxt:break
                        a+=8*nxt
        assert members==set(self.fixups),(len(members),len(self.fixups));self.pointer_formats=formats
        for a,old in self.fixups.items():
            word=struct.unpack('<Q',self.read(a,8))[0];auth=bool(word>>63);bind=bool((word>>62)&1)
            assert auth==old['kind'].startswith('auth-') and bind==old['kind'].endswith('bind')
            r={'address':hex(a),'word':hex(word),'authenticated':auth,'bind':bind,'pointer_format':12}
            if bind:
                ordinal=word&0xffffff;assert ordinal<count
                stride=4 if fmt==1 else 8;iw=struct.unpack_from('<I',self.data,fo+imports+stride*ordinal)[0]
                addend=0 if fmt==1 else struct.unpack_from('<i',self.data,fo+imports+stride*ordinal+4)[0]
                name=string(self.data,fo+symbols+(iw>>9));assert old['target'].split('/',1)[1]==name
                pa=0 if auth else (word>>32)&0x7ffff
                if pa&0x40000:pa-=0x80000
                lib=iw&255;lib=lib-256 if lib&128 else lib
                r.update({'target':old['target'],'symbol':name,'library_ordinal':lib,'import_addend':addend,'pointer_addend':pa,
                    'total_addend':addend+pa,'import_ordinal':ordinal,'library_path':self.loads[lib-1] if 0<lib<=len(self.loads) else 'special ordinal'})
            else:
                target=self.base+(word&0xffffffff) if auth else self.base+(word&((1<<43)-1))+(((word>>43)&255)<<56)
                assert target==old['target'];r['target']=hex(target)
            if auth:r.update({'diversity':hex((word>>32)&65535),'address_diversity':(word>>48)&1,'key':('IA','IB','DA','DB')[(word>>49)&3]})
            self.decoded_fixups[a]=r

    def read(self,a,n):return self.image.read(a,n)
    def qword(self,a):
        if a in self.fixups:return self.fixups[a]['target']
        return struct.unpack('<Q',self.read(a,8))[0]
    def cstring(self,a,limit=4096):
        out=bytearray()
        for j in range(limit):
            b=self.read(a+j,1)
            if b==b'\0':return out.decode()
            out+=b
        raise ValueError('original string extent budget')

    def class_inventory(self):
        rows=[];sec=next(r for r in self.sections if r['section']=='__objc_classlist')
        for slot in range(sec['address'],sec['address']+sec['size'],8):
            cls=self.qword(slot);ro=self.qword(cls+32)&~7
            name=self.cstring(self.qword(ro+24));meta=self.qword(cls);mro=self.qword(meta+32)&~7
            rows.append({'name':name,'slot':hex(slot),'class':hex(cls),'class_ro':hex(ro),'metaclass_ro':hex(mro),
                'instance_method_list':hex(self.qword(ro+32)),'class_method_list':hex(self.qword(mro+32))})
        return rows


def main():
    a=Agent(prepare=True);pb=PLIST.read_bytes();classes=a.class_inventory()
    r={'scope':__doc__,'source':str(SOURCE),'source_sha256':SHA,'source_size_bytes':SOURCE.stat().st_size,
        'slices':a.slices,'thin_path':THIN.name,'thin_sha256':THIN_SHA,'uuid':a.meta['uuid'],'entry':hex(a.entry),
        'loads':a.loads,'segments':a.meta['segments'],'sections':a.sections,'function_starts':[hex(v) for v in a.starts],
        'encryption_commands':a.encryption,'fixups':list(a.decoded_fixups.values()),'fixup_chain_membership_matches_dyld_info':True,
        'fixup_text_sha256':sha(FIXUP_TEXT.read_bytes()),'pointer_formats':a.pointer_formats,'import_format':a.import_format,
        'classes':classes,'code_signature':code_signature(a.data),'launch_agent_path':str(PLIST),'launch_agent_sha256':sha(pb),
        'launch_agent':plistlib.loads(pb),'native_agent_executed':False,'native_launchd_observed':False,
        'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'appstore_agent_inventory.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'uuid':r['uuid'],'functions':len(a.starts),'fixups':len(a.fixups),'classes':len(classes),'import_format':a.import_format}))
    for row in classes:
        if any(k in row['name'].lower() for k in ('repair','listener','broker')):print(json.dumps(row))


if __name__=='__main__':main()
