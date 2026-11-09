#!/usr/bin/env python3
"""Read-only identity, original-byte/fixup reader for the installed XPC service.

No target loader, framework, IPC or executable entry point runs. dyld_info is
an analyst-side binary parser. O(B+F+I) time/space for bytes, fixups, instructions.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import uleb

ROOT=Path(__file__).resolve().parent
BUNDLE=Path('/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/XPCServices/com.apple.fpsd.arcadeservice.xpc')
SOURCE=BUNDLE/'Contents/MacOS/com.apple.fpsd.arcadeservice'
SHA='91ff94a78b525339eaa5f0f94a0358adb173e891d4de0e6ba6ad59ca089d44f4'
THIN_SHA='fed08b800dc88a83fb71b81008791faab457dca99b514ea01aed2fb6fffee694'
THIN=ROOT/'arcade_service.arm64e'
FIXUP_TEXT=ROOT/'arcade_service_fixups.txt'
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)


def sha(b):return hashlib.sha256(b).hexdigest()


def code_signature(data):
    """Parse bounded embedded metadata; do not authenticate any signature."""
    at=next(a for a,c,n in commands(data,0) if c==0x1d)
    off,n=struct.unpack_from('<II',data,at+8);blob=data[off:off+n]
    magic,length,count=struct.unpack_from('>3I',blob);assert magic==0xfade0cc0 and length<=len(blob) and count<=32
    rows=[]
    for j in range(count):
        slot,start=struct.unpack_from('>2I',blob,12+j*8);m,size=struct.unpack_from('>2I',blob,start)
        assert start+size<=length and size>=8
        raw=blob[start:start+size];r={'slot':hex(slot),'magic':hex(m),'size_bytes':size,'sha256':sha(raw)}
        if m==0xfade0c02:
            version,flags,hashoff,identoff=struct.unpack_from('>4I',raw,8)
            assert 0<identoff<size
            r.update({'version':hex(version),'flags':hex(flags),'identifier':string(raw,identoff),
                'hash_size_bytes':raw[36],'hash_type':raw[37],'platform_byte':raw[38],'page_size_power':raw[39]})
            if version>=0x20200:
                teamoff=struct.unpack_from('>I',raw,48)[0];r['team_identifier']=string(raw,teamoff) if teamoff else None
        if m==0xfade7171:
            r['xml_entitlements']=plistlib.loads(raw[8:]);r['xml_payload_hex']=raw[8:].hex()
        rows.append(r)
    return {'command_file_offset':off,'command_size_bytes':n,'superblob_sha256':sha(blob),'blobs':rows,
        'signature_authentication_executed':False,'effective_entitlements':'unknown','der_entitlements_decoded':False}


class Service:
    def __init__(self,prepare=False):
        raw=SOURCE.read_bytes();assert sha(raw)==SHA
        assert raw[:4]==bytes.fromhex('cafebabe')
        self.arches=[]
        for j in range(struct.unpack_from('>I',raw,4)[0]):
            cpu,sub,off,n,align=struct.unpack_from('>5I',raw,8+20*j)
            self.arches.append({'cpu':hex(cpu),'subtype':hex(sub),'offset':off,'size_bytes':n,'alignment_power':align,
                'sha256':sha(raw[off:off+n])})
        selected=next(a for a in self.arches if a['cpu']=='0x100000c' and a['subtype']=='0x80000002')
        self.data=raw[selected['offset']:selected['offset']+selected['size_bytes']];assert sha(self.data)==THIN_SHA
        self.meta=macho(self.data,0,'com.apple.fpsd.arcadeservice arm64e subtype 0x80000002')
        self.base=next(s['address'] for s in self.meta['segments'] if s['name']=='__TEXT')
        self.loads=[];self.starts=[];self.sections=self.meta['sections'];self.segment_protections={}
        self.entry=None;self.encryption=[]
        for at,c,n in commands(self.data,0):
            if c in (0xc,0x80000018,0x8000001f,0x80000023,0x20):self.loads.append(string(self.data,at+struct.unpack_from('<I',self.data,at+8)[0]))
            if c==0x19:self.segment_protections[self.data[at+8:at+24].split(b'\0')[0].decode()]=struct.unpack_from('<I',self.data,at+60)[0]
            if c==0x80000028:self.entry=self.base+struct.unpack_from('<Q',self.data,at+8)[0]
            if c==0x2c:self.encryption.append(struct.unpack_from('<3I',self.data,at+8))
            if c==0x26:
                off,n=struct.unpack_from('<II',self.data,at+8);buf=self.data[off:off+n];p=0;a=self.base
                while p<len(buf):
                    d,p=uleb(buf,p)
                    if not d:break
                    a+=d;self.starts.append(a)
        if prepare:
            THIN.write_bytes(self.data)
            run=subprocess.run(['/usr/bin/dyld_info','-fixups',str(THIN)],capture_output=True,text=True,check=True)
            assert not run.stderr,run.stderr
            FIXUP_TEXT.write_text(run.stdout)
        assert sha(THIN.read_bytes())==THIN_SHA
        self.fixups={}
        for line in FIXUP_TEXT.read_text().splitlines():
            m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)(.*)',line)
            if m:self.fixups[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],
                'annotation':m[4].strip(),'line':line.strip()}
        at=next(a for a,c,n in commands(self.data,0) if c==0x80000034)
        self.fixoff,self.fixsize=struct.unpack_from('<II',self.data,at+8)
        version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',self.data,self.fixoff)
        assert (version,fmt,symfmt)==(0,1,0),(version,fmt,symfmt)
        self.import_format=fmt
        self.imports_offset=self.fixoff+imports;self.symbols_offset=self.fixoff+symbols;self.imports_count=count
        st=self.fixoff+starts;nseg=struct.unpack_from('<I',self.data,st)[0];formats=[];members=set()
        for j in range(nseg):
            delta=struct.unpack_from('<I',self.data,st+4+j*4)[0]
            if not delta:continue
            info=st+delta
            size,page_size,pf,vmoff,maxptr,pages=struct.unpack_from('<IHHQIH',self.data,info);assert pf==12
            formats.append(pf)
            for p in range(pages):
                start=struct.unpack_from('<H',self.data,info+22+p*2)[0]
                if start==0xffff:continue
                assert not start&0x8000,'overflow page chain not used in this source'
                a=self.base+vmoff+p*page_size+start
                while True:
                    assert a not in members;members.add(a)
                    word=struct.unpack('<Q',self.read(a,8))[0];nxt=(word>>51)&0x7ff
                    if not nxt:break
                    a+=8*nxt
        assert members==set(self.fixups),(len(members),len(self.fixups))
        self.pointer_formats=formats
        self.decoded_fixups={a:self.decode_fixup(a) for a in self.fixups}

    def read(self,a,n):
        for s in self.meta['segments']:
            if s['address']<=a and a+n<=s['address']+s['file_size']:
                p=s['file_offset']+a-s['address'];return self.data[p:p+n]
        raise ValueError((hex(a),n))

    def decode_fixup(self,a):
        word=struct.unpack('<Q',self.read(a,8))[0];auth=bool(word>>63);bind=bool((word>>62)&1);r=self.fixups[a]
        assert auth==r['kind'].startswith('auth-') and bind==r['kind'].endswith('bind')
        out={'address':hex(a),'word':hex(word),'authenticated':auth,'bind':bind,'pointer_format':12}
        if bind:
            ordinal=word&0xffffff;assert ordinal<self.imports_count
            iw=struct.unpack_from('<I',self.data,self.imports_offset+4*ordinal)[0];addend=0
            lib=iw&255;lib=lib-256 if lib&128 else lib
            name=string(self.data,self.symbols_offset+(iw>>9));assert r['target'].split('/',1)[1]==name
            pointer_addend=0 if auth else (word>>32)&0x7ffff
            if pointer_addend&0x40000:pointer_addend-=0x80000
            out.update({'symbol':name,'library_ordinal':lib,'library_path':self.loads[lib-1] if 0<lib<=len(self.loads) else 'special ordinal',
                'import_table_addend':addend,'pointer_addend':pointer_addend,'total_addend':addend+pointer_addend,
                'target':r['target'],'import_ordinal':ordinal})
        else:
            target=self.base+(word&0xffffffff) if auth else self.base+(word&((1<<43)-1))+(((word>>43)&255)<<56)
            assert target==r['target'];out['target']=hex(target)
        if auth:
            out.update({'diversity':hex((word>>32)&65535),'address_diversity':(word>>48)&1,'key':('IA','IB','DA','DB')[(word>>49)&3]})
        return out

    def qword(self,a):
        if a in self.fixups:return self.fixups[a]['target']
        return struct.unpack('<Q',self.read(a,8))[0]

    def bank(self,left,right,key):
        l,r=self.read(left,256),self.read(right,256);v={x^r[l[x]^key] for x in range(256)};assert len(v)==1
        return {'left':hex(left),'right':hex(right),'key':hex(key),'constant':hex(v.pop()),'inputs_checked':256}

    def cstring(self,a,limit=4096):
        b=bytearray()
        for j in range(limit):
            c=self.read(a+j,1)
            if c==b'\0':return b.decode()
            b+=c
        raise ValueError('unterminated string')

    def ranges(self):
        text=next(s for s in self.sections if s['section']=='__text')
        out=[]
        for i,a in enumerate(self.starts):
            z=self.starts[i+1] if i+1<len(self.starts) else text['address']+text['size']
            raw=self.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
            out.append({'start':hex(a),'end':hex(z),'sha256':sha(raw),'bytes':raw.hex(),
                'instructions':[{'ea':hex(v.address),'mnemonic':v.mnemonic,'operands':v.op_str} for v in ins]})
        return out


def main():
    s=Service(prepare=True);plist_path=BUNDLE/'Contents/Info.plist';pb=plist_path.read_bytes()
    installed=BUNDLE.parents[1]/'fairplayd'
    r={'scope':__doc__,'source':str(SOURCE),'sha256':SHA,'size_bytes':SOURCE.stat().st_size,'slices':s.arches,
        'selected_thin':THIN.name,'selected_sha256':THIN_SHA,'uuid':s.meta['uuid'],'entry':hex(s.entry),
        'loads':s.loads,'segments':s.meta['segments'],'sections':s.sections,'function_starts':[hex(a) for a in s.starts],
        'encryption_commands':s.encryption,'fixups':list(s.decoded_fixups.values()),'fixup_chain_membership_matches_dyld_info':True,
        'fixup_text_sha256':sha(FIXUP_TEXT.read_bytes()),'pointer_formats':s.pointer_formats,
        'plist_path':str(plist_path),'plist_sha256':sha(pb),'plist':plistlib.loads(pb),
        'installed_daemon_path':str(installed),'installed_daemon_sha256':sha(installed.read_bytes()),
        'embedded_code_signature':code_signature(s.data),
        'native_target_executed':False,'runtime_service_pairing':'unknown'}
    from daemon_receive_tools import SOURCE as DAEMON
    r['reference_daemon_thin_code_signature']={'path':str(DAEMON),'sha256':sha(DAEMON.read_bytes()),
        'metadata':code_signature(DAEMON.read_bytes())}
    (ROOT/'arcade_service_inventory.json').write_text(json.dumps(r,indent=2)+'\n')
    (ROOT/'arcade_service_original_functions.json').write_text(json.dumps({'source_sha256':THIN_SHA,'ranges':s.ranges()},indent=2)+'\n')
    print(json.dumps({'entry':r['entry'],'functions':len(s.starts),'fixups':len(s.fixups),'uuid':r['uuid']}))


if __name__=='__main__':main()
