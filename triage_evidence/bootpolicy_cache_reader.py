#!/usr/bin/env python3
"""Read-only, unslid original-cache reader for the local BootPolicy investigation.

No dyld loading, target calls, host IOKit or IPC. Read only selected file ranges.
Cache v5 pointer decoding is permitted only after verifying page-chain membership.
"""
from pathlib import Path
import bisect
import hashlib
import struct
import uuid
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

CACHE=Path('/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')
ROOT=Path(__file__).resolve().parent
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)


def file_read(path,offset,size):
    with path.open('rb') as f:
        f.seek(offset);data=f.read(size)
    assert len(data)==size,(str(path),hex(offset),size)
    return data


def uleb(data,at):
    value=0;shift=0
    while True:
        b=data[at];at+=1;value|=(b&127)<<shift
        if not b&128:return value,at
        shift+=7;assert shift<70


class Cache:
    def __init__(self):
        self.files={};self.maps=[];self.used=set();self.chains={}
        head=file_read(CACHE,0,0x200)
        self.uuid=str(uuid.UUID(bytes=head[88:104]))
        suboff,subcount=struct.unpack_from('<II',head,0x188)
        entries=file_read(CACHE,suboff,subcount*56)
        files=[(CACHE,None)]
        for i in range(subcount):
            raw=entries[i*56:(i+1)*56]
            ext=raw[24:56].split(b'\0')[0].decode()
            assert ext.startswith('.') and '/' not in ext
            files.append((Path(str(CACHE)+ext),raw[:16]))
        for p,wanted in files:
            h=file_read(p,0,0x200)
            assert h[:16].startswith(b'dyld_v1') and b'arm64e' in h[:16]
            if wanted is not None:assert h[88:104]==wanted,p
            self.files[str(p)]={'path':str(p),'uuid':str(uuid.UUID(bytes=h[88:104])),
                                'size_bytes':p.stat().st_size}
            mo,mc=struct.unpack_from('<II',h,0x138)
            raw=file_read(p,mo,mc*56)
            for j in range(mc):
                va,size,off,slide,slidesize,flags,maxp,initp=struct.unpack_from('<6Q2I',raw,j*56)
                assert off+size<=p.stat().st_size
                self.maps.append({'path':str(p),'va':va,'size':size,'off':off,
                    'slide_off':slide,'slide_size':slidesize,'flags':flags,'initprot':initp})
        self.maps.sort(key=lambda m:m['va'])
        self.starts=[m['va'] for m in self.maps]
        for a,b in zip(self.maps,self.maps[1:]):assert a['va']+a['size']<=b['va']
        io,ic=struct.unpack_from('<II',head,0x1c0)
        image_info=file_read(CACHE,io,ic*32)
        self.images=[]
        for i in range(ic):
            va,mtime,inode,pathoff,pad=struct.unpack_from('<3Q2I',image_info,i*32)
            name=file_read(CACHE,pathoff,512).split(b'\0')[0].decode()
            self.images.append({'address':va,'path':name})

    def mapping(self,address):
        i=bisect.bisect_right(self.starts,address)-1
        assert i>=0
        m=self.maps[i];assert address<m['va']+m['size'],hex(address)
        return m

    def read(self,address,size):
        result=b''
        while size:
            m=self.mapping(address);n=min(size,m['va']+m['size']-address)
            self.used.add(m['path'])
            result+=file_read(Path(m['path']),m['off']+address-m['va'],n)
            address+=n;size-=n
        return result

    def pointer(self,address):
        m=self.mapping(address);assert m['slide_off'] and m['slide_size']
        key=(m['path'],m['va'])
        if key not in self.chains:
            h=file_read(Path(m['path']),m['slide_off'],24)
            ver,page_size,count,pad,add=struct.unpack('<4IQ',h)
            assert ver==5 and page_size in (4096,16384)
            starts=struct.unpack('<'+'H'*count,file_read(Path(m['path']),m['slide_off']+24,2*count))
            self.chains[key]=(page_size,starts,add)
        page_size,starts,add=self.chains[key]
        page=(address-m['va'])//page_size
        assert page<len(starts) and starts[page]!=0xffff
        at=m['va']+page*page_size+starts[page]
        visited=0
        while True:
            word=struct.unpack('<Q',self.read(at,8))[0]
            if at==address:break
            delta=((word>>52)&0x7ff)*8
            assert delta and at<address,(hex(address),hex(at))
            at+=delta;visited+=1;assert visited<page_size//8
        auth=bool(word>>63)
        target=add+(word&0x3ffffffff)
        if not auth:target|=((word>>34)&255)<<56
        return {'address':hex(address),'raw_word':hex(word),'target':hex(target),
            'slide_version':5,'value_add':hex(add),'authenticated':auth,
            'chain_membership_verified':True,'path':m['path'],
            'file_offset':hex(m['off']+address-m['va'])}

    def cstring(self,address,limit=4096):
        data=self.read(address,limit)
        assert b'\0' in data
        return data.split(b'\0')[0].decode()


class Dylib:
    def __init__(self,cache,path):
        self.cache=cache;self.path=path
        self.base=next(r['address'] for r in cache.images if r['path']==path)
        head=cache.read(self.base,32)
        magic,cpu,sub,kind,ncmds,nbytes,flags,reserved=struct.unpack('<8I',head)
        assert magic==0xfeedfacf
        data=cache.read(self.base,32+nbytes)
        self.commands=[];self.segments=[];self.sections=[]
        at=32
        for _ in range(ncmds):
            cmd,n=struct.unpack_from('<II',data,at)
            raw=data[at:at+n];self.commands.append((cmd,raw))
            if cmd==0x19:
                name=raw[8:24].split(b'\0')[0].decode()
                va,size,off,length=struct.unpack_from('<4Q',raw,24)
                self.segments.append({'name':name,'address':va,'size':size,'offset':off,'filesize':length})
                ns=struct.unpack_from('<I',raw,64)[0]
                for j in range(ns):
                    s=raw[72+j*80:152+j*80]
                    self.sections.append({'name':s[:16].split(b'\0')[0].decode(),
                        'segment':s[16:32].split(b'\0')[0].decode(),
                        'address':struct.unpack_from('<Q',s,32)[0],'size':struct.unpack_from('<Q',s,40)[0]})
            elif cmd==0x1b:self.uuid=str(uuid.UUID(bytes=raw[8:24]))
            at+=n
        assert at==len(data)
        self.linkedit=next(s for s in self.segments if s['name']=='__LINKEDIT')
        self.exports={}
        trie=next((raw for cmd,raw in self.commands if cmd==0x80000033),None)
        if trie:
            off,size=struct.unpack_from('<II',trie,8)
            self.export_bytes=self.read_offset(off,size)
            def visit(at,prefix,ancestors):
                assert at not in ancestors
                n,cur=uleb(self.export_bytes,at);end=cur+n
                if n:
                    fl,loc=uleb(self.export_bytes,cur)
                    if not fl&8:
                        address,_=uleb(self.export_bytes,loc)
                        self.exports[prefix]={'flags':fl,'address':self.base+address}
                count=self.export_bytes[end];cur=end+1
                for _ in range(count):
                    term=self.export_bytes.index(0,cur)
                    suffix=self.export_bytes[cur:term].decode()
                    child,cur=uleb(self.export_bytes,term+1)
                    visit(child,prefix+suffix,ancestors|{at})
            visit(0,'',set())
        self.functions=[]
        for cmd,raw in self.commands:
            if cmd==0x26:
                off,size=struct.unpack_from('<II',raw,8);buf=self.read_offset(off,size)
                cur=0;address=self.base
                while cur<len(buf):
                    delta,cur=uleb(buf,cur)
                    if not delta:break
                    address+=delta;self.functions.append(address)

    def symbols_at(self,address):
        """Names from original cached nlist records; no extracted-symbol trust."""
        cmd=next(raw for cmd,raw in self.commands if cmd==2)
        symoff,count,stroff,strsize=struct.unpack_from('<4I',cmd,8)
        assert count<1000000
        rows=self.read_offset(symoff,count*16)
        found=[]
        for i in range(count):
            idx,typ,sect,desc,value=struct.unpack_from('<IBBHQ',rows,i*16)
            if value==address and idx:
                assert idx<strsize
                raw=self.read_offset(stroff+idx,min(512,strsize-idx))
                assert b'\0' in raw
                found.append({'name':raw.split(b'\0')[0].decode(),'n_type':typ,
                    'n_sect':sect,'n_desc':desc,'n_value':hex(value),'nlist_index':i})
        return found

    def read_offset(self,off,size):
        return self.cache.read(self.linkedit['address']+off-self.linkedit['offset'],size)

    def function(self,address):
        assert address in self.functions,hex(address)
        ix=self.functions.index(address);end=self.functions[ix+1]
        raw=self.cache.read(address,end-address)
        return {'start':hex(address),'end':hex(end),'bytes':raw.hex(),
            'sha256':hashlib.sha256(raw).hexdigest(),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                for i in CS.disasm(raw,address)]}


if __name__=='__main__':
    import json
    c=Cache();d=Dylib(c,'/usr/lib/libbootpolicy.dylib')
    print(json.dumps({'cache_uuid':c.uuid,'images':len(c.images),'mappings':len(c.maps),
        'library_uuid':d.uuid,'exports':{k:hex(v['address']) for k,v in d.exports.items()
        if k in ['_bootpolicy_get_security_mode','_bootpolicy_get_security_mode_ex',
            '_bootpolicy_default_policy_volume_path_value','_bootpolicy_root_volume_uuid_value']},
        'functions':len(d.functions)},indent=2))
