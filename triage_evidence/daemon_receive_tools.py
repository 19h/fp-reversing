#!/usr/bin/env python3
"""Read-only original-image helpers for bounded receive-callback recovery."""
import hashlib
import json
from pathlib import Path
import re
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from verify_interface_contracts import Image
from resolve_kernel_collection_interfaces import commands

ROOT=Path(__file__).resolve().parent
SOURCE=Path('/Users/___/Downloads/zut/fairplayd.arm64e')
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
IMAGE=Image(SOURCE)
FIXUPS={}
for line in (ROOT/'daemon_receive_fixups.txt').read_text().splitlines():
    m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)(.*)',line)
    if m:
        FIXUPS[int(m[1],16)]={'kind':m[2],'target':int(m[3],16) if m[3].startswith('0x') else m[3],
                             'annotation':m[4].strip(),'line':line.strip()}
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
POOL=0x1010a1960
TABLE=0x101039ef0
MASK64=(1<<64)-1


def qword(address):
    if address in FIXUPS:return FIXUPS[address]['target']
    return struct.unpack('<Q',IMAGE.read(address,8))[0]


def bank(left,right,key):
    l,r=IMAGE.read(left,256),IMAGE.read(right,256)
    values={x^r[l[x]^key] for x in range(256)}
    assert len(values)==1,(hex(left),hex(right),hex(key),values)
    return values.pop()


def selected(left,right,key,additive,base=TABLE,bias=0):
    c=bank(left,right,key);index=additive+c;slot=base+index*8
    target=qword(slot)
    if isinstance(target,int):target=(target+bias)&MASK64
    elif bias:raise ValueError('bias on imported target')
    return {'left':hex(left),'right':hex(right),'key':hex(key),'constant':hex(c),
            'additive':hex(additive),'index':hex(index),'slot':hex(slot),
            'bias':hex(bias&MASK64),'target':hex(target) if isinstance(target,int) else target,
            'original_slot_word':IMAGE.read(slot,8).hex(),'fixup':FIXUPS.get(slot),
            'inputs_checked':256}


def block(start,limit=0x800):
    out=[]
    for i in CS.disasm(IMAGE.read(start,limit),start):
        out.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
        if i.mnemonic in ('braa','braaz','br','b','ret','retab','retaa'):break
    assert out
    end=int(out[-1]['ea'],16)+4
    return {'start':hex(start),'end':hex(end),'bytes':IMAGE.read(start,end-start).hex(),
            'instructions':out}


def dump(start,limit=0x800):
    r=block(start,limit)
    for i in r['instructions']:print(i['ea'],i['mnemonic'],i['operands'])


def verify_original_fixups(addresses):
    """Independently check used format-12 words and import names against dyld_info.

    Chained membership is supplied by Apple's fixup walk. This decoder checks
    the original bit fields and original import table, not authenticated runtime
    addresses or successful hardware authentication.
    """
    data=SOURCE.read_bytes()
    at=next(o for o,c,n in commands(data,0) if c==0x80000034)
    fo,sz=struct.unpack_from('<II',data,at+8)
    version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,fo)
    assert (version,fmt,symfmt)==(0,2,0)
    st=fo+starts;nseg=struct.unpack_from('<I',data,st)[0]
    formats=[]
    for j in range(nseg):
        delta=struct.unpack_from('<I',data,st+4+j*4)[0]
        if delta:formats.append(struct.unpack_from('<H',data,st+delta+6)[0])
    assert set(formats)=={12}
    records=[]
    for a in sorted(set(addresses)):
        rec=FIXUPS[a]
        word=struct.unpack('<Q',IMAGE.read(a,8))[0]
        auth,bind=word>>63,(word>>62)&1
        assert bool(auth)==rec['kind'].startswith('auth-')
        assert bool(bind)==rec['kind'].endswith('bind')
        out={'address':hex(a),'word':hex(word),'pointer_format':12,
             'authenticated':bool(auth),'bind':bool(bind)}
        if bind:
            ordinal=word&0xffffff;assert ordinal<count
            iw,addend=struct.unpack_from('<Ii',data,fo+imports+ordinal*8)
            lib=iw&255;nameoff=iw>>9
            start=fo+symbols+nameoff;end=data.index(0,start)
            name=data[start:end].decode()
            assert rec['target'].split('/',1)[1]==name
            assert addend==0 and auth
            out.update({'import_ordinal':ordinal,'library_ordinal':lib,
                        'import_name':name,'import_addend':addend})
        else:
            decoded=0x100000000+(word&0xffffffff) if auth else (
                0x100000000+(word&((1<<43)-1))+(((word>>43)&255)<<56))
            assert decoded==rec['target']
            out['decoded_target']=hex(decoded)
        if auth:
            m=re.search(r'div=(0x[0-9a-fA-F]+) ad=(\d) key=(\w+)',rec['annotation'])
            assert m
            div,ad,key=(word>>32)&65535,(word>>48)&1,('IA','IB','DA','DB')[(word>>49)&3]
            assert (int(m[1],16),int(m[2]),m[3])==(div,ad,key)
            out.update({'diversity':hex(div),'address_diversity':ad,'key':key})
        records.append(out)
    return {'imports_format':fmt,'pointer_formats':formats,'imports_count':count,
            'records':records,'result':'all used words/imports match dyld_info'}
