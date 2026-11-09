#!/usr/bin/env python3
"""Original normalized-kext helpers; no target execution or IDB edits."""
import hashlib,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from verify_interface_contracts import Image
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT.parent/'com.apple.driver.FairPlayIOKit'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
IMAGE=Image(SOURCE)
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
TABLE=0xfffffe0008472f20
POOL=0xfffffe0008471f00
MASK32=0xffffffff
MASK64=(1<<64)-1
SYMBOLS=json.loads((ROOT/'kernel_collection_interfaces.json').read_text())['resolved_external_values']


def qword(address):return struct.unpack('<Q',IMAGE.read(address,8))[0]


def bank(left,right,key):
    l,r=IMAGE.read(left,256),IMAGE.read(right,256)
    values={x^r[l[x]^key] for x in range(256)}
    assert len(values)==1,(hex(left),hex(right),hex(key),values)
    return values.pop()


def selected(left,right,key,additive,base=TABLE,bias=0):
    c=bank(left,right,key);ix=additive+c;slot=base+ix*8
    target=(qword(slot)+bias)&MASK64
    return {'left':hex(left),'right':hex(right),'key':hex(key),'constant':hex(c),
            'additive':hex(additive),'index':hex(ix),'slot':hex(slot),
            'bias':hex(bias&MASK64),'target':hex(target),'inputs_checked':256}


def block(start,limit=0x1800):
    out=[]
    for i in CS.disasm(IMAGE.read(start,limit),start):
        out.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
        if i.mnemonic in ('braa','br','b','ret','retab','retaa'):break
    end=int(out[-1]['ea'],16)+4
    return {'start':hex(start),'end':hex(end),'bytes':IMAGE.read(start,end-start).hex(),
            'instructions':out}


def dump(start,limit=0x1800):
    for i in block(start,limit)['instructions']:print(i['ea'],i['mnemonic'],i['operands'])
