#!/usr/bin/env python3
"""Independent integer/byte interpretation of startup sorting and dispatch.

Original sort/comparator instructions run on a private relocated table. PAC is
an explicit logical identity model. Dispatch observers and callbacks are ABI
return models, not their bodies. No target executes. O(visits+compared bytes)
time and O(code+private table+stack) space; no universal sorting proof follows.
"""
from collections import Counter
from hashlib import sha256
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM
from audit_event_wait_table import StartupIntegers, MASK64
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

CURSOR=0xfffffe000cbc9a48;PHASE=0xfffffe0007f8b5f0;STACK=0x60000000;STOP=0x12340000


class OrderIntegers(StartupIntegers):
    def __init__(self,code):
        super().__init__(code);self.calls=[];self.dispatch_mode=False

    def key(self,name):return super().key({'fp':'x29','lr':'x30'}.get(name,name))

    def condition(self,name):
        if name in ['lt','ge','le']:
            a,b,width=self.flags;mask=(1<<width)-1
            signed=lambda v:(v&mask)-(1<<width)if v&(1<<(width-1))else v&mask
            return signed(a)<signed(b)if name=='lt'else signed(a)>=signed(b)if name=='ge'else signed(a)<=signed(b)
        return super().condition(name)

    def clobber(self,salt):
        for j in range(19):self.put('x'+str(j),(salt+0x9e3779b97f4a7c15*(j+1))&MASK64)

    def step(self,pc):
        i=self.code[pc];m,o=i.mnemonic,i.operands
        names=[i.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m in ['pacibsp','autibsp','pacia','bti']:
            self.visits+=1;return pc+4
        if m in ['bl','blraa']:
            self.visits+=1;target=o[0].imm&MASK64 if m=='bl'else self.get(names[0]);self.put('lr',pc+4)
            if self.dispatch_mode:
                if target==0xfffffe000bd3ad04:
                    self.calls.append(('observer',self.get('w0')));self.clobber(self.get('w0'));return pc+4
                assert pc==0xfffffe000c630370 and m=='blraa'and self.get('x17')==0x2abe
                cursor=self.load(CURSOR,8);phase=self.load(cursor,4)
                assert self.get('x0')==self.load(cursor+16,8)and target==self.load(cursor+8,8)
                assert self.load(PHASE,4)==(phase-1)&0xffffffff
                self.calls.append(('callback',cursor,phase,target,self.get('x0')))
                self.clobber(target);return pc+4
            assert target in [0xfffffe000c61b4ec,0xfffffe000c630754],(hex(pc),hex(target))
            self.calls.append(('source',pc,target));return target
        if m in ['ret','retab']:
            self.visits+=1;return self.get('lr')
        if m in ['ldr','str','ldrb','strb','ldp','stp']and i.writeback:
            self.visits+=1;index=next(j for j,x in enumerate(o)if x.type==ARM64_OP_MEM);address=self.address(i,o[index]);base=i.reg_name(o[index].mem.base)
            width=1 if m in ['ldrb','strb']else self.width(names[0])//8
            for j,name in enumerate(names[:index]):
                if m in ['ldr','ldrb','ldp']:self.put(name,self.load(address+j*width,width))
                else:self.store(address+j*width,width,self.get(name))
            self.put(base,address if index==len(o)-1 else self.get(base)+o[-1].imm);return pc+4
        if m in ['asr','ror','madd','neg','cneg','adds']:
            self.visits+=1;d=names[0];width=self.width(d);a=self.value(i,o[1]);mask=(1<<width)-1
            if m=='asr':v=(a-(1<<width)if a&(1<<(width-1))else a)>>o[2].imm
            elif m=='ror':n=o[2].imm;v=(a>>n)|(a<<(width-n))
            elif m=='madd':v=a*self.value(i,o[2])+self.value(i,o[3])
            elif m=='neg':v=-a
            elif m=='cneg':v=-a if self.condition(i.op_str.rsplit(',',1)[1].strip())else a
            else:v=a+self.value(i,o[2]);self.flags=(v&mask,0,width)
            self.put(d,v);return pc+4
        return super().step(pc)


def machine(code):
    m=OrderIntegers(code)
    for j in range(31):m.put('x'+str(j),0x100+j)
    m.put('sp',STACK);m.put('lr',STOP)
    for a in range(STACK-65536,STACK+256):m.memory[a]=(a*13+31)&255
    return m


def run(m,start,stop,bound):
    pc=start;limit=m.visits+bound
    while pc!=stop:
        assert m.visits<limit,('visit bound',hex(pc),m.visits)
        pc=m.step(pc)


def audit():
    e=json.loads(read(ROOT/'startup_dispatch_checks.json'));cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    table=int(e['startup_section']['address']);raw=bytes.fromhex(e['logical_table_bytes_hex']);end=table+len(raw)
    m=machine(code)
    for j,b in enumerate(bytes([0xa5])*64+raw+bytes([0x5a])*64):m.memory[table-64+j]=b
    run(m,0xfffffe000c62f4e4,0xfffffe000c630240,8000000)
    sorted_raw=bytes(m.memory[table+j]for j in range(len(raw)))
    chunks=lambda data:[data[j:j+24]for j in range(0,len(data),24)]
    keys=lambda data:[(int.from_bytes(r[:4],'little'),int.from_bytes(r[4:8],'little'))for r in chunks(data)]
    assert Counter(chunks(raw))==Counter(chunks(sorted_raw))and keys(sorted_raw)==sorted(keys(raw))
    assert bytes(m.memory[table-64+j]for j in range(64))==bytes([0xa5])*64
    assert bytes(m.memory[end+j]for j in range(64))==bytes([0x5a])*64
    sort_visits=m.visits;sort_calls=len(m.calls)
    # Original dispatcher bodies; observer and callback bodies are deliberately
    # absent. Returned caller-saved registers are patterned clobbers.
    d=machine(code);d.dispatch_mode=True
    for j,b in enumerate(sorted_raw):d.memory[table+j]=b
    d.store(CURSOR,8,table);d.store(PHASE,4,0);d.store(0xfffffe0007e64510,4,0)
    checkpoints=[];callbacks=[]
    for target in [3,4,5,6,7,13,14,15,16,19,0xffffffff]:
        d.put('w0',target);d.put('lr',STOP);start=len(d.calls);old=d.load(CURSOR,8)
        run(d,0xfffffe000c6302c4,STOP,250000)
        assert d.get('sp')==STACK and d.load(PHASE,4)==target
        calls=[r for r in d.calls[start:]if r[0]=='callback'];callbacks.extend(calls)
        eligible=[j for j,r in enumerate(chunks(sorted_raw))if table+24*j>=old and int.from_bytes(r[:4],'little')<=target]
        assert [r[1]for r in calls]==[table+24*j for j in eligible]
        assert d.load(CURSOR,8)==old+24*len(calls)
        checkpoints.append({'target32':target,'callbacks':len(calls),'cursor':hex(d.load(CURSOR,8))})
    assert len(callbacks)==3519 and d.load(CURSOR,8)==end
    selected=[r for r in callbacks if r[3]==0xfffffe000c6319e4];assert len(selected)==1 and selected[0][2]==14 and selected[0][4]==0
    # All rank-zero peers compare equal; the finite sort does not turn that into
    # a stability or universal tie-order claim.
    comparisons=0
    for p in [0,1,14,0x80000000,0xffffffff]:
      for rank in [0,1,0x80000000,0xffffffff]:
       for q in [0,1,14,0x80000000,0xffffffff]:
        for other in [0,1,0x80000000,0xffffffff]:
            v=machine(code);v.put('x0',0x700000);v.put('x1',0x710000)
            v.store(0x700000,4,p);v.store(0x700004,4,rank);v.store(0x710000,4,q);v.store(0x710004,4,other)
            run(v,0xfffffe000c630754,STOP,32)
            expected=0 if (p,rank)==(q,other)else 0xffffffff if(p,rank)<(q,other)else 1
            assert v.get('w0')==expected;comparisons+=1
    return {'sort_instruction_visits':sort_visits,'sort_source_calls':sort_calls,'sort_records':3519,
      'sorted_table_sha256':sha256(sorted_raw).hexdigest(),'dispatch_instruction_visits':d.visits,'dispatch_callback_models':len(callbacks),
      'dispatch_thresholds':checkpoints,'comparator_cases':comparisons,'selected_wait_callback_sorted_index':(selected[0][1]-table)//24,
      'sort_guard_bytes':128,'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()),flush=True)
