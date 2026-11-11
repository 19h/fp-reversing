#!/usr/bin/env python3
"""Independent finite integer/byte-memory checks for AES event registration.

Private scalar/canvas semantics only; no new generator or Z3 import. No native
queue, mutex, register, thread, device or IPC operation. O(cases*source visits)
time and O(code+private bytes) space; comparison bytes add linear time.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_EXT_SXTW, ARM64_SFT_LSL, ARM64_SFT_LSR
from audit_aes_trace_wakeup import TraceIntegers, MASK64
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read


class EventIntegers(TraceIntegers):
    def value(self,ins,o):
        value=self.get(ins.reg_name(o.reg))if o.type==ARM64_OP_REG else o.imm
        if o.ext:
            assert o.ext==ARM64_EXT_SXTW and not o.shift.type
            value&=0xffffffff
            if value&(1<<31):value-=1<<32
        if o.shift.type:
            assert o.shift.type in [ARM64_SFT_LSL,ARM64_SFT_LSR]
            value=value<<o.shift.value if o.shift.type==ARM64_SFT_LSL else value>>o.shift.value
        return value

    def step(self,pc):
        ins=self.code[pc];m,o=ins.mnemonic,ins.operands
        names=[ins.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m not in ['eor','mul','umull','ldrh','strh','ccmp','cmn','cset','mrs','casl','casa','subs']:
            return super().step(pc)
        self.visits+=1
        if m in ['eor','mul','umull']:
            a,b=self.value(ins,o[1]),self.value(ins,o[2]);self.put(names[0],a^b if m=='eor'else a*b)
        elif m=='subs':
            width=self.width(names[0]);result=(self.value(ins,o[1])-self.value(ins,o[2]))&((1<<width)-1)
            self.put(names[0],result);self.flags=(result,0,width)
        elif m=='ldrh':self.put(names[0],self.load(self.address(ins,o[1]),2))
        elif m=='strh':self.store(self.address(ins,o[1]),2,self.get(names[0]))
        elif m=='ccmp':
            cond=ins.op_str.rsplit(',',1)[1].strip()
            self.flags=(self.value(ins,o[0]),self.value(ins,o[1]),self.width(names[0]))if self.condition(cond)else(0 if o[2].imm&4 else 1,0,32)
        elif m=='cmn':
            width=self.width(names[0]);self.flags=((self.value(ins,o[0])+self.value(ins,o[1]))&((1<<width)-1),0,width)
        elif m=='cset':self.put(names[0],int(self.condition(ins.op_str.rsplit(',',1)[1].strip())))
        elif m=='mrs':assert ins.op_str.endswith(', tpidr_el1');self.put(names[0],self.declared_thread)
        elif m in ['casl','casa']:
            n=self.width(names[0])//8;at=self.address(ins,o[2]);old=self.load(at,n)
            if old==self.get(names[0]):self.store(at,n,self.get(names[1]))
            self.put(names[0],old)
        return pc+4


def audit():
    e=json.loads(read(ROOT/'aes_event_registration_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    T,M,S=0x310000,0x320000,0x330000
    events=[0,1,2,0xffffffff,MASK64]+[((j+1)*0x9e3779b97f4a7c15)&MASK64 for j in range(256)]
    totals={'hash_pair_cases':0,'mark_wait_cases':0,'wait_publication_cases':0,'mutex_result_cases':0,
            'unlock_RMW_cases':0,'relock_RMW_cases':0,'counter_pair_cases':0,'empty_membership_cases':0,'wake_translation_cases':0}
    for event in events:
      for n in [1,2,16,256,65536,1<<26]:
       for base in [0x110000,0x220000]:
        h=((event^(event>>31))*0x7fb5d329728ea185)&MASK64
        h=((h^(h>>27))*0x81dadef4bc2dd44d)&MASK64
        index=((h^(h>>33))&0xffffffff)&(n-1);offset=index*24
        for start,end,reg in [(0xfffffe000bd283c0,0xfffffe000bd28434,'x9'),(0xfffffe000bd2b4ac,0xfffffe000bd2b51c,'x10')]:
            m=EventIntegers(code);m.put('x20',event);m.put('x19',2);m.put('x8',event)
            m.store(0xfffffe0007e66df8,8,base);m.store(0xfffffe0007e66e00,4,n);m.cut(start,end)
            assert m.get('x0')==base+offset and m.get('x1')==event and m.get(reg)==offset
            if reg=='x9':assert m.get('x2')==2
        totals['hash_pair_cases']+=1
    for interruptibility in [0,1,2,3,0xffffffff]:
      for cap in [0,1,2,3,0xffff]:
       for flags in [0,16,32,48,0xffffffff]:
        m=EventIntegers(code);m.put('x0',T);m.put('x1',interruptibility)
        m.store(T+0xc8,2,cap);m.store(T+0x210,4,flags)
        pc=m.route(0xfffffe000bd282a0,{0xfffffe000bd282e4,0xfffffe000bd282f0})
        effective=min(interruptibility&3,cap&3)
        aborted=bool(effective and flags&16 and(effective==2 or not flags&32))
        assert(pc==0xfffffe000bd282e4)==aborted and m.get('w21')==effective
        assert m.load(T+0x210,4)==(flags&0xffffffcf if aborted and flags&32 else flags)
        totals['mark_wait_cases']+=1
        if not aborted:
            m.store(T+0x1f8,4,4);m.store(T+0x58d,1,0x2a)
            m.cut(0xfffffe000bd282f8,0xfffffe000bd28304);m.cut(0xfffffe000bd28338,0xfffffe000bd28364)
            assert m.load(T+0x1f8,4)==4|(9 if effective==0 else 1)
            assert m.load(T+0xcb,1)==int(effective==2)
            assert m.load(T+0x58e,1)==0x2a and m.load(T+0x58d,1)==0 and m.load(T+0xd8,4)==0xffffffff
            totals['wait_publication_cases']+=1
    for result in [0,1,2,0xffffffff,0xfffffffe,0x80000000]:
        m=EventIntegers(code);m.put('w0',result);m.put('w19',16)
        frontier=m.route(0xfffffe000bd0c944,{0xfffffe000bd0c990,0xfffffe000bd0ca70})
        assert frontier==(0xfffffe000bd0c990 if result==0xffffffff else 0xfffffe000bd0ca70)
        totals['mutex_result_cases']+=1
    for tid in [0,1,0x80000000,0xffffffff]:
      for observed in [0,1,0x80000000,0xffffffff]:
       for policy in [0,1,0xffffffff]:
        for upper in [0,0xdeadbeef]:
            m=EventIntegers(code);m.declared_thread=T;m.put('x20',M)
            m.store(0xfffffe000cb0bc50,4,policy);m.store(T+0x518,4,tid);m.store(M+8,8,(upper<<32)|observed)
            m.cut(0xfffffe000bd0c990,0xfffffe000bd0c9b4)
            assert m.get('w2')==observed
            assert m.load(M+8,8)==(upper<<32)|(0 if observed==tid else observed)
            assert m.condition('eq')==bool(observed==tid and policy==0)
            totals['unlock_RMW_cases']+=1
      for observed in [0,1,1<<32,MASK64]:
       for policy in [0,1,0xffffffff]:
        m=EventIntegers(code);m.put('x20',M);m.put('x9',tid);m.put('x8',policy);m.store(M+8,8,observed)
        m.cut(0xfffffe000bd0c9e0,0xfffffe000bd0c9f0)
        assert m.get('x2')==observed and m.load(M+8,8)==(tid if observed==0 else observed)
        assert(m.get('x8')==0)==bool(observed==0 and policy==0)
        totals['relock_RMW_cases']+=1
    for initial in [0,1,2,65534,65535]:
        m=EventIntegers(code);m.declared_thread=T;m.put('sp',S);m.store(T+0x21e,2,initial)
        m.cut(0xfffffe000bd0c924,0xfffffe000bd0c938)
        assert m.load(T+0x21e,2)==(initial+1)&0xffff and m.load(S+0x18,8)==T
        m.cut(0xfffffe000bd56214,0xfffffe000bd56224)
        assert m.load(T+0x21e,2)==initial
        totals['counter_pair_cases']+=1
    for event in events:
        m=EventIntegers(code);q=0x350000
        for j in range(0x40):m.memory[T+j]=(j*11+37)&255
        before=bytes(m.memory[T+j]for j in range(0x40));m.put('x20',T);m.put('x24',q);m.put('x25',event);m.put('x19',q)
        m.cut(0xfffffe000bd6be34,0xfffffe000bd6be44)
        want=bytearray(before)
        for at,value in [(0,T),(8,T),(0x18,event),(0x28,q)]:want[at:at+8]=value.to_bytes(8,'little')
        assert bytes(m.memory[T+j]for j in range(0x40))==bytes(want)and m.load(q+8,8)==T
        totals['empty_membership_cases']+=1
    for result in [0,1,2,0xffffffff,0x80000000]:
        m=EventIntegers(code);m.put('w0',result);m.cut(0xfffffe000bd2b524,0xfffffe000bd2b530)
        assert m.get('w0')==(48 if result==0 else 0);totals['wake_translation_cases']+=1
    return totals


if __name__=='__main__':print(json.dumps(audit()))
