#!/usr/bin/env python3
"""Independent finite source interpretation for event-table startup.

No generator or Z3 import. Declared scalars, private patterned byte arrays and
return snapshots only. O(cases*visits+canvas bytes) time, O(code+canvas) space.
No native option parser, allocator, wait queue, thread or IDB operation executes.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from audit_aes_event_registration import EventIntegers, MASK64
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read


class StartupIntegers(EventIntegers):
    def __init__(self,code):super().__init__(code);self.writes=[]

    def store(self,address,n,value):
        super().store(address,n,value);self.writes.append((address,n,value&((1<<(8*n))-1)))

    def step(self,pc):
        ins=self.code[pc];m,o=ins.mnemonic,ins.operands
        names=[ins.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m not in ['clz','umulh','umull','mvn','lsl','lsr']:return super().step(pc)
        self.visits+=1
        if m=='clz':
            v=self.get(names[1]);self.put(names[0],self.width(names[1])-v.bit_length())
        elif m in ['umulh','umull']:
            product=self.get(names[1])*self.get(names[2]);self.put(names[0],product>>64 if m=='umulh'else product)
        elif m=='mvn':self.put(names[0],~self.value(ins,o[1]))
        else:
            n=self.width(names[0]);a=self.get(names[1]);shift=self.value(ins,o[2])&(n-1)
            self.put(names[0],a<<shift if m=='lsl'else a>>shift)
        return pc+4


def audit():
    e=json.loads(read(ROOT/'event_wait_table_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    totals={'default_budget_cases':0,'budget_geometry_cases':0,'option_return_routes':0,
            'whole_allocation_canvases':0,'initialized_records':0,'wrapper_validity_routes':0,
            'allocator_return_pairs':0,'special_queue_canvases':0}
    defaults=[0,1,2,2560,0x7fffffff,0x80000000,0xffffffff]+[((j+1)*0x9e3779b9)&0xffffffff for j in range(256)]
    for value in defaults:
        m=StartupIntegers(code);m.store(0xfffffe000caa30c4,4,value)
        m.cut(0xfffffe000c631a2c,0xfffffe000c631a58)
        expected=((((value*24)&0xffffffff)//5)+0x3fff)&0x7fffc000
        assert m.get('x8')==expected and expected%16384==0 and expected<=0x7fffc000
        if expected:assert 24<=expected<24*(1<<27)
        totals['default_budget_cases']+=1
    budgets={24,16384,0, MASK64}
    for b in range(64):
        for delta in [-1,0,1]:
            value=(1<<b)+delta
            if 0<=value<=MASK64:budgets.add(value)
    for b in range(59):
        for delta in [-1,0,1]:
            value=24*(1<<b)+delta
            if 0<=value<=MASK64:budgets.add(value)
    for budget in sorted(budgets):
        m=StartupIntegers(code);m.put('x8',budget);m.cut(0xfffffe000c631a58,0xfffffe000c631a94)
        q=budget//24;c=64-q.bit_length()
        count=0x80000000>>(c&31)
        extent=(((24<<((~c)&31))+0x3fff)&0xffffffff)&0xffffc000
        assert m.load(0xfffffe0007e66e00,4)==count and m.get('w1')==extent
        if 24<=budget<24*(1<<27):
            want=1<<(q.bit_length()-1)
            assert count==want and extent==((24*want+16383)//16384)*16384
            assert 24*count<=extent<24*count+16384 and count<=1<<26
        totals['budget_geometry_cases']+=1
    stack=0x510000
    for result in [0,1,0xffffffff]:
      for parameter in [1,2560,0xffffffff]:
       for option in [24,16384,1<<30]:
        m=StartupIntegers(code);m.put('w0',result);m.put('sp',stack)
        m.store(stack+8,8,option);m.store(0xfffffe000caa30c4,4,parameter)
        pc=m.route(0xfffffe000c631a20,{0xfffffe000c631a58})
        default=((((parameter*24)&0xffffffff)//5)+0x3fff)&0x7fffc000
        assert pc==0xfffffe000c631a58 and m.get('x8')==(option if result else default)
        totals['option_return_routes']+=1
    for status in [0,1,0xffffffff]:
      for value in [0,0x410000,MASK64]:
        m=StartupIntegers(code);m.put('w27',status);m.put('x26',value)
        m.cut(0xfffffe000bdc1094,0xfffffe000bdc109c)
        assert m.get('w0')==status and m.get('x1')==value
        totals['allocator_return_pairs']+=1
    special=0xfffffe000cb4ff08
    for pattern in [0,0x55,0xff]:
        m=StartupIntegers(code)
        for j in range(64):m.memory[special-16+j]=pattern
        m.store(0xfffffe000700dd78,8,12)
        m.cut(0xfffffe000c631b14,0xfffffe000c631b34)
        want=bytearray([pattern]*64);want[16:40]=(12).to_bytes(4,'little')+(0x144).to_bytes(4,'little')+bytes(16)
        assert bytes(m.memory[special-16+j]for j in range(64))==bytes(want)
        totals['special_queue_canvases']+=1
    header=(9).to_bytes(4,'little')+(0x144).to_bytes(4,'little')+bytes(16)
    for n in [1,2,4,16,64,512]:
      for base in [0x410000,0xfffffe0051000000]:
        capacity=((24*n+16383)//16384)*16384;lo=base-16;length=capacity+32
        m=StartupIntegers(code)
        for j in range(length):m.memory[lo+j]=(j*17+89)&255
        before=bytes(m.memory[lo+j]for j in range(length))
        m.store(0xfffffe0007e66e00,4,n);m.store(0xfffffe000700dd70,8,9)
        m.put('x19',0xfffffe0007e66000);m.put('x1',base);m.writes=[]
        pc=0xfffffe000c631ab4;bound=m.visits+20*n+32
        while pc!=0xfffffe000c631b0c:
            assert m.visits<bound;pc=m.step(pc)
        expected=bytearray(before);expected[16:16+24*n]=header*n
        assert bytes(m.memory[lo+j]for j in range(length))==bytes(expected)
        assert m.load(0xfffffe0007e66df8,8)==base
        assert m.writes[0]==(0xfffffe0007e66df8,8,base)and len(m.writes)==1+4*n
        assert m.get('x9')==n
        totals['whole_allocation_canvases']+=1;totals['initialized_records']+=n
    for valid in [0,1,255]:
      for entry,stop_good,stop_bad in [(0xfffffe000bd6e004,0xfffffe000bd6e00c,0xfffffe000bd6e0f4),
                                      (0xfffffe000bd6e24c,0xfffffe000bd6e254,0xfffffe000bd6e30c)]:
        m=StartupIntegers(code);m.put('x0',0x410000);m.store(0x410005,1,valid)
        frontier=m.route(entry,{stop_good,stop_bad})
        assert frontier==(stop_good if valid&1 else stop_bad)
        totals['wrapper_validity_routes']+=1
    assert header.hex()=='090000004401000000000000000000000000000000000000'
    return totals


if __name__=='__main__':print(json.dumps(audit()),flush=True)
