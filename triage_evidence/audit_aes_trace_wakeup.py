#!/usr/bin/env python3
"""Independent finite integer/byte-memory interpretation of AES ring/IRQ cuts.

Private declared byte arrays and scalar snapshots only. No target operation.
O(cases * decoded source visits + compared bytes) time; O(code+private bytes)
space. This interpreter does not import the new symbolic generator or Z3.
"""
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTW, ARM64_OP_REG
from audit_aes_configuration_packets import Integers, H, MASK64
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read


class TraceIntegers(Integers):
    def value(self, ins, operand):
        if operand.ext == ARM64_EXT_SXTW:
            assert operand.type==ARM64_OP_REG and not operand.shift.type
            n=self.get(ins.reg_name(operand.reg))&0xffffffff
            return n-(1<<32) if n&(1<<31) else n
        return super().value(ins,operand)

    def step(self, pc):
        ins=self.code[pc];m,o=ins.mnemonic,ins.operands
        names=[ins.reg_name(x.reg)for x in o if x.type==ARM64_OP_REG]
        if m not in ['movi','adrp','lsl','lsr','and','tst','movk','csinc','ubfiz','ldrb','strb','tbz','tbnz']:
            return super().step(pc)
        self.visits+=1
        if m=='movi':
            assert ins.op_str in ['v0.2s, #1','v0.2s, #2','v0.2s, #4']
            n=o[1].imm;self.put('q0',n|(n<<32))
        elif m=='adrp':self.put(names[0],o[1].imm&MASK64)
        elif m in ['lsl','lsr']:
            n=self.get(names[1]);self.put(names[0],n<<o[2].imm if m=='lsl'else n>>o[2].imm)
        elif m=='and':self.put(names[0],self.value(ins,o[1])&self.value(ins,o[2]))
        elif m=='tst':self.flags=(self.value(ins,o[0])&self.value(ins,o[1]),0,self.width(names[0]))
        elif m=='movk':
            shift=o[1].shift.value;mask=0xffff<<shift
            self.put(names[0],(self.get(names[0])&~mask)|(o[1].imm<<shift))
        elif m=='csinc':
            cond=ins.op_str.rsplit(',',1)[1].strip()
            self.put(names[0],self.get(names[1])if self.condition(cond)else self.get(names[2])+1)
        elif m=='ubfiz':self.put(names[0],(self.get(names[1])&((1<<o[3].imm)-1))<<o[2].imm)
        elif m=='ldrb':self.put(names[0],self.load(self.address(ins,o[1]),1))
        elif m=='strb':self.store(self.address(ins,o[1]),1,self.get(names[0]))
        elif m in ['tbz','tbnz']:
            take=((self.get(names[0])&(1<<o[1].imm))==0)==(m=='tbz')
            return (o[2].imm&MASK64)if take else pc+4
        return pc+4


def audit():
    e=json.loads(read(ROOT/'aes_trace_wakeup_checks.json'))
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code={i.address:i for row in e['spans']for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16))}
    # Independent source intervals and expected records, not generator constants.
    records=[
      ('start_enter',0xf434,0xf458,0xf458,0xf468,1,1,'x20','x22'),
      ('start_leave',0xf480,0xf4a4,0xf4a4,0xf4b4,1,2,'x20','x22'),
      ('enable_enter',0xf9a8,0xf9e0,0xf9fc,0xfa00,1,1,'x20','x21'),
      ('disable_enter',0xf9a8,0xf9e0,0xfa4c,0xfa50,1,3,'x20','x21'),
      ('state_leave',0xfb6c,0xfbc0,0xfbc0,0xfbc0,1,None,'x20','x21'),
      ('completion_status',0x11590,0x115e4,0x115e4,0x115e4,3,None,'x19','x27'),
      ('completion_progress',0x11794,0x117cc,0x117cc,0x117cc,4,None,'x19','x27'),
      ('command_word',0x11eb8,0x11ef0,0x11ef0,0x11ef0,2,None,'x20','x24')]
    P,S=0x130000,0x170000;ring_cases=0
    for name,a,z,u,v,tag,fixed,preg,breg in records:
        for index in range(256):
            for payload in [0,1,2,4,0xffffffff,0x87654321]:
                m=TraceIntegers(code)
                for j in range(0xa00):m.memory[P+j]=(j*29+73)&255
                m.store(P+0x9fc,4,index);before=bytes(m.memory[P+j]for j in range(0xa00))
                m.put(preg,P);m.put(breg,P+0x1fc);m.put('w8',index)
                if name=='start_leave':m.store(0xfffffe000771c5f8,8,0x200000001)
                if name=='state_leave':m.put('w8',payload)
                if name=='completion_status':m.put('w26',payload)
                if name=='completion_progress':m.put('x8',P+0x164);m.store(P+0x164,4,payload)
                if name=='command_word':m.put('x8',S);m.store(S,4,payload)
                # The declared progress input is part of the initial canvas.
                before=bytes(m.memory[P+j]for j in range(0xa00))
                m.cut(H+a,H+z)
                if name=='enable_enter':m.cut(H+0xf9e4,H+0xf9fc)
                elif name=='disable_enter':m.cut(H+0xfa30,H+0xfa4c)
                if u<v:m.cut(H+u,H+v)
                value=fixed if fixed is not None else payload
                expected=bytearray(before);at=0x1fc+8*index
                expected[at:at+8]=tag.to_bytes(4,'little')+value.to_bytes(4,'little')
                expected[0x9fc:0xa00]=((index+1)%256).to_bytes(4,'little')
                assert bytes(m.memory[P+j]for j in range(0xa00))==bytes(expected),(name,index,payload)
                ring_cases+=1
    irq_cases=0;R=0x180000
    statuses=[0,33,0xffffffff]+[1<<i for i in range(32)]
    for enabled in [0,1,2,255]:
      for waiting in [0,1,2,255]:
       for version in [0,1,2,0xffffffff]:
        for status in statuses:
         for control in [0,0xffffffff]:
          m=TraceIntegers(code);m.put('x0',P)
          for at,n,value in [(P+0x1f8,1,enabled),(P+0x150,1,waiting),(P+0x178,8,R),(P+0x128,4,version),
                              (R+0x18,4,status),(R+0x1c,4,control)]:m.store(at,n,value)
          frontier=m.route(H+0xf570,{H+0xf5c4,H+0xf5f8,H+0xf608,H+0xf62c,H+0xf630})
          mask=0x1ffde if version<2 else 0x3efde
          if not enabled&1:expected=H+0xf62c
          elif status&mask:expected=H+0xf630
          elif status&1 and waiting&1:expected=H+0xf5c4
          elif status&32:expected=H+0xf608
          else:expected=H+0xf5f8
          assert frontier==expected
          assert m.load(R+0x18,4)==status
          assert m.load(P+0x150,1)==(0 if frontier==H+0xf5c4 else waiting)
          cleared=bool(enabled&1 and not status&mask and status&1)
          assert m.load(R+0x1c,4)==(control&~1 if cleared else control)
          irq_cases+=1
    return {'ring_full_canvas_cases':ring_cases,'interrupt_snapshot_cases':irq_cases,
            'cursor_values_per_record':256,'record_sites':8,'record_extent_B':8,'provider_prefix_B':2560}


if __name__=='__main__':print(json.dumps(audit()))
