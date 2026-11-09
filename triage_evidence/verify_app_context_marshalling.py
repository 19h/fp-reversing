#!/usr/bin/env python3
"""Symbolic byte-origin check for the constructor's native marshalling slices.

No concrete guest is executed. All data values remain byte-origin labels.
Assumes entry saves survive intervening calls and the record receives a u32
result before the output slice. This is not full function/path verification.
O(K) time/space for K bytes moved by the bounded slices.
"""
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
from verify_interface_contracts import Image

ROOT = Path(__file__).resolve().parent


def main():
    image = Image(ROOT.parent/'com.apple.driver.FairPlayIOKit')
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    regs = {f'x{i}': [f'arg{i}.byte{j}' for j in range(8)] for i in range(31)}
    stack = {}
    output = None
    steps = []

    def width(reg):
        return 4 if reg.startswith('w') else 8

    def get(reg):
        return regs['x'+reg[1:]][:width(reg)]

    def put(reg, value):
        assert len(value) == width(reg)
        regs['x'+reg[1:]] = value+[0]*(8-len(value))

    def load(offset, n):
        return [stack[offset+j] for j in range(n)]

    def save(offset, value):
        for j, byte in enumerate(value):
            stack[offset+j] = byte

    def run(a,z):
        nonlocal output
        for ins in cs.disasm(image.read(a,z-a),a):
            ops=ins.operands
            assert ins.mnemonic in ('str','stp','ldr','ldp')
            assert ops[0].type == ARM64_OP_REG
            mem=ops[-1]
            assert mem.type == ARM64_OP_MEM and not mem.mem.index
            base=ins.reg_name(mem.mem.base)
            names=[ins.reg_name(o.reg) for o in ops[:-1]]
            if ins.mnemonic.startswith('st'):
                value=sum((get(n) for n in names),[])
                if base=='sp':
                    save(mem.mem.disp,value)
                else:
                    assert ins.mnemonic=='str' and base=='x9' and mem.mem.disp==0
                    assert get(base)==[f'arg5.byte{j}' for j in range(8)]
                    output=value
            else:
                assert base=='sp'
                off=mem.mem.disp
                for name in names:
                    n=width(name);put(name,load(off,n));off+=n
            steps.append({'address':hex(ins.address),'mnemonic':ins.mnemonic,
                          'operands':ins.op_str,'bytes':ins.bytes.hex()})

    run(0xfffffe000a66a804,0xfffffe000a66a814)
    # Intervening instructions do not appear in this bounded transfer proof.
    run(0xfffffe000a66aa84,0xfffffe000a66aa9c)
    mappings=[(0,8,0),(16,8,1),(24,8,2),(32,4,3),(36,4,4)]
    verified=[]
    for offset,n,arg in mappings:
        value=load(0x40+offset,n)
        assert value==[f'arg{arg}.byte{j}' for j in range(n)]
        verified.append({'record_offset':hex(offset),'bytes':n,
                         'entry_register':f'X{arg}' if n==8 else f'W{arg}',
                         'byte_origins':value})
    save(0x48,[f'result.byte{j}' for j in range(4)])
    run(0xfffffe000a66ab58,0xfffffe000a66ab64)
    assert output==[f'result.byte{j}' for j in range(4)]+[0]*4
    result={'scope':__doc__,'steps':steps,'record_fields':verified,
            'published_64bit_output_byte_origins':output,'result':'all assertions passed'}
    (ROOT/'app_context_marshalling_validation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'instructions':len(steps),'input_fields':len(verified),
                      'output_zero_extends_u32':True}))


if __name__=='__main__':
    main()
