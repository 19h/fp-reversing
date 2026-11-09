#!/usr/bin/env python3
"""Aligned LDR64 SP-immediate census and short direct-store candidate scan.
O(text words + candidates*16) time, O(candidates) space. Frame equivalence,
SP aliases, indirect branches and interprocedural pointer flow excluded.
Candidates are not established writers of the shared flag.
"""
import json,struct
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG,ARM64_OP_IMM
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from daemon_arena_consumer_symbolic import CS
from capture_daemon_record720 import sha
from capture_daemon_record720_spill import text_section
from daemon_digest_output_access import key

def recover():
    A,N=text_section();data=IMAGE.read(A,N);groups=[]
    for off in [0x998,0x1c8]:
        rows=[];writers=[]
        for j,(w,)in enumerate(struct.iter_unpack('<I',data)):
            if w&0xffffffe0!=(0xf94003e0|((off//8)<<10)):continue
            pc=A+j*4;i=next(CS.disasm(IMAGE.read(pc,4),pc));name=key(i.reg_name(i.operands[0].reg));aliases={name};rows.append({'pc':hex(pc),'word':hex(w),'instruction':i.mnemonic+' '+i.op_str})
            block=[]
            for k in CS.disasm(IMAGE.read(pc+4,64),pc+4):
                block.append({'pc':hex(k.address),'instruction':k.mnemonic+' '+k.op_str,'bytes_hex':bytes(k.bytes).hex()})
                if k.mnemonic.startswith(('b.','bra','blr'))or k.mnemonic in ['b','br','bl','ret','retab','cbz','cbnz','tbz','tbnz']:break
                if k.mnemonic in ['str','stur','strb','strh','sturb','sturh']:
                    o=k.operands[1]
                    if o.type==ARM64_OP_MEM and key(k.reg_name(o.mem.base))in aliases and not o.mem.index and o.mem.disp==0:
                        writers.append({'load_pc':hex(pc),'store_pc':hex(k.address),'store_instruction':k.mnemonic+' '+k.op_str,'pointer_register':k.reg_name(o.mem.base),'SP_offset_bytes':off,'context':list(block),'frame_equivalence_established':False})
                old=aliases.copy()
                for r in k.regs_access()[1]:aliases.discard(key(k.reg_name(r)))
                if k.mnemonic=='mov'and len(k.operands)==2 and k.operands[1].type==ARM64_OP_REG and key(k.reg_name(k.operands[1].reg))in old and k.reg_name(k.operands[0].reg).startswith('x'):aliases.add(key(k.reg_name(k.operands[0].reg)))
                if not aliases:break
        groups.append({'SP_offset_bytes':off,'LDR64_candidates':rows,'direct_store_candidates':writers})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'text_start':hex(A),'text_size_bytes':N,'groups':groups,'source_pointer_preparation':{'pc':'0x1002900a0','slot':'SP+0x998','meaning':'Source stores decoded global address; not the global u32 value'},'native_writer_established':False,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
    r=recover();(ROOT/'daemon_arena_lifetime_refs.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([{'SP_offset_bytes':g['SP_offset_bytes'],'LDR64_candidates':len(g['LDR64_candidates']),'direct_store_candidates':[(w['load_pc'],w['store_pc'],w['store_instruction'])for w in g['direct_store_candidates']]}for g in r['groups']]),flush=True)
