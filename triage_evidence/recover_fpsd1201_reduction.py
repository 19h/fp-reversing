#!/usr/bin/env python3
"""Original CoreFP1201 reduction, Montgomery-square and complete child return.

Continue the pinned subtraction prefix without supplied results. Positive
one-word controls reach the next original call; zero stops after 64 subtraction
returns. Full outer request and native transport remain open.
O(I+C*(B+F+V+P*J+R)) time and O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. Private continuation instruction budget: 500000.
"""
import json
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_subtraction import Execute as Previous,sources as old_sources,configurations as old_configurations
from recover_fpsd1201_import import local_reference,ROOT,CS,HALT
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();CHILD=0x14f8d28;WRAP=0x9dd7e4;SQUARE=0x9dc6d4
PRINCIPALS=[CHILD,WRAP,SQUARE,0x5a600c,0x649430,0x33abec,0x5e8158]
STAGES=[0x14f9258,0x14f9d78,0x14fae3c,0x14fae5c]
DEPS=['recover_fpsd1201_subtraction.py','audit_fpsd1201_subtraction.py','fpsd1201_subtraction_checks.json',
 'fpsd1201_subtraction_audit.json','fpsd1201_subtraction_ida_readback.json','fpsd1201_comparison_checks.json',
 'fpsd1201_shift_checks.json','fpsd1201_operand_checks.json','fpsd1201_import_checks.json','fpsd1201_record_checks.json',
 'corefp_library_inventory.json','corefp_lookup_contracts.json','corefp_fixups_inventory.json']


def sources():
    code,banks,D=old_sources();att=json.loads(read(ROOT/'fpsd1201_reduction_ida_readback.json'))
    return code+[{**r,'role':role}for r,role in zip(att['spans'],['square_cursor_wrapper','montgomery_square'])],banks,D


def configurations():
    old=list(old_configurations())[:8]
    for c in old:yield {**c,'label':'reduced_'+c['label']}
    for j,v in enumerate([17,65537,0xffffffff,0x80000001,0x7fffffff]):yield {**old[0],'label':'additional_'+hex(v),'operand_u32':v,'second_seed_u64':[0,1,(1<<64)-1,0x0123456789abcdef][j%4]}


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__(c,code[:17],banks,D);self.following=False;self.skip_resume=False;self.subtraction_returns=0
        self.family_points=[];self.family_stack=[];self.u.mem_map(0x9dc000,8192)
        for r in code[17:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.exits={i.address:int(r['start'],16)for r in code if int(r['start'],16)in PRINCIPALS for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))if i.mnemonic in ['retab','ret']}
        assert len(self.exits)==len(PRINCIPALS)
    def family_state(self,pc,entry,r,cursor):
        raw=self.ram(r,40);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');views={};extra={}
        if entry in [CHILD,WRAP,SQUARE]:
            q=ptr(8)if entry==CHILD else ptr(16);n=ptr(16)if entry==CHILD else ptr(8);pair=self.ram(q,24)
            views={'modulus':self.desc(n),'pair_first':self.desc(int.from_bytes(pair[:8],'little')),'pair_second':self.desc(int.from_bytes(pair[8:16],'little'))}
            extra={'pair_pointer':hex(q),'pair24_hex':pair.hex(),'cursor_pointer':hex(cursor),'cursor_u64':hex(int.from_bytes(self.ram(cursor,8),'little'))}
            if entry!=CHILD:views.update({'input':self.desc(ptr(24)),'output':self.desc(ptr(32))})
        elif entry in [0x649430,0x33abec]:views={'first':self.desc(ptr(0)),'second':self.desc(ptr(16))}
        elif entry==0x5e8158:views={'first':self.desc(ptr(8)),'second':self.desc(ptr(16))}
        else:views={'operand':self.desc(ptr(8))}
        return {'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record40_hex':raw.hex(),'views':views,**extra,'CPU':self.frame()}
    def observe(self,pc):
        if pc in PRINCIPALS:
            entry,r,cursor=pc,self.reg(0),self.reg(1);self.family_stack.append((entry,r,cursor))
            if pc==CHILD:self.child_signature=(entry,r,cursor)
        elif pc in self.exits:
            entry,r,cursor=self.family_stack.pop();assert entry==self.exits[pc]
        elif pc in STAGES:entry,r,cursor=self.child_signature
        else:return
        self.family_points.append(self.family_state(pc,entry,r,cursor))
    def continued_hook(self,u,pc,n,data):
        self.flush()
        if pc==HALT:self.stop='returned';self.terminal=self.frame();self.frontier=None;u.emu_stop();return
        assert any(lo<=pc<hi for lo,hi in self.ranges)
        raw=self.ram(pc,4);i=next(CS.disasm(raw,pc));target=modifier=None
        if pc in [0x981104,0x981218,0x981520]:
            point={'pc':hex(pc),'CPU':self.frame()}
            if pc in [0x981104,0x981218]:point.update({'cursor_pointer':hex(self.reg(1)),'cursor_u64':hex(int.from_bytes(self.ram(self.reg(1),8),'little'))})
            else:
                at=self.u.reg_read(A.UC_ARM64_REG_SP)+0x48;point.update({'descriptor16_address':hex(at),'descriptor16_hex':self.ram(at,16).hex()})
            self.points.append(point)
        if i.mnemonic in ['braa','blraa']:
            regs=[r.strip().upper()for r in i.op_str.split(',')];target=u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[0]));modifier=u.reg_read(getattr(A,'UC_ARM64_REG_'+regs[1]))
            slots=[int(r['address'],16)for r in reversed(self.reads)if r['size_B']==8 and int(r['address'],16)in self.D and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(modifier)];assert slots
            slot=slots[0];row=self.D[slot];assert row['key']=='IA'and row['address_diversity']==0
            if i.mnemonic=='blraa'and not any(lo<=target<hi for lo,hi in self.ranges):
                self.used.add(slot);self.stop='unretained_callee';self.terminal=self.frame()
                self.frontier={'pc':hex(pc),'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slot),'instruction':i.mnemonic+' '+i.op_str,'instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()};u.emu_stop();return
        self.visits.append({'phase':self.phase,'pc':hex(pc),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str});assert len(self.visits)<500000
        if i.mnemonic in ['pacibsp','retab','braa','blraa']:
            e={'pc':hex(pc),'kind':i.mnemonic,'before':self.frame()}
            if target is not None:
                e.update({'target':hex(target),'modifier':hex(modifier),'original_slot':hex(slot)})
                if i.mnemonic=='blraa':self.setreg(30,pc+4)
                u.reg_write(A.UC_ARM64_REG_PC,target)
            else:u.reg_write(A.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else pc+4)
            self.pac.append(e)
    def hook(self,u,pc,n,data):
        self.flush()
        if self.skip_resume:
            assert pc==0x14f9d78;self.skip_resume=False
        else:
            self.observe(pc)
            if pc==0x14f9d78:
                self.subtraction_returns+=1
                if self.c['operand_u32']==0 and self.subtraction_returns==64:
                    self.stop='zero_control_iteration_limit';self.terminal=self.frame();self.frontier={'pc':hex(pc),'instruction_executed':False,'completed_subtraction_returns':64};u.emu_stop();return
        if self.following:return self.continued_hook(u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        p=super().run();assert p['stop_reason']=='after_subtraction_return'
        boundary={k:p[k]for k in ['stop_reason','frontier','terminal','final_RAM','final_delta_cell_u64','final_status_u32','used_original_pointer_rows']}
        boundary['lengths']={k:len(p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points']}
        self.following=True;self.skip_resume=True;self.stop=None;self.frontier=None
        self.u.emu_start(0x14f9d78,0,count=500000);self.flush();assert self.stop in ['unretained_callee','zero_control_iteration_limit']
        p.update({'prefix_boundary':boundary,'family_points':self.family_points,'pending_family_entries':[hex(x[0])for x in self.family_stack],
          'subtraction_returns':self.subtraction_returns,'stop_reason':self.stop,'frontier':self.frontier,'terminal':self.terminal,'final_RAM':self.dump(),
          'final_delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),'final_status_u32':hex(int.from_bytes(self.ram(RECORD+0x30,4),'little')),
          'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)]});return p


def proofs():
    seed=z3.BitVec('square_cursor_seed',64);top=z3.LShR(seed*0x2ecd+1,60);pad=((top<<4)+31)&0x1f0
    claims=[('square_cursor_restore_u64',seed-80+80==seed),('square_wrapper_zero_delta',((seed-80+80-seed)&0xffff)<<4==0),
      ('square_padding_exact_u64',pad==16*(top+1)),('square_padding_bounds_u64',z3.And(z3.UGE(pad,16),z3.ULE(pad,256))),('square_padding_alignment_u64',(pad&15)==0)]
    out=[]
    for label,claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));r=str(q.check());assert r=='unsat'
        out.append({'label':label,'query':q.sexpr()+'\n(check-sat)\n','result':r,'timeout_ms':60000})
    return out


def main():
    code,banks,D=sources();f=local_reference(code,banks,D);profiles=[]
    for c in configurations():
        profiles.append(Execute(c,code,banks,D).run());p=profiles[-1]
        print(json.dumps({'completed_profiles':len(profiles),'operand':c['operand_u32'],'visits':len(p['source_visits']),'stop':p['stop_reason']}),flush=True)
    queries=proofs();counts={'profiles':len(profiles),'complete_child_profiles':sum(p['configuration']['operand_u32']!=0 for p in profiles),'bounded_zero_profiles':1,
      **{k:sum(len(p[k])for p in profiles)for k in ['source_visits','source_reads','source_writes','PAC_models','family_points']},
      'subtraction_returns':sum(p['subtraction_returns']for p in profiles),'fresh_IDA_spans':2,'fresh_IDA_bytes':4904,'source_code_bytes':31040,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':f,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_reduction_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_reduction_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
