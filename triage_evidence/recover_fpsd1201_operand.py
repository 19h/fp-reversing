#!/usr/bin/env python3
"""Original CoreFP1201 operand prefix, cursor wrapper and inverse coefficient.

Unbacked context paths stop before a dereference. Explicit descriptor/seed
controls are private diagnostic backing, never native context production.
Follow the retained scalar-one initializer; stop before the next helper.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. No native operation or protected result is supplied.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
import z3
from unicorn import arm64_const as A
from recover_fpsd1201_import import Execute as Previous,prior_sources,prior_configurations,local_reference,CS,ROOT,CONTEXT,OWNER,SP,FP,HALT,RAM
from recover_fpsd1201_record import RECORD,OUT
from verify_daemon_reader_record_payloads_publication import read

K=0x1ac70ef2;PAYLOAD=OWNER+0x3000;WRAPPER=0x14fac64;CHILD=0x14f8d28
DEPS=['recover_fpsd1201_import.py','audit_fpsd1201_import.py','fpsd1201_import_checks.json',
 'fpsd1201_import_audit.json','fpsd1201_import_ida_readback.json','recover_fpsd1201_record.py',
 'audit_fpsd1201_record.py','fpsd1201_record_checks.json','fpsd1201_record_ida_readback.json',
 'fpsd1201_caller_ida_readback.json','corefp_library_inventory.json','corefp_lookup_contracts.json',
 'corefp_fixups_inventory.json','probe_daemon_descriptor_source.py']
SHA=lambda b:sha256(b).hexdigest()


def sources():
    code,banks,D=prior_sources();code.append({**json.loads(read(ROOT/'fpsd1201_import_ida_readback.json'))['spans'][0],'role':'byte_importer'})
    code.extend({**r,'role':'operand_wrapper'if r['start']==hex(WRAPPER)else'operand_child'}for r in json.loads(read(ROOT/'fpsd1201_operand_ida_readback.json'))['spans'])
    return code,banks,D


class Execute(Previous):
    def __init__(self,c,code,banks,D):
        super().__init__(c,code[:5],banks,D);self.u.mem_map(0x14f8000,0x3000)
        for r in code[5:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        self.operand_points=[];self.operand_controls=[]
    def point(self,pc):
        r=self.operand_record;pair=int.from_bytes(self.ram(r+8,8),'little')
        first=int.from_bytes(self.ram(pair,8),'little');second=int.from_bytes(self.ram(pair+8,8),'little');imported=int(self.import_points[-1]['descriptor_pointer'],16)
        return {'first_descriptor16_hex':self.ram(first,16).hex(),'second_descriptor16_hex':self.ram(second,16).hex(),'first_limb_hex':self.ram(int.from_bytes(self.ram(first+8,8),'little'),4).hex(),'import_descriptor_pointer':hex(imported),'import_descriptor16_hex':self.ram(imported,16).hex(),'pc':hex(pc),'CPU':self.frame(),'record_pointer':hex(r),'record32_hex':self.ram(r,32).hex(),
          'pair_pointer':hex(pair),'pair24_hex':self.ram(pair,24).hex(),'context_descriptor16_hex':self.ram(CONTEXT+0x290,16).hex(),
          'output_cell_pointer':hex(self.operand_output),'output_cell_u64':hex(int.from_bytes(self.ram(self.operand_output,8),'little'))}
    def hook(self,u,pc,n,data):
        self.flush()
        if pc==WRAPPER:
            self.operand_record=self.reg(0);self.operand_output=self.reg(1)
            def patch(a,b):
                self.operand_controls.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
            if self.c['backed']:
                v=self.c['operand_u32'];patch(CONTEXT+0x290,struct.pack('<IIQ',1,0x4b0cf050+(v!=0),PAYLOAD));patch(PAYLOAD,struct.pack('<I',v^K));patch(self.operand_output,struct.pack('<Q',self.c['second_seed_u64']))
            self.operand_points.append(self.point(pc))
        if pc in [CHILD,0x14f8e50,0x14f9030,0x14f9208,0x14f9258,0x14f932c,0x14f9330]:self.operand_points.append(self.point(pc))
        if (pc==0x14f8edc and not self.c['backed'])or pc==0x14f9408:
            self.stop='callee_boundary'if self.c['backed']else'unbacked_context_payload';self.terminal=self.frame()
            self.frontier={'pc':hex(pc),'instruction_executed':False}
            if self.c['backed']:
                target=self.reg(8);mod=self.reg(17);slot=next(int(r['address'],16)for r in reversed(self.reads)if r['size_B']==8 and int(r['address'],16)in self.D and self.D[int(r['address'],16)].get('target')==hex(target)and self.D[int(r['address'],16)].get('diversity')==hex(mod));self.used.add(slot)
                self.frontier.update({'target':hex(target),'modifier':hex(mod),'original_slot':hex(slot),'argument_record24_hex':self.ram(self.reg(0),24).hex()})
            else:self.frontier.update({'read_address':hex(self.reg(10)),'read_size_B':4})
            u.emu_stop();return
        super().hook(u,pc,n,data)
    def run(self):
        self.u.emu_start(0x8f3448,0x8f34f8,count=10000);self.flush();assert self.frame()['pc']=='0x8f34f8'
        constructor=self.frame();before=self.ram(RECORD,80).hex();controls=[]
        if self.c['control']=='null_auxiliary':
            a=RECORD+0x28;b=b'\0'*8;controls.append({'address':hex(a),'before_hex':self.ram(a,8).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        else:assert self.c['control']=='as_staged'
        after=self.ram(RECORD,80).hex();self.phase='nested';self.setreg(0,RECORD);self.setreg(1,OUT);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,0x981c38);entry=self.frame()
        self.u.emu_start(0x981c38,0,count=50000);self.flush();assert hasattr(self,'stop')
        return {'configuration':self.c,'initial':self.initial,'initial_RAM':self.initial_RAM,'constructor_terminal':constructor,
          'record80_before_controls_hex':before,'record_controls':controls,'record80_after_controls_hex':after,'nested_entry':entry,
          'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'PAC_models':self.pac,'CPU_points':self.points,
          'import_points':self.import_points,'operand_points':self.operand_points,'operand_controls':self.operand_controls,
          'stop_reason':self.stop,'frontier':self.frontier,'terminal':self.terminal,'final_RAM':self.dump(),
          'final_delta_cell_u64':hex(int.from_bytes(self.ram(OUT,8),'little')),'final_status_u32':hex(int.from_bytes(self.ram(RECORD+0x30,4),'little')),
          'used_original_pointer_rows':[self.D[a]for a in sorted(self.used)],'native_effects':False}


def configurations():
    base=[c for c in prior_configurations()if c['control']in ['as_staged','null_auxiliary']]
    for c in base:yield {**c,'label':'unbacked_'+c['label'],'mode':'nested','backed':False}
    values=[1,3,5,7,17,65537,0xffffffff,0x80000001,0xa5a5a5a5,0x7fffffff]
    x=0x12345678
    for j in range(14):x=(1664525*x+1013904223)&0xffffffff;values.append(x|1)
    values.extend([0,2,0x80000000,0xfffffffe])
    for j,v in enumerate(values):yield {**base[j%8],'label':'backed_'+hex(v),'mode':'nested','backed':True,'operand_u32':v,'second_seed_u64':[0,1,0xffffffffffffffff,0x0123456789abcdef][j%4]}


def lift(ins,registers,start,end):
    """Closed u32 straight-line source lifter; unsupported instructions reject."""
    r=dict(registers);bv=lambda v:z3.BitVecVal(v,32)
    def value(s):return bv(int(s[1:],0))if s.startswith('#')else r[s]
    for pc in range(start,end,4):
        i=ins[pc];o=i.op_str.split(', ');d=o[0];m=i.mnemonic;assert d.startswith('w')
        if m=='mov':r[d]=value(o[1]);continue
        if m=='movk':
            k=int(o[2].split('#')[1]);r[d]=(r[d]&bv(~(65535<<k)))|(value(o[1])<<k);continue
        x=value(o[1]);y=value(o[2])
        if len(o)>3:
            mode,k=o[3].split(' #');assert mode in ['lsl','lsr'];k=int(k,0);y=y<<k if mode=='lsl'else z3.LShR(y,k)
        if m in ['lsl','lsr']and not o[2].startswith('#'):y=y&31
        r[d]={'eor':lambda:x^y,'orr':lambda:x|y,'and':lambda:x&y,'add':lambda:x+y,'sub':lambda:x-y,'lsl':lambda:x<<y,'lsr':lambda:z3.LShR(x,y),'mul':lambda:x*y}[m]()
    return r


def proofs(code):
    ins={i.address:i for r in code for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))};bv=lambda v:z3.BitVecVal(v,32)
    n,q,inv,bit=z3.BitVecs('operand quotient candidate bit',32);r={'w24':n^bv(K),'w30':bv(0x8f3b)}
    r=lift(ins,r,0x14f8ee0,0x14f8f40);r=lift(ins,r,0x14f8f94,0x14f8fec)
    r.update({'w24':q^bv(K),'w30':bv(0x8f3b),'w8':bv(0x4a2d180),'w20':bit,'w1':inv})
    r=lift(ins,r,0x14f9030,0x14f9048)
    claims=[('source_shift_codec',r['w25']==(z3.LShR(q,1)^bv(K))),('source_bit_test',(r['w17']==r['w24'])==((q&2)!=0))]
    r=lift(ins,r,0x14f9064,0x14f91f8)
    claims.extend([('source_encoded_add_byte_'+str(j),z3.Extract(8*j+7,8*j,r['w25'])==z3.Extract(8*j+7,8*j,(z3.LShR(q,1)+n)^bv(K)))for j in range(4)])
    claims.extend([('source_candidate_bit',z3.Implies(z3.And(z3.UGE(bit,1),z3.ULE(bit,31)),r['w1']==inv+(bv(1)<<bit)))])
    rloop=lift(ins,{'w21':bv(0xb960),'w20':bit,'w0':bv(0xbabf),'w2':bv(0x25),'w3':bv(0x246d),'w4':bv(0x1237)},0x14f8ff4,0x14f900c)
    claims.append(('source_loop_increment_and_state',z3.And(rloop['w20']==bit+1,rloop['w30']==0x8f3b)))
    seed=z3.BitVec('second_cursor',64);claims.append(('second_cursor_cancel_u64',seed-144+144==seed))
    # P denotes n*candidate modulo 2^32. Shifts/additions preserve this
    # relation by distributivity; these obligations close each fixed bit.
    product=z3.BitVec('product',32)
    for j in range(1,32):
        mask=(1<<(33-j))-1;take=(q&2)!=0;pn=product+z3.If(take,n<<j,bv(0));qn=z3.LShR(q,1)+z3.If(take,n,bv(0))
        premise=z3.And((n&1)==1,(product&((1<<j)-1))==1,(q&mask)==z3.LShR(product,j-1))
        claim=z3.And((pn&((1<<(j+1))-1))==1,(qn&((1<<(32-j))-1))==z3.LShR(pn,j))
        claims.append(('inverse_induction_bit_'+str(j),z3.Implies(premise,claim)))
    out=[]
    for name,c in claims:
        s=z3.Solver();s.set(timeout=60000);s.add(z3.Not(c));result=str(s.check());assert result=='unsat',name+':'+result
        out.append({'label':name,'query':s.sexpr()+'\n(check-sat)\n','result':result,'timeout_ms':60000})
    return out


def bindings(banks,D):
    tests=[(0x1ac19c0,0x1c78040,0x78,0x2e),(0x1ac19c0,0x1c78040,0x27,0x18),(0x1ac19c0,0x1c78040,0x20,0x94),(0x174f320,0x18ac370,0xe4,0xec),(0x18ac070,0x1ac18c0,0x8c,0xa3)]
    exhaustive=[]
    for a,b,k,c in tests:
        assert {v^banks[b][banks[a][v]^k]for v in range(256)}=={c}
        exhaustive.append({'first':hex(a),'second':hex(b),'key':hex(k),'constant':hex(c),'inputs':256})
    B=0x1d05fa0;T=0x1c81940
    rows=[('wrapper_stateA',B+0x1445*8,-4,0x1d33698),('wrapper_stateB',B+0x1821*8,0,0x1d37f68),('wrapper_cursor_meta',B+0x16d6*8,-4,0x1d332a0),('wrapper_table',B+0x1529*8,-4,T),('child_stateA',B+0x2d3*8,-4,0x1d43800),('child_stateB',B+0x1821*8,0,0x1d37f68),('child_table',B+0x1529*8,-4,T),('outer_wrapper',0x1d05948,0,0x14fac64),('nested_child',0x1d04c30,0,0x14f8d28),('loop_entry',T+0xb9d0*8,0,0x14f9030),('loop_add',T+0x8f3b*8,0,0x14f9064),('loop_skip',T+0x8f3f*8,0,0x14f8ff4),('loop_exit',T+0xb960*8,0,0x14f9208),('scalar_initializer',0x1d039d8,0,0x181b00),('next_helper',0x1d03860,0,0x5a600c)]
    out=[]
    for role,a,bias,target in rows:
        assert int(D[a]['target'],16)+bias==target
        out.append({'role':role,'slot':hex(a),'bias':bias,'effective_target':hex(target),'original':D[a]})
    return {'exhaustive_banks':exhaustive,'selected_bindings':out}


def main():
    code,banks,D=sources();f=local_reference(code,banks,D);selected=bindings(banks,D);queries=proofs(code);profiles=[Execute(c,code,banks,D).run()for c in configurations()]
    counts={'profiles':len(profiles),'unbacked_context_frontiers':sum(not p['configuration']['backed']for p in profiles),
      'backed_operand_prefixes':sum(p['configuration']['backed']for p in profiles),'source_visits':sum(len(p['source_visits'])for p in profiles),
      'source_reads':sum(len(p['source_reads'])for p in profiles),'source_writes':sum(len(p['source_writes'])for p in profiles),
      'PAC_models':sum(len(p['PAC_models'])for p in profiles),'fresh_IDA_spans':2,'fresh_IDA_bytes':8504,'source_code_bytes':13852,'local_queries_unsat':len(queries)}
    e={'scope':__doc__,'code_spans':code,'profiles':profiles,'proofs':queries,'reference_file_check':f,'bindings':selected,'verified_counts':counts,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'generator_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'fpsd1201_operand_ida_readback.json').encode()),'whole_parent_replayed':False,
      'native_target_executed':False,'IDB_edit_operations_requested':False,'full_goal_complete':False}
    (ROOT/'fpsd1201_operand_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
