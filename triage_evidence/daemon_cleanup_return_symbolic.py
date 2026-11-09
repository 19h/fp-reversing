#!/usr/bin/env python3
"""Byte-symbolic normal-free-return continuation, conservative scalar ABI clobbers and retired owner.
O(instructions + effects + BV expressions) time/space plus optional solver
resources. No native target or concrete value for an unavailable byte.
"""
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_MEM,ARM64_OP_IMM,ARM64_EXT_UXTH,ARM64_EXT_SXTW,ARM64_EXT_SXTX,ARM64_EXT_UXTW
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from prove_daemon_record720_fingerprint import FingerprintLift
from lskd_values_symbolic import resize
from recover_daemon_object_clock import sections
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_digest_output_access import key
from replay_daemon_descriptor_producers import IMPORTS
from daemon_import_bindings import binding
from validate_daemon_record720_spill import parse_value
from lskd_values_symbolic import Lift

CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True
from daemon_arena_list_symbolic import ListFlags
from daemon_arena_consumer_symbolic import ConsumerFlags
from daemon_arena_lifetime_symbolic import LifetimeFlags
class Frontier(Exception):
    def __init__(self,detail):self.detail=detail
def numeric(value,role,pc):
    value=z3.simplify(value)
    if not z3.is_bv_value(value):raise Frontier({'pc':hex(pc),'kind':'symbolic_'+role,'expression':value.sexpr()})
    return value.as_long()

def analyze(source):
    ctx=source['context'];ram={};effects=[];unknown={int(r['address'],16):z3.BitVec(r['variable'],8)for r in ctx['unknown_variable_origins']};steps=[];edges=[];observables=[];origins={n:int(a,16)for n,a in ctx['register_pointer_origins'].items()};memory_origins={int(a,16):int(v,16)for a,v in ctx.get('memory_pointer_origins',{}).items()};fix=set();stores=[];pc=int(ctx['entry_PC'],16);owner=ctx['frame_owner'];lo=int(owner['address'],16);hi=lo+owner['size_bytes'];WRITABLE=[s for s in sections()if s['segment']=='__DATA']
    for g in ctx['known_byte_groups']:
        for j,b in enumerate(bytes.fromhex(g['bytes_hex'])):ram[int(g['address'],16)+j]=z3.BitVecVal(b,8)
    variables={v.decl().name():v for v in unknown.values()};flag=z3.BitVec('lifetime_runtime_flag32',32);variables['lifetime_runtime_flag32']=flag
    for r in ctx['symbolic_bytes']:ram[int(r['address'],16)]=parse_value(r['expression'],8,variables)
    flag=z3.BitVec('lifetime_runtime_flag32',32);variables['lifetime_runtime_flag32']=flag
    path=flag==0 if ctx['path_class']=='zero'else flag!=0;resolutions=[];resolved={};API_models=[];ABI_variables=[];ABI_direct_reads=[];ABI_pending=set();ABI_flags_pending=False;retired=[];stack_havoc=[]
    for g in ctx['symbolic_global_words']:
        assert g['width_bits']==32 and g['variable']=='lifetime_runtime_flag32'
        for j in range(4):ram[int(g['address'],16)+j]=z3.Extract(8*j+7,8*j,flag)
    def numeric(value,role,pc):
        expr=z3.simplify(value)
        if z3.is_bv_value(expr):return expr.as_long()
        key=expr.sexpr()
        if key in resolved:return resolved[key]
        solver=z3.Solver();solver.set(timeout=30000);solver.add(path);assert solver.check()==z3.sat;candidate=solver.model().eval(expr,model_completion=True);assert z3.is_bv_value(candidate)
        solver.add(expr!=candidate);answer=solver.check()
        if answer!=z3.unsat:raise Frontier({'pc':hex(pc),'kind':'nonunique_'+role,'expression':key,'path_class':ctx['path_class'],'solver_answer':str(answer)})
        number=candidate.as_long();resolved[key]=number;resolutions.append({'pc':hex(pc),'role':role,'expression':key,'width_bits':expr.size(),'unique_value':hex(number),'path_condition':path.sexpr(),'result':'unsat'});return number
    def address_value(a,role,n):
        observables.append((role,pc,a));return numeric(a,role,pc)
    class V(LifetimeFlags):
        last_load_slot=None
        def read(self,name):
            if key(name)in ABI_pending:ABI_direct_reads.append({'pc':hex(pc),'register':name})
            return super().read(name)
        def write(self,name,value):
            ABI_pending.discard(key(name));return super().write(name,value)
        def set_flags(self,a,b,add=False):
            nonlocal ABI_flags_pending
            ABI_flags_pending=False;return super().set_flags(a,b,add)
        def condition(self,cc):
            if ABI_flags_pending:ABI_direct_reads.append({'pc':hex(pc),'NZCV_condition':cc})
            return super().condition(cc)

        def address(self,i,o):
            a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
            if o.mem.index:
                x=self.read(i.reg_name(o.mem.index))
                if o.ext==ARM64_EXT_SXTW:x=z3.SignExt(32,resize(x,32))
                elif o.ext==ARM64_EXT_SXTX:x=resize(x,64)
                elif o.ext==ARM64_EXT_UXTW:x=z3.ZeroExt(32,resize(x,32))
                else:x=resize(x,64)
                a+=x<<o.shift.value
            return z3.simplify(a)
        def load(self,a,n):
            at=address_value(a,'read_address',n)
            if any(at<o['address']+o['size_bytes']and o['address']<at+n for o in retired):raise Frontier({'pc':hex(pc),'kind':'before_retired_owner_read','address':hex(at),'size_bytes':n})
            self.last_load_slot=memory_origins.get(at)if n==8 else None
            if at in FIXUPS and n==8:
                target=FIXUPS[at]['target']
                if isinstance(target,str):target=IMPORTS[target]+binding(at)['total_addend']
                self.last_load_slot=at;fix.add(at);value=z3.BitVecVal(target,64)
            else:
                vals=[]
                for j in range(n):
                    here=at+j
                    if here in ram:value=ram[here]
                    elif any(o['start']<=here<o['end']for o in stack_havoc):raise Frontier({'pc':hex(pc),'kind':'before_API_clobbered_stack_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    elif lo<=here<hi:
                        if here not in unknown:unknown[here]=z3.BitVec('consumer_unavailable_byte_%x'%here,8)
                        value=unknown[here]
                    elif any(int(o['address'],16)<=here<int(o['address'],16)+o['size_bytes']for o in ctx.get('additional_owners',[])):raise Frontier({'pc':hex(pc),'kind':'before_undefined_arena_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    elif any(s['start']<=here<s['start']+s['size_bytes']for s in WRITABLE):raise Frontier({'pc':hex(pc),'kind':'before_unmodeled_runtime_read','address':hex(at),'size_bytes':n,'first_missing_byte':hex(here)})
                    else:
                        try:value=z3.BitVecVal(IMAGE.read(here,1)[0],8)
                        except ValueError:raise Frontier({'pc':hex(pc),'kind':'before_unowned_external_read','address':hex(at),'size_bytes':n})
                    vals.append(value)
                value=z3.Concat(*reversed(vals))if n>1 else vals[0]
            effects.append({'pc':hex(pc),'kind':'read','address':hex(at),'size_bytes':n,'expression':value.sexpr()});return value
        def store(self,a,n,value,atpc):
            at=address_value(a,'write_address',n)
            if any(at<o['address']+o['size_bytes']and o['address']<at+n for o in retired):raise Frontier({'pc':hex(pc),'kind':'before_retired_owner_write','address':hex(at),'size_bytes':n})
            if not(lo<=at<at+n<=hi or any(int(o['address'],16)<=at<at+n<=int(o['address'],16)+o['size_bytes']for o in ctx.get('additional_owners',[]))or any(s['start']<=at<at+n<=s['start']+s['size_bytes']for s in WRITABLE)):raise Frontier({'pc':hex(pc),'kind':'before_unowned_write','address':hex(at),'size_bytes':n})
            value=resize(value,n*8);effects.append({'pc':hex(pc),'kind':'write','address':hex(at),'size_bytes':n,'expression':value.sexpr()});stores.append((pc,at,n,value))
            for j in range(n):ram[at+j]=z3.Extract(8*j+7,8*j,value)
    v=V({'spans':[]});v.seed('sp',int(ctx['SP'],16))
    for name,value in ctx['known_GPRs'].items():v.seed(name,int(value,16))
    for name,expr in ctx['symbolic_GPR_expressions'].items():v.seed(name,parse_value(expr,64,variables))
    flags=int(ctx['NZCV'],16)>>28
    v.negative=z3.BoolVal(bool(flags&8));v.equal=z3.BoolVal(bool(flags&4));v.carry=z3.BoolVal(bool(flags&2));v.overflow=z3.BoolVal(bool(flags&1))
    boundary=None;milestones=[];direct_edges=[];return_edges=[];call_stack=[dict(r)for r in ctx['active_calls']];sign_events=[]
    try:
        for _ in range(100000):
            i=next(CS.disasm(IMAGE.read(pc,4),pc));v.pc=pc;old_origins=origins.copy();first=len(effects)
            if i.mnemonic in ['pacibsp','paciasp']:
                assert call_stack;frame=call_stack[-1];sp=numeric(v.read('sp'),'sign_SP',pc);lr=numeric(v.read('x30'),'sign_LR',pc);assert sp==frame['SP']and lr==frame['return'];frame['signing']={'pc':hex(pc),'SP':hex(sp),'key':'IB'if i.mnemonic=='pacibsp'else'IA'};sign_events.append(dict(frame['signing']));steps.append([pc,bytes(i.bytes).hex()]);pc+=4;continue
            if i.mnemonic in ['ret','retab']:
                name=i.op_str.strip()if i.op_str.strip()else'x30';origin=next((r for r in ctx['logical_return_origins']if int(r['return_pc'],16)==pc),None)
                if origin is None and call_stack:
                    frame=call_stack[-1];target=numeric(v.read(name),'return_target',pc);sp=numeric(v.read('sp'),'return_SP',pc);assert target==frame['return']and sp==frame['SP']
                    if i.mnemonic=='retab':assert frame.get('signing',{}).get('key')=='IB'
                    call_stack.pop();return_edges.append({'pc':hex(pc),'target':hex(target),'SP':hex(sp),'kind':i.mnemonic,'origin':frame});steps.append([pc,bytes(i.bytes).hex()]);pc=target;continue
                if origin is not None:
                    target=numeric(v.read(name),'return_target',pc);sp=numeric(v.read('sp'),'return_SP',pc);assert target==int(origin['target'],16)and sp==int(origin['expected_SP'],16)
                    return_edges.append({'pc':hex(pc),'target':hex(target),'SP':hex(sp),'kind':i.mnemonic,'origin':origin});steps.append([pc,bytes(i.bytes).hex()]);pc=target;continue
                raise Frontier({'pc':hex(pc),'kind':'before_source_return','instruction':i.mnemonic,'SP':hex(numeric(v.read('sp'),'return_SP',pc)),'return_target_expression':v.read(name).sexpr(),'result_X0_expression':z3.simplify(v.read('x0')).sexpr()})
            if i.mnemonic=='b'or i.mnemonic.startswith('b.')or i.mnemonic in ['cbz','cbnz','tbz','tbnz']:
                if i.mnemonic=='b':condition=z3.BoolVal(True);target=i.operands[0].imm
                elif i.mnemonic.startswith('b.'):condition=v.condition(i.mnemonic[2:]);target=i.operands[0].imm
                else:
                    reg=i.reg_name(i.operands[0].reg);value=v.read(reg)
                    if i.mnemonic in ['cbz','cbnz']:condition=value==0;target=i.operands[1].imm
                    else:condition=(value&(1<<i.operands[1].imm))==0;target=i.operands[2].imm
                    if i.mnemonic in ['cbnz','tbnz']:condition=z3.Not(condition)
                nextpc=numeric(z3.If(condition,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64)),'direct_branch_target',pc);direct_edges.append({'pc':hex(pc),'instruction':i.mnemonic+' '+i.op_str,'target':hex(nextpc),'condition':condition.sexpr()});steps.append([pc,bytes(i.bytes).hex()]);pc=nextpc;continue
            if i.mnemonic in ['braa','blraa','braaz','blraaz','ret','retab']:
                ret=i.mnemonic.startswith('ret');name='x30'if ret else i.op_str.split(',')[0].strip();value=v.read(name);observables.append(('branch_target',pc,value));target=numeric(value,'branch_target',pc)
                assert not ret,('unexpected return',hex(pc))
                slot=origins.get(key(name))
                if slot not in FIXUPS:raise Frontier({'pc':hex(pc),'kind':'unresolved_pointer_origin','register':name,'target':hex(target)})
                word=int.from_bytes(IMAGE.read(slot,8),'little');modifier=0 if i.mnemonic.endswith('z')else numeric(v.read(i.op_str.split(',')[1].strip()),'PAC_modifier',pc)
                assert word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0;fix.add(slot)
                if i.mnemonic.startswith('bl'):
                    if not isinstance(FIXUPS[slot]['target'],str):
                        assert FIXUPS[slot]['target']==target;call_stack.append({'call_pc':hex(pc),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'SP':numeric(v.read('sp'),'call_SP',pc),'return':pc+4});edges.append({'pc':hex(pc),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'kind':i.mnemonic});steps.append([pc,bytes(i.bytes).hex()]);v.seed('x30',pc+4);origins.pop('x30',None);pc=target;continue
                    bound=binding(slot);assert isinstance(FIXUPS[slot]['target'],str)and target==IMPORTS[FIXUPS[slot]['target']]+bound['total_addend']
                    if pc==0x1001c6100 and bound['symbol']=='_free'and not API_models:
                        address=numeric(v.read('x0'),'free_argument',pc);model=ctx['normal_free_return_model'];assert address==int(model['owner_address'],16);size=model['owner_size_bytes'];before=sum(address+j in ram for j in range(size))
                        for j in range(size):ram.pop(address+j,None)
                        retired.append({'address':address,'size_bytes':size});call_SP=numeric(v.read('sp'),'API_call_SP',pc);removed_stack=[a for a in ram if lo<=a<call_SP]
                        for a in removed_stack:ram.pop(a)
                        for a in list(memory_origins):
                            if address<=a<address+size or lo<=a<call_SP:memory_origins.pop(a)
                        stack_havoc.append({'start':lo,'end':call_SP})
                        for name in model['caller_saved_scalar_registers']:
                            variable='cleanup_free_'+name;value=z3.BitVec(variable,64);variables[variable]=value;v.seed(name,value);ABI_pending.add(name);origins.pop(name,None);ABI_variables.append({'variable':variable,'sort':'BitVec','width_bits':64,'register':name})
                        for attr,name in [('negative','N'),('equal','Z'),('carry','C'),('overflow','V')]:
                            variable='cleanup_free_NZCV_'+name;value=z3.Bool(variable);variables[variable]=value;setattr(v,attr,value);ABI_variables.append({'variable':variable,'sort':'Bool','width_bits':1,'flag':name})
                        ABI_flags_pending=True;API_models.append({'pc':hex(pc),'return_pc':hex(pc+4),'binding':bound,'argument_X0':hex(address),'retired_owner_size_bytes':size,'previously_defined_bytes_removed':before,'modeled_stack_havoc':{'start':hex(lo),'end':hex(call_SP),'defined_bytes_removed':len(removed_stack)},'normal_return_assumed':True,'native_call_executed':False});steps.append([pc,bytes(i.bytes).hex()]);pc+=4;continue
                    arg=z3.simplify(v.read('x0'));raise Frontier({'pc':hex(pc),'kind':'before_import_call','binding':bound,'argument_X0_expression':arg.sexpr(),'logical_target':hex(target)})
                assert FIXUPS[slot]['target']==target
                edges.append({'pc':hex(pc),'target':hex(target),'slot':hex(slot),'modifier':hex(modifier),'kind':i.mnemonic});steps.append([pc,bytes(i.bytes).hex()]);pc=target;continue
            v.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':bytes(i.bytes).hex()}]};v.last_load_slot=None
            try:v.run('one')
            except Exception as e:e.add_note('source PC '+hex(pc)+' '+i.mnemonic+' '+i.op_str);raise
            rr,ww=i.regs_access()
            new_effects=effects[first:]
            for e in new_effects:
                if e['kind']=='write':
                    at=int(e['address'],16)
                    for oldat in list(memory_origins):
                        if at<oldat+8 and oldat<at+e['size_bytes']:memory_origins.pop(oldat)
            if i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
                es=[e for e in new_effects if e['kind']=='write'];o=old_origins.get(key(i.reg_name(i.operands[0].reg)))
                if o is not None and len(es)==1 and es[0]['size_bytes']==8:memory_origins[int(es[0]['address'],16)]=o
            elif i.mnemonic=='stp'and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
                es=[e for e in new_effects if e['kind']=='write'];assert len(es)==2
                for operand,e in zip(i.operands,es):
                    o=old_origins.get(key(i.reg_name(operand.reg)))
                    if o is not None:memory_origins[int(e['address'],16)]=o
            for reg in ww:origins.pop(key(i.reg_name(reg)),None)
            if i.mnemonic in['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x')and v.last_load_slot is not None:origins[key(i.reg_name(i.operands[0].reg))]=v.last_load_slot
            elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
                o=old_origins.get(key(i.reg_name(i.operands[1].reg)))
                if o is not None:origins[key(i.reg_name(i.operands[0].reg))]=o
            steps.append([pc,bytes(i.bytes).hex()]);pc+=4
        else:raise Frontier({'pc':hex(pc),'kind':'instruction_limit'})
    except Frontier as e:boundary=e.detail
    except AssertionError as e:
        if e.args and isinstance(e.args[0],tuple)and e.args[0][0]=='unsupported symbolic instruction':boundary={'pc':hex(pc),'kind':'before_unsupported_source_instruction','instruction':e.args[0][2],'operands':e.args[0][3]}
        else:raise
    assert boundary is not None
    return {'context':ctx,'API_models':API_models,'ABI_symbolic_variables':ABI_variables,'ABI_reads_before_definition':ABI_direct_reads,'retired_owners':retired,'path_condition':path.sexpr(),'resolution_certificates':resolutions,'symbolic_global_variables':[{'variable':'lifetime_runtime_flag32','width_bits':32,'address':'0x1010b6cb8'}],'end_NZCV_expressions':{n:z3.simplify(e).sexpr()for n,e in [('N',v.negative),('Z',v.equal),('C',v.carry),('V',v.overflow)]},'milestones':milestones,'steps':steps,'effects':effects,'edges':edges,'direct_edges':direct_edges,'return_edges':return_edges,'logical_sign_events':sign_events,'active_calls':call_stack,'boundary':boundary,'unknown_bytes':[{'address':hex(a),'variable':b.decl().name()}for a,b in sorted(unknown.items())],'end_GPR_expressions':{n:z3.simplify(x).sexpr()for n,x in v.regs.items()},'original_fixups':verify_used_fixups(fix),'native_target_executed':False,'unknown_bytes_assigned_values':False,'full_goal_complete':False},observables,stores,v

if __name__=='__main__':
    source=json.loads((ROOT/'daemon_cleanup_return_source.json').read_text());rows=[]
    for case in source['cases']:
        r,obs,stores,v=analyze(case);rows.append({'label':case['label'],'result':r});print(json.dumps({'label':case['label'],'source_steps':len(r['steps']),'boundary':r['boundary']}),flush=True)
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_cleanup_return_source.json','daemon_arena_lifetime_symbolic.py','daemon_arena_consumer_symbolic.py','validate_daemon_record720_spill.py']},'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_cleanup_return_symbolic.json').write_text(json.dumps(out,indent=2)+'\n')
