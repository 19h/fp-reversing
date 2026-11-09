#!/usr/bin/env python3
"""Continuous independent A64 execution through the verified parent and new
consumer; compare reconstructed checkpoint bytes/registers before continuing.
O(source bytes + witnesses*visits + solver resources) time, O(case + map) space.
Logical PAC edges are checked, not authenticated by hardware. No host API/IPC.
"""
import json,random,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_arena_consumer import capture
from validate_daemon_record720_spill import materializations,parse_value
from validate_daemon_object_clock import logical_read
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True

def replay(symbolic,label,values,parsed,checkpoint):
    c=symbolic['context'];u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();index=0;pending=[];current=0
    def ensure(a,n):
        for pg in range(a&~4095,(a+n+4095)&~4095,4096):
            if pg in pages:continue
            if 0x100000000<=pg<0x102000000:
                try:b=logical_read(pg,4096)
                except ValueError:b=bytes(4096)
            else:b=bytes([0x39 if label=='zero'else 0xc7])*4096
            u.mem_map(pg,4096);u.mem_write(pg,b);pages.add(pg)
    def reg(name):return getattr(ar,'UC_ARM64_REG_'+name.upper())
    def get(name):return u.reg_read(reg(name))
    replacements=[(z3.BitVec(r['variable'],8),z3.BitVecVal(b,8))for r,b in zip(symbolic['unknown_bytes'],values,strict=True)]
    def evaluated(expr):
        value=z3.simplify(z3.substitute(expr,*replacements));assert z3.is_bv_value(value);return value.as_long()
    for g in c['known_byte_groups']:
        a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b)
    for r,b in zip(symbolic['unknown_bytes'],values,strict=True):
        a=int(r['address'],16);ensure(a,1);u.mem_write(a,bytes([b]))
    for name,value in c['known_GPRs'].items():u.reg_write(reg(name),int(value,16))
    u.reg_write(ar.UC_ARM64_REG_SP,int(c['SP'],16));u.reg_write(ar.UC_ARM64_REG_NZCV,0x50000000 if label in['zero','a5']else 0xa0000000)
    def hook(_,kind,a,n,value,__):
        nonlocal index
        expected=symbolic['effects'][index];expr=parsed[index];index+=1;assert expected['pc']==hex(current)and int(expected['address'],16)==a and expected['size_bytes']==n
        if kind==uc.UC_MEM_READ:
            assert expected['kind']=='read';actual=int.from_bytes(bytes(u.mem_read(a,n)),'little');assert actual==evaluated(expr);counts['reads_checked']+=1
        else:assert expected['kind']=='write';pending.append((a,n,expr));counts['writes_checked']+=1
    u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook);edge_iter=iter(symbolic['edges']);pc=int(c['entry_PC'],16)
    checked_checkpoint=False
    for expected,raw in symbolic['steps']:
        if pc==0x10031f248 and not checked_checkpoint:
            for g in checkpoint['known_byte_groups']:
                a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);assert bytes(u.mem_read(a,len(b)))==b;counts['checkpoint_known_bytes_checked']+=len(b)
            variables={r['variable']:z3.BitVec(r['variable'],8)for r in symbolic['unknown_bytes']}
            for r in checkpoint['symbolic_bytes']:
                a=int(r['address'],16);assert bytes(u.mem_read(a,1))[0]==evaluated(parse_value(r['expression'],8,variables));counts['checkpoint_symbolic_bytes_checked']+=1
            for name,value in checkpoint['known_GPRs'].items():assert get(name)==int(value,16);counts['checkpoint_GPRs_checked']+=1
            for name,expr in checkpoint['symbolic_GPR_expressions'].items():assert get(name)==evaluated(parse_value(expr,64,variables));counts['checkpoint_GPRs_checked']+=1
            checked_checkpoint=True;counts['continuous_checkpoints_checked']+=1
        assert pc==expected;current=pc;i=next(CS.disasm(IMAGE.read(pc,4),pc));assert bytes(i.bytes).hex()==raw;ensure(pc,4)
        if i.mnemonic=='braa':
            edge=next(edge_iter);target,modifier=[get(x.strip())for x in i.op_str.split(',')];slot=int(edge['slot'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert edge['pc']==hex(pc)and edge['target']==hex(target)and edge['modifier']==hex(modifier)and FIXUPS[slot]['target']==target and word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0;pc=target;counts['logical_PAC_edges_checked']+=1;continue
        # Map only the known fixed address recorded by the symbolic source
        # model; Unicorn computes and checks the actual effective address.
        j=index
        while j<len(symbolic['effects'])and symbolic['effects'][j]['pc']==hex(pc):
            e=symbolic['effects'][j];ensure(int(e['address'],16),e['size_bytes']);j+=1
        u.emu_start(pc,0,count=1);pc=u.reg_read(ar.UC_ARM64_REG_PC);counts['A64_instructions_checked']+=1
        for a,n,expr in pending:assert int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluated(expr)
        pending.clear()
    assert checked_checkpoint
    assert index==len(symbolic['effects'])and next(edge_iter,None)is None and pc==int(symbolic['boundary']['pc'],16)
    for name,text in symbolic['end_GPR_expressions'].items():assert get(name)==evaluated(parse_value(text,64,{r['variable']:z3.BitVec(r['variable'],8)for r in symbolic['unknown_bytes']})),name
    counts['witnesses_checked']+=1;counts['opaque_byte_materializations']+=len(values)
    return {'label':label,'bytes_hex':values.hex(),'materialization_sha256':hashlib.sha256(values).hexdigest(),'counts':dict(counts),'same_symbolic_frontier':True,'source_definitions_added':False}

def number(expr,n=64,variables=None):
    value=z3.simplify(parse_value(expr,n,variables or{}));assert z3.is_bv_value(value);return value.as_long()

def instruction_microchecks(result):
    candidates=[(pc,raw)for pc,raw in result['steps']if next(CS.disasm(bytes.fromhex(raw),pc)).mnemonic=='csel'];assert candidates;pc,raw=candidates[0];i=next(CS.disasm(bytes.fromhex(raw),pc));ldpc=0x100607350;u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
    def put(a,b):
        if a&~4095 not in pages:u.mem_map(a&~4095,4096);pages.add(a&~4095)
        u.mem_write(a,b)
    put(ldpc,IMAGE.read(ldpc,4));base=0x6600000000;put(base,bytes(64));counts=Counter()
    for b in range(256):
        u.mem_write(base+32,bytes([b]));u.reg_write(ar.UC_ARM64_REG_X12,base);u.reg_write(ar.UC_ARM64_REG_X13,0xffffffffffffffff);u.emu_start(ldpc,0,count=1);assert u.reg_read(ar.UC_ARM64_REG_X13)==(b if b<128 else b-256)&0xffffffff;counts['LDRSB_byte_cases']+=1
    from daemon_arena_consumer_symbolic import ConsumerFlags
    put(pc,bytes.fromhex(raw));rn=lambda n:getattr(ar,'UC_ARM64_REG_'+n.upper());r=random.Random(934)
    for flags in range(16):
        for _ in range(16):
            v=ConsumerFlags({'spans':[{'label':'csel','start':hex(pc),'bytes_hex':raw}]});v.negative=z3.BoolVal(bool(flags&8));v.equal=z3.BoolVal(bool(flags&4));v.carry=z3.BoolVal(bool(flags&2));v.overflow=z3.BoolVal(bool(flags&1))
            for op in i.operands[:3]:
                name=i.reg_name(op.reg)
                if name not in ['wzr','xzr']:
                    val=r.getrandbits(64);v.seed(name,val);u.reg_write(rn(name),val&((1<<v.width(name))-1))
            u.reg_write(ar.UC_ARM64_REG_NZCV,flags<<28);v.run('csel');u.emu_start(pc,0,count=1);dest=i.reg_name(i.operands[0].reg);assert u.reg_read(rn(dest))==z3.simplify(v.read(dest)).as_long();counts['CSEL_flag_operand_cases']+=1
    return dict(counts),{'CSEL_pc':hex(pc),'CSEL_instruction':i.op_str,'LDRSB_pc':hex(ldpc)}

def audit_case(row):
    r=row['result'];S=int(r['context']['SP'],16);H=int(r['context']['additional_owners'][0]['address'],16);D=0x1010b5ef0;M=0x5e878c613b8123ea;variables={b['variable']:z3.BitVec(b['variable'],8)for b in r['unknown_bytes']}
    assert r['boundary']=={'pc':'0x10062b32c','kind':'before_unmodeled_runtime_read','address':'0x1010b6cb8','size_bytes':4,'first_missing_byte':'0x1010b6cb8'}and len(r['steps'])==66132 and len(r['unknown_bytes'])==104
    writes=[e for e in r['effects']if e['kind']=='write'];saved={int(e['address'],16):number(e['expression'],e['size_bytes']*8,variables)for e in writes if int(e['address'],16)in [S+0x1a8,S+0x1b0]};assert saved=={S+0x1a8:H+0x15904,S+0x1b0:H+0x15278}
    fills=[e for e in writes if e['pc']=='0x1006081f8'];assert len(fills)==1724 and [int(e['address'],16)for e in fills]==list(range(H+88300-1,H+86624-49,-1))
    late={int(e['address'],16):number(e['expression'],e['size_bytes']*8,variables)for e in writes if int(e['pc'],16)in [0x10058835c,0x100588378,0x1005883cc,0x1005883d8]};assert late[D+40]==0x1aa4071f0801765b+3352 and late[H+8]==M+86624 and late[H+86624]==M+86624 and late[H+86624+8]==M-1676 and late[H+88300]==M
    gate=[{'pc':e['pc'],'value':hex(number(e['expression'],32,variables))}for e in writes if int(e['address'],16)==0x1010b5de0];assert gate==[{'pc':'0x100503d18','value':'0xa94ef'},{'pc':'0x100634280','value':'0x5d96'},{'pc':'0x1005f437c','value':'0xa94ef'}]
    accesses={}
    for name,p in [('first',H+0x15904),('second',H+0x15278)]:
        accesses[name]=[e for e in r['effects']if p<=int(e['address'],16)<p+1652]
    return {'label':row['label'],'source_steps':len(r['steps']),'source_effects':len(r['effects']),'logical_edges':len(r['edges']),'unknown_frame_bytes':104,'first_payload':hex(H+0x15904),'second_payload':hex(H+0x15278),'second_boundary':hex(H+86624),'second_remaining_bytes':86624,'second_account_debit_bytes':1676,'cumulative_account_debit_bytes':3352,'fill_bytes':len(fills),'gate_transitions':gate,'payload_range_accesses':accesses,'milestones':r['milestones']}

def main():
    from prove_daemon_arena_consumer import obligations
    source=json.loads((ROOT/'daemon_arena_consumer_source.json').read_text());assert source==capture();stored=json.loads((ROOT/'daemon_arena_consumer_symbolic.json').read_text());parent=json.loads((ROOT/'daemon_arena_list_symbolic.json').read_text());parents={r['label']:r['result']for r in parent['cases']};proofs=json.loads((ROOT/'daemon_arena_consumer_proofs.json').read_text());out=Counter();total=Counter();witnesses=[];audits=[]
    for obj,script in [(source,'capture_daemon_arena_consumer.py'),(stored,'daemon_arena_consumer_symbolic.py'),(proofs,'prove_daemon_arena_consumer.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
    qs,counts=obligations();assert counts==proofs['source_lift_counts']
    for (name,query),row in zip(qs,proofs['proofs'],strict=True):
        assert name==row['name']
        for key,expr in [('original_file',query),('file',z3.simplify(query))]:
            p=ROOT/row[key];assert sha(p)==row['original_sha256'if key=='original_file'else'sha256'];items=z3.parse_smt2_file(str(p));s=z3.Solver();s.set(timeout=30000);s.add(*items);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*items),expr));assert s.check()==z3.unsat;out['SMT_files_checked']+=1
        out['source_obligations_rebuilt']+=1
    assert {p.name for p in ROOT.glob('daemon_arena_consumer_*.smt2')}=={r[k]for r in proofs['proofs']for k in ['file','original_file']}
    micro,micro_source=instruction_microchecks(stored['cases'][0]['result']);out.update(micro);print('microchecks',micro,flush=True)
    for case,row in zip(source['cases'],stored['cases'],strict=True):
        assert case['label']==row['label'];r=row['result'];assert r['context']==case['context'];audit=audit_case(row);audits.append(audit);p=parents[row['label']];combined={**r,'context':p['context'],'steps':p['steps']+r['steps'],'effects':p['effects']+r['effects'],'edges':p['edges']+r['edges']};variables={b['variable']:z3.BitVec(b['variable'],8)for b in r['unknown_bytes']};cache={}
        def parsed_effect(e):
            k=(e['expression'],e['size_bytes'])
            if k not in cache:cache[k]=parse_value(e['expression'],8*e['size_bytes'],variables)
            return cache[k]
        parsed=[parsed_effect(e)for e in combined['effects']]
        for j in [0,2,3,6]:
            label,values=materializations(104)[j];w=replay(combined,label,values,parsed,case['context']);w['case']=row['label'];witnesses.append(w);total.update(w['counts']);print(row['label'],label,w['counts'],flush=True)
        out.update(consumer_source_steps=len(r['steps']),consumer_effects=len(r['effects']),consumer_logical_edges=len(r['edges']),parent_source_steps_reconstructed=case['checkpoint_audit']['parent_source_visits_checked'])
    out.update(cases=2,source_data_lift_visits=sum(counts.values()),unknown_frame_bytes_per_case=104)
    d={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_consumer_source.json','daemon_arena_consumer_symbolic.json','daemon_arena_consumer_proofs.json','capture_daemon_arena_consumer.py','daemon_arena_consumer_symbolic.py','prove_daemon_arena_consumer.py','daemon_arena_list_symbolic.json']},'verified_counts':dict(out),'independent_A64_totals':dict(total),'microcheck_source':micro_source,'audits':audits,'witnesses':witnesses,'all_checks_pass':True,'native_target_executed':False,'unknown_bytes_assigned_source_values':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_arena_consumer_checks.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'verified_counts':dict(out),'A64_totals':dict(total)}),flush=True)
if __name__=='__main__':main()
