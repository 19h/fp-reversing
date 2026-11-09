#!/usr/bin/env python3
"""Continuous original-instruction replay through both retained ancestors and
universal-class lifetime suffixes. Finite runtime-flag/frame witnesses do not
supply source definitions. Logical PAC calls/signs/returns are checked, never
hardware-authenticated. O(visits + proof resources) time, O(case + map) space.
"""
import json,random,hashlib
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from capture_daemon_arena_lifetime import capture
from validate_daemon_record720_spill import materializations,parse_value
from validate_daemon_object_clock import logical_read
from daemon_digest_output_access import key
CS=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);CS.detail=True

def replay(symbolic,label,values,parsed,checkpoint,flag_value):
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
    variables={r['variable']:z3.BitVec(r['variable'],8)for r in symbolic['unknown_bytes']};variables['lifetime_runtime_flag32']=z3.BitVec('lifetime_runtime_flag32',32)
    replacements=[(variables[r['variable']],z3.BitVecVal(b,8))for r,b in zip(symbolic['unknown_bytes'],values,strict=True)]+[(variables['lifetime_runtime_flag32'],z3.BitVecVal(flag_value,32))]
    def evaluated(expr):
        value=z3.simplify(z3.substitute(expr,*replacements));assert z3.is_bv_value(value);return value.as_long()
    for g in c['known_byte_groups']:
        a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);ensure(a,len(b));u.mem_write(a,b)
    for r,b in zip(symbolic['unknown_bytes'],values,strict=True):
        a=int(r['address'],16);ensure(a,1);u.mem_write(a,bytes([b]))
    ensure(0x1010b6cb8,4);u.mem_write(0x1010b6cb8,flag_value.to_bytes(4,'little'))
    for name,value in c['known_GPRs'].items():u.reg_write(reg(name),int(value,16))
    u.reg_write(ar.UC_ARM64_REG_SP,int(c['SP'],16));u.reg_write(ar.UC_ARM64_REG_NZCV,0x50000000 if label in['zero','a5']else 0xa0000000)
    def hook(_,kind,a,n,value,__):
        nonlocal index
        expected=symbolic['effects'][index];expr=parsed[index];index+=1;assert expected['pc']==hex(current)and int(expected['address'],16)==a and expected['size_bytes']==n
        if kind==uc.UC_MEM_READ:
            assert expected['kind']=='read';actual=int.from_bytes(bytes(u.mem_read(a,n)),'little');assert actual==evaluated(expr);counts['reads_checked']+=1
        else:assert expected['kind']=='write';pending.append((a,n,expr));counts['writes_checked']+=1
    u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook);edge_iter=iter(symbolic['edges']);return_iter=iter(symbolic['return_edges']);pc=int(c['entry_PC'],16)
    checked_checkpoint=False
    for expected,raw in symbolic['steps']:
        if pc==0x10062b32c and not checked_checkpoint:
            for g in checkpoint['known_byte_groups']:
                a=int(g['address'],16);b=bytes.fromhex(g['bytes_hex']);assert bytes(u.mem_read(a,len(b)))==b;counts['checkpoint_known_bytes_checked']+=len(b)
            for r in checkpoint['symbolic_bytes']:
                a=int(r['address'],16);assert bytes(u.mem_read(a,1))[0]==evaluated(parse_value(r['expression'],8,variables));counts['checkpoint_symbolic_bytes_checked']+=1
            for name,value in checkpoint['known_GPRs'].items():assert get(name)==int(value,16);counts['checkpoint_GPRs_checked']+=1
            for name,expr in checkpoint['symbolic_GPR_expressions'].items():assert get(name)==evaluated(parse_value(expr,64,variables));counts['checkpoint_GPRs_checked']+=1
            assert u.reg_read(ar.UC_ARM64_REG_NZCV)==int(checkpoint['NZCV'],16);counts['checkpoint_NZCV_checked']+=1
            checked_checkpoint=True;counts['continuous_checkpoints_checked']+=1
        assert pc==expected;current=pc;i=next(CS.disasm(IMAGE.read(pc,4),pc));assert bytes(i.bytes).hex()==raw;ensure(pc,4)
        if i.mnemonic in ['braa','blraa']:
            edge=next(edge_iter);target,modifier=[get(x.strip())for x in i.op_str.split(',')];slot=int(edge['slot'],16);word=int.from_bytes(IMAGE.read(slot,8),'little');assert edge['pc']==hex(pc)and edge['target']==hex(target)and edge['modifier']==hex(modifier)and FIXUPS[slot]['target']==target and word>>63==1 and(word>>32)&0xffff==modifier and(word>>48)&7==0;
            if i.mnemonic=='blraa':u.reg_write(ar.UC_ARM64_REG_X30,pc+4);counts['logical_call_edges_checked']+=1
            pc=target;counts['logical_PAC_edges_checked']+=1;continue
        if i.mnemonic=='retab':
            e=next(return_iter);assert e['pc']==hex(pc)and get('x30')==int(e['target'],16)and get('sp')==int(e['SP'],16);pc=int(e['target'],16);counts['logical_return_edges_checked']+=1;continue
        if i.mnemonic=='pacibsp':
            assert pc==0x100435b9c and get('x30')==0x100be0c54;pc+=4;counts['logical_PAC_signs_checked']+=1;continue
        # Map only the known fixed address recorded by the symbolic source
        # model; Unicorn computes and checks the actual effective address.
        j=index
        while j<len(symbolic['effects'])and symbolic['effects'][j]['pc']==hex(pc):
            e=symbolic['effects'][j];ensure(int(e['address'],16),e['size_bytes']);j+=1
        u.emu_start(pc,0,count=1);pc=u.reg_read(ar.UC_ARM64_REG_PC);counts['A64_instructions_checked']+=1
        for a,n,expr in pending:assert int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluated(expr)
        pending.clear()
    assert checked_checkpoint
    assert index==len(symbolic['effects'])and next(edge_iter,None)is None and next(return_iter,None)is None and pc==int(symbolic['boundary']['pc'],16)
    for name,text in symbolic['end_GPR_expressions'].items():assert get(name)==evaluated(parse_value(text,64,variables)),name
    counts['witnesses_checked']+=1;counts['opaque_byte_materializations']+=len(values)
    return {'label':label,'bytes_hex':values.hex(),'materialization_sha256':hashlib.sha256(values).hexdigest(),'counts':dict(counts),'same_symbolic_frontier':True,'source_definitions_added':False}

def number(expr,n=64):
    v=z3.simplify(parse_value(expr,n,{}));assert z3.is_bv_value(v);return v.as_long()

def microchecks():
    from daemon_arena_lifetime_symbolic import LifetimeFlags
    from lskd_values_symbolic import mem
    u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();out=Counter();rng=random.Random(8311);rn=lambda n:getattr(ar,'UC_ARM64_REG_'+n.upper())
    def put(a,b):
        for p in range(a&~4095,(a+len(b)+4095)&~4095,4096):
            if p not in pages:u.mem_map(p,4096);pages.add(p)
        u.mem_write(a,b)
    for pc,n in [(0x1005438d4,32),(0x1005a91e8,64)]:
        raw=IMAGE.read(pc,4);i=next(CS.disasm(raw,pc));put(pc,raw);corners=[0,1,2,(1<<(n-1))-1,1<<(n-1),(1<<n)-2,(1<<n)-1];pairs=[(a,b)for a in corners for b in corners]+[(rng.getrandbits(n),rng.getrandbits(n))for _ in range(512-49)]
        for a,b in pairs:
            v=LifetimeFlags({'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]});aa=i.reg_name(i.operands[1].reg);bb=i.reg_name(i.operands[2].reg);dst=i.reg_name(i.operands[0].reg);v.seed(aa,a);v.seed(bb,b);u.reg_write(rn(aa),a);u.reg_write(rn(bb),b);u.reg_write(ar.UC_ARM64_REG_NZCV,0xb0000000);v.run('one');u.emu_start(pc,0,count=1);assert u.reg_read(rn('x'+dst[1:]))==z3.simplify(v.read('x'+dst[1:])).as_long();assert u.reg_read(ar.UC_ARM64_REG_NZCV)==0xb0000000;out[i.mnemonic+'_cases']+=1
    pc=0x1004a4698;raw=IMAGE.read(pc,4);put(pc,raw)
    for bits in range(16):
        for _ in range(16):
            a=rng.getrandbits(32);v=LifetimeFlags({'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]});v.seed('w9',a);v.negative=z3.BoolVal(bool(bits&8));v.equal=z3.BoolVal(bool(bits&4));v.carry=z3.BoolVal(bool(bits&2));v.overflow=z3.BoolVal(bool(bits&1));v.run('one');u.reg_write(ar.UC_ARM64_REG_W9,a);u.reg_write(ar.UC_ARM64_REG_X13,(1<<64)-1);u.reg_write(ar.UC_ARM64_REG_NZCV,bits<<28);u.emu_start(pc,0,count=1);assert u.reg_read(ar.UC_ARM64_REG_X13)==z3.simplify(v.read('x13')).as_long();assert u.reg_read(ar.UC_ARM64_REG_NZCV)==bits<<28;out['CSINC_cases']+=1
    base=0x6600000000;put(base,bytes(4096))
    for pc in [0x10061aaf0,0x100523898]:
        raw=IMAGE.read(pc,4);put(pc,raw);i=next(CS.disasm(raw,pc))
        for j in range(64):
            sp=base+0x100+(j%16)*16;a,b=rng.getrandbits(64),rng.getrandbits(64);v=LifetimeFlags({'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]});v.seed('sp',sp);u.reg_write(ar.UC_ARM64_REG_SP,sp)
            if i.mnemonic=='ldp':
                mem(v,sp,8,a);mem(v,sp+8,8,b);u.mem_write(sp,a.to_bytes(8,'little')+b.to_bytes(8,'little'))
            else:
                v.seed('x28',a);v.seed('x27',b);u.reg_write(ar.UC_ARM64_REG_X28,a);u.reg_write(ar.UC_ARM64_REG_X27,b)
            v.run('one');u.emu_start(pc,0,count=1);assert u.reg_read(ar.UC_ARM64_REG_SP)==z3.simplify(v.read('sp')).as_long()
            if i.mnemonic=='ldp':assert u.reg_read(ar.UC_ARM64_REG_X28)==a and u.reg_read(ar.UC_ARM64_REG_X27)==b
            else:assert bytes(u.mem_read(sp-96,16))==a.to_bytes(8,'little')+b.to_bytes(8,'little')
            out['writeback_cases']+=1
    return dict(out)

def audit(case,row,initial):
    import base64,zlib
    r=row['result'];c=case['context'];H=int(c['additional_owners'][0]['address'],16);D=0x1010b5ef0;M=0x5e878c613b8123ea;A=0x1aa4071f0801765b;R=0x680002de90;ram={}
    for g in c['known_byte_groups']:ram.update({int(g['address'],16)+j:b for j,b in enumerate(bytes.fromhex(g['bytes_hex']))})
    assert r['boundary']['pc']=='0x1001c6100'and r['boundary']['binding']['symbol']=='_free'and r['boundary']['argument_X0']=='0x6800070000';assert len(r['unknown_bytes'])==104
    writes=[e for e in r['effects']if e['kind']=='write'];arena_writes=[e for e in writes if H<=int(e['address'],16)<H+90000]
    for e in writes:
        a=int(e['address'],16);n=e['size_bytes']
        if H<=a<H+90000 or D<=a<D+88 or R<=a<R+32:
            val=number(e['expression'],n*8)
            for j,b in enumerate(val.to_bytes(n,'little')):ram[a+j]=b
    load=lambda a,n:int.from_bytes(bytes(ram[a+j]for j in range(n)),'little')
    debit=[number(e['expression'],64)for e in writes if e['pc']=='0x10061d6d0'];nonzero=c['path_class']=='nonzero';assert debit==([A+1676,A]if nonzero else[])
    if nonzero:
        desc=bytes.fromhex(initial['descriptor']['bytes_hex']);mask=bytes.fromhex(initial['descriptor']['source_written_mask_hex']);heap=zlib.decompress(base64.b64decode(initial['heap_snapshot']['bytes_zlib_base64']));hm=zlib.decompress(base64.b64decode(initial['heap_snapshot']['known_mask_zlib_base64']));assert sum(bool(b)for b in mask)==80 and sum(bool(b)for b in hm)==48
        for j,m in enumerate(mask):
            if m:assert ram[D+j]==desc[j]
        for j,m in enumerate(hm):
            if m:assert ram[H+j]==heap[j]
    else:assert not arena_writes and load(D+40,8)==A+3352
    status=[e for e in writes if e['pc']=='0x10061aabc'];assert len(status)==1 and status[0]['address']==hex(R+28)and number(status[0]['expression'],32)==0x74c29d8a
    cursor=[e for e in writes if e['pc']=='0x100537110'];assert len(cursor)==1 and cursor[0]['address']=='0x6800023988'and number(cursor[0]['expression'])==0
    assert load(R+8,8)==0x6800070000 and(load(R+16,4)+(((R&0xffffffff)^0xb5da7ac1)*0x5de29be3))&0xffffffff==0xbbb3
    start=next(j for j,(pc,raw)in enumerate(r['steps'])if pc==0x100537104);kill=None;visits=0
    for pc,raw in r['steps'][start:]:
        i=next(CS.disasm(bytes.fromhex(raw),pc));rr,ww=i.regs_access();assert not any(key(i.reg_name(v))=='x0'for v in rr);visits+=1
        if any(key(i.reg_name(v))=='x0'for v in ww):kill=pc;break
    assert kill==0x100be0c48
    return_cuts={};event_cursor=0
    for pc,raw in r['steps']:
        while event_cursor<len(r['effects'])and r['effects'][event_cursor]['pc']==hex(pc):event_cursor+=1
        if any(edge['pc']==hex(pc)for edge in r['return_edges']):return_cuts[hex(pc)]=event_cursor
    assert event_cursor==len(r['effects'])
    for edge in r['return_edges']:
        a=int(edge['origin']['saved_word_address'],16);prior_writes=[e for e in r['effects'][:return_cuts[edge['pc']]]if e['kind']=='write'];assert not any(int(e['address'],16)<a+8 and a<int(e['address'],16)+e['size_bytes']for e in prior_writes)
    return {'label':case['label'],'flag_class':c['path_class'],'source_steps':len(r['steps']),'memory_effects':len(r['effects']),'logical_PAC_edges':len(r['edges']),'logical_return_edges':len(r['return_edges']),'account_values_after_debits':[hex(v)for v in debit],'descriptor_defined_bytes_restored':80 if nonzero else 0,'initializer_heap_bytes_restored':48 if nonzero else 0,'arena_write_visits':len(arena_writes),'record_result':'0x74c29d8a','cursor_adjustment_bytes':0,'cleanup_private_control':'0xbbb3','ordinary_owner_free_argument':'0x6800070000','unused_X0_prefix_visits':visits,'X0_first_overwrite':hex(kill)}

def main():
    from prove_daemon_arena_lifetime import obligations
    from recover_daemon_arena_lifetime_refs import recover
    source=json.loads((ROOT/'daemon_arena_lifetime_source.json').read_text());assert source==capture();stored=json.loads((ROOT/'daemon_arena_lifetime_symbolic.json').read_text());proofs=json.loads((ROOT/'daemon_arena_lifetime_proofs.json').read_text());refs=json.loads((ROOT/'daemon_arena_lifetime_refs.json').read_text());assert refs==recover();out=Counter();total=Counter();audits=[];witnesses=[]
    for obj,script in [(source,'capture_daemon_arena_lifetime.py'),(stored,'daemon_arena_lifetime_symbolic.py'),(proofs,'prove_daemon_arena_lifetime.py'),(refs,'recover_daemon_arena_lifetime_refs.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h
    qs,counts,meta=obligations();assert counts==proofs['source_lift_counts']and meta==proofs['metadata']
    for (name,query),row in zip(qs,proofs['proofs'],strict=True):
        assert name==row['name']
        for keyname,expr in [('original_file',query),('file',z3.simplify(query))]:
            p=ROOT/row[keyname];assert sha(p)==row['original_sha256'if keyname=='original_file'else'sha256'];items=z3.parse_smt2_file(str(p));s=z3.Solver();s.set(timeout=30000);s.add(*items);assert s.check()==z3.unsat;s=z3.Solver();s.set(timeout=30000);s.add(z3.Xor(z3.And(*items),expr));assert s.check()==z3.unsat;out['SMT_files_checked']+=1
        out['source_obligations_rebuilt']+=1
    assert {r[k]for r in proofs['proofs']for k in ['file','original_file']}=={p.name for p in ROOT.glob('daemon_arena_lifetime_*.smt2')}
    out.update(microchecks());print('microchecks',dict(out),flush=True)
    initial=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text())['cases'];p1={r['label']:r['result']for r in json.loads((ROOT/'daemon_arena_list_symbolic.json').read_text())['cases']};p2={r['label']:r['result']for r in json.loads((ROOT/'daemon_arena_consumer_symbolic.json').read_text())['cases']}
    for case,row in zip(source['cases'],stored['cases'],strict=True):
        assert case['label']==row['label']and case['context']==row['result']['context'];r=row['result'];a=p1[case['parent_case']];b=p2[case['parent_case']];audits.append(audit(case,row,initial[0 if case['parent_case']=='initial_arena0'else 1]));combined={**r,'context':a['context'],'steps':a['steps']+b['steps']+r['steps'],'effects':a['effects']+b['effects']+r['effects'],'edges':a['edges']+b['edges']+r['edges']};variables={v['variable']:z3.BitVec(v['variable'],8)for v in r['unknown_bytes']};variables['lifetime_runtime_flag32']=z3.BitVec('lifetime_runtime_flag32',32);cache={}
        def parse_effect(e):
            k=(e['expression'],e['size_bytes'])
            if k not in cache:cache[k]=parse_value(e['expression'],8*e['size_bytes'],variables)
            return cache[k]
        parsed=[parse_effect(e)for e in combined['effects']];choices=[(0,0),(2,0)]if case['context']['path_class']=='zero'else[(3,1),(6,0xffffffff)]
        for material,flag_value in choices:
            label,values=materializations(104)[material];w=replay(combined,label,values,parsed,case['context'],flag_value);w['case']=case['label'];w['flag_value']=hex(flag_value);witnesses.append(w);total.update(w['counts']);print(case['label'],label,hex(flag_value),w['counts'],flush=True)
        out.update(lifetime_source_steps=len(r['steps']),lifetime_effects=len(r['effects']),lifetime_PAC_edges=len(r['edges']),universal_class_resolution_checks=len(r['resolution_certificates']))
    raw=json.loads((ROOT/'daemon_arena_lifetime_ida.json').read_text());matches=[]
    for capture_ida in raw['captures']:
        body=capture_ida['content'][0]['text'].split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip()
        for item in json.loads(body)['results']:
            a=int(item['address'],16);data=bytes.fromhex(item['bytes']);assert IMAGE.read(a,len(data))==data;matches.append({'address':hex(a),'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    assert len(matches)==15 and sum(r['size_bytes']for r in matches)==2304;out.update(IDB_ranges=15,IDB_bytes=2304,source_lift_visits=sum(counts.values()),cases=4,original_unconstrained_frame_bytes_per_case=104,symbolic_runtime_flag_bits=32,static_SP_load_candidates=sum(len(g['LDR64_candidates'])for g in refs['groups']),static_direct_store_candidates=sum(len(g['direct_store_candidates'])for g in refs['groups']))
    result={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_lifetime_source.json','daemon_arena_lifetime_symbolic.json','daemon_arena_lifetime_proofs.json','daemon_arena_lifetime_refs.json','daemon_arena_lifetime_ida.json','daemon_arena_lifetime_symbolic.py','prove_daemon_arena_lifetime.py','daemon_arena_consumer_symbolic.json','daemon_arena_list_symbolic.json']},'verified_counts':dict(out),'independent_A64_totals':dict(total),'audits':audits,'live_IDB_matches':matches,'witnesses':witnesses,'all_checks_pass':True,'native_target_executed':False,'runtime_flag_concretized_in_source':False,'host_free_executed':False,'new_port_emission_established':False,'full_goal_complete':False};(ROOT/'daemon_arena_lifetime_checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'verified_counts':dict(out),'A64_totals':dict(total)}),flush=True)
if __name__=='__main__':main()
