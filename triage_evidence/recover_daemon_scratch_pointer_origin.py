#!/usr/bin/env python3
"""Source-local scratch reservation, conditional admission and cursor restoration.

The component is separate from the retained IOKit caller. Explicit phase,
status and frame fixtures do not prove native admission or a lifetime join.
O(text words+cases*(instructions+effects)+queries) time and space;
30 s/query. No native API/IPC, allocation, free or PAC executes.
"""
import itertools,json,struct
from collections import Counter
from hashlib import sha256
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,qword,verify_original_fixups,selected
from recover_daemon_iokit_census import text_section
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha

P='daemon_scratch_pointer_origin';MASK=(1<<64)-1;PHASE_MASK=0x6f95d3ef
ENTRY=0x10066f180;WRITER=0x10070e738;SPECIAL=0x1007b2fdc;RETURN=0x1007920a8
SPECS=[('admission',ENTRY,0x10066f1d4),('reservation',WRITER,0x10070e808),
       ('signed_status_split',0x10083039c,0x1008303ec),('lower_status',0x1007505ac,0x1007505f8),
       ('upper_status',0x100827e5c,0x100827e98),('restore_cursor',0x10095f530,0x10095f548),
       ('special_helper_prefix',SPECIAL,0x1007b305c),('helper_return_selector',0x1007b305c,0x1007b3090),
       ('consumer_register_copy',0x1007fb820,0x1007fb85c),
       ('consumer_error_copy',0x10085ead4,0x10085eae4),('consumer_record_copy',0x1009acd80,0x1009acd94)]
INDICES=[0x1d4b,0x1366,0x6298,0x7712,0x770f,0x1f74,0x1f87,0x3c16,0xebf]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py',
      'recover_daemon_return_bank_origins.py','recover_daemon_return_cache_codec.py',
      'daemon_return_cache_codec_checks.json','daemon_return_cache_codec_audit.json',
      'daemon_return_bank_origins_checks.json','daemon_return_bank_origins_audit.json']

def source():
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
                             for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in SPECS]

def slots():
    return [{'index':hex(j),'slot':hex(TABLE+8*j),'bytes_hex':IMAGE.read(TABLE+8*j,8).hex(),
             'target':hex(qword(TABLE+8*j)),'original_fixup':FIXUPS[TABLE+8*j]} for j in INDICES]

def census():
    a,n=text_section();raw=IMAGE.read(a,n);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    examined=0;hits=[];unsupported=[]
    widths={'b':1,'h':2,'s':4,'w':4,'d':8,'x':8,'q':16}
    for j,(word,) in enumerate(struct.iter_unpack('<I',raw)):
        if (word>>5)&31!=31:continue
        examined+=1
        for i in cs.disasm(raw[4*j:4*j+4],a+4*j):
            for op in i.operands:
                if op.type!=ARM64_OP_MEM or i.reg_name(op.mem.base)!='sp':continue
                # Register-indexed SP accesses require runtime information.
                if op.mem.index:continue
                names=[i.reg_name(o.reg) for o in i.operands if o.type==ARM64_OP_REG]
                if not names:continue
                width=8 if names[0] in ['fp','lr'] else widths.get(names[0][0]);m=i.mnemonic
                if m.endswith('b'):width=1
                elif m.endswith('h'):width=2
                elif m.endswith('sw'):width=4
                if m in ['stp','ldp','stnp','ldnp']:width=2*width if width else None
                if width is None:
                    if 0x49e0<=op.mem.disp<=0x4a28:unsupported.append({'pc':hex(i.address),'instruction':m+' '+i.op_str})
                    continue
                if op.mem.disp<0x4a28 and 0x4a20<op.mem.disp+width:
                    hits.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':m,'operands':i.op_str,
                                 'offset_bytes':op.mem.disp,'access_bytes':width,'writes':m.startswith('st')})
    assert not unsupported,unsupported
    mods=[]
    for mod in [0x4768,0xd08c]:
        pattern=struct.pack('<I',0xd2800000|(mod<<5)|17)
        sites=[hex(a+j) for j in range(0,n,4) if raw[j:j+4]==pattern]
        candidates=[{'slot':hex(at),'index_from_base':hex((at-TABLE)//8),'target':hex(f['target'])}
                    for at,f in sorted(FIXUPS.items()) if at>=TABLE and (at-TABLE)%8==0
                    and f['kind']=='auth-rebase' and f'div=0x{mod:04X} ' in f['annotation']]
        mods.append({'modifier16':hex(mod),'MOVZ_X17_sites':sites,'authenticated_rebase_candidates':candidates})
    assert [h['pc'] for h in hits if h['writes']]==['0x10070e780']
    return {'text_start':hex(a),'text_bytes':n,'text_sha256':sha256(raw).hexdigest(),'aligned_words_checked':n//4,
            'base_field31_words_decoded':examined,'overlapping_literal_SP_accesses':hits,'unclassified_nearby_widths':unsupported,
            'modifier_census':mods,'W32_unsigned_immediate_max_offset_bytes':4095*4,
            'W32_unsigned_immediate_encoding_at_4a20_possible':False,
            'scope':'Fixed-immediate decoded SP operands in original aligned text; conventional scalar/vector and pair widths. Register-indexed/computed aliases, different SP epochs and other sections excluded. Modifier matches alone do not establish edges.'}

def obligations():
    S,U,Q,V=z3.BitVecs('spo_SP64 spo_cursor64 spo_saved26_64 spo_pointer64',64)
    phase,status=z3.BitVecs('spo_phase32 spo_status32',32);qs=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        solver=z3.Solver();solver.set(timeout=30000);solver.add(premise);assert solver.check()==z3.sat
        solver.add(z3.simplify(bad));assert solver.check()==z3.unsat,label
        qs.append({'label':label,'query':solver.to_smt2(),'result':'unsat','premise_query':premise.sexpr(),'premises_nonvacuous':True})
    v=Algebra();v.seed('w8',phase);v.run_block(ENTRY,0x10066f19c)
    masked=phase&PHASE_MASK;index=(v.read('w11')-0x546b)^v.read('w12')
    prove('exact_all_phase_admission_class',(index==0x1d4b)!=(masked==0x1366))
    prove('admitted_phase_saved_continuation_and_outgoing_index',z3.Or(v.read('w12')!=0x1366,v.read('w11')!=0x6298),masked==0x1366)
    # Use the established admission contract for the complete writer body.
    v=Algebra();v.seed('sp',S)
    for j in range(31):v.seed('x'+str(j),z3.BitVec('spo_incoming_'+str(j),64))
    for r,x in [('w8',status),('w11',0x6298),('w12',0x1366),('x1',S+0x6000),('x13',S+0x4684),('x14',S+0x2520),('x26',Q)]:v.seed(r,x)
    mem(v,S+0x9d8,8,TABLE);mem(v,S+0x16d0,8,U)
    for j in [0x1366,0x6298]:mem(v,TABLE+8*j,8,qword(TABLE+8*j))
    v.run_block(WRITER,0x10070e804);R=S+0xc070+U
    checks=[cell(v,S+off,n)!=want for off,n,want in [(0x7dc8,8,R),(0x2c58,8,R+0x30),(0x4a20,8,R+0x40),
            (0x7928,8,R+0x5f),(0x16d0,8,U+0x80),(0x5f40,8,RETURN),(0x5288,8,Q),
            (0x7a8c,4,status),(0x78b8,4,0),(0x211f,1,z3.If(status==0x8b3dc650,z3.BitVecVal(1,8),z3.BitVecVal(0,8))),
            (0x5c48,8,0xe87f552eb3388cb6),(0xf0c,4,0x8b3dc651),(0x20bc,4,0x8b3dc651),
            (0x7820,8,0),(0x12a0,8,0),(0x8950,8,0),(0x73c0,8,0),(0x630c,4,0),(0x2154,4,0)]]
    prove('complete_reservation_views_status_and_continuation',z3.Or(*checks,v.read('w10')!=0x770f,v.read('x9')!=0x10083039c,v.read('x17')!=0xbbef))
    split=Algebra();split.seed('w10',0x770f);split.seed('w8',status);split.run_block(0x10083039c,0x1008303dc)
    low=status<z3.BitVecVal(0x8b3dc653,32)
    prove('signed_status_split_and_common_index',z3.Or(split.read('w21')!=0x1f74,split.read('w9')!=0x1f74,
          split.read('w10')!=z3.If(low,z3.BitVecVal(0x7712,32),z3.BitVecVal(0x770f,32))))
    lowv=Algebra();lowv.seed('w9',0x1f74);lowv.seed('w8',status);lowv.run_block(0x1007505ac,0x1007505e4)
    highv=Algebra();highv.seed('w21',0x1f74);highv.seed('w8',status);highv.run_block(0x100827e5c,0x100827e88)
    selected=z3.If(low,lowv.read('w8'),highv.read('w8'))
    special=z3.Or(status==0x8b3dc650,status==0x8b3dc653)
    prove('all_statuses_select_two_exact_special_values',selected!=z3.If(special,z3.BitVecVal(0x1f87,32),z3.BitVecVal(0x1f74,32)))
    v=Algebra();v.seed('sp',S);mem(v,S+0x16d0,8,U+0x80);mem(v,S+0x5f40,8,RETURN)
    v.run_block(0x10095f530,0x10095f544)
    prove('modular_reservation_restoration_and_saved_return',z3.Or(cell(v,S+0x16d0,8)!=U,v.read('x8')!=RETURN,v.read('x17')!=0xd08c))
    v=Algebra();v.seed('sp',S);mem(v,S+0x4a20,8,V);v.run_block(0x10085ead8,0x10085eae4)
    w=Algebra();w.seed('sp',S);mem(w,S+0x4a20,8,V);w.run_block(0x1009acd88,0x1009acd94)
    prove('two_complete_pointer_copy_slices',z3.Or(cell(v,S+0x8ad0,8)!=V,cell(w,S+0xa990,8)!=V))
    A,B,L,H,P0,P1=z3.BitVecs('spo_clock_A64 spo_clock_B64 spo_bankL64 spo_bankH64 spo_clock_cell0 spo_clock_cell1',64)
    C0,C1=z3.BitVecs('spo_controller0_32 spo_controller1_32',32);b0,b1=z3.BitVecs('spo_bank_byte0 spo_bank_byte1',8)
    class Clock(Algebra):
        def __init__(self):super().__init__();self.bank_reads=[]
        def load(self,at,n):
            if self.pc in [0x1007b301c,0x1007b3030]:
                assert n==1;self.bank_reads.append(at);return b0 if self.pc==0x1007b301c else b1
            return super().load(at,n)
    v=Clock();v.seed('sp',S);v.seed('w21',0x1f74);v.seed('x0',A)
    for off,n,x in [(0x9c8,8,P0),(0x9c0,8,P1),(0x870,8,L),(0x868,8,H),(0x9d8,8,TABLE)]:mem(v,S+off,n,x)
    mem(v,P0,4,C0);mem(v,P1,4,C1);v.run_block(SPECIAL,0x1007b304c)
    v.run_block(0x1007b3050,0x1007b3058);mix=((C0+C1)^0xa6)*0xa5cd4cf
    ix=0xcbf2+z3.ZeroExt(24,z3.Extract(7,0,mix)^b1)
    prove('complete_clock_helper_bank_addresses_and_call_ABI',z3.Or(v.bank_reads[0]!=L+z3.ZeroExt(56,z3.Extract(7,0,mix)),
          v.bank_reads[1]!=H+z3.ZeroExt(56,b0^0x56),v.read('w8')!=ix,v.read('x0')!=A,v.read('x1')!=0,
          v.read('x17')!=0x9298,v.read('w19')!=0x79ea,v.read('w24')!=2,v.read('w25')!=0x367a,
          z3.ULT(ix,0xcbf2),z3.UGT(ix,0xccf1)))
    ret=z3.BitVec('spo_clock_return32',32);v=Algebra()
    for r,x in [('w0',ret),('w19',0x79ea),('w24',2),('w25',0x367a),('w21',0x1f74)]:v.seed(r,x)
    v.run_block(0x1007b305c,0x1007b307c)
    prove('clock_return_zero_selects_success_path',v.read('w8')!=z3.If(ret==0,z3.BitVecVal(0x3c16,32),z3.BitVecVal(0x1f74,32)))
    return qs

def clock_bank():
    row=selected(0x100e99700,0x100f4e190,0x56,0xcbf2)
    left=IMAGE.read(0x100e99700,256);right=IMAGE.read(0x100f4e190,256)
    row.update(left256_hex=left.hex(),right256_hex=right.hex(),XOR_outputs_256=[j^right[left[j]^0x56] for j in range(256)])
    assert row['XOR_outputs_256']==[0x14]*256 and row['target']=='libSystem/_gettimeofday'
    upstream=[]
    for c in json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases']:
        f=int(c['frame_base'],16);fields=[]
        for off,value in [(0x870,0x100e99700),(0x868,0x100f4e190)]:
            writes=[w for w in c['source_writes'] if int(w['address'],16)<f+off+8 and f+off<int(w['address'],16)+w['size_bytes']]
            assert len(writes)==1 and writes[0]['size_bytes']==8 and int.from_bytes(bytes.fromhex(writes[0]['after_hex']),'little')==value
            fields.append({'offset_bytes':off,'pointer':hex(value),'writer':writes[0]})
        upstream.append({'configuration':c['configuration'],'variant':c['variant'],'fields':fields,'boundary':c['boundary']['pc']})
    return {'bank':row,'initializer_fields':upstream,'source_fixup':verify_original_fixups({TABLE+8*0xcc06}),
            'initializer_to_component_join_established':False,'native_clock_API_executed':False}

class Trace(Algebra):
    def __init__(self):super().__init__();self.events=[]
    def load(self,a,n):
        key=(z3.simplify(a).sexpr(),n)
        if key in self.memory:x=super().load(a,n)
        else:
            at=z3.simplify(a).as_long();assert n==8 and at in FIXUPS and isinstance(qword(at),int)
            x=z3.BitVecVal(qword(at),64)
        self.events.append({'kind':'read','address':hex(z3.simplify(a).as_long()),'size_bytes':n,'value':hex(z3.simplify(x).as_long())});return x
    def store(self,a,n,x,pc):
        super().store(a,n,x,pc)
        self.events.append({'kind':'write','address':hex(z3.simplify(a).as_long()),'size_bytes':n,'value':hex(z3.simplify(resize(x,n*8)).as_long())})

def configurations():
    for placement,phase,status,cursor in itertools.product([0,0x100],[0x1366,0x1366|(~PHASE_MASK&0xffffffff)],
             [0,1,0x7fffffff,0x80000000,0x8b3dc64f,0x8b3dc650,0x8b3dc651,0x8b3dc652,0x8b3dc653,0x8b3dc654,0xffffffff],
             [0,0x80,MASK-0x7f]):
        yield {'SP':hex(0x6e00020000+placement),'phase32':hex(phase),'status32':hex(status),'cursor64':hex(cursor)}

def flags(v):
    return sum(int(z3.is_true(z3.simplify(getattr(v,n))))<<bit for n,bit in [('n',31),('z',30),('carry',29),('overflow',28)])

def retained_context():
    banks=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))
    cache=json.loads(read(ROOT/'daemon_return_cache_codec_checks.json'));upstream=[];caller=[]
    for c in banks['upstream_cases']:
        f=int(c['frame_base'],16)
        overlap=[w for w in c['source_writes'] if int(w['address'],16)<f+0x4a28 and f+0x4a20<int(w['address'],16)+w['size_bytes']]
        assert not overlap
        upstream.append({'configuration':c['configuration'],'variant':c['variant'],'frame_base':c['frame_base'],
                         'boundary':c['boundary']['pc'],'writes_overlapping_pointer_cell':0})
    for c in cache['cases']:
        s=int(c['configuration']['caller_SP'],16);value=c['trace']['boundary']['registers31'][27]
        expected={'terms':[{'origin':s+0x4a20+j-0x640000b520} for j in range(8)]};assert value==expected
        caller.append({'parent_case_index':c['parent_case_index'],'variant':c['variant'],'caller_SP':hex(s),
                       'boundary':c['trace']['boundary']['pc'],'pointer_value':value})
    assert len(upstream)==12 and len(caller)==8
    return {'prior_initializer_paths':upstream,'prior_caller_unknown_pointer_boundaries':caller,
            'direct_saved_return_is_retained_IOKit_entry':False,'saved_return_diversity':'0xd08c',
            'retained_IOKit_entry':'0x10084c9b8','retained_IOKit_entry_diversity':'0xe8b8',
            'continuous_source_control_or_lifetime_join_proved':False}

def run_case(c):
    S=int(c['SP'],16);phase=int(c['phase32'],16);status=int(c['status32'],16);cursor=int(c['cursor64'],16)
    v=Trace();initial={'sp':S,**{'x'+str(j):((j+1)*0x0102030405060708)&MASK for j in range(31)}}
    initial['x8']=phase
    for n,x in initial.items():v.seed(n,x)
    for n in ['n','z','carry','overflow']:setattr(v,n,z3.BoolVal(False))
    fixtures=[(S+0x9d8,8,TABLE),(S+0x16d0,8,cursor),(S+0xda0,8,0x6e00001000),(S+0x70c4,4,status)]
    for a,n,x in fixtures:mem(v,a,n,x)
    steps=[];edges=[];pc=ENTRY;endpoints={a:b for _,a,b in SPECS[:6]}
    while pc not in [SPECIAL,RETURN]:
        end=endpoints[pc]
        for i in CS.disasm(IMAGE.read(pc,end-pc),pc):
            before={n:z3.simplify(v.read(n)).as_long() for n in initial};v.events=[];v.pc=i.address
            if i.mnemonic=='braa':
                dest,mod=[s.strip() for s in i.op_str.split(',')];target=z3.simplify(v.read(dest)).as_long();modifier=z3.simplify(v.read(mod)).as_long()
                assert target in [WRITER,0x10083039c,0x1007505ac,0x100827e5c,0x10095f530,SPECIAL,RETURN]
                edge={'pc':hex(i.address),'target':hex(target),'modifier':hex(modifier)};edges.append(edge);pc=target
            else:v.run_block(i.address,i.address+4)
            after={n:z3.simplify(v.read(n)).as_long() for n in initial}
            steps.append({'pc':hex(i.address),'registers_after':{n:hex(x) for n,x in after.items() if before[n]!=x},
                          'NZCV_after':hex(flags(v)),'events':list(v.events)})
    stores=[{'pc':r['pc'],**e} for r in steps for e in r['events'] if e['kind']=='write']
    assert pc==(SPECIAL if status in [0x8b3dc650,0x8b3dc653] else RETURN)
    return {'configuration':c,'initial_registers':{n:hex(x) for n,x in initial.items()},'initial_NZCV':'0x0',
            'initial_private_fixtures':[{'address':hex(a),'size_bytes':n,'value':hex(x)} for a,n,x in fixtures],
            'steps':steps,'logical_edges':edges,'writes':stores,'boundary':{'pc':hex(pc),'kind':'before_separate_helper' if pc==SPECIAL else 'before_saved_continuation'},
            'counts':{'source_visits':len(steps),'read_events':sum(e['kind']=='read' for r in steps for e in r['events']),
                      'write_events':len(stores),'logical_edges':len(edges)}}

def build():
    cases=[run_case(c) for c in configurations()];counts=Counter()
    for c in cases:counts.update(c['counts'])
    cc=census();assert len(cases)==132
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_regions':source(),'original_slots':slots(),'source_fixups':verify_original_fixups({TABLE+8*j for j in INDICES}),
            'bounded_census':cc,'source_proofs':obligations(),'retained_context':retained_context(),'clock_helper':clock_bank(),
            'cases':cases,'verified_counts':{'cases':len(cases),**counts},
            'retained_IOKit_caller_join_established':False,'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
