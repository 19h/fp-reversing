#!/usr/bin/env python3
"""Independent projected replay and masked-copy/descending-counter contracts.
O(parent bytes + text words + profile visits*fields + selected visits +
source DAG + finite controls) time;
O(receipts + source DAG) space, excluding solver search; 30 s/query.
No new target intervals, bank premises, native API, PAC or IPC execution.
"""
import json
from copy import deepcopy
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_append_fields import Trace,number
from audit_daemon_alternative_fill import Source
from lskd_values_symbolic import resize
import recover_daemon_record_banks as R

DEPS=['audit_daemon_append_fields.py','audit_daemon_alternative_fill.py',
      'audit_daemon_state_table_mixing.py','lskd_values_symbolic.py']
CODEC=0x8b3dc651
INDEX=0x313680c7
BIAS={0x390:0xffffffff8e3944f6,0x398:0xfffffffffbe3654e,0x3a0:0xffffffffb2d27371}
SELECTED={0x390:[0x1004c3344,0x1004c3348,0x1004c3350,0x1004c3354,0x1004c3358,0x1004c335c],
          0x398:list(range(0x1004c2ae8,0x1004c2b00,4)),
          0x3a0:[0x1004c28c4,0x1004c28c8,0x1004c28dc,0x1004c28e0,0x1004c28e4,0x1004c28e8]}


def obligations(e):
    proofs=[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises)
        assert s.check()==z3.sat,label
        s.add(z3.simplify(bad));result=s.check()
        assert result==z3.unsat,(label,str(result),s.reason_unknown())
        proofs.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    c=z3.BitVec('bank_count32',32)
    v=Source();v.seed('w11',c^CODEC);v.seed('w13',0x6613)
    v.run_block(0x10084fcc4,0x10084fdb8)
    prove('all_u32_prefix_decrements_encoded_count_and_forms_index',z3.Or(
        v.read('w11')!=((c-1)^CODEC),v.read('w14')!=((c-1)^INDEX),v.read('w15')!=INDEX))
    frame,src,dst,a,b,d=z3.BitVecs('bank_frame64 bank_src64 bank_dst64 bank_A64 bank_B64 bank_C64',64)
    offset,t,phase=z3.BitVecs('bank_offset32 bank_index_word32 bank_phase32',32)
    x,ba,bb,bc=z3.BitVecs('bank_input8 bank_A8 bank_B8 bank_C8',8)
    i=t^INDEX;o=i+offset;n=o&15
    values={0x10084fdbc:(1,x),0x10084fdcc:(8,a),0x10084fdd4:(1,ba),
            0x10084fdd8:(8,b),0x10084fde0:(1,bb),0x10084fde4:(8,d),0x10084fdec:(1,bc)}
    v=Source(values)
    for reg,value in {'sp':frame,'w14':t,'w8':offset,'w13':phase,'x9':src,'x10':dst}.items():v.seed(reg,value)
    v.run_block(0x10084fdb0,0x10084fe24)
    addresses={0x10084fdbc:src+z3.ZeroExt(32,i),0x10084fdcc:frame+0x390,
        0x10084fdd4:a+z3.ZeroExt(32,n),0x10084fdd8:frame+0x3a0,
        0x10084fde0:b+z3.ZeroExt(32,n),0x10084fde4:frame+0x398,
        0x10084fdec:d+z3.ZeroExt(32,n)+3}
    assert len(v.loads)==7 and len(v.stores)==1
    prove('all_u32_consumer_addresses_and_four_bit_bounds',z3.Or(
        *[addr!=addresses[pc] for pc,addr,size in v.loads],z3.UGT(n,15),
        v.stores[0]['address']!=dst+z3.ZeroExt(32,o)))
    byte=x^ba^bb^bc^z3.Extract(7,0,n|(n<<5))^0x23
    prove('all_u8_source_byte_store_equation',z3.Or(v.stores[0]['size_bytes']!=1,v.stores[0]['value']!=byte))
    prove('source_tail_selects_exit_exactly_at_decoded_zero',v.read('w14')!=(phase^z3.If(i==0,
        z3.BitVecVal(0x45,32),z3.BitVecVal(0,32))))
    mask=bytes.fromhex(e['mask16_hex']);aa,bbank,cc=[bytes.fromhex(e['banks'][hex(k)]['bytes_hex']) for k in [0x390,0x3a0,0x398]]
    nib=z3.BitVec('bank_nibble4',4);xn=z3.BitVec('bank_arbitrary_byte8',8)
    def table(raw,start=0):
        out=z3.BitVecVal(raw[start+15],8)
        for j in reversed(range(15)):out=z3.If(nib==j,z3.BitVecVal(raw[start+j],8),out)
        return out
    nn=z3.ZeroExt(4,nib)
    prove('sixteen_immutable_bank_rows_collapse_to_position_mask',
        (xn^table(aa)^table(bbank)^table(cc,3)^(nn|(nn<<5))^0x23)!=(xn^table(mask)))
    for off,(start,end,inputreg,resultreg,addend) in R.SUFFIXES.items():
        word=z3.BitVec('bank_pool_word_'+hex(off)[2:]+'_64',64)
        sel=z3.BitVec('bank_selector_'+hex(off)[2:]+'_8',8)
        load=next(pc for pc in SELECTED[off] if R.instruction(pc).mnemonic=='ldr')
        v=Source({load:(8,word)});v.seed('sp',frame);v.seed('x25',POOL);v.seed(inputreg,z3.ZeroExt(24,sel))
        for pc in SELECTED[off]:v.run_block(pc,pc+4)
        assert len(v.stores)==len(v.loads)==1
        prove('bank_'+hex(off)[2:]+'_all_u64_loaded_word_affine_decoder',z3.Or(
            v.loads[0][1]!=POOL+8*(z3.ZeroExt(56,sel)+addend),
            v.stores[0]['address']!=frame+off,v.stores[0]['value']!=word+BIAS[off],
            v.stores[0]['size_bytes']!=8))
    widened=z3.ZeroExt(1,c);next_c=c-1
    prove('positive_u32_descending_rank_and_no_underflow',z3.Or(
        z3.UGE(z3.ZeroExt(1,next_c),widened),z3.ZeroExt(1,next_c)!=widened-1),[c!=0])
    base=z3.BitVec('bank_destination_offset32',32);idx=z3.BitVec('bank_iteration_index32',32)
    total=z3.ZeroExt(1,base)+z3.ZeroExt(1,c)
    prove('nonwrapping_destination_interval_for_admitted_positive_count',z3.Or(
        z3.ULT(base+idx,base),z3.UGE(z3.ZeroExt(1,base+idx),total)),
        [c!=0,z3.ULT(idx,c),z3.ULE(total,z3.BitVecVal(1<<32,33))])
    return proofs


class MemoryTrace(Trace):
    def __init__(self,reads,writes,frame):
        super().__init__(reads,writes);self.memory={};self.frame_base=frame;self.private_bytes_checked=0;self.internal_bytes_checked=0;self.controller_bytes_checked=0

    def load(self,address,n):
        value=super().load(address,n);a=number(address)
        if self.frame_base<=a<a+n<=self.frame_base+0x10d50:
            expected=number(value).to_bytes(n,'little')
            assert all(a+k in self.memory for k in range(n)),('missing projected private writer',hex(self.pc),hex(a))
            assert bytes(self.memory[a+k] for k in range(n))==expected
            self.private_bytes_checked+=n
        expected=number(value).to_bytes(n,'little')
        for k,b in enumerate(expected):
            if a+k in self.memory:
                assert self.memory[a+k]==b
                self.internal_bytes_checked+=1
                if a in [0x1010b8dc8,0x1010c4670]:self.controller_bytes_checked+=1
        return value

    def store(self,address,n,value,pc):
        super().store(address,n,value,pc);a=number(address)
        self.memory.update({a+k:b for k,b in enumerate(number(resize(value,n*8)).to_bytes(n,'little'))})


def replay(e):
    out=[];counts=Counter()
    for qi,q in enumerate(e['profiles']):
        for p in q['projections']:
            rr=[r for row in p['instructions'] for r in row['reads']]
            ww=[w for row in p['instructions'] for w in row['writes']]
            v=MemoryTrace(rr,ww,int(p['frame_base'],16))
            for j in range(31):v.seed('x'+str(j),0)
            v.seed('sp',int(p['frame_base'],16))
            for row in p['instructions']:
                pc=int(row['pc'],16);assert row['bytes_hex']==IMAGE.read(pc,4).hex()
                i=R.instruction(pc);assert (row['mnemonic'],row['operands'])==(i.mnemonic,i.op_str)
                v.events=[];v.one(i);counts['source_projection_instruction_visits']+=1
            assert v.ri==len(rr) and v.wi==len(ww)
            for r in p['external_read_bytes']:
                readrow=r['reader'];a=int(readrow['address'],16);n=readrow['size_bytes'];k=r['byte_index']
                if a in R.FIXUPS:
                    value=R.FIXUPS[a]['target'];assert isinstance(value,int) and n==8
                    expected=value.to_bytes(8,'little')
                elif a<0x6000000000 and a not in [0x1010b8dc8,0x1010c4670]:expected=IMAGE.read(a,n)
                else:continue
                assert bytes.fromhex(readrow['bytes_hex'])[k]==expected[k]
                counts['original_external_bytes_checked']+=1
            counts['store_read_bytes_checked']+=v.internal_bytes_checked
            counts['controller_read_bytes_checked']+=v.controller_bytes_checked
            counts['private_read_bytes_checked']+=v.private_bytes_checked
            counts['projected_reads_checked']+=len(rr);counts['projected_writes_checked']+=len(ww)
            out.append({'profile_index':qi,'field_offset':p['field_offset'],'instructions':len(p['instructions']),
                        'reads':len(rr),'writes':len(ww),'all_checks_pass':True})
    return out,dict(counts)


def controls(e):
    mask=bytes.fromhex(e['mask16_hex']);controls=[]
    for n in range(16):
        for x in range(256):assert (x^mask[n])^mask[n]==x
    for c in [0,1,2,20,0xffffffff]:
        v=Source();v.seed('w11',c^CODEC);v.seed('w13',0x6613)
        v.run_block(0x10084fcc4,0x10084fdb8)
        actual=number(v.read('w11'))^CODEC
        assert actual==(c-1)&0xffffffff
        controls.append({'incoming_count32':c,'postdecrement32':actual,'positive_count_domain':c!=0})
    for f in e['frontiers']:
        raw=bytes.fromhex(f['input20_hex'])
        expected=bytes(raw[j]^mask[(165+j)&15] for j in range(20))
        assert expected.hex()==f['conditional_prediction20_hex'] and expected[19]==0xeb
    # Independent source evaluation rejects a one-bit corruption of M[0].
    aa,bb,cc=[bytes.fromhex(e['banks'][hex(k)]['bytes_hex']) for k in [0x390,0x3a0,0x398]]
    vals={0x10084fdbc:(1,0),0x10084fdcc:(8,R.FIELDS[0x390]),0x10084fdd4:(1,aa[0]),
          0x10084fdd8:(8,R.FIELDS[0x3a0]),0x10084fde0:(1,bb[0]),
          0x10084fde4:(8,R.FIELDS[0x398]),0x10084fdec:(1,cc[3])}
    v=Source(vals)
    for name,value in {'sp':0x6800000000,'w14':INDEX,'w8':0,'w13':0x6613,'x9':0x6900000000,'x10':0x6a00000000}.items():v.seed(name,value)
    v.run_block(0x10084fdb0,0x10084fe24)
    assert number(v.stores[0]['value'])==mask[0] and number(v.stores[0]['value'])!=(mask[0]^1)
    bad=deepcopy(e);p=bad['profiles'][0]['projections'][0]
    missing=p['internal_read_byte_links'][0]['origins'][0]['writer']['source_visit_index']
    p['instructions']=[x for x in p['instructions'] if x['source_visit_index']!=missing]
    try:replay(bad)
    except AssertionError as error:
        assert 'missing projected private writer' in str(error)
    else:raise AssertionError('missing private writer admitted')
    return {'altered_mask_source_control_rejected':1,'missing_private_writer_rejected':1,
            'all_byte_nibble_involution_cases':4096,'counter_boundaries':controls,
            'conditional_frontier_predictions':len(e['frontiers']),'new_bank_premise_bytes':0}


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build()
    projected,counts=replay(e);proofs=obligations(e);finite=controls(e)
    assert counts['store_read_bytes_checked']==e['verified_counts']['store_read_byte_links']==704
    assert counts['private_read_bytes_checked']==512 and counts['controller_read_bytes_checked']==192
    protected={'sp','x8','x9','x10','x13'};visited=0
    for pc in range(*R.SPANS['loop'],4):
        ins=R.instruction(pc);writes={R.norm(ins.reg_name(k)) for k in ins.regs_access()[1]}
        assert not protected&writes;visited+=1
    preserved={'source_instructions_checked':visited,'unchanged_registers':sorted(protected)}
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'generator_sha256':sha(R.__file__),
            'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'verified_counts':e['verified_counts'],
            'independent_totals':counts,'loop_register_preservation':preserved,'projected_replay':projected,'source_proofs':proofs,
            'source_queries_unsat':len(proofs),'finite_controls':finite,
            'original_fixups':verify_original_fixups([int(r['slot'],16) for r in e['routes']+e['pool_fixups']]),
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,
            'initializer_to_current_caller_join_established':False,'full_goal_complete':False,'all_checks_pass':True}


if __name__=='__main__':
    a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({'independent_totals':a['independent_totals'],'source_queries_unsat':a['source_queries_unsat'],
                      'finite_controls':a['finite_controls']}),flush=True)
