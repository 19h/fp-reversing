#!/usr/bin/env python3
"""Strict initializer bank lifetime and conditional post-error counter consumer.

Source initializer execution and later caller execution are distinct paths.
Two source-compatible bank-cell effects are additional caller premises; no
continuous initializer-to-caller path or native delivery is inferred.
O(receipts+text words+C*(state bytes+visits+effects)+queries) time/space,
30 s/query. No native API, IPC, free or pointer authentication executes.
"""
import json,struct
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS,POOL,qword,bank
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_seed_material_symbolic import apply_journal
from recover_daemon_iokit_census import text_section
from lskd_values_symbolic import mem,cell
import recover_daemon_iokit_error_return as Parent
import probe_daemon_shared_roots as Shared
import probe_daemon_descriptor_producers as Base

P='daemon_return_bank_origins'; ENTRY=0x1004f6508; STOP=0x100792b28
PIN='191d641b67e9200cb7f906a0b96f3c89715cfeb1936a910cb4febdbfa9b6cc83'
ROOTS={0x600:0x100e99a00,0x5f8:0x100f4e390}; COUNTER=0x1010c8258

class Run(Parent.Run):
    def one(self,i):
        if i.mnemonic=='clz':
            self.pc=i.address; name=i.reg_name(i.operands[0].reg); n=self.width(name)
            x=self.operand(i,i.operands[1],n); count=z3.BitVecVal(n,n)
            for j in range(n): count=z3.If(z3.Extract(j,j,x)==1,z3.BitVecVal(n-1-j,n),count)
            self.write(name,count); return
        return super().one(i)

class Algebra(Run,Parent.Ingress.Algebra):
    def __init__(self): Parent.Ingress.Algebra.__init__(self)
    def load(self,a,n): return Parent.Ingress.Algebra.load(self,a,n)
    def store(self,a,n,v,pc): return Parent.Ingress.Algebra.store(self,a,n,v,pc)
    def write(self,n,v): return Parent.Ingress.Algebra.write(self,n,v)

class Upstream(Shared.Run):
    def code(self,u,a,n,d):
        if a==0x100528e20:
            self.flush(); return self.stop('before_original_outer_RETAB')
        return Base.Run.code(self,u,a,n,d)

def upstream():
    Base.SOURCE_CAPTURE=json.loads(read(ROOT/'daemon_descriptor_producers_source.json'))
    out=[]
    for c in list(Shared.cases())[::2]:
        for variant in ['opaque_RPC502','declared_RPC502','unsupported_operation']:
            cfg={**c,'operation32':0x80000000 if variant=='unsupported_operation' else 0xbc84919b}
            v=Upstream(cfg)
            if variant=='declared_RPC502':
                raw=bytearray(120)
                for off,val in {8:Base.P+0x3000,0x48:Base.P+0x3100,0x50:Base.P+0x3200}.items(): struct.pack_into('<Q',raw,off,val)
                v.fixture(Base.P+0x1000,bytes(raw)); v.fixture(Base.P+0x3000,b'\0')
            v.ensure(Shared.ENTRY); v.u.emu_start(Shared.ENTRY,0,count=20000); v.flush(); assert v.reason
            f=v.C-0x10dd0; fields=[]
            for off,expected in ROOTS.items():
                ww=[w for w in v.writes if int(w['address'],16)<f+off+8 and f+off<int(w['address'],16)+w['size_bytes']]
                assert len(ww)==1 and ww[0]['size_bytes']==8 and int.from_bytes(bytes.fromhex(ww[0]['after_hex']),'little')==expected
                assert int.from_bytes(v.u.mem_read(f+off,8),'little')==expected and all(v.known[f+off-Base.P:f+off-Base.P+8])
                fields.append({'offset_bytes':off,'value':hex(expected),'writer':ww[0],'later_overwrites':0})
            result={'configuration':cfg,'variant':variant,'entry_PC':hex(Shared.ENTRY),'entry_SP':hex(v.C),
                    'entry_FP':hex(v.FP),'record_address':hex(v.R),'entry_registers31':v.entry_regs,
                    'entry_Q_registers32':v.entry_Q,'entry_NZCV':v.entry_NZCV,'entry_TPIDRRO_EL0':hex(Base.TLS),
                    'initial_private_fixtures':v.initial,'initial_image_fixtures':v.image_fixtures,
                    'source_visits':v.visits,'source_reads':v.reads,'source_writes':v.writes,
                    'logical_edges':v.edges,'source_calls':v.calls,'boundary':v.boundary,
                    'frame_base':hex(f),'bank_fields':fields,'fixture_PC_transitions':0}
            if variant=='opaque_RPC502':
                assert v.boundary['pc']=='0x1007fc58c' and v.reason=='before_unknown_private_read'
            elif variant=='declared_RPC502':
                assert v.boundary['pc']=='0x1007fc754' and v.reason=='before_unmodeled_import_call'
                assert v.boundary['detail']['symbol']=='libbsm/_audit_token_to_au32'
            else:
                assert v.reason=='before_original_outer_RETAB' and v.boundary['SP']==hex(v.C)
                result['protected_result32']=hex(int.from_bytes(v.u.mem_read(v.R+0x18,4),'little'))
                assert result['protected_result32']=='0x74c29dee'
            out.append(result)
    return out

def decoder():
    left,right=ROOTS.values(); c=bank(left,right,0x78)
    v=Parent.Ingress.Algebra(); v.run_block(0x1004f6530,0x1004f6538); bias=v.read('x9').as_long()
    slot=POOL+8*(0xe07+c); word=qword(slot); pointer=(word+bias)&((1<<64)-1)
    assert c==0xa1 and pointer==COUNTER
    return {'left':hex(left),'right':hex(right),'left256_hex':IMAGE.read(left,256).hex(),'right256_hex':IMAGE.read(right,256).hex(),
            'key_u8':'0x78','XOR_outputs_256':[j^IMAGE.read(right+ (IMAGE.read(left+j,1)[0]^0x78),1)[0] for j in range(256)],
            'constant_u8':hex(c),'additive':'0xe07','index':hex(0xe07+c),'slot':hex(slot),
            'slot_bytes_hex':IMAGE.read(slot,8).hex(),'word_u64':hex(word),'bias_u64':hex(bias),'decoded_address':hex(pointer)}

def source():
    ranges=[('left_writer',0x1004c2820,0x1004c2840),('right_writer',0x1004c3428,0x1004c3440),
            ('conditional_counter_consumer',ENTRY,0x1004f6620),('outer_return',0x100528dd8,0x100528e24),
            ('CLZ_slice',0x1007d35f0,0x1007d3604),('counter_increment',0x1004dc32c,0x1004dc350),
            ('new_unknown_pointer',0x100792af8,0x100792b40),('less_than_leaf',0x100427514,0x1004275b4)]
    return [{'name':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),
             'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,z-a),a)]} for n,a,z in ranges]

def census():
    a,n=text_section(); raw=IMAGE.read(a,n); out=[]
    for off in ROOTS:
        for width,opcode in [(4,0xb90003e0),(8,0xf90003e0)]:
            pattern=opcode|((off//width)<<10)
            sites=[hex(a+4*j) for j,(word,) in enumerate(struct.iter_unpack('<I',raw)) if word&0xffffffe0==pattern]
            out.append({'SP_offset_bytes':off,'width_bytes':width,'sites':sites,'count':len(sites)})
    return {'text_start':hex(a),'text_bytes':n,'text_sha256':__import__('hashlib').sha256(raw).hexdigest(),
            'aligned_words_checked':n//4,'rows':out,'scope':'Exact unsigned-immediate STR Wn/Xn at the two literal SP offsets, including WZR/XZR. Pair, unscaled, vector, aliased/computed bases and SP epoch equivalence excluded.'}

def obligations():
    qs=[]; S,U,C=z3.BitVecs('rbo_SP64 rbo_unknown64 rbo_counter64',64)
    def prove(label,bad,partition_low_byte=False):
        partition=None
        if partition_low_byte:
            # The 256 low-byte partitions cover every U64; upper 56 bits stay
            # symbolic in each original-source obligation. Reduce concrete
            # ROM reads before SAT instead of asking array theory to rediscover
            # the exhaustive byte map under a timing-sensitive search.
            branches=[z3.simplify(z3.substitute(bad,(U,z3.Concat(z3.Extract(63,8,U),z3.BitVecVal(j,8))))) for j in range(256)]
            assert all(z3.is_false(b) for b in branches)
            bad=z3.Or(*branches)
            partition={'variable':'rbo_unknown64','low_bits':8,'values':list(range(256)),
                       'upper_bits_remain_symbolic':56,'source_bad_predicates_simplified_false':256}
        q=z3.Solver(); q.set(timeout=30000); assert q.check()==z3.sat; q.add(bad); assert q.check()==z3.unsat,label
        qs.append({'label':label,'query':q.to_smt2(),'result':'unsat','premises_nonvacuous':True,'exhaustive_partition':partition})
    v=Parent.Ingress.Algebra(); v.seed('sp',S); v.seed('x2',ROOTS[0x600]); v.run_block(0x1004c2838,0x1004c283c)
    prove('left_initializer_store',cell(v,S+0x600,8)!=ROOTS[0x600])
    v=Parent.Ingress.Algebra(); v.seed('sp',S); v.seed('x22',ROOTS[0x5f8]); v.run_block(0x1004c343c,0x1004c3440)
    prove('right_initializer_store',cell(v,S+0x5f8,8)!=ROOTS[0x5f8])
    class BankSlice(Parent.Ingress.Algebra):
        def __init__(self):
            super().__init__(); self.arrays={}; self.bounds=[]
            for pc,root in [(0x1004f6510,ROOTS[0x600]),(0x1004f651c,ROOTS[0x5f8])]:
                array=z3.K(z3.BitVecSort(64),z3.BitVecVal(0,8))
                for j,b in enumerate(IMAGE.read(root,256)): array=z3.Store(array,z3.BitVecVal(root+j,64),z3.BitVecVal(b,8))
                self.arrays[pc]=(root,array)
        def load(self,a,n):
            if self.pc in self.arrays:
                root,array=self.arrays[self.pc]; assert n==1
                self.bounds.append(z3.UGT(a-root,255)); return z3.Select(array,a)
            return super().load(a,n)
    v=BankSlice(); v.seed('sp',S); v.seed('w8',z3.Extract(31,0,U))
    for off,value in ROOTS.items(): mem(v,S+off,8,value)
    v.run_block(ENTRY,0x1004f6528)
    prove('original_bank_chain_all_u32_and_read_bounds',z3.Or(v.read('w8')!=0xa1,*v.bounds),partition_low_byte=True)
    v=Parent.Ingress.Algebra(); v.seed('x8',qword(POOL+0xea8*8)); v.run_block(0x1004f6530,0x1004f653c)
    prove('original_pool_bias_decodes_counter',v.read('x8')!=COUNTER)
    v=Parent.Ingress.Algebra(); v.seed('sp',S); v.seed('x8',COUNTER); v.run_block(0x1004f653c,0x1004f6540)
    prove('caller_counter_pointer_publication',cell(v,S+0x920,8)!=COUNTER)
    v=Parent.Ingress.Algebra(); v.seed('x8',COUNTER); mem(v,COUNTER,4,z3.Extract(31,0,C)); v.run_block(0x1004f6540,0x1004f6544)
    prove('caller_loads_counter_as_u32',v.read('x14')!=z3.ZeroExt(32,z3.Extract(31,0,C)))
    # This later local is source-defined in retained caller paths; it is not a new unknown frontier.
    v=Parent.Ingress.Algebra(); v.seed('w13',z3.Extract(31,0,U)); v.seed('w10',z3.Extract(31,0,C)); v.run_block(0x1004f6568,0x1004f656c)
    prove('later_local_low_word_dependency',v.read('w10')!=z3.Extract(31,0,U+C))
    v=Algebra(); x=z3.Extract(31,0,U); v.seed('w10',x); v.run_block(0x1007d35f8,0x1007d35fc); count=v.read('w10')
    prove('source_CLZ32_exact_leading_zero_contract',z3.Or(z3.UGT(count,32),(count==32)!=(x==0),
          z3.And(x!=0,z3.Or(z3.Extract(31,31,x<<count)!=1,z3.LShR(x,32-count)!=0))))
    r,a,b=z3.BitVecs('rbo_compare_record64 rbo_compare_A64 rbo_compare_B64',64)
    mode,mask,yes,no=z3.BitVecs('rbo_compare_mode32 rbo_compare_mask32 rbo_compare_true32 rbo_compare_false32',32)
    v=Parent.Ingress.Algebra(); v.seed('x0',r); v.run_block(0x100427514,0x100427560)
    k=v.read('x8'); low=z3.Extract(31,0,k)
    for off,n,x in [(0,8,a-k),(8,4,mode^low),(0x10,4,yes^low),(0x14,4,no-low),(0x18,8,b^k),(0x20,4,mask^low)]: mem(v,r+off,n,x)
    v.run_block(0x100427560,0x1004275b0)
    choose=z3.If(mode&1!=0,a<b,z3.ULT(a,b)); expected=mask^z3.If(choose,yes,no)
    assert len(v.stores)==1
    prove('complete_signed_unsigned_less_than_leaf',z3.Or(cell(v,r+12,4)!=expected,v.read('x0')!=r,
          v.stores[0]['address']!=r+12,v.stores[0]['size_bytes']!=4))
    return qs

def build(limit=None):
    assert sha(ROOT/'daemon_iokit_error_return_checks.json')==PIN
    e=json.loads(read(ROOT/'daemon_iokit_error_return_checks.json')); prior=json.loads(read(ROOT/'daemon_iokit_result_checks.json'))
    assert e['generator_sha256']==sha(Parent.__file__)
    pins,old,ingress,preparations,processing=Parent.Parent.Parent.inputs(); post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    cases=[]; counts=Counter(); used=set()
    for c in e['cases'][:limit]:
        cfg=c['configuration']; po=post['cases'][c['parent_case_index']]
        pc=next(x for x in prior['cases'] if x['parent_case_index']==c['parent_case_index'] and x['variant']==c['variant'])
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
        proc=next(x for x in processing['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
        v=Parent.restore(pins,old,original,prep,proc,po,pc); apply_journal(v,c['trace']); s=int(cfg['caller_SP'],16)
        models=[]
        for off,value in ROOTS.items():
            at=s+off
            before=v.shape(z3.Concat(*[v.bytes.get(at+j,z3.BitVec('unknown_'+hex(at+j),8)) for j in range(7,-1,-1)]),8)
            assert 'terms' in before
            Parent.Parent.Core.put(v,at,8,value)
            models.append({'address':hex(at),'size_bytes':8,'before':before,'bytes_hex':value.to_bytes(8,'little').hex(),
                           'provenance':'additional initializer-compatible bank-cell premise; control/epoch join unproved'})
        v.__class__=Run; Parent.Parent.reset(v); initial=Parent.Parent.shape_registers(v); b=v.run_revisit(ENTRY,limit=200000)
        assert b['kind']=='before_unresolved_source_effect' and b['pc']==hex(STOP) and not b.get('uncommitted_events') and not v.definitions,b
        trace={'start':hex(ENTRY),'initial_registers':initial,'steps':v.steps,'boundary':b,'source_pool':v.pool,
               'used_fixups':list(map(hex,sorted(v.fixups))),'logical_retired_spans':[{'start':hex(a),'end':hex(z)} for a,z in v.retired]}
        count={'source_visits':len(v.steps),'read_events':sum(e['kind']=='read' for st in v.steps for e in st['events']),
               'write_events':sum(e['kind']=='write' for st in v.steps for e in st['events'])}
        counts.update(count); used.update(v.fixups)
        cases.append({'parent_case_index':c['parent_case_index'],'configuration':cfg,'variant':c['variant'],
                      'additional_bank_contract':models,'trace':trace,'counts':count})
        print(json.dumps({'parent':c['parent_case_index'],'variant':c['variant'],**count,'frontier':b['pc']}),flush=True)
    up=upstream(); deps={**e['dependencies'],'recover_daemon_iokit_error_return.py':sha(Parent.__file__)}
    for n in ['probe_daemon_shared_roots.py','probe_daemon_descriptor_producers.py','daemon_descriptor_producers_source.json',
              'daemon_shared_roots_profiles.json','daemon_shared_roots_source.json','daemon_builder_owner_join_source.json',
              'daemon_prng_output_checks.json','daemon_prng_output_contracts.json','replay_daemon_descriptor_producers.py']:
        deps[n]=sha(ROOT/n)
    deps['daemon_return_bank_origins_IDA_context.json']=sha(ROOT/'daemon_return_bank_origins_IDA_context.json')
    return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':deps,'parent_checks_sha256':PIN,
            'source_sha256':e['source_sha256'],'source_regions':source(),'source_fixups':Parent.Parent.Core.verify_fixups(used),
            'decoder':decoder(),'literal_store_census':census(),'source_proofs':obligations(),'upstream_cases':up,'cases':cases,
            'verified_counts':{'conditional_caller_cases':len(cases),**counts,'upstream_cases':len(up),
                               'upstream_source_visits':sum(len(x['source_visits']) for x in up)},
            'initializer_to_caller_control_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n'); print(json.dumps(e['verified_counts']),flush=True)
