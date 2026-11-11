#!/usr/bin/env python3
"""Original FPSD1200 environment, seed and certificate-input continuations.

Startup/provider snapshot composition, scalar atomics, random returns and
timeval outputs are explicit private fixtures. No native startup continuity,
RNG, clock, allocator, credentials, authentication or IPC is established.
"""
import json,struct,base64,zlib
from pathlib import Path
from functools import lru_cache
import unicorn as uc
import recover_fpsd1200_arena as arena_module
from recover_fpsd1200_arena import Arena,library,sources,ROOT
from recover_fpsd1200_identity import IMAGE,SOURCE,CS,SHA
from recover_fpsd1200_admission import fixup_checks,bank_proofs
from verify_daemon_reader_record_payloads_publication import read
from unicorn import arm64_const as A

VISIT_LIMIT=4000000
arena_module.LIMIT=VISIT_LIMIT


@lru_cache(maxsize=1)
def startup_context():
    p=json.loads(read(ROOT/'rpc502_startup_profiles.json'))
    r=next(r for r in p['cases']if r['case']['label']=='initialized_worker')
    row=json.loads(zlib.decompress(base64.b64decode(r['payload_zlib_base64'])));s=row['startup_snapshot']
    cells={};count=0
    for c in row['startup_chunks']:
        if c['phase']!='startup':continue
        d=json.loads(zlib.decompress(base64.b64decode(c['payload_zlib_base64'])))
        for w in d['image_writes']:
            a=int(w['address'],16);n=w['size'];v=int(w['value'],16)&((1<<(8*n))-1)
            cells.update({a+i:b for i,b in enumerate(v.to_bytes(n,'little'))});count+=1
    spans=[]
    for a in sorted(cells):
        if spans and a==spans[-1]['address']+len(spans[-1]['bytes']):spans[-1]['bytes'].append(cells[a])
        else:spans.append({'address':a,'bytes':bytearray([cells[a]])})
    return {'source_artifact':'rpc502_startup_profiles.json','case':'initialized_worker',
      'descriptor_base':s['descriptor_base'],'descriptor88_hex':s['descriptor60_hex'][:176],
      'readiness_hex':s['readiness_hex'],'heap_owners':s['heap_owners'],
      'source_global_spans':[{'address':hex(x['address']),'bytes_hex':x['bytes'].hex()}for x in spans],
      'source_global_write_count':count,
      'native_temporal_continuity_established':False}


class Context(Arena):
    def __init__(self,wire,fixture,lib):
        self.random_models=[];self.random_points=[]
        self.startup_owners=[];self.startup_reads=[];self.startup_writes=[];self.composed_context=None
        self.window_reads=[];self.window=None
        self.later_atomics=[]
        self.context_guard=None;self.ool_byte_reads=[];self.seed_snapshots=[]
        super().__init__(wire,fixture,lib)
        if fixture.get('startup_context'):
            self.composed_context=startup_context()
            for o in self.composed_context['heap_owners']:
                a=int(o['address'],16);n=o['size_bytes'];u=self.u
                u.mem_map(a,(n+4095)&~4095);u.mem_write(a,bytes.fromhex(o['bytes_hex']))
                self.startup_owners.append({'address':a,'size_B':n,'known':bytearray.fromhex(o['known_mask_hex'])})
            self.u.mem_write(0x1010b5ef0,bytes.fromhex(self.composed_context['descriptor88_hex']))
            self.u.mem_write(0x1010c5798,bytes.fromhex(self.composed_context['readiness_hex']))
            if fixture.get('startup_globals'):
                for w in self.composed_context['source_global_spans']:
                    self.u.mem_write(int(w['address'],16),bytes.fromhex(w['bytes_hex']))
                self.window=int.from_bytes(self.u.mem_read(0x1010ca2a8,8),'little')^0x12af5504870a589f
        if 'readiness'in fixture:self.u.mem_write(0x1010c5798,bytes([fixture['readiness']]))
        if fixture.get('provider_window'):
            p=self.provider_snapshot;self.u.mem_write(0x1010c6800,int(p['encoded_window_mask64'],16).to_bytes(8,'little'))
            self.u.mem_write(0x1010ca2a8,int(p['encoded_window_base64'],16).to_bytes(8,'little'))
            self.window=int(p['encoded_window_base64'],16)^0x12af5504870a589f
        if fixture.get('provider_state'):
            p=self.provider_snapshot;self.u.mem_write(0x1010c784c,bytes.fromhex(p['state_bytes_hex']))
            self.u.mem_write(0x1010c67dc,struct.pack('<I',p['index32']));self.u.mem_write(0x1010c8258,struct.pack('<I',p['counter32']))
        if fixture.get('certificate_ool'):
            raw=(ROOT/'corefp_fppineboard_certificate.der').read_bytes();assert len(raw)==756
            self.u.mem_write(self.ool,raw)
        self.initial_ool756=bytes(self.u.mem_read(self.ool,756)).hex()
        self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.startup_write)

    def startup_write(self,u,access,a,n,v,data):
        for o in self.startup_owners:
            if o['address']<=a<a+n<=o['address']+o['size_B']:
                off=a-o['address'];self.startup_writes.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),
                  'owner':hex(o['address']),'offset_B':off,'width_B':n,'value':hex(v&((1<<(8*n))-1))})
                o['known'][off:off+n]=bytes([1])*n

    def read_hook(self,u,access,a,n,v,data):
        if self.ool<=a<self.ool+756:
            assert a+n<=self.ool+756
            self.ool_byte_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),
              'offset_B':a-self.ool,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        if self.window is not None and self.window<=a<self.window+32768:
            self.window_reads.append({'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'address':hex(a),
              'offset_B':a-self.window,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        for o in self.startup_owners:
            if o['address']<=a<o['address']+o['size_B']:
                off=a-o['address'];e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'owner':hex(o['address']),
                  'offset_B':off,'width_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),
                  'all_bytes_defined':a+n<=o['address']+o['size_B']and all(o['known'][off:off+n])}
                self.startup_reads.append(e)
                if not e['all_bytes_defined']:return self.stop('unknown_startup_owner_read')
        return super().read_hook(u,access,a,n,v,data)

    def hook(self,u,pc,n,data):
        if pc in [0x100543cc0,0x100466d54]:
            er,dr,ar=(12,14,13)if pc==0x100543cc0 else(11,1,15)
            a=self.reg(ar);old=int.from_bytes(u.mem_read(a,4),'little');expect=self.reg(er)&0xffffffff;desired=self.reg(dr)&0xffffffff
            e={'pc':hex(pc),'address':hex(a),'old32':hex(old),'expected32':hex(expect),'desired32':hex(desired),
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)],'executed':self.fixture.get('later_atomic_fixture',False),
              'expected_register':er,'desired_register':dr,'address_register':ar}
            self.later_atomics.append(e)
            if not e['executed']:return self.stop('before_later_atomic_boundary')
            if old==expect:u.mem_write(a,struct.pack('<I',desired))
            self.setreg(er,old);e['stored32']=hex(desired if old==expect else old)
            self.visited.append(pc);u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc in [0x10063044c,0x100405a78,0x100405a9c,0x100405ab0,0x100405af8,0x100405b6c,
          0x10047ab44,0x10049d978,0x1006303f0,0x100405b8c,0x100633cb4]:
            p={'pc':hex(pc),'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),
              'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)]}
            if pc==0x10047ab44:p['flag_byte_hex']=bytes(u.mem_read(self.reg(8),1)).hex()
            if pc==0x100405a78:p['timeval16_hex']=bytes(u.mem_read(self.reg(21)+16,16)).hex()
            if pc==0x100405b8c:
                p['material_address']=hex(self.reg(22));p['material16_hex']=bytes(u.mem_read(self.reg(22),16)).hex()
            self.random_points.append(p)
        guard=None
        if pc==0x10049d978 and self.reg(10)==4:guard=('missing_seed_base_guard',self.reg(10),4)
        if pc==0x10049da00 and self.window is None:guard=('missing_text_window_guard',self.reg(14),4)
        if pc==0x10062826c and not self.fixture.get('startup_context'):guard=('missing_startup_descriptor_guard',(self.reg(22)+8)&((1<<64)-1),8)
        if guard:
            reason,a,width=guard
            self.context_guard={'pc':hex(pc),'address':hex(a),'width_B':width,
              'sp':hex(u.reg_read(A.UC_ARM64_REG_SP)),'nzcv':hex(u.reg_read(A.UC_ARM64_REG_NZCV)),
              'registers31':[hex(self.reg(j))for j in range(31)]}
            return self.stop(reason)
        if pc==0x100405a74:
            self.seed_snapshots.append({'pc':hex(pc),'seed624_hex':bytes(u.mem_read(0x1010c784c,2496)).hex()})
        if pc in self.imports and self.imports[pc]=='libSystem/_arc4random'and self.reg(30)-4 in [0x100630448,0x100405af4,0x100405b68]:
            values=self.fixture.get('random_words',[]);i=len(self.random_models)
            if i<len(values):
                e={'kind':'import_fixture','name':self.imports[pc],'site':hex(self.reg(30)-4),
                  'args':[hex(self.reg(j))for j in range(8)],
                  'model':'explicit uint32 random-result fixture; no native RNG or entropy claim'}
                self.events.append(e);self.random_models.append({'event':e,'index':i,'word32':hex(values[i])})
                return self.fixture_return(e,values[i])
        if pc in self.imports and self.imports[pc]=='libSystem/_gettimeofday'and self.reg(30)-4==0x100405a74 and 'timeval'in self.fixture:
            assert self.reg(1)==0
            raw=struct.pack('<qi',*self.fixture['timeval'])
            e={'kind':'import_fixture','name':self.imports[pc],'site':hex(self.reg(30)-4),
              'args':[hex(self.reg(j))for j in range(8)],'model':'explicit 12-byte timeval fixture; padding preserved; no native clock',
              'timeval16_before':bytes(u.mem_read(self.reg(0),16)).hex(),'modeled_timeval12_hex':raw.hex()}
            self.events.append(e);u.mem_write(self.reg(0),raw);return self.fixture_return(e,0)
        return super().hook(u,pc,n,data)

    def run_context(self):
        r=self.run_arena();r.update(random_models=self.random_models,random_points=self.random_points,
          self_text_reads=self.window_reads,self_text_window_base=hex(self.window)if self.window is not None else None,
          later_atomics=self.later_atomics,
          initial_ool756_hex=self.initial_ool756,
          context_guard=self.context_guard,input_ool_byte_reads=self.ool_byte_reads,seed_snapshots=self.seed_snapshots,
          startup_context=self.composed_context,startup_owner_reads=self.startup_reads,startup_owner_writes=self.startup_writes,
          startup_owners_final=[{'address':hex(o['address']),'size_B':o['size_B'],
            'bytes_hex':bytes(self.u.mem_read(o['address'],o['size_B'])).hex(),'known_mask_hex':bytes(o['known']).hex()}for o in self.startup_owners],
          terminal_registers31=[hex(self.reg(j))for j in range(31)],
          terminal_sp=hex(self.u.reg_read(A.UC_ARM64_REG_SP)))
        if r['reply_completed']and r['reply_size_B']==36:
            r['reply_status_u32']=struct.unpack_from('<I',bytes.fromhex(r['reply212']),32)[0]
        return r


def fixtures():
    random=[0x12345678,0x9abcdef0,0x0fedcba9];time=[1710000000,123456]
    rows=[{'label':'entropy_boundary'},
      {'label':'time_boundary','random_words':random[:1]},
      {'label':'seed_zero_time_boundary','random_words':[0]},
      {'label':'seed_max_time_boundary','random_words':[0xffffffff]},
      {'label':'second_entropy_boundary','random_words':random[:1],'timeval':time},
      {'label':'cold_seed_base_guard','random_words':random,'timeval':time},
      {'label':'readiness_only_guard','random_words':random,'timeval':time,'readiness':1},
      {'label':'arena_without_window','random_words':random,'timeval':time,'startup_context':True},
      {'label':'arena_with_window_gate','random_words':random,'timeval':time,'startup_context':True,'provider_window':True},
      {'label':'arena_with_window_return','random_words':random,'timeval':time,'startup_context':True,'provider_window':True,'later_atomic_fixture':True},
      {'label':'provider_word2_der','provider_state':True,'provider_window':True,'certificate_ool':True},
      {'label':'provider_word3_synthetic','provider_state':True,'provider_window':True,'word56':3},
      {'label':'startup_word2_der','startup_context':True,'startup_globals':True,'certificate_ool':True},
      {'label':'startup_word3_der_gate','startup_context':True,'startup_globals':True,'certificate_ool':True,'word56':3},
      {'label':'startup_word3_der_allocator','startup_context':True,'startup_globals':True,'certificate_ool':True,'word56':3,'later_atomic_fixture':True}]
    rows.extend({'label':f'word56_{v}','word56':v,'provider_state':True,'provider_window':True}for v in [0,1,4])
    rows.append({'label':'word52_1_reference','word52':1,'provider_state':True,'provider_window':True,'certificate_ool':True})
    for f in rows:
        f['request_changes']=[[52,f.pop('word52',2),4],[56,f.pop('word56',2),4],[40,756,4],[60,756,4]]
        yield {'provider_case':0,'execute_once_callback':True,'model_lock':True,'atomic_fixture':True,**f}


def proofs():
    import z3
    x=z3.BitVec('scalar32',32);s=z3.Solver();s.set(timeout=15000)
    s.add(x-((x<<1)&0xf8ac9030)+0xfc564818!=(x^0xfc564818));q=s.to_smt2();assert s.check()==z3.unsat
    return {'material_xor_codec':{'query':q,'result':'unsat',
      'scope':'All-u32 local arithmetic under the recorded phase constants; no whole-path or native theorem.'}}


def main():
    lib=library();wire=sources()[3];rows=[]
    allowed={'unmodeled_import_boundary','missing_seed_base_guard','missing_text_window_guard',
      'missing_startup_descriptor_guard','before_later_atomic_boundary','returned_to_fixture'}
    for f in fixtures():
        r=Context(wire,f,lib).run_context();rows.append(r)
        print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'pc':r['last_pc'],'visits':len(r['visited']),
          'status':r['application_status_u32'],'ool_reads':len(r['input_ool_reads']),
          'owner_reads':len(r['startup_owner_reads']),'later_atomics':len(r['later_atomics']),
          'last_import':next((e for e in reversed(r['events'])if e['kind']=='import_fixture'),None)}),flush=True)
        assert r['stop_reason']in allowed
    sites={int(a,16)for r in rows for a in r['visited']if int(a,16)<0x200000000}
    guards={int(r['last_pc'],16)for r in rows if r['context_guard']or r['stop_reason']=='before_later_atomic_boundary'}
    spans=[]
    for a in sorted(sites|guards):
        if spans and a==spans[-1][1]:spans[-1][1]+=4
        else:spans.append([a,a+4])
    banks,pairs,unpaired=bank_proofs(rows)
    out={'scope':__doc__,'daemon_sha256':SHA(SOURCE.read_bytes()),'library':lib,'profiles':rows,
      'spans':[{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':SHA(IMAGE.read(a,z-a)),
        'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for a,z in spans],
      'unretired_guard_sites':[hex(a)for a in sorted(guards)],
      'fixups':fixup_checks({int(a,16)for r in rows for a in r['fixup_reads']}),'byte_bank_proofs':banks,
      'byte_bank_pairs':pairs,'unpaired_byte_bank_reads':unpaired,'proofs':proofs(),
      'reference_certificate_sha256':SHA((ROOT/'corefp_fppineboard_certificate.der').read_bytes()),
      'generator_sha256':SHA(Path(__file__).read_bytes()),'visit_limit':VISIT_LIMIT,
      'dependencies':{n:SHA(read(ROOT/n).encode())for n in ['recover_fpsd1200_arena.py','audit_fpsd1200_arena.py',
        'fpsd1200_arena_checks.json','recover_fpsd1200_identity.py','audit_fpsd1200_identity.py',
        'recover_fpsd1200_admission.py','audit_fpsd1200_admission.py','daemon_rpc502_probe.py',
        'daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','bootpolicy_cache_reader.py',
        'daemon_object_initialization_context.json','rpc502_startup_profiles.json','rpc502_startup_checks.json',
        'daemon_entropy_return_contracts.json','corefp_client_paths_contracts.json']},
      'new_IDA_access':True,'new_IDB_mutations':False,'new_native_execution':False,'full_goal_complete':False}
    out['verified_counts']={'profiles':len(rows),'source_spans':len(spans),'source_instructions_including_guards':len(sites|guards),
      'daemon_visits':sum(sum(int(a,16)<0x200000000 for a in r['visited'])for r in rows),
      'library_visits':sum(sum(int(a,16)>=0x200000000 for a in r['visited'])for r in rows),
      'original_copy_calls':sum(len(r['copies'])for r in rows),'returned_replies':sum(r['reply_completed']for r in rows),
      'environment_guards':sum(r['context_guard']is not None for r in rows),
      'later_atomic_guards':sum(r['stop_reason']=='before_later_atomic_boundary'for r in rows),
      'later_atomic_fixtures':sum(sum(a['executed']for a in r['later_atomics'])for r in rows),
      'random_fixtures':sum(len(r['random_models'])for r in rows),'seed_snapshots':sum(len(r['seed_snapshots'])for r in rows),
      'OOL_read_events':sum(len(r['input_ool_reads'])for r in rows),'self_text_reads':sum(len(r['self_text_reads'])for r in rows),
      'startup_owner_reads':sum(len(r['startup_owner_reads'])for r in rows),
      'startup_owner_writes':sum(len(r['startup_owner_writes'])for r in rows),
      'queries_unsat':len(out['proofs']),'format12_rebases':len(out['fixups']['records']),
      'format12_bindings':len(out['fixups']['bindings']),'bank_identities':len(banks),
      'bank_inputs':256*len(banks),'bank_pair_uses':pairs,'unpaired_byte_bank_reads':len(unpaired)}
    (ROOT/'fpsd1200_context_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out['verified_counts']),flush=True)


if __name__=='__main__':main()
