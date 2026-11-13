#!/usr/bin/env python3
"""Complete first payload-driven mixing pass with packed source intervals.

Frozen caller/arena/API premises remain inherited. No new API, private or
image data is supplied. Compressed per-iteration receipts preserve complete
GP/Q/NZCV, opcodes and byte effects; fixture compaction preserves byte state.
O(parent receipts+iterations*(visits+state+effects)) time, O(largest interval
+compressed receipts) space. No native API/IPC/PAC or IDB mutation executes.
"""
import json,zlib,base64,struct
from collections import Counter
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes,fixture_bytes
import recover_daemon_arena_split as Parent

P='daemon_payload_mix';ENTRY=Parent.NEXT;EXIT=0x100aaefc0;G=0x1010c784c
RunBase=Parent.Parent.Parent.Parent.Parent.Run
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_arena_split.py',
      'daemon_arena_split_checks.json','daemon_arena_split_audit.json',
      'recover_daemon_context_unseal.py','recover_daemon_context_lock_use.py',
      'recover_daemon_return_bank_origins.py','audit_daemon_arena_split.py',
      'audit_daemon_clock_record.py','audit_daemon_context_state_publish.py']

class Run(RunBase):
    def code(self,u,a,n,d):
        if a==EXIT and self.reg(24)==1:
            self.flush();return self.stop('before_final_first_pass_counter_decrement')
        skip=a==ENTRY and self.seq==0 and a in self.cut_stops
        if skip:self.cut_stops.remove(a)
        out=super().code(u,a,n,d)
        if skip:self.cut_stops.add(a)
        return out

def fixtures(data,provenance):
    out=[];keys=sorted(data);j=0
    while j<len(keys):
        k=j+1
        while k<len(keys) and keys[k]==keys[k-1]+1:k+=1
        out.append({'address':hex(keys[j]),'bytes_hex':bytes(data[a] for a in keys[j:k]).hex(),'provenance':provenance});j=k
    return out

def compact_fixtures(v):
    for name in ['initial','image_fixtures']:
        data={int(f['address'],16)+j:b for f in getattr(v,name) for j,b in enumerate(bytes.fromhex(f['bytes_hex']))}
        setattr(v,name,fixtures(data,'byte_equivalent_preceding_source_state'))

def restore(row):
    v=Run(row['configuration']);v.foreign_owners=[(int(r['address'],16),r['size_bytes']) for r in row['foreign_owners']]
    v.foreign_defined=set();v.cut_stops=set()
    for j,x in enumerate(row['boundary']['registers31']):v.set(j,int(x,16))
    for j,x in enumerate(row['boundary']['Q_registers32']):v.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(row['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['boundary_NZCV'],16))
    for kind in ['private','image']:
        for f in row['initial_'+kind+'_fixtures']:
            a=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
            if kind=='private':v.fixture(a,raw)
            elif a>=0x6000000000:v.foreign_fixture(a,raw,f['provenance'])
            else:v.image_fixture(a,raw,f['provenance'])
    for w in row['source_writes']:
        a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
        if 0x6800000000<=a<a+len(raw)<=0x6800100000:v.fixture(a,raw)
        elif a>=0x6000000000:v.foreign_fixture(a,raw,'preceding_original_source_write')
        else:v.image_fixture(a,raw,'preceding_original_source_write')
    compact_fixtures(v);return v

def pack(row):
    raw=json.dumps(row,separators=(',',':')).encode()
    return {'decoded_sha256':__import__('hashlib').sha256(raw).hexdigest(),'decoded_size_bytes':len(raw),
            'payload_zlib_base64':base64.b64encode(zlib.compress(raw,9)).decode()}

def unpack(row):
    raw=zlib.decompress(base64.b64decode(row['payload_zlib_base64']))
    assert len(raw)==row['decoded_size_bytes'] and __import__('hashlib').sha256(raw).hexdigest()==row['decoded_sha256']
    return json.loads(raw)

def case(index,parent,limit=None):
    before=parent['intervals'][-1];assert before['boundary']['pc']==hex(ENTRY)
    v=restore(before);sp=int(before['boundary']['SP'],16);q=sp+0x220;rows=[];counts=Counter();used=set()
    start_state=state_bytes(before);records=[]
    for iteration in range(623 if limit is None else limit):
        v.cut_stops={ENTRY};r=v.interval(ENTRY,'original_complete_first_pass_iteration')
        counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
        used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
        assert r['boundary']['pc']==hex(EXIT if iteration==622 else ENTRY)
        records.append({'iteration':iteration+2,'entry_i32':int(r['entry_registers31'][19],16),'entry_j32':int(r['entry_registers31'][27],16),
                        'entry_remaining32':int(r['entry_registers31'][24],16),'exit_i32':int(r['boundary']['registers31'][19],16),
                        'exit_j32':int(r['boundary']['registers31'][27],16),'exit_remaining32':int(r['boundary']['registers31'][24],16),
                        'key16_hex':bytes(v.u.mem_read(q,16)).hex(),'global_writes':[w for w in r['source_writes'] if G<=int(w['address'],16)<G+2496]})
        rows.append(pack(r));compact_fixtures(v)
        if iteration%64==0:print(json.dumps({'parent_seed_case_index':index,'iteration':iteration+2,**counts}),flush=True)
    exit_rows=[];first_boundary=r['boundary'];first_NZCV=r['boundary_NZCV']
    if limit is None:
        final=Parent.Parent.Parent.Parent.restore(r);final.cut_stops={0x100aaf008}
        a=final.interval(EXIT,'original_final_counter_decrement_and_target_selection');exit_rows.append(a)
        target=int(a['boundary']['registers31'][9],16);assert target==0x100abba18 and a['boundary']['registers31'][24]=='0x0'
        final.cut_stops={target};a=final.interval(0x100aaf008,'original_first_pass_exit_transfer');exit_rows.append(a)
        assert a['boundary']['pc']==hex(target)
        for a in exit_rows:
            counts.update(source_visits=len(a['source_visits']),reads=len(a['source_reads']),writes=len(a['source_writes']),logical_edges=len(a['logical_edges']),source_calls=len(a['source_calls']))
            used.update(int(x['address'],16) for x in a['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'parent_seed_case_index':index,'intervals_packed':rows,'iteration_records':records,'exit_intervals_packed':[pack(a) for a in exit_rows],
            'entry_state2496_hex':bytes(start_state[G+j] for j in range(2496)).hex(),'entry_key16_hex':bytes(start_state[q+j] for j in range(16)).hex(),
            'final_state2496_hex':bytes(v.u.mem_read(G,2496)).hex(),'final_key16_hex':bytes(v.u.mem_read(q,16)).hex(),
            'first_pass_boundary':first_boundary,'first_pass_NZCV':first_NZCV,
            'final_boundary':exit_rows[-1]['boundary'] if exit_rows else first_boundary,
            'final_NZCV':exit_rows[-1]['boundary_NZCV'] if exit_rows else first_NZCV,'counts':dict(counts),'used_fixups':[hex(a) for a in sorted(used)]}

def source():
    specs=[('first_mix',ENTRY,0x1009c4714),('key_wrap_mutation',0x100a7d924,0x100a7d984),
           ('first_pass_counter',EXIT,0x100aaf00c),('nonwrap_consumer',Parent.STOP,0x100a07724),
           ('state_wrap',0x100c0bb9c,0x100c0bbc0),('next_stage_entry',0x100abba18,0x100abba38)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]}
            for n,a,b in specs]

def build(limit=None):
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[case(j,parent['seed_cases'][j],limit) for j in [0,7]]
    counts=Counter()
    for c in cases:counts.update(c['counts'])
    used={int(a,16) for c in cases for a in c['used_fixups']}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_regions':source(),'source_fixups':Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),
            'cases':cases,'verified_counts':{'cases':len(cases),'intervals':sum(len(c['intervals_packed'])+len(c['exit_intervals_packed']) for c in cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
