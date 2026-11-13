#!/usr/bin/env python3
"""Conditional original context-reference decoder and 552-byte unsealer.

Producer and network caller epochs remain separate. Original producer output,
table/controller cells, one caller root and foreign owner extents are explicit
premises. O(receipts+cases*(visits+effects)) time/space. No native API/IPC,
allocation/free or hardware PAC executes.
"""
import json,struct,zlib,base64,itertools
from collections import Counter
from unicorn import arm64_const as ar
from capstone.arm64_const import ARM64_OP_MEM,ARM64_EXT_SXTW,ARM64_EXT_SXTX
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_callback_revisit import snapshot_read
import recover_daemon_network_record as Parent

P='daemon_context_unseal';ENTRY=0x10048192c;END=0x100481d9c
POINTS=[0x100481c1c,0x100481c78,0x100481d90,END]
CELL=0x1010c9298;D=0x6500115b20;TABLE_DATA=0x6500115d6c
ROOT_FIELD=(0x878,0x1010c67d4,0x1004c2e14)
IMAGE_CELLS=[(0x1010c8268,8),(0x1010c67d4,4),(0x1010c6800,8),(0x1010ca2a8,8)]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_network_record.py',
      'recover_daemon_network_gate.py','daemon_network_gate_checks.json','daemon_network_gate_audit.json',
      'daemon_context_lock_success.json','daemon_context_lock_profiles.json','daemon_context_lock_snapshot.json',
      'daemon_context_lock_checks.json','daemon_context_seal_contracts.json','daemon_context_seal_checks.json',
      'recover_daemon_callback_revisit.py','probe_daemon_descriptor_producers.py',
      'recover_daemon_return_bank_origins.py','daemon_return_bank_origins_checks.json']

class Run(Parent.Parent.Run):
    def foreign_fixture(self,a,raw,provenance):
        for pg in range(a&~4095,((a+len(raw)-1)&~4095)+4096,4096):
            if pg not in self.pages:self.u.mem_map(pg,4096);self.pages.add(pg)
        self.u.mem_write(a,raw);self.foreign_defined.update(range(a,a+len(raw)))
        self.image_fixtures.append({'address':hex(a),'bytes_hex':raw.hex(),'provenance':provenance})

    def preflight(self,i):
        if not super().preflight(i):return False
        if not i.mnemonic.startswith(('ldr','ldur','ldp')):return True
        op=next((o for o in i.operands if o.type==ARM64_OP_MEM),None)
        if op is None:return True
        a=self.register(i.reg_name(op.mem.base))+op.mem.disp
        if op.mem.index:
            idx=self.register(i.reg_name(op.mem.index))
            if op.ext in [ARM64_EXT_SXTW,ARM64_EXT_SXTX]:
                bits=32 if op.ext==ARM64_EXT_SXTW else 64;idx&=(1<<bits)-1;idx-=1<<bits if idx>>(bits-1)else 0
            a+=idx<<op.shift.value
        a&=(1<<64)-1;reg=i.reg_name(i.operands[0].reg)
        n=1 if i.mnemonic.endswith('b') else 2 if i.mnemonic.endswith('h') else 4 if i.mnemonic.endswith('sw') or reg.startswith(('w','s')) else 16 if reg.startswith('q') else 8
        if i.mnemonic=='ldp':n*=2
        if a<0x6000000000 or Parent.Parent.Parent.Base.P<=a<a+n<=Parent.Parent.Parent.Base.P+Parent.Parent.Parent.Base.SIZE:return True
        if not all(x in self.foreign_defined for x in range(a,a+n)):
            self.stop('before_undefined_foreign_owner_read',{'address':hex(a),'size_bytes':n});return False
        return True

    def read(self,u,t,a,n,value,d):
        if a in self.foreign_defined:
            assert all(x in self.foreign_defined for x in range(a,a+n))
        return super().read(u,t,a,n,value,d)

    def write(self,u,t,a,n,value,d):
        if any(lo<=a<a+n<=lo+size for lo,size in self.foreign_owners):
            self.foreign_defined.update(range(a,a+n))
            e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n}
            self.writes.append(e);self.pending.append(e);return
        return super().write(u,t,a,n,value,d)

    def code(self,u,a,n,d):
        q=[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)];before=self.seq
        out=super().code(u,a,n,d)
        if self.seq>before:self.frames[-1]['Q_registers32']=q
        return out

    def interval(self,start,role):
        q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)]
        row=super().interval(start,role);row['entry_Q_registers32']=q
        row['boundary']['Q_registers32']=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)]
        row['foreign_owners']=[{'address':hex(a),'size_bytes':n} for a,n in self.foreign_owners]
        return row

def producer():
    snap=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'));success=json.loads(read(ROOT/'daemon_context_lock_success.json'))
    profiles=json.loads(read(ROOT/'daemon_context_lock_profiles.json'));seal=json.loads(read(ROOT/'daemon_context_seal_contracts.json'))
    rows=[]
    for j,(c,block) in enumerate(zip(profiles['cases']+[success['case']],seal['cases'])):
        raw=zlib.decompress(base64.b64decode(c['payload_zlib_base64']));assert __import__('hashlib').sha256(raw).hexdigest()==c['payload_sha256']
        t=json.loads(raw);pub=[s for s in t['steps'] if s['pc']=='0x1003c43b4'];assert len(pub)==1
        e=pub[0]['events'];assert len(e)==1 and e[0]['kind']=='write' and e[0]['address']==hex(CELL) and e[0]['size_bytes']==8
        assert block['name']==c['configuration']['name'] and len(bytes.fromhex(block['after_hex']))==552
        assert e[0]['value']['hex']=='c1f0000600a0f6e5'
        rows.append({'producer_case_index':j,'name':block['name'],'payload_sha256':c['payload_sha256'],
                     'publication':pub[0],'sealed_context_hex':block['after_hex'],'raw_context_hex':block['before_hex'],
                     'context_seed32':block['seed32'],'raw_lock_value64':block['raw_lock_value_before_seal']})
    assert len(rows)==13
    effects=[{'address':hex(a),'bytes_hex':snapshot_read(snap,a,n).hex(),'provenance':'separate_constructor_compatible_image_state'} for a,n in IMAGE_CELLS]
    return rows,effects,snapshot_read(snap,TABLE_DATA,512)

def root_evidence():
    off,value,pc=ROOT_FIELD;out=[]
    for c in json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))['upstream_cases']:
        s=int(c['frame_base'],16);ws=[w for w in c['source_writes'] if int(w['address'],16)<s+off+8 and s+off<int(w['address'],16)+w['size_bytes']]
        assert len(ws)==1 and ws[0]['pc']==hex(pc) and ws[0]['after_hex']==struct.pack('<Q',value).hex() and ws[0]['size_bytes']==8
        out.append({'frame_base':hex(s),'writer':ws[0],'later_overwrites':0})
    assert len(out)==12;return out

def case(index,before,p,effects,table):
    v=Run(before['configuration']);v.cut_stops=set();v.foreign_defined=set();v.foreign_owners=[(D,552),(TABLE_DATA,512)]
    for j,x in enumerate(before['boundary']['registers31']):v.set(j,int(x,16))
    v.u.reg_write(ar.UC_ARM64_REG_SP,int(before['boundary']['SP'],16));v.u.reg_write(ar.UC_ARM64_REG_NZCV,int(before['boundary_NZCV'],16))
    for f in before['initial_private_fixtures']:v.fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']))
    for f in before['initial_image_fixtures']:v.image_fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']),f['provenance'])
    for w in before['source_writes']:
        a=int(w['address'],16);raw=bytes.fromhex(w['after_hex'])
        if Parent.Parent.Parent.Base.P<=a<a+len(raw)<=Parent.Parent.Parent.Base.P+Parent.Parent.Parent.Base.SIZE:v.fixture(a,raw)
        else:v.image_fixture(a,raw,'preceding_original_source_write')
    for f in effects:v.image_fixture(int(f['address'],16),bytes.fromhex(f['bytes_hex']),f['provenance'])
    v.foreign_fixture(D,bytes.fromhex(p['sealed_context_hex']),'separate_original_constructor_sealed_context')
    v.foreign_fixture(TABLE_DATA,table,'separate_original_constructor_cached_table')
    encoded=p['publication']['events'][0]['value']['hex'];v.image_fixture(CELL,bytes.fromhex(encoded),'separate_constructor_encoded_reference')
    # The frozen gate loaded this register before its branch. Replace the
    # same-cell/register pair together as an explicit alternative entry premise.
    v.set(9,int.from_bytes(bytes.fromhex(encoded),'little'))
    off,value,pc=ROOT_FIELD;root={'address':hex(v.C+off),'bytes_hex':struct.pack('<Q',value).hex(),'source_initializer_writer':hex(pc),'separate_caller_premise':True}
    assert not any(v.known[v.C+off-Parent.Parent.Parent.Base.P:v.C+off+8-Parent.Parent.Parent.Base.P]);v.fixture(v.C+off,struct.pack('<Q',value))
    rows=[];start=ENTRY
    for stop in POINTS:
        v.cut_stops={stop};r=v.interval(start,'original_reference_decode_and_context_unseal');rows.append(r);assert r['boundary']['pc']==hex(stop)
        start=stop
    assert int.from_bytes(v.u.mem_read(CELL,8),'little')==D
    assert bytes(v.u.mem_read(D,552)).hex()==p['raw_context_hex']
    assert int.from_bytes(v.u.mem_read(D+8,8),'little')==int(p['raw_lock_value64'],16)
    return {'parent_consumer_index':index,'producer_case_index':p['producer_case_index'],'producer_name':p['name'],
            'root_premise':root,'image_premises':effects,'encoded_reference_premise_hex':encoded,'entry_X9_premise':hex(int.from_bytes(bytes.fromhex(encoded),'little')),
            'foreign_owner_premises':[{'address':hex(D),'bytes_hex':p['sealed_context_hex']},{'address':hex(TABLE_DATA),'bytes_hex':table.hex()}],
            'intervals':rows,'final_context_hex':bytes(v.u.mem_read(D,552)).hex(),'final_raw_reference64':hex(D),
            'final_raw_lock64':hex(int.from_bytes(v.u.mem_read(D+8,8),'little')),'native_epoch_join_established':False}

def source():
    specs=[('reference_decode_and_unseal',ENTRY,END),('reference_encoder_preamble',0x1003c40a8,0x1003c41dc),
           ('reference_encoder_publication',0x1003c4324,0x1003c43b8)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in specs]

def reference_encode(pointer,fold):
    k=(fold*0xeb36c1ca)&0xffffffff;raw=bytearray(struct.pack('<Q',pointer));f=0x01000193
    for i in range(7,0,-1):j=((((k+i)&0xffffffff)^k)*f&0xffffffff)%i;raw[i],raw[j]=raw[j],raw[i]
    a=[((k*k)^k)&0xffffffff,(((k|1)*k)^k)&0xffffffff];words=struct.unpack('<2I',raw)
    return int.from_bytes(struct.pack('<2I',*[(a[j]+words[j]*f)&0xffffffff ^ a[j] for j in range(2)]),'little')

def reference_case(cfg,pointer,fold):
    v=Run(cfg);v.foreign_owners=[];v.foreign_defined=set();v.set(16,pointer);v.set(17,fold);v.set(6,0xeb36c1ca);v.set(19,CELL)
    vectors={8:[7,6],10:[5,3],11:[0xcccccccd,0xaaaaaaab],12:[0xfffffffe,0xffffffff],13:[0x01000193]*2,14:[0x80000000,0]}
    for j,words in vectors.items():v.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int.from_bytes(struct.pack('<2I',*words),'little')|((pointer^fold)<<64))
    v.fixture(v.C+0x98,struct.pack('<2I',0x24924925,0xaaaaaaab));v.cut_stops={0x1003c41d0}
    pre=v.interval(0x1003c40a8,'isolated_reference_encoder_preamble');assert pre['boundary']['pc']=='0x1003c41d0'
    v.cut_stops={0x1003c43b8};post=v.interval(0x1003c4324,'isolated_reference_encoder_publication_without_context_body')
    assert post['boundary']['pc']=='0x1003c43b8';encoded=int.from_bytes(v.u.mem_read(CELL,8),'little');assert encoded==reference_encode(pointer,fold)
    v.set(9,encoded);v.set(10,fold);v.set(8,0xeb36c1ca);v.cut_stops={0x100481c1c}
    dec=v.interval(0x100481a14,'isolated_reference_decoder_without_object_dereference')
    assert int.from_bytes(v.u.mem_read(v.C+0xb6b0,8),'little')==pointer
    return {'pointer_word64':hex(pointer),'fold32':hex(fold),'encoded_reference64':hex(encoded),'intervals':[pre,post,dec],
            'context_body_not_executed_in_this_component_control':True,'native_pointer_validity_claimed':False}

def intervals(e):return [r for c in e['cases']+e['reference_cases'] for r in c['intervals']]

def build():
    parent=json.loads(read(ROOT/'daemon_network_gate_checks.json'));selected=[];seen=set()
    for j,c in enumerate(parent['consumer_cases']):
        if c['final_boundary']!='0x10048192c':continue
        acq=parent['acquisition_cases'][c['acquisition_index']];key=acq['parent_warm_case_index']
        if key not in seen:seen.add(key);selected.append((j,c['intervals'][-1]))
    assert len(selected)==8;prod,effects,table=producer()
    pairs=[(selected[0],p) for p in prod]+[(s,prod[-1]) for s in selected[1:]]
    refs=[reference_case(b['configuration'],ptr,fold) for (_,b),ptr,fold in itertools.product([selected[0],selected[-1]],
        [0,1,0x0123456789abcdef,0xffffffffffffffff,D,D+1],[0,1,0x7fffffff,0x80000000,0xffffffff,0xc41c69cd])]
    e={'producer_evidence':prod,'cases':[case(j,b,p,effects,table) for (j,b),p in pairs],'reference_cases':refs};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Env.fixups(used),root_writer_evidence=root_evidence(),
        verified_counts={'cases':20,'producer_profiles':13,'caller_contexts':8,'reference_controls':len(refs),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
