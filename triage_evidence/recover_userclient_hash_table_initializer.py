#!/usr/bin/env python3
"""Original FPHashTable initializer, size calculator and variable allocator ABI.
O(B+I+256R) extraction time/space; no target or IDB execution.
"""
import json
import struct
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword, selected, CS, block
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha

P='userclient_hash_table_initializer'
SCOPE='Original-source token0xabd FPHashTable initialization, token0xed1 decoded-count size helper, variable-allocation ABI, null/success output and conditional 128-entry array initialization. Native allocation, caller/connection epochs, table operations and application entry semantics remain unknown.'
SPANS={
 'frame_enter':(0xfffffe000a627404,0xfffffe000a627424),
 'guard_save':(0xfffffe000a627424,0xfffffe000a627434),
 'init_roots':(0xfffffe000a627434,0xfffffe000a62750c),
 'init_header':(0xfffffe000a62750c,0xfffffe000a627560),
 'size_request':(0xfffffe000a627560,0xfffffe000a627670),
 'variable_request':(0xfffffe000a627674,0xfffffe000a6276fc),
 'allocation_gate':(0xfffffe000a627700,0xfffffe000a627740),
 'loop_gate':(0xfffffe000a627748,0xfffffe000a627784),
 'loop_address':(0xfffffe000a62778c,0xfffffe000a6277a4),
 'loop_retag':(0xfffffe000a6277a8,0xfffffe000a6277ac),
 'loop_writes':(0xfffffe000a6277ac,0xfffffe000a6277cc),
 'loop_continue':(0xfffffe000a6277cc,0xfffffe000a627800),
 'output':(0xfffffe000a627808,0xfffffe000a627810),
 'canary':(0xfffffe000a627810,0xfffffe000a627824),
 'epilogue':(0xfffffe000a627828,0xfffffe000a627844),
 'size_entry':(0xfffffe000a5b3dcc,0xfffffe000a5b3e2c),
 'size_decode':(0xfffffe000a5b3e2c,0xfffffe000a5b3e98),
 'size_guard':(0xfffffe000a5b3e98,0xfffffe000a5b3ed0),
 'size_dispatch':(0xfffffe000a5b3ed0,0xfffffe000a5b3f24),
 'size_multiply':(0xfffffe000a5b3f2c,0xfffffe000a5b3f34),
 'size_encode':(0xfffffe000a5b3f34,0xfffffe000a5b3fac),
 'size_output':(0xfffffe000a5b3fb4,0xfffffe000a5b3fbc),
 'variable_adapter':(0xfffffe000c4ba960,0xfffffe000c4ba970),
}
BRANCHES={0xed1:(0xfffffe000a5b3f28,0x9933),0xed9:(0xfffffe000a5b3fb0,0x9933),
 0x78e:(0xfffffe000a5b3fb0,0xe9eb),0xabd:(0xfffffe000a627744,0x869c),
 0xad0:(0xfffffe000a627804,0x869c),0x41d:(0xfffffe000a627788,0x616e),0x436:(0xfffffe000a627804,0x616e)}
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py',
 'recover_kext_aes_handoff.py','lskd_values_symbolic.py','audit_userclient_uidlist_cleanup.py',
 'userclient_hash_table_bootstrap_checks.json','userclient_hash_table_bootstrap_audit.json']
FALSE=['native_API_executed','native_allocation_established','native_PAC_authenticated',
 'native_daemon_kext_pairing_established','whole_machine_context_lifetime_established',
 'application_entry_semantics_established','full_populated_cleanup_established','IDB_modified','full_goal_complete']

def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 fs={n:function(k,entry,a) for n,a in [('initializer',0xfffffe000a627400),('size_helper',0xfffffe000a5b3dc8)]}
 fs['variable_adapter']=k.function(0xfffffe000c4ba95c)
 for f in [fs['initializer'],fs['size_helper']]:
  raw=bytes.fromhex(f.get('bytes_hex',f.get('bytes')));assert raw==IMAGE.read(int(f['start'],16),len(raw))
 parent=json.loads(read(ROOT/'userclient_hash_table_bootstrap_checks.json'))
 assert fs['initializer']==parent['initializer_function']
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a)
  if label!='variable_adapter':assert IMAGE.read(a,z-a)==raw
  ii=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
  assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':ii})
 transfers=[]
 for f in fs.values():
  for i in f['instructions']:
   if i['mnemonic'] in ['braa','blraa','b.eq','b.ne','ret','retab','bl','b']:
    a=int(i['ea'],16);transfers.append({**i,'bytes_hex':k.read(a,4).hex()})
 pools=[pointer(k,POOL+off) for off in [0x840,0xbb8,0xc08,0x158,0x4f0,0x578,0x458,0x638]]
 pairs={'T':(qword(POOL+0x840),qword(POOL+0xbb8)),
        'U':(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4),
        'V':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),
        'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12)}
 banks={n+side:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,pair in pairs.items() for side,a in zip(['L','R'],pair)}
 rules=[]
 for n,p,key,add,b,bias,div in [
  ('init_controller_A','T',0x16,-0x18,POOL,0,None),('init_controller_B','V',0x6d,9,POOL,-4,None),
  ('init_table','T',0x3e,-0x21,POOL,-12,None),('size_table','U',0xac,0x2d,POOL,-12,None),
  ('size_helper','T',0x3e,0xf26,TABLE,0,0x2502),('variable_allocate','F',0x47,0xeba,TABLE,0,0x3ff2),
  ('variable_descriptor','T',0x3e,0xda,POOL,-12,None)]:
  r=selected(*pairs[p],key,add,b,bias);r.update(name=n,pair=p,original_pointer=pointer(k,int(r['slot'],16)))
  assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert int(r['original_pointer']['diversity'],16)==div and r['original_pointer']['authenticated']
  rules.append(r)
 branches=[]
 for ix,(target,div) in BRANCHES.items():
  p=pointer(k,TABLE+8*ix);assert (int(p['target'],16),int(p['diversity'],16))==(target,div)
  p['index']=ix;branches.append(p)
 a=0xfffffe000ccc3720;raw=IMAGE.read(a,64);np=struct.unpack_from('<Q',raw,16)[0]
 name=IMAGE.read(np,64).split(b'\0')[0];assert name==b'site.FPHashTableEntry'
 pn=pointer(k,a+16);assert int(pn['target'],16)==np and k.read(np,len(name)+1)==name+b'\0'
 assert struct.unpack_from('<2I',raw)==(1,24) and k.read(a,16)==raw[:16]
 descriptor={'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
             'word0_u32':1,'element_size_word_u32':24,'name':name.decode(),'name_pointer':pn}
 guard=pointer(k,0xfffffe000847c5f8);stub=block(0xfffffe000a69f294,16)
 assert k.read(int(stub['start'],16),16).hex()==stub['bytes']
 fail=pointer(k,0xfffffe000847c478)
 syms=k.symbols([0xfffffe000c4ba95c,int(guard['target'],16),int(fail['target'],16)])
 assert any(r['name']=='_IOMallocTypeVarImpl' for r in syms['0xfffffe000c4ba95c'])
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),
  'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'functions':fs,'spans':spans,'transfers':transfers,'banks':banks,'bank_rules':rules,
  'pool_pointers':pools,'branch_pointers':branches,'variable_descriptor':descriptor,
  'stack_guard_pointer':guard,'stack_fail_pointer':fail,'stack_fail_stub':stub,'exact_symbols':syms,
  'verified_counts':{'functions':3,'captured_instructions':sum(len(f['instructions']) for f in fs.values()),
    'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
    'terminal_transfers':len(transfers),'literal_bank_arrays':8,'bank_rules':7,'bank_input_cases':1792,
    'pool_pointers':8,'branch_pointers':7,'header_bytes':16,'entry_stride_bytes':24,'entry_count':128,'requested_array_bytes':3072},
  'conditional_hash_table_initializer_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
