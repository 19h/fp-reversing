#!/usr/bin/env python3
"""Freeze schema payload to FPMessageAttr construction and kernel random ABI.
O(B+I+C*W+256R) construction/space; original inputs and IDBs remain read-only.
"""
import json,struct
from kext_port_tools import ROOT,IMAGE,CS,TABLE,POOL,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_schema_lookup_result as Parent
P='userclient_message_attributes';pc=Parent.pc
SCOPE='Conditional actual schema/table hit to site.FPMessageAttr typed allocation, 64 kernel-random requests, complete constructor and payload-dependent attribute overlay. Exact kernel random callback/request and return-mask source cuts; explicit allocator/random ordinary-return and owned-storage premises. Initial workspace status remains symbolic. Native allocation/provider effects, payload provenance/lifetime, transport and complete operation remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('attr_begin',0xa636958,0xa6369c8),('attr_bridge',0xa652df0,0xa652e34),('attr_allocate',0xa652e34,0xa652ed0),('attr_allocate_return',0xa652ed0,0xa652f18),
 ('attr_initial_header',0xa652f18,0xa652f70),('attr_first_random_request',0xa652f70,0xa652fc0),('attr_first_random_return',0xa652fc0,0xa653010),
 ('attr_second_random_request',0xa653010,0xa653060),('attr_second_random_return',0xa653060,0xa6530b0),('attr_constructor_finish',0xa6530b0,0xa653150),('attr_constructor_return',0xa653150,0xa65316c),
 ('attr_caller_return',0xa6369c8,0xa636a1c),('attr_caller_nonnull',0xa636a1c,0xa636a74),('attr_copy16_mode',0xa636a74,0xa636b4c),('attr_nonzero_mode',0xa636b4c,0xa636b68),
 ('attr_copy32',0xa636b68,0xa636ccc),('attr_reload_payload',0xa636ccc,0xa636ce4),('attr_copy_header',0xa636ce4,0xa636d34),('attr_error',0xa641af8,0xa641b3c),
 ('random_enter_provider',0xbf09e48,0xbf09e68),('random_generate_provider',0xbf09e68,0xbf09e8c),('random_mask_return',0xbf09e8c,0xbf09e94)]}
BRANCHES=Parent.BRANCHES|{pc(k):v for k,v in {0xa6369a8:[0x7ec],0xa652e14:[0x1f1],0xa652e20:[0xa2f],0xa652f00:[0x4c3,0x4fd],0xa652f44:[0x3fc],0xa653004:[0x3fc,0x430],0xa6530a4:[0x430,0x918],0xa653124:[0x4c3],0xa6369ec:[0xc54,0xc7f],0xa636a5c:[0xa73,0xadb],0xa636b40:[0xb73,0xb7c],0xa636b5c:[0x3ad],0xa636cb4:[0xd5b,0xd75],0xa636cd8:[0x3ad],0xa636d14:[0xcf1],0xa641b2c:[0x41f]}.items()}
BANK_PCS={'allocate':(pc(0xa652e64),pc(0xa652e74),pc(0xa652e90)),'descriptor':(pc(0xa652e9c),pc(0xa652ea8),pc(0xa652ec0)),'random_first':(pc(0xa652f90),pc(0xa652fa0),pc(0xa652fb4)),'random_second':(pc(0xa653030),pc(0xa65303c),pc(0xa653054))}
ROOTS=[(0x670,8,'C',0x90),(0x678,8,'C',0x1b0),(0xa10,8,'literal',pc(0x7949fd0)),(0xa18,8,'literal',pc(0x792ffc0)),(0xa40,8,'literal',pc(0x792fbc0)),(0xa00,8,'literal',pc(0x792fcc0)),(0xa20,8,'literal',pc(0x79391f0)),(0x50c,4,'literal',0x987edcfb),(0x524,4,'encoded_extent',0),(0x740,8,'C',0x360),(0x8f8,8,'original_input',0)]
FALSE=Parent.FALSE+['native_random_provider_executed','native_attribute_object_identity_established','native_payload_type_established','attribute_padding_initialized','native_full_message_completed']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_schema_lookup_result_checks.json'));assert prior==Parent.build();parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));spans=[]
 for label,(a,z)in SPANS.items():
  raw=k.read(a,z-a)
  if a<pc(0xb000000):assert IMAGE.read(a,z-a)==raw
  ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[];banks={}
 for name,L,R,key,add,base,bias in [('allocate',pc(0x7949fd0),pc(0x792ffc0),0xac,0xf0d,TABLE,0),('descriptor',pc(0x792fcc0),pc(0x79391f0),0x87,-0x14,POOL,-12),('random_first',pc(0x7949dd0),pc(0x792fbc0),0xd8,0xf28,TABLE,0),('random_second',pc(0x7941f60),pc(0x794a0d0),0x98,0xeb3,TABLE,0)]:
  r=selected(L,R,key,add,base,bias);r.update(name=name,left_name=name+'_L',right_name=name+'_R',original_pointer=pointer(k,int(r['slot'],16)));rules.append(r)
  for side,a in [('L',L),('R',R)]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[name+'_'+side]={'address':hex(a),'bytes_hex':raw.hex()}
  assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 a=pc(0x847b1e0);raw=IMAGE.read(a,64);namep,sigp=struct.unpack_from('<Q',raw,16)[0],struct.unpack_from('<Q',raw,32)[0];name=IMAGE.read(namep,64).split(b'\0')[0];sig=IMAGE.read(sigp,64).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40);assert(name,sig,flags,size)==(b'site.FPMessageAttr',b'',0x6c,112)
 for at,want in [(namep,name+b'\0'),(sigp,sig+b'\0'),(a+40,raw[40:48])]:assert k.read(at,len(want))==want
 descriptor={'address':hex(a),'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'original64_bytes_hex':k.read(a,64).hex(),'normalized64_bytes_hex':raw.hex(),'name_pointer':pointer(k,a+16),'signature_pointer':pointer(k,a+32)}
 random=k.function(pc(0xbf09e30));assert random['sha256']=='87f398b6e41e9ea2714e346f572f1bf38b22ee4f9811044c8a7453754aef2891';symbols=k.symbols([pc(0xbf09e30),pc(0xc4ba154),pc(0x7e6c9a0),pc(0xcb88f48)])
 assert any(q['name']=='_random'for q in symbols[hex(pc(0xbf09e30))]);adapter=k.function(pc(0xc4ba154));rows=[]
 for p in prior['predecessor_states']:
  r=parents['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);g=[int(v,16)for v in p['handoff_state']['registers31']];C=g[11];cells=[];I=int(r['input']['inputs8'][0],16)if isinstance(r['input']['inputs8'][0],str)else r['input']['inputs8'][0];N=int(r['input']['inputs8'][1],16)if isinstance(r['input']['inputs8'][1],str)else r['input']['inputs8'][1]
  for off,n,kind,value in ROOTS:
   want=C+value if kind=='C'else (N&0xffffffff)^0x31ae0066 if kind=='encoded_extent'else I if kind=='original_input'else value;state=[None]*n;touches=[]
   for w in r['source_writes']:
    at=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(at,F+off);hi=min(at+len(b),F+off+n)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-F-off]=b[addr-at]
   assert None not in state and int.from_bytes(bytes(state),'little')==want,(hex(off),kind);cells.append({'root':'F','offset':hex(off),'size_bytes':n,'source_role':kind,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches})
  unknown=[w for w in r['source_writes']if int(w['address'],16)<=g[3]+0xd0c<int(w['address'],16)+w['size_bytes']];assert not unknown;rows.append({**p,'attribute_additional_source_cells':cells,'original_input64':hex(I),'original_extent32':N&0xffffffff,'initial_workspace_d0c_defined_by_prefix':False})
 names=set(prior['dependencies'])|{'recover_userclient_schema_lookup_result.py','audit_userclient_schema_lookup_result.py','userclient_schema_lookup_result_checks.json','userclient_schema_lookup_result_audit.json','recover_secure_tunnel_allocation.py','secure_tunnel_allocation_checks.json','secure_tunnel_allocation_audit.json'}
 return {**prior,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'lookup_result_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'attribute_banks':banks,'attribute_bank_rules':rules,'attribute_descriptor':descriptor,'attribute_allocator_adapter':adapter,'kernel_random_function':random,'kernel_random_symbols':symbols,'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(rows),'additional_source_cells_per_state':len(ROOTS),'additional_source_cell_bytes_per_state':sum(q[1]for q in ROOTS),'new_bank_rules':4,'new_bank_input_cases':1024,'attribute_extent_bytes':112,'attribute_written_bytes':107,'attribute_untouched_bytes':5,'random_calls_per_successful_constructor':64,'minimum_payload_read_extent_bytes':56},'conditional_message_attribute_contract_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
