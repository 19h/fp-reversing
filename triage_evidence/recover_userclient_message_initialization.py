#!/usr/bin/env python3
"""Freeze FPMessage formation, byte-fill interface and parser re-entry.
O(B+I+C*W+1536) extraction time/space; original inputs remain read-only.
"""
import json,struct
from hashlib import sha256
from kext_port_tools import ROOT,IMAGE,CS,TABLE,POOL,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_message_attributes as Parent
P='userclient_message_initialization';pc=Parent.pc
SCOPE='Conditional actual source-built FPMessageAttr to 128-byte site.FPMessage allocation, complete selected initialization, fixed 16-byte XOR transform and handoff into the common FPTTLV parser. Source-proved 32-byte local zero-fill summary, allocation-NULL error publication and independent all-extent caller gate. Native allocation/PAC/provider effects, message ownership, input-layer identity, parsing completion and transport remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [('message_entry',0xa6575b0,0xa65764c),('message_after_clear',0xa65764c,0xa6576b8),('message_allocate',0xa6576b8,0xa65775c),('message_after_allocate',0xa65775c,0xa6577c4),('message_gate',0xa6577c4,0xa657810),('message_zero0',0xa657810,0xa657828),('message_gate8',0xa657828,0xa657864),('message_zero8',0xa657864,0xa65787c),('message_attr_gate',0xa65787c,0xa6578b8),('message_attr_entry',0xa657904,0xa657940),('message_copy_entry',0xa653874,0xa6538d8),('message_copy_fields',0xa6538d8,0xa653b8c),('message_copy16',0xa653b8c,0xa653c94),('message_flags',0xa653c94,0xa653d18),('message_flags_length',0xa653d18,0xa653d4c),('message_flag_one',0xa653d4c,0xa653d64),('message_copy_return',0xa653d64,0xa653d74),('message_bridge',0xa653e54,0xa653e78),('message_parser_prepare',0xa656b74,0xa656bc0),('message_parser_extent',0xa656bc0,0xa656be8),('message_parser_request',0xa656be8,0xa656c08),('message_early_return',0xa665154,0xa66516c),('message_outer_return',0xa636d34,0xa636dac),('message_error',0xa641af8,0xa641b3c)]}
BRANCHES={pc(a):js for a,js in {0xa6575c0:[0x131],0xa6576a0:[0xaed,0xafe],0xa6577b4:[0x9c9,0x9cb],0xa657804:[0xb3b,0xb40],0xa65781c:[0x9de],0xa657858:[0x92b],0xa657870:[0x320],0xa6578ac:[0xe95],0xa657928:[0x30e],0xa653894:[0xfc],0xa6538c0:[0xef5],0xa653b38:[0x28f],0xa653c84:[0x28f,0x2d3],0xa653cd8:[0xe4e],0xa653d40:[0xe11,0xdfb],0xa653d58:[0xdfb],0xa653e6c:[0xccd],0xa656ba4:[0xc8a],0xa656bd4:[0xd68],0xa656bf4:[0x89b],0xa636d70:[0x44d],0xa641b2c:[0x41f]}.items()}
RULES=[('clear',0xa657614,0xa657620,0xa657634,0x7949ed0,0x792fec0,0x92,0xe48,TABLE,0),('allocate',0xa6576ec,0xa6576fc,0xa657714,0x792fcc0,0x79391f0,0x47,0xe98,TABLE,0),('descriptor',0xa657724,0xa657734,0xa65774c,0x7949fd0,0x792ffc0,0xef,0x3b,POOL,-12),('mask1',0xa653bbc,0xa653bc4,0xa653bdc,0x7949ed0,0x792fec0,0x32,0xe3,POOL,0),('mask2',0xa653bf4,0xa653bfc,0xa653c10,0x7941f60,0x794a0d0,0x98,-0x8b,POOL,0),('mask3',0xa653c28,0xa653c34,0xa653c44,0x792fcc0,0x79391f0,0x47,0xdd,POOL,0)]
ROOTS=[(0x6b8,'C',0x498),(0x3e8,'S',0xcc8),(0xa38,'literal',pc(0xccc32f8)),(0xa50,'literal',pc(0x7941f60)),(0xa58,'literal',pc(0x794a0d0))]
FALSE=Parent.FALSE+['native_message_identity_established','whole_message_parse_completed','message_padding_initialized','new_native_transport_identity_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_message_attributes_checks.json'));assert prior==Parent.build();originals=json.loads(read(ROOT/'userclient_early_data_checks.json'));spans=[]
 for name,(a,z)in SPANS.items():
  raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert 4*len(ii)==len(raw);spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[];banks={}
 for name,lp,rp,pp,l,r,key,add,base,bias in RULES:
  L,R=pc(l),pc(r);q=selected(L,R,key,add,base,bias);q.update(name=name,left_PC=hex(pc(lp)),right_PC=hex(pc(rp)),pointer_PC=hex(pc(pp)),original_pointer=pointer(k,int(q['slot'],16)));assert(int(q['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(q['target'],16);rules.append(q)
  for side,a in [('L',L),('R',R)]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[name+'_'+side]={'address':hex(a),'bytes_hex':raw.hex()}
 arrays=[]
 for name,a in [('mask1',pc(0x7945f20)),('mask2',pc(0x7942886)),('mask3',pc(0x7932064))]:
  raw=k.read(a,16);assert raw==IMAGE.read(a,16);arrays.append({'name':name,'start':hex(a),'size_bytes':16,'bytes_hex':raw.hex()})
 mask=bytes((((j-15)*-0x37-0x39)&255)^bytes.fromhex(arrays[0]['bytes_hex'])[j]^bytes.fromhex(arrays[1]['bytes_hex'])[j]^bytes.fromhex(arrays[2]['bytes_hex'])[j]^0x70 for j in range(16));assert mask.hex()=='e43a4ec1536f29ded6b30e155e083e20'
 a=pc(0x847b560);raw=IMAGE.read(a,64);np,sp=struct.unpack_from('<Q',raw,16)[0],struct.unpack_from('<Q',raw,32)[0];name=IMAGE.read(np,64).split(b'\0')[0];sig=IMAGE.read(sp,64).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40);assert(name,sig,flags,size)==(b'site.FPMessage',b'1122222222222222',0x64,128)
 for at,b in [(np,name+b'\0'),(sp,sig+b'\0'),(a+40,raw[40:48])]:assert k.read(at,len(b))==b
 descriptor={'address':hex(a),'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),'name_pointer':pointer(k,a+16),'signature_pointer':pointer(k,a+32)}
 a,z=pc(0xa687d64),pc(0xa687ecc);raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);zero={'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'sha256':sha256(raw).hexdigest(),'captured_words':len(raw)//4,'scope':'Only zero value and exactly32 bytes, all eight destination alignments; no generic memset-return claim.'};rows=[]
 for p in prior['predecessor_states']:
  r=originals['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);regs=[int(v,16)for v in p['handoff_state']['registers31']];C,S=regs[11],regs[3];cells=[]
  for off,root,value in ROOTS:
   want=C+value if root=='C'else S+value if root=='S'else value;b=[None]*8;touch=[]
   for w in r['source_writes']:
    at=int(w['address'],16);data=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+off),min(at+len(data),F+off+8)
    if lo<hi:
     touch.append(w)
     for j in range(lo,hi):b[j-F-off]=data[j-at]
   assert None not in b and int.from_bytes(bytes(b),'little')==want;cells.append({'root':'F','offset':hex(off),'size_bytes':8,'source_role':root,'reconstructed_bytes_hex':bytes(b).hex(),'overlapping_source_stores':touch})
  rows.append({**p,'message_additional_source_cells':cells})
 deps=set(prior['dependencies'])|{'recover_userclient_message_attributes.py','audit_userclient_message_attributes.py','userclient_message_attributes_checks.json','userclient_message_attributes_audit.json'}
 return {**prior,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'attribute_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]},'message_bank_rules':rules,'message_banks':banks,'message_mask_arrays':arrays,'message_mask16_hex':mask.hex(),'message_descriptor':descriptor,'zero_helper_envelope':zero,'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(s['instructions'])for s in spans),'original_table_pointers':len({j for js in BRANCHES.values()for j in js}),'predecessor_states':len(rows),'additional_source_cells_per_state':5,'additional_source_cell_bytes_per_state':40,'new_bank_rules':6,'new_bank_input_cases':1536,'zero_helper_captured_words':zero['captured_words'],'zero_helper_bytes':32,'message_extent_bytes':128,'message_written_bytes':123,'message_unwritten_bytes':5,'fixed_mask_bytes':16},'conditional_message_initialization_contract_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
