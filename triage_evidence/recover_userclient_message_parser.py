#!/usr/bin/env python3
"""Freeze the FPMessage parser epoch and caller-qualified completion interface.
O(I+256R+B) extraction time/space; original inputs are read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,POOL,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_userclient_entry_execution import descriptor
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_message_initialization as Parent
P='userclient_message_parser';pc=Parent.pc
SCOPE='Actual source-built FPMessage handoff through the second FPTTLV allocation, nullable result routing, new-container initialization and pending first raw-input read. Independent completion-interface cuts establish message+0 publication, caller-tag dispatch, all-status routing and source-built message+0x60 consumption. Completion cuts are not a completed second parse; input bytes, native ownership/PAC and transport identity remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('parser_entry',0xa636338,0xa636408),('parser_result',0xa636408,0xa6366ac),
 ('parser_zero',0xa6366ac,0xa6366e0),('parser_cursor',0xa660af4,0xa660b2c),
 ('parser_next',0xa660c28,0xa660c80),('parser_header',0xa660c80,0xa660d68),
 ('parser_header_address',0xa660d68,0xa660dcc),
 ('completion_exhaustion',0xa660b2c,0xa660b64),('completion_publish',0xa660b64,0xa660b88),
 ('completion_tag1',0xa660b88,0xa660bb8),('completion_tag2',0xa660bb8,0xa660bc8),
 ('completion_tag3',0xa660bc8,0xa660bd8),('completion_status',0xa661144,0xa661180),
 ('completion_flag',0xa661180,0xa6611e4)]}
# A left observation may feed two right-bank lookups with different keys.
RULES=[(0xa6363a4,0xa6363b0,0x7949dd0,0x792fbc0,0x5c),
 (0xa6363d8,0xa6363e4,0x7949ed0,0x792fec0,0x32),
 (0xa636470,0xa63647c,0x7949ed0,0x792fec0,0x32),
 (0xa6364ac,0xa6364b8,0x7949dd0,0x792fbc0,0x16),
 (0xa6364ac,0xa6364d4,0x7949dd0,0x792fbc0,0xd8),
 (0xa636500,0xa63650c,0x7949dd0,0x792fbc0,0x5c),
 (0xa636530,0xa63653c,0x7949ed0,0x792fec0,0x32),
 (0xa636560,0xa63656c,0x7941f60,0x794a0d0,0x05),
 (0xa63658c,0xa636598,0x7941f60,0x794a0d0,0x98),
 (0xa6365c4,0xa6365d4,0x7941f60,0x794a0d0,0x05),
 (0xa6365f4,0xa636604,0x7949fd0,0x792ffc0,0x37)]
LITERALS={pc(a):base+8*j for a,base,j in [
 (0xa6363c0,TABLE,0xf13),(0xa6363d0,POOL,0x16e),(0xa6363e0,POOL,0x142),
 (0xa6363f8,POOL,0x200),(0xa63648c,POOL,0x11c),(0xa6364c8,POOL,0x179),
 (0xa6364ec,POOL,0x183),(0xa63651c,POOL,0xe1),(0xa63654c,POOL,0x155),
 (0xa63657c,POOL,0x162),(0xa6365a8,POOL,0x23),(0xa6365e4,POOL,0x157),
 (0xa636614,POOL,0x112),(0xa636624,POOL,0x56),(0xa636634,POOL,0x138),
 (0xa636644,POOL,0x111),(0xa636650,POOL,0x89),(0xa63665c,POOL,0x8b),
 (0xa636664,POOL,0xc7)]}
BRANCHES={pc(a):js for a,js in [
 (0xa636448,[0x68e,0x693]),(0xa6366cc,[0x4a2]),(0xa660b20,[0xc89,0xcd0]),
 (0xa660c68,[0x69c,0x6a2]),(0xa660d54,[0x6a2,0x6bb]),
 (0xa660b50,[0x6c7]),(0xa660b74,[0x693]),
 (0xa661174,[0x75,0x2ce]),(0xa6611c4,[0x2b4,0xdd2])]}
DIRECT={pc(a):(m,pc(t))for a,m,t in [(0xa660bb4,'b.eq',0xa66128c),(0xa660bc4,'b.eq',0xa661144),(0xa660bd4,'b.ne',0xa636310)]}
FALSE=['native_target_executed','idb_mutated','continuous_guest_extended','whole_message_parse_completed','input_content_custody_established','native_transport_identity_established','native_parser_ownership_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));assert prior==Parent.build();spans=[]
 for name,(a,z)in SPANS.items():
  raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 rules=[];banks={}
 for lp,rp,l,r,key in RULES:
  q=selected(pc(l),pc(r),key,0,POOL,0);rules.append({n:q[n]for n in ['left','right','key','constant','inputs_checked']}|{'left_PC':hex(pc(lp)),'right_PC':hex(pc(rp))})
  for a in [pc(l),pc(r)]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[hex(a)]=raw.hex()
 deps=['recover_userclient_message_initialization.py','audit_userclient_message_initialization.py','userclient_message_initialization_checks.json','userclient_message_initialization_audit.json']
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in deps},'source':{'container':prior['source']['container'],'spans':spans,'literal_pointers':[{'source_PC':hex(p),'slot':hex(a),'original_pointer':pointer(k,a)}for p,a in LITERALS.items()],'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]},'bank_rules':rules,'banks':banks,'container_descriptor':descriptor(k,pc(0x847bb60)),'parent_profiles':['mode_zero_success','mode_nonzero_success'],'completion_cut_premises':{'cursor_exhaustion_executed':False,'input_bytes_supplied':0,'register_inputs':{'X2':'retained C','X4':'retained S','X7':hex(TABLE),'W1':hex(0x7795e642),'W3':hex(0x886a1ca3),'W22':hex(0x7795e3ce),'X28':hex(pc(0x7949dd0))},'status_cut':'W23 arbitrary u32; source-retained caller tag; no publication assumed','exhaustion_cut':'W12=0x69c and W30=SUCCESS at 0xfffffe000a660b2c; source emits SUCCESS and publication index, without executing record parsing'},'composition_boundary':'0xfffffe000a654ae4','verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'bank_rules':len(rules),'certified_bank_inputs':256*len(rules),'original_literal_pointers':len(LITERALS),'original_branch_pointers':len({j for js in BRANCHES.values()for j in js}),'parent_profiles':2,'container_extent_bytes':16,'input_content_bytes_supplied':0},'conditional_message_parser_interfaces_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
