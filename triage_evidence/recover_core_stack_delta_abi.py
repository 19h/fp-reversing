#!/usr/bin/env python3
"""Original three-call stack-delta adapter,seed/header ABI and preservation frontier."""
import json,re,struct,hashlib
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_versioned_request_abi import FLAGS
P='core_stack_delta_abi'
SCOPE='Source-bound resolution of three core private calls to one seed/header adapter,its exact16-byte delta encoding,bounded private allocation,inner header restoration and conditional zero-delta contracts. Full inner write/call/CFG preservation and native frame/transaction identity remain unproved.'
FUNCTIONS={'adapter':0xfffffe000a688ebc,'inner':0xfffffe000a687ee0,'probe_entry':0xfffffe000a5a1cc4,'probe_body':0xfffffe000a5a1ccc,'hardware_init':0xfffffe000a508030}
SPANS={'caller0':(0xfffffe000a63ccf0,0xfffffe000a63cd48),'caller1':(0xfffffe000a64396c,0xfffffe000a6439e4),'caller2':(0xfffffe000a643ffc,0xfffffe000a644074),'caller0_roots':(0xfffffe000a63cbf0,0xfffffe000a63cc0c),'return0':(0xfffffe000a63cd4c,0xfffffe000a63cd5c),'return1':(0xfffffe000a6439e8,0xfffffe000a6439f8),'return2':(0xfffffe000a644078,0xfffffe000a644088),'seed_selector':(0xfffffe000a636588,0xfffffe000a6365a4),'seed_publication':(0xfffffe000a63664c,0xfffffe000a63665c),'root_EL':(0xfffffe000a6352e8,0xfffffe000a6352f0),'root_ER':(0xfffffe000a635300,0xfffffe000a63530c),'save_EL':(0xfffffe000a6354f8,0xfffffe000a6354fc),'root_DL':(0xfffffe000a6353f8,0xfffffe000a635404),'root_DR':(0xfffffe000a635414,0xfffffe000a635420),'adapter_prefix':(0xfffffe000a688ed4,0xfffffe000a689010),'adapter_probe_args':(0xfffffe000a689010,0xfffffe000a68901c),'adapter_header_init':(0xfffffe000a689020,0xfffffe000a689034),'adapter_inner_call':(0xfffffe000a689034,0xfffffe000a6890b4),'adapter_output':(0xfffffe000a6890b8,0xfffffe000a6890c8),'adapter_restore_SP':(0xfffffe000a6890c8,0xfffffe000a6890cc),'inner_prefix':(0xfffffe000a687f14,0xfffffe000a687ffc),'inner_header_restore':(0xfffffe000a687ff0,0xfffffe000a687ffc),'inner_first_call':(0xfffffe000a68816c,0xfffffe000a6881dc),'probe_small_prefix':(0xfffffe000a5a1ccc,0xfffffe000a5a1cd4),'probe_small_read':(0xfffffe000a5a1cec,0xfffffe000a5a1cf4)}
DEPS=['context_descriptor_task_flow_source.json','context_descriptor_task_flow_checks.json','userclient_context_lifecycle_source.json','userclient_context_lifecycle_checks.json','kext_query_getter_values_source.json','kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','validate_context_descriptor_task_flow.py','validate_userclient_context_lifecycle.py','validate_daemon_list_output.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_container_origins.py','daemon_word_round_tools.py']
def inventory(f):
 ii=f['instructions'];stores=[i for i in ii if i['mnemonic'].startswith('st')];calls=[i for i in ii if i['mnemonic']in['bl','blr','blraa','blrab']];returns=[i for i in ii if i['mnemonic']in['ret','retab','retaa']]
 return {'store_instructions':stores,'call_instructions':calls,'return_instructions':returns,'scope':'Complete compiler-envelope syntactic inventory;not a store-footprint,alias,call-effect or path-closure proof.'}
def input_x1_audit(f):
 """Explore direct-branch CFG until the incoming X1 is defined;no target executes."""
 dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True;ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));at={i.address:i for i in ii};todo=[ii[0].address];seen=set();reads=[];escapes=[];definitions=[];returns=[]
 while todo:
  a=todo.pop()
  if a in seen:continue
  seen.add(a);i=at[a];rr,ww=i.regs_access();r={i.reg_name(x)for x in rr};w={i.reg_name(x)for x in ww}
  if i.mnemonic in['cmp','cmn','tst','ccmp','ccmn']:w={x for x in w if not re.fullmatch(r'[xw]\d+',x)}
  if{'x1','w1'}&r:reads.append(hex(a))
  if i.mnemonic in['bl','blr','blraa','blrab']:escapes.append(hex(a));continue
  if{'x1','w1'}&w:definitions.append(hex(a));continue
  if i.mnemonic in['ret','retab','retaa']:returns.append(hex(a));continue
  if i.mnemonic=='b':succ=[int(i.op_str[1:],0)]
  elif i.mnemonic.startswith(('b.','cb','tb')):succ=[i.address+4,int(i.op_str.rsplit('#',1)[1],0)]
  else:succ=[i.address+4]
  assert all(x in at for x in succ),(hex(a),succ);todo.extend(succ)
 assert not reads and not escapes
 return {'visited_instruction_sites':[hex(a)for a in sorted(seen)],'incoming_X1_reads':reads,'calls_before_incoming_X1_definition':escapes,'first_definitions':definitions,'early_returns':returns,'scope':'Original direct-branch control graph until X1 is overwritten or returns;callee internals after a new X1 value are outside this input-deadness fact.'}
def build():
 assert sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');fs={}
 for n,a in FUNCTIONS.items():
  f=function(k,e,a);raw=bytes.fromhex(f.pop('bytes_hex'));assert IMAGE.read(a,len(raw))==raw;f['bytes']=raw.hex();fs[n]=f
 ep=fs['adapter']['instructions'];assert[(i['mnemonic'],i['operands'])for i in ep[:6]]==[('pacibsp',''),('stp','x22, x21, [sp, #-0x30]!'),('stp','x20, x19, [sp, #0x10]'),('stp','x29, x30, [sp, #0x20]'),('add','x29, sp, #0x20'),('sub','sp, sp, #0x10')];assert[(i['mnemonic'],i['operands'])for i in ep[-5:]]==[('sub','sp, x29, #0x20'),('ldp','x29, x30, [sp, #0x20]'),('ldp','x20, x19, [sp, #0x10]'),('ldp','x22, x21, [sp], #0x30'),('retab','')]
 parent=json.loads(read(ROOT/'context_descriptor_task_flow_source.json'));old=parent['functions']['core26'];core=function(k,e,0xfffffe000a635208);assert core['sha256']==old['sha256']and bytes.fromhex(core['bytes_hex'])==bytes.fromhex(old['bytes'])and core['instructions']==old['instructions'];core['bytes']=core.pop('bytes_hex');fr={}
 for n,(a,z)in SPANS.items():
  f=next(f for f in list(fs.values())+[core]if int(f['start'],16)<=a<z<=int(f['end'],16));ii=[i for i in f['instructions']if a<=int(i['ea'],16)<z];assert len(ii)*4==z-a;fr[n]={'start':hex(a),'end':hex(z),'bytes':k.read(a,z-a).hex(),'instructions':ii}
 pairs={'A':(qword(POOL+0xb70),qword(POOL+0xa10)),'D':(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4),'E':(qword(POOL+0xc08)-8,qword(POOL+0x158)-4),'T':(qword(POOL+0x840),qword(POOL+0xbb8)),'F':(qword(POOL+0x458)-8,qword(POOL+0x638)-12)}
 banks={n+s:{'address':hex(a),'bytes':IMAGE.read(a,256).hex()}for n,lr in pairs.items()for s,a in zip(['L','R'],lr)};rules=[]
 for name,pair,key,add,base,bias in [('CALL_D','D',0xef,0xeea,TABLE,0),('CALL_A','A',0x92,0xea9,TABLE,0),('SEED_ROOT','E',0x98,-12,POOL,-4),('CTRL','T',0xb4,0x6e,POOL,0),('SHARED','A',0x32,-0xdd,POOL,-4),('SEED_UPDATE','F',0x47,0xe,POOL,-4),('INNER','T',0x3e,0xebb,TABLE,0),('TABLE','T',0x73,-0x14,POOL,-12),('HW','F',0x47,0xec5,TABLE,0),('INNER_CTRL','E',0x98,0x9a,POOL,-4),('INNER_SHARED','E',5,-0x11,POOL,-4)]:
  r=selected(*pairs[pair],key,add,base,bias);p=pointer(k,int(r['slot'],16));assert(int(p['target'],16)+bias)&((1<<64)-1)==int(r['target'],16);r.update(name=name,pair=pair,original_pointer=p);rules.append(r)
 assert rules[0]['target']==rules[1]['target']=='0xfffffe000a688ebc'and rules[2]['target']=='0xfffffe000ccc30c8'and rules[6]['target']=='0xfffffe000a687ee0'
 offs=[0xb70,0xa10,0x4f0,0x578,0xc08,0x158,0x840,0xbb8,0x458,0x638];pr=[pointer(k,POOL+o)for o in offs]+[pointer(k,0xfffffe000847c618)];syms=k.symbols([int(p['target'],16)for p in pr]+list(FUNCTIONS.values()))
 for p in pr:p['exact_symbols']=syms[p['target']]
 dc=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dc.detail=True;gap=[]
 for i in dc.disasm(k.read(0xfffffe000a63cc0c,0xfffffe000a63cd48-0xfffffe000a63cc0c),0xfffffe000a63cc0c):
  writes={i.reg_name(r)for r in i.regs_access()[1]}
  if i.mnemonic in['cmp','cmn','tst','ccmp','ccmn']:writes={r for r in writes if not re.fullmatch(r'[xw]\d+',r)}
  assert not writes&{'x22','w22','x26','w26','x28','w28'}
  if i.mnemonic in['bl','blraa']:gap.append({'site':hex(i.address),'kind':'ordinary callee-saved preservation required'})
 cp=SOURCE.parent/(SOURCE.name+'.c');lines=cp.read_text().splitlines();cx=[{'input_name':cp.name,'input_sha256':sha(cp),'first_line':a,'last_line':z,'text':'\n'.join(lines[a-1:z])}for a,z in[(233539,233563),(234407,234455)]];inv=inventory(fs['inner']);audit=input_x1_audit(fs['hardware_init'])
 counts={'captured_functions':len(fs),'captured_instructions':sum(len(f['instructions'])for f in fs.values()),'captured_code_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'recaptured_core_instructions':len(core['instructions']),'source_fragments':len(fr),'literal_bank_arrays':10,'bank_rules':len(rules),'bank_input_cases':256*len(rules),'pool_and_import_pointers':len(pr),'selected_call_sites':3,'inner_store_instructions':len(inv['store_instructions']),'inner_call_instructions':len(inv['call_instructions']),'inner_return_instructions':len(inv['return_instructions']),'hardware_X1_prefix_CFG_sites':len(audit['visited_instruction_sites'])}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n)for n in DEPS},'functions':fs,'fragments':fr,'banks':banks,'bank_rules':rules,'pointer_records':pr,'exact_symbols':syms,'core_recapture':{'parent_source':'context_descriptor_task_flow_source.json','start':core['start'],'end':core['end'],'sha256':core['sha256'],'instruction_count':len(core['instructions']),'complete_original_code_and_instruction_match':True,'caller0_root_preservation_gap_calls':gap},'inner_inventory':inv,'hardware_incoming_X1_audit':audit,'original_seed_word':{'address':'0xfffffe000ccc30c8','bytes':k.read(0xfffffe000ccc30c8,8).hex(),'source_image_u64':hex(qword(0xfffffe000ccc30c8)),'mutable_runtime_snapshot_not_a_constant':True},'associated_C':cx,'new_IDA_access':False,'semantic_memory_claims_used':0,'verified_source_counts':counts,**{n:False for n in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
