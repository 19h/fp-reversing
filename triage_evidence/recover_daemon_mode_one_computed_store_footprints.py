#!/usr/bin/env python3
"""Recapture ten original computed stores and their finite epoch contracts."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_mode_one_computed_store_footprints'
SCOPE='Fresh source models and exact finite byte footprints for ten formerly premise-only computed stores:two48-iteration four-word expansions and one32-iteration two-byte absorption. Root,entry ABI,epoch and counter domains remain explicit;164 other array sites,236 alias sites,whole control closure,native owners/return and transport pairing remain unproved.'
SPECS=[{'phase':'record','parent':'daemon_mode_one_record_word_extension','root':0x8b0,'multiplier':227,'modulus':280,'labels':[227,159,16,87],'iterations':48,'width_bytes':4,'sites':['0x100c55de4','0x100c565ec','0x100c56dbc','0x100c56eac']},{'phase':'secondary','parent':'daemon_mode_one_secondary_word_extension','root':0xc80,'multiplier':241,'modulus':286,'labels':[88,16,158,228],'iterations':48,'width_bytes':4,'sites':['0x100c50dd0','0x100c50f1c','0x100c524c4','0x100c525bc']},{'phase':'absorption','parent':'daemon_mode_one_source_absorption','root':0xd00,'multiplier':757,'modulus':963,'labels':[40,112],'iterations':32,'width_bytes':1,'sites':['0x100bd7a4c','0x100bd7ae4']}]
DEPS=[n+'_'+k+'.json'for n in[r['parent']for r in SPECS]for k in['source','checks']]+['daemon_mode_one_budget_store_audit_source.json','daemon_mode_one_budget_store_audit_checks.json','validate_daemon_mode_one_record_word_extension.py','validate_daemon_mode_one_secondary_word_extension.py','validate_daemon_mode_one_source_absorption.py','validate_daemon_mode_one_record_join.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_state_materialization.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);fs={};stores=[];catalogue=json.loads(read(ROOT/'daemon_mode_one_budget_store_audit_source.json'));old={r['ea']:r for r in catalogue['source_store_catalogue']};assert sum(r['category']=='retained_computed_array_contract'for r in old.values())==174
 for spec in SPECS:
  src=json.loads(read(ROOT/(spec['parent']+'_source.json')));cc=json.loads(read(ROOT/(spec['parent']+'_checks.json')));assert cc['all_checks_pass']
  for name,f in src['fragments'].items():
   raw=bytes.fromhex(f['bytes']);a=int(f['start'],16);assert IMAGE.read(a,len(raw))==raw;ii=list(dc.disasm(raw,a));assert len(ii)*4==len(raw);assert[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]==f['instructions'];fs[spec['phase']+'_'+name]={**f,'parent_source':spec['parent']+'_source.json','sha256':h(raw)}
  for pc,label in zip(spec['sites'],spec['labels']):
   row=old[pc];assert row['category']=='retained_computed_array_contract';raw=IMAGE.read(int(pc,16),4);w=int.from_bytes(raw,'little');assert row['raw_bytes']==raw.hex()and row['mnemonic']==('str'if spec['width_bytes']==4 else'strb')
   assert w&0x3b000000 in[0x39000000,0x38000000]and not w&(1<<26)and (w>>22)&3==0 and 1<<(w>>30)==spec['width_bytes']
   stores.append({'phase':spec['phase'],'site':pc,'label':label,'width_bytes':spec['width_bytes'],'original_bytes':raw.hex(),'original_mnemonic':row['mnemonic'],'original_operands':row['operands'],'prior_category':row['category']})
 counts={'source_ranges':len(fs),'source_instructions_recaptured':sum(len(f['instructions'])for f in fs.values()),'source_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'computed_store_sites_source_bound':len(stores),'word_store_sites':8,'byte_store_sites':2,'finite_store_instances':448,'finite_byte_write_operations':1600,'array_sites_remaining_without_new_footprint':164}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'image_name':SOURCE.name,'image_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fs,'phase_specs':SPECS,'store_source_ledger':stores,'verified_source_counts':counts,'new_IDA_access':False,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
