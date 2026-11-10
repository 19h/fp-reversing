#!/usr/bin/env python3
"""Pin the missing86-phase bridge and audit the bounded captured-source inventory."""
import collections,json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
from validate_daemon_list_output import split
from recover_daemon_mode_one_output_verification import logical_mask
P='daemon_mode_one_second_phase_handoff'
SCOPE='Source-proved86 equality/complementary bank repack and set-bit workspace handoff;selected reentry preservation and captured-artifact budget/control coverage limits. No whole-core budget preservation,native return,algorithm identity or daemon-kext transport claim.'
BLOCKS={'round_gate':0x100cad378,'first_equal':0x100cec684,'first_repack':0x100db4af0,'second_equal':0x100dc9674,'second_repack':0x100b74ff4,'phase_gate':0x100c4c834,'workspace':0x100d9d804,'advance':0x100c8df0c}
EDGES={'round_gate':[0x2aca,0x2ac4],'first_equal':[0x56a0,0x32ff],'first_repack':[0x30fa],'second_equal':[0x3305,0x32ff],'second_repack':[0x30fa],'phase_gate':[0x6284,0x8aaf],'workspace':[0x7a8c,0x7acf],'advance':[0x30fa,0x3146]}
INVENTORY=['daemon_mode_one_adapter_source.json', 'daemon_mode_one_bank_combine_source.json', 'daemon_mode_one_carry_table_source.json', 'daemon_mode_one_digit_maps_source.json', 'daemon_mode_one_encoded_addition_source.json', 'daemon_mode_one_even_view_import_source.json', 'daemon_mode_one_inverse_tables_source.json', 'daemon_mode_one_lookup_bounds_source.json', 'daemon_mode_one_lookup_roles_source.json', 'daemon_mode_one_nibble_operation_suite_source.json', 'daemon_mode_one_output_verification_source.json', 'daemon_mode_one_parity_state_adapters_source.json', 'daemon_mode_one_phase_handoff_source.json', 'daemon_mode_one_plane_consumer_source.json', 'daemon_mode_one_post_table_passes_source.json', 'daemon_mode_one_record_adder_source.json', 'daemon_mode_one_record_checkpoint_source.json', 'daemon_mode_one_record_codecs_source.json', 'daemon_mode_one_record_input_planes_source.json', 'daemon_mode_one_record_join_source.json', 'daemon_mode_one_record_long_planes_source.json', 'daemon_mode_one_record_long_prefix_source.json', 'daemon_mode_one_record_passes_source.json', 'daemon_mode_one_record_permutation_source.json', 'daemon_mode_one_record_reentry_source.json', 'daemon_mode_one_record_rescan_source.json', 'daemon_mode_one_record_rounds_source.json', 'daemon_mode_one_record_scan_source.json', 'daemon_mode_one_record_word_extension_source.json', 'daemon_mode_one_record_word_gather_source.json', 'daemon_mode_one_result_publication_source.json', 'daemon_mode_one_scatter_source.json', 'daemon_mode_one_secondary_reentry_source.json', 'daemon_mode_one_secondary_rounds_source.json', 'daemon_mode_one_secondary_word_extension_source.json', 'daemon_mode_one_secondary_word_import_source.json', 'daemon_mode_one_source_absorption_source.json', 'daemon_mode_one_source_passes_source.json', 'daemon_mode_one_state_materialization_source.json', 'daemon_mode_one_word_mix_source.json', 'daemon_mode_one_word_rounds_source.json', 'daemon_mode_one_word_schedule_source.json', 'daemon_mode_one_word_xor_plane_refresh_source.json', 'daemon_mode_one_workspace_passes_source.json', 'daemon_mode_one_workspace_state_install_source.json']
CHECKS=['daemon_mode_one_phase_handoff_checks.json','daemon_mode_one_state_materialization_checks.json','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_plane_consumer_checks.json','daemon_mode_one_word_schedule_checks.json','daemon_mode_one_word_rounds_checks.json','daemon_mode_one_adapter_checks.json']
DEPS=INVENTORY+CHECKS+['validate_daemon_mode_one_result_publication.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','recover_daemon_mode_one_output_verification.py','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;isa=[];corrections=[];census={}
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);ii=list(dc.disasm(raw,int(f['start'],16)));assert len(ii)*4==len(raw);control=[]
  for i in ii:
   p=split(i.op_str);m=i.mnemonic;w=int.from_bytes(i.bytes,'little');width=64 if w>>31 else 32;writes={i.reg_name(r)for r in i.regs_access()[1]}
   if m in['cmp','cmn']:
    bad=sorted(v for v in writes if re.fullmatch('[wx][0-9]+',v))
    if bad:corrections.append({'site':hex(i.address),'Capstone_GPR_writes':bad,'architectural_GPR_writes':[]})
    writes-=set(bad)
   assert 'sp'not in writes
   row=None
   if m=='lsl'and not p[2].startswith('#'):
    assert w&0x7fe0fc00==0x1ac02000 and[int(v[1:])for v in p]==[w&31,(w>>5)&31,(w>>16)&31];row={'kind':'register_LSL','width_bits':width,'shift_mask':width-1}
   if m in['and','orr']and p[2].startswith('#'):
    assert w&0x7f800000=={'and':0x12000000,'orr':0x32000000}[m]and w&31==int(p[0][1:])and(w>>5)&31==int(p[1][1:])and logical_mask(w)==int(p[2][1:],0);row={'kind':'logical_immediate','operation':m,'width_bits':width,'mask':hex(logical_mask(w))}
   if m=='adrp':
    assert w&0x9f000000==0x90000000;imm=((w>>5&0x7ffff)<<2)|(w>>29&3);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert target==int(p[1][1:],0);row={'kind':'ADRP','page_target':hex(target)}
   if m in['stur','ldur']:
    imm=(w>>12)&511;imm=imm-512 if imm&256 else imm;assert imm==int(p[1].split('#')[-1].strip(']'),0);row={'kind':'unscaled_access','operation':m,'immediate_s9':imm}
   if row:isa.append({'site':hex(i.address),'bytes':i.bytes.hex(),**row})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','hvc','smc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert control==['braa'];census[n]=dict(collections.Counter(i.mnemonic for i in ii))
 slots=set();edges=[]
 for n,indices in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix in indices:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and(w>>32)&65535==mod and not(w>>48&7);slots.add(a);edges.append({'fragment':n,'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target']),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(a,8).hex()})
 parent=json.loads(read(ROOT/'daemon_mode_one_phase_handoff_source.json'));roots=parent['codec_roots']
 for r in roots:
  a=int(r['slot'],16);assert IMAGE.read(a,8).hex()==r['raw_bytes']and FIXUPS[a]==r['fixup'];raw=bytes.fromhex(r['bytes']);assert IMAGE.read(int(r['target'],16),len(raw))==raw;slots.add(a)
 ranges={};instructions={};rec=[]
 for name in INVENTORY:
  old=json.loads(read(ROOT/name));fragments=old.get('fragments',{})
  for label,f in fragments.items():
   if not isinstance(f,dict)or'instructions'not in f or'bytes'not in f:continue
   a=int(f['start'],16);raw=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(raw))==raw;rec.append({'source':name,'fragment':label,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
   ranges.setdefault((a,a+len(raw)),[]).append({'source':name,'fragment':label})
   for i in f['instructions']:
    pc=int(i['ea'],16)
    if pc in instructions:assert instructions[pc]['mnemonic']==i['mnemonic']and instructions[pc]['operands']==i['operands']
    instructions[pc]=i
 census_sp=[];census_calls=[];census_stores=[]
 for pc,i in sorted(instructions.items()):
  raw=IMAGE.read(pc,4);dec=list(dc.disasm(raw,pc));assert len(dec)==1 and dec[0].mnemonic==i['mnemonic']and dec[0].op_str==i['operands'];d=dec[0];m=i['mnemonic'];ww={d.reg_name(r)for r in d.regs_access()[1]}
  if 'sp'in ww and m not in['cmp','cmn','tst']:census_sp.append(i)
  if m in['bl','blraa','blr','blrab']:census_calls.append(i)
  if m.startswith('st'):census_stores.append(i)
 locator={'scope':'Pinned45-artifact instruction union includes core,adapter and outer-caller frames. It is a locator inventory,not whole-program control/store coverage. Unrepresented targets,epochs,aliases and saved continuations must be analyzed separately.','artifacts':len(INVENTORY),'distinct_ranges':len(ranges),'distinct_instruction_sites':len(instructions),'unique_bytes':4*len(instructions),'candidate_store_sites':len(census_stores),'SP_write_sites':census_sp,'call_sites':census_calls,'range_ledger':[{'start':hex(a),'end':hex(b),'sha256':h(IMAGE.read(a,b-a)),'owners':v}for(a,b),v in sorted(ranges.items())],'source_sha256':{n:sha(ROOT/n)for n in INVENTORY}}
 pointers=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_bindings':len(edges),'pointer_records':len(pointers),'ISA_decodes_checked':len(isa),'comparison_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'locator_artifacts':len(INVENTORY),'locator_distinct_ranges':len(ranges),'locator_distinct_instruction_sites':len(instructions),'locator_candidate_store_sites':len(census_stores),'SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'image_name':SOURCE.name,'image_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fs,'branch_edges':edges,'pointer_records':pointers,'original_fixup_checks':verify_original_fixups(slots),'codec_roots':roots,'ISA_decode_checks':isa,'comparison_role_corrections':corrections,'mnemonic_census':census,'prior_recaptures':rec,'captured_artifact_locator_inventory':locator,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
