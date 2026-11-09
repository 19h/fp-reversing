#!/usr/bin/env python3
"""Source recovery of keyed u32 option, fallback default and nested admission."""
import json,struct,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import sha,read
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_option_default'
SCOPE='Selected first-child keyed u32 accessor writes the N19 discriminator, exact success preserves that value, exact missing-key marker computes a context-word default, and every other raw status selects error. N19 admission is selected option/default zero, not a universal context-header equality. Native caller/owner/PAC/peer, complete parser/cleanup and daemon-kext pairing remain unproved.'
BLOCKS={'outer_missing':0x100781014,'outer_flag':0x100861958,'flag25':0x100864a48,'caller':0x1008b35a4,'entry':0x100847998,'publish':0x100506a0c,'relay':0x1006f76a8,'returned':0x100736108,'partition':0x1006c4600,'success':0x10093c438,'missing':0x1006a9e90,'preserve':0x1008cf6cc,'default':0x1006bf434,'head':0x1006ab91c,'stage':0x100609e2c,'select':0x100801774,'nested_caller':0x1004e1f94,'error':0x100975d34}
EDGES={'outer_missing':[0x43ec,0xb9a],'outer_flag':[0x7b40,0xbb19],'flag25':[0xa656,0x62f8],'caller':[0x3b01],'entry':[0x3cc0,0x3d4f],'publish':[0x3cc0],'relay':[],'returned':[0x84ca],'partition':[0x4f26,0x4ee7],'success':[0xb17d,0x445a],'missing':[0x4979,0x445a],'preserve':[0x2122],'default':[0x2122],'head':[0x8754,0x8755],'stage':[0x4b1d,0x4b59],'select':[0x342d,0x344e],'nested_caller':[0x3884],'error':[0xc022,0xc04f]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];ixs={0x935};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));ixs.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),a));assert not any('sp'in{i.reg_name(r)for r in i.regs_access()[1]}for i in ii);assert [i.mnemonic for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')]==['braa']
 rec=[]
 for fn in ['daemon_existing_scalar_reader_source.json','daemon_constructor_lookup_source.json','daemon_scalar_field_population_source.json']:
  for n,f in json.loads(read(ROOT/fn))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'file':fn,'fragment':n,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 a=0x100001058;n=14849960;raw=IMAGE.read(a,n);pattern=0x91000000|(0x3ac<<10)|(11<<5)|11;hits=[a+4*j for j,(w,)in enumerate(struct.iter_unpack('<I',raw))if w==pattern];assert hits==[0x1008b35d0]
 locator={'text_start':hex(a),'text_bytes':n,'text_sha256':h(raw),'aligned_words':n//4,'literal_word_pattern':hex(pattern),'sites':[hex(v)for v in hits],'scope':'Exact ADD X11,X11,#3ac encoding only; not all F-cell address producers or aliases.'}
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(ixs)]
 deps=['daemon_reader_nested_input_source.json','daemon_reader_nested_input_checks.json','daemon_reader_outer_lifecycle_source.json','daemon_reader_outer_lifecycle_checks.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_scalar_field_population_source.json','daemon_scalar_field_population_checks.json','validate_daemon_reader_nested_input.py','validate_daemon_reader_outer_lifecycle.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_terminated_ranges':len(BLOCKS),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'literal_OUT_address_candidates':1,'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(q['slot'],16)for q in ptr}),'prior_recaptures':rec,'OUT_address_locator':locator,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
