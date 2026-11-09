#!/usr/bin/env python3
"""Original source outer first-key lookup,typed span,mode split and option bridge.
O(B+I+R) time/space; no target execution,requests,IDB edits or memory updates.
"""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_outer_first_key'
SCOPE='Selected C0 publication -> first-match keyd719dce3 -> exact missing-key option/default bridge or fitted span/type/mode1 helper frontier. Mode0 and other modes,error/recognized-scalar statuses and private pointer/extent/return interfaces are distinguished. Native owner/caller/PAC,whole-parser memory continuity and daemon-kext exchange remain unproved.'
BLOCKS={'publish':0x100758ae8,'parser_return':0x1008c8b80,'outer_return':0x1008b3a7c,'head':0x10069a00c,'lookup_call':0x10066e5b0,'lookup_entry':0x1006fd1b8,'lookup_return':0x1008949cc,'partition':0x100939f18,'missing':0x100781014,'option_flag':0x100861958,'option_mode':0x100864a48,'option_call':0x1008b35a4,'found_gate':0x1006fd600,'buffer':0x1008b4120,'minimum':0x100852344,'word_prepare':0x10089811c,'word_return':0x100609488,'tag_return':0x100538e08,'word_call':0x100530d34,'extent':0x1005cf4c8,'fit':0x100611778,'type':0x1007978d0,'low':0x1005a3f34,'upper':0x10047e474,'u32':0x100574164,'span':0x1004d7710,'known_other':0x100552c64,'stage':0x1005a55d0,'mode_partition':0x1004dc9e0,'mode_low':0x1007f70fc,'mode_high':0x1005b0834,'mode_zero':0x1005e74d8,'mode_one':0x1005b0494,'helper_setup':0x10090151c,'error':0x100941a74}
EDGES={'publish':[0x188e],'parser_return':[],'outer_return':[0xc6db,0x445a],'head':[0xa80a,0xa80f],'lookup_call':[0x18e2],'lookup_entry':[0xc157,0xc1ca],'lookup_return':[0xc92d],'partition':[0x3610,0x3613],'missing':[0x43ec,0xb9a],'option_flag':[0x7b40,0xbb19],'option_mode':[0xa656,0x62f8],'option_call':[0x3b01],'found_gate':[0x7228,0x445a],'buffer':[0x796e,0x7976],'minimum':[0x5209,0x2167],'word_prepare':[0x2520],'word_return':[0x1f39],'tag_return':[0x3a31],'word_call':[0x8c3f],'extent':[0x8ff0,0x9004],'fit':[0x22ff],'type':[0x39bd,0x39ec],'low':[0xc45e,0x9004],'upper':[0x6e96,0x6e9f],'u32':[0xa9d3,0x8aed],'span':[0xb45d,0x419a],'known_other':[0x8aed],'stage':[0x2356],'mode_partition':[0x4449,0x448b],'mode_low':[0x722b,0x2167],'mode_high':[0x5fe6,0x419a],'mode_zero':[0x9004],'mode_one':[0x24b2],'helper_setup':[0x2486],'error':[0xc04f]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={};edges=[];ixs={0x1649,0x12d9,0xf1,0x208,0xf4,0x935};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));ixs.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),a));assert not any('sp'in{i.reg_name(r)for r in i.regs_access()[1]}for i in ii);assert [i.mnemonic for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')]==['braa']
 old=json.loads(read(ROOT/'daemon_reader_nested_input_source.json'));prep=block(0x1006f6bf0,0x3000);prep['sha256']=h(bytes.fromhex(prep['bytes']));assert prep==old['preparation'];rec=[]
 prior=['daemon_constructor_lookup_source.json','daemon_existing_scalar_reader_source.json','daemon_reader_u64_codec_source.json','daemon_outer_record_ingress_source.json','daemon_reader_option_default_source.json']
 def walk(obj,fn,path=''):
  if isinstance(obj,dict):
   raw=obj.get('bytes',obj.get('bytes_hex'));a=obj.get('start')
   if isinstance(raw,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(raw);assert IMAGE.read(int(a,16),len(bb))==bb,(fn,path);rec.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in obj.items():walk(v,fn,path+'/'+k)
  elif isinstance(obj,list):
   for j,v in enumerate(obj):walk(v,fn,path+'/'+str(j))
 for fn in prior:walk(json.loads(read(ROOT/fn)),fn)
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(ixs)]
 deps=prior+['daemon_reader_nested_input_source.json','daemon_constructor_lookup_checks.json','daemon_existing_scalar_reader_checks.json','daemon_reader_u64_codec_checks.json','daemon_reader_option_default_checks.json','validate_daemon_reader_outer_lifecycle.py','recover_daemon_reader_context_footprint.py','validate_daemon_reader_context_footprint.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_lookup.py','validate_daemon_constructor_inputs.py','validate_daemon_reader_container_origins.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_terminated_ranges':len(fs),'preparation_instructions':len(prep['instructions']),'preparation_bytes':len(bytes.fromhex(prep['bytes'])),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'preparation':prep,'preparation_write_ledger':old['preparation_write_ledger'],'preparation_read_ledger':old['preparation_read_ledger'],'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(q['slot'],16)for q in ptr}),'prior_recaptures':rec,'tag_preserves_X28':old['tag_preserves_X28'],'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
