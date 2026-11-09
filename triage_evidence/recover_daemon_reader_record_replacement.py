#!/usr/bin/env python3
"""Static N19 first-match lookup, position-preserving replacement and retirement."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,h,FLAGS,selected
from daemon_receive_tools import verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha,read
P='daemon_reader_record_replacement'
SCOPE='Conditional N19 first-match lookup and output/status contract,position-preserving replacement,normal-return retirement calls and saved-end reader-loop back edge. Finite stable valid owners,frame epochs,bank roots and call/PAC completion remain premises;u64 reader/native transport and complete parser remain unproved.'
BLOCKS={'post_payload':0x1005c635c,'entry':0x1006fd1b8,'nonnull':0x10070d1f0,'next':0x100697188,'candidate':0x100914e3c,'prepare':0x1006f6bf0,'decode':0x100800004,'compare':0x100615a1c,'advance':0x1005bb1b0,'publish':0x100914a10,'mediator':0x1006c5c2c,'returned':0x1007c4d4c,'status':0x1006b9728,'found':0x10086c7d4,'absent':0x100767b58,'replace':0x10076e3a8,'prev_patch':0x1004ea7f8,'next_gate':0x100742378,'next_patch':0x1006efc1c,'head_gate':0x1008143c8,'head_patch':0x1008cb940,'tail_gate':0x100700228,'tail_patch':0x1006bb36c,'retire':0x1006cc840,'free_buffer':0x1006c7710,'free_node':0x1008b3144,'loop_return':0x1009a1808}
EDGES={'post_payload':[0x18e2],'entry':[0xc157,0xc1ca],'nonnull':[0x5e28],'next':[0x57d4,0x582e],'candidate':[0x2520],'prepare':[0x8c3f],'decode':[0xc8],'compare':[0xa924,0xa93d],'advance':[0x5e28],'publish':[0x8209],'returned':[0x416a],'status':[0x411a,0x4124],'found':[0xbd96,0x27fc],'absent':[0x1c48,0x1c16],'replace':[0x9384,0x9307],'prev_patch':[0x9384],'next_gate':[0xc04a,0xc052],'next_patch':[0xaf42],'head_gate':[0x7224,0xa663],'head_patch':[0x7224],'tail_gate':[0x2705,0x7eda],'tail_patch':[0x2705],'retire':[0x8ef5,0x8f00],'free_buffer':[0x3405],'free_node':[0x9467],'loop_return':[0x3599]}
CALLS={'free_buffer':0x1006c7788,'free_node':0x1008b31b8}
BANKS=[('buffer',0x100e99a00,0x100f4e390,0xd7,0xcb7c,0x600,0x5f8),('node',0x100e99700,0x100f4e190,0x56,0xcbf4,0x870,0x868)]
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={};edges=[];indices={0x1308,0xcc08};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;controls={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES.get(n,[]):
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),FIXUPS[slot]);indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  cc=[]
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):
   assert 'sp'not in{i.reg_name(q)for q in i.regs_access()[1]}
   if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc'):cc.append({'site':hex(i.address),'mnemonic':i.mnemonic})
  assert cc==([{'site':hex(CALLS[n]),'mnemonic':'blraa'}]if n in CALLS else[])+[{'site':f['instructions'][-1]['ea'],'mnemonic':'braa'}],(n,cc);controls[n]=cc
 banks=[]
 for n,l,r,k,add,lf,rf in BANKS:
  b=selected(l,r,k,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);v=[i^rb[lb[i]^k]for i in range(256)];assert len(set(v))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30';b.update(name=n,left_bytes=lb.hex(),right_bytes=rb.hex(),key_u8=k,additive_u32=add,left_frame_offset=hex(lf),right_frame_offset=hex(rf),results_256=v);banks.append(b)
 old=json.loads(read(ROOT/'daemon_constructor_lookup_source.json'));refs=[]
 for n in['prepare_decoder','decode','next','candidate','compare','advance','publish','mediator']:
  f=old['fragments'][n];raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;refs.append({'file':'daemon_constructor_lookup_source.json','fragment':n,'bytes_checked':len(raw),'sha256':h(raw)})
 assert fs['prepare']==old['fragments']['prepare_decoder']and fs['decode']==old['fragments']['decode']
 origin=json.loads(read(ROOT/'daemon_constructor_bank_origins_source.json'));roots=[]
 for off in[0x870,0x868]:
  p=origin['field_projections'][hex(off)]
  for ins in p['instructions']:
   decoded=next(CS.disasm(IMAGE.read(int(ins['ea'],16),4),int(ins['ea'],16)));assert decoded.mnemonic==ins['mnemonic']and decoded.op_str==ins['operands']
  roots.append({'file':'daemon_constructor_bank_origins_source.json','field_offset':hex(off),'expected_value':p['expected_value'],'writer':p['writer'],'scope':'Prior initializer projection,not a new native reaching-definition proof.'})
 owner=json.loads(read(ROOT/'daemon_builder_owner_join_source.json'))
 for q in owner['child1_bank_root_fields']:
  i=q['original_instruction'];assert IMAGE.read(int(i['ea'],16),4).hex()==i['bytes']
  roots.append({'file':'daemon_builder_owner_join_source.json','field_offset':q['field_offset'],'value':q['value'],'site':i['ea'],'scope':'Retained initializer writer evidence;later epoch/reaching definition remains a premise.'})
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 deps=['daemon_reader_record_payloads_source.json','daemon_reader_record_payloads_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_constructor_bank_origins_source.json','daemon_constructor_bank_origins_checks.json','daemon_builder_owner_join_source.json','daemon_reader_record_headers_source.json','daemon_reader_record_headers_checks.json','daemon_receive_fixups.txt','verify_daemon_reader_record_payloads_publication.py']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'normal_free_call_boundaries':2,'bank_inputs_checked':512,'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_source_ranges_recaptured':len(refs),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'banks':banks,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'control_ledger':controls,'prior_source_recaptures':refs,'initializer_bank_root_references':roots,'call_boundaries':{n:hex(pc)for n,pc in CALLS.items()},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
