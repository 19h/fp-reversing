#!/usr/bin/env python3
"""Static N19 typed-payload routing, recoding and post-payload lookup interfaces."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_record_payloads'
SCOPE='Conditional N19 full u16 payload type/extent partition, scalar writer interfaces, span count and address-dependent recoding, post-payload lookup handoff, conditional append and cursor back edge. Full replacement/cleanup, native owners/PAC/endpoints and daemon-kext pairing remain unproved.'
BLOCKS={'setup':0x1008ecb78,'router':0x1004a0f64,'upper':0x1007996e8,'check64':0x1004f83a4,'check32':0x1004cd790,'checkspan':0x10055497c,'length64':0x1006072c8,'length32':0x1005c3574,'call64':0x10053f020,'call32':0x10053ea88,'word_call':0x100615004,'span_gate':0x1004b9ce0,'span_setup':0x1007fd5e4,'span_loop':0x100791cfc,'post_payload':0x1005c635c,'lookup_entry':0x1006fd1b8,'lookup_null':0x1006c5c2c,'lookup_nonnull':0x10070d1f0,'lookup_return':0x1007c4d4c,'lookup_status':0x1006b9728,'status_low':0x10086c7d4,'status_high':0x100767b58,'append_gate':0x100853de0,'append_empty':0x10071e7f0,'append_nonempty':0x10090064c,'append_return':0x1009a1808,'replace_stage':0x10076e3a8}
CUTS={'count_prefix':(0x1004d617c,0x1004d6234),'count_save':(0x1004d62cc,0x1004d62d4),'writer64_entry':(0x1005a2c2c,0x1005a2c68),'writer64_exit':(0x1005a37c4,0x1005a37d0)}
EDGES={'setup':[0x9da7],'router':[0xa630,0xa631],'upper':[0xaeb8,0xaec5],'check64':[0x1c16,0xa8bf],'check32':[0x1c16,0x77a2],'checkspan':[0x1c16,0xc9b8],'length64':[0x27fc,0x9641],'length32':[0x1c16,0x7fdb],'call64':[0x7d2d],'call32':[0x1824],'word_call':[0x9da7],'span_gate':[0xcadc,0xcafd],'span_setup':[0x3802],'span_loop':[0x3802,0x37fd],'post_payload':[0x18e2],'lookup_entry':[0xc157,0xc1ca],'lookup_nonnull':[0x5e28],'lookup_return':[0x416a],'lookup_status':[0x411a,0x4124],'status_low':[0xbd96,0x27fc],'status_high':[0x1c48,0x1c16],'append_gate':[0x86d2,0x8704],'append_empty':[0x9467],'append_nonempty':[0x9467],'append_return':[0x3599],'replace_stage':[0x9384,0x9307]}
from verify_daemon_reader_record_payloads_publication import sha,read,exists,size

def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];indices={0x2a5,0x1351,0x37fd,0x1308};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;writes={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f
  mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES.get(n,[]):
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),hex(mod),FIXUPS[slot]);indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 for n,(a,z)in CUTS.items():
  raw=IMAGE.read(a,z-a);fs[n]={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'scope':'Explicit half-open source prefix or relay;not a complete branch-terminated range.'}
 for n,f in fs.items():
  wr=set();cc=[]
  for i in dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):
   wr.update(i.reg_name(x)for x in i.regs_access()[1]);
   if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc'):cc.append(i.mnemonic)
  assert 'sp'not in wr and cc==(['braa']if n in BLOCKS else[]),(n,wr,cc);writes[n]=sorted(wr)
 old=json.loads(read(ROOT/'daemon_typed_scalar_source.json'));f=old['fragments']['u64_writer'];raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;refs=[{'file':'daemon_typed_scalar_source.json','fragment':'u64_writer','bytes_checked':len(raw),'sha256':h(raw)}]
 hdr=json.loads(read(ROOT/'daemon_header_codec_source.json'))
 for n in['word','tag']:
  f=hdr['fragments'][n];raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;refs.append({'file':'daemon_header_codec_source.json','fragment':n,'bytes_checked':len(raw),'sha256':h(raw)})
 assert fs['setup']==json.loads(read(ROOT/'daemon_reader_record_headers_source.json'))['fragments']['write_prepare']
 n19=json.loads(read(ROOT/'daemon_reader_record_headers_source.json'))
 for name in['after_identifier','after_tag','after_extent']:
  f=n19['fragments'][name];raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw
  refs.append({'file':'daemon_reader_record_headers_source.json','fragment':name,'bytes_checked':len(raw),'sha256':h(raw)})
  written=set()
  for ins in dc.disasm(raw,int(f['start'],16)):written.update(ins.reg_name(q)for q in ins.regs_access()[1])
  assert not{p+str(j)for p in('x','w')for j in[8,9,10,11,12,13,15,28,30]}&written
  if name=='after_extent':assert not{'x20','w20'}&written
 keys={8,9,10,11,12,13,15,28,30};live=[]
 for n in['router','upper','check64','check32','checkspan','length64','length32','call64']:
  assert not{p+str(j)for j in keys|{20}for p in('x','w')}&set(writes[n]);live.append({'fragment':n,'preserved_registers':sorted(keys|{20})})
 for n in['word','after_identifier','tag','after_tag','word_call','after_extent']:
  assert not{p+str(j)for j in keys for p in('x','w')}&set(hdr['register_write_sets'][n])
 for ix,div in[(0x2a5,0xa918),(0x1351,0xd08c),(0x37fd,0x8388)]:
  word=int.from_bytes(IMAGE.read(TABLE+8*ix,8),'little');assert FIXUPS[TABLE+8*ix]['target']==BLOCKS['post_payload']and((word>>32)&65535)==div
 gap_start,gap_end=0x1004d6234,0x1004d62cc;gap=IMAGE.read(gap_start,gap_end-gap_start)
 for i in dc.disasm(gap,gap_start):
  assert not{'x8','w8'}&{i.reg_name(q)for q in i.regs_access()[1]}
  assert not i.mnemonic.startswith(('b.','cb','tb'))and i.mnemonic not in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc')
 span_fixed={0,1,2,3,4,5,8,9,10,11,12,13,14,15,22,24,25,26,27,28,30}
 assert not{p+str(j)for p in('x','w')for j in span_fixed}&set(writes['span_loop'])
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 deps=['daemon_reader_record_headers_source.json','daemon_reader_record_headers_checks.json','daemon_reader_value_consumers_source.json','daemon_reader_value_consumers_checks.json','daemon_typed_scalar_source.json','daemon_typed_scalar_checks.json','daemon_header_codec_source.json','daemon_header_codec_checks.json','validate_daemon_reader_record_headers.py','validate_daemon_typed_scalar.py','daemon_receive_fixups.txt','verify_daemon_reader_record_payloads_publication.py']
 counts={'source_fragments':len(fs),'branch_terminated_ranges':len(BLOCKS),'explicit_source_cuts':len(CUTS),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_source_ranges_recaptured':len(refs),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'register_write_sets':writes,'key_liveness':live,'count_X8_preservation_gap':{'start':hex(gap_start),'end':hex(gap_end),'bytes':gap.hex(),'sha256':h(gap)},'span_loop_preserved_registers':sorted(span_fixed),'prior_source_recaptures':refs,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
