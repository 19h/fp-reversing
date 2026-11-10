#!/usr/bin/env python3
"""Pin mode1 caller result verification, address-bound span codec and retry ABI."""
import collections,json,re,struct,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
from validate_daemon_list_output import split
P='daemon_mode_one_output_verification'
SCOPE='Conditional normal-return/zero-delta mode1 consumer: encoded span length32, full32-byte address-bound equality reduction, option-parser join and alternate object-source retry. Whole core budget history, native ownership/return, algorithm identity and daemon-kext transport remain unknown.'
BLOCKS={'setup':0x10090151c,'caller_return':0x100911fe0,'length_gate':0x10084fbc4,'length_reject':0x100901ec4,'first_seed':0x1006cb98c,'compare_entry':0x10093cec4,'compare_loop':0x100baddd0,'compare_finish':0x1006d5464,'compare_relay':0x10087a3b8,'first_result':0x1006a9f68,'fallback_gate':0x10075b2f8,'option_gate':0x1009aab5c,'option_call':0x1008b35a4,'retry':0x1006869dc,'retry_return':0x10070815c,'retry_length':0x1009b19ac,'retry_seed':0x1008f0ba4,'retry_result':0x10068ab84,'error':0x100941a74,'staging':0x100975d34,'helper_entry':0x100729920,'wrapper_relay':0x10068b47c}
CUTS={'preserve_seed':(0x1009bb534,0x1009bb540),'restore_seed':(0x1009bb544,0x1009bb56c)}
EDGES={'setup':[0x2486],'caller_return':[0xa1da,0xb9a],'length_gate':[0x8653,0x865d],'length_reject':[0x744f],'first_seed':[0x7dc8],'compare_entry':[0x5619,0x5667],'compare_loop':[0x2b3f,0x2b4b],'compare_finish':[0x5667],'compare_relay':[],'first_result':[0x744f,0x96b9],'fallback_gate':[0x4382,0x43c1],'option_gate':[0x3c37,0xab4b],'option_call':[0x3b01],'retry':[0x2486],'retry_return':[0xb9a,0x5c9d],'retry_length':[0x7b31,0x87a3],'retry_seed':[0x7dc8],'retry_result':[0x7b31,0x7b40],'error':[0xc04f],'staging':[0xc022,0xc04f],'helper_entry':[0x9d05,0x9d0d],'wrapper_relay':[]}
SAVED_CONTINUATIONS=[(0x15db,0x3275),(0x15cc,0x3275),(0x7b9,0x7af9),(0x7b7,0x7af9)]
LINEAGE=['daemon_mode_one_adapter','daemon_mode_one_result_publication','daemon_outer_first_key','daemon_reader_outer_lifecycle']
DEPS=[v+s for v in LINEAGE for s in ['_source.json','_checks.json']]+['validate_daemon_mode_one_result_publication.py','validate_daemon_mode_one_record_checkpoint.py','validate_daemon_mode_one_record_join.py','daemon_mode_one_handoff_tools.py','daemon_word_round_tools.py','validate_daemon_existing_scalar_reader.py','validate_daemon_list_output.py','daemon_receive_fixups.txt']
def logical_mask(w):
 width=64 if w>>31 else 32;N=(w>>22)&1;imms=(w>>10)&63;immr=(w>>16)&63;l=((N<<6)|((~imms)&63)).bit_length()-1;assert l>=1
 size=1<<l;assert size<=width;s=imms&(size-1);r=immr&(size-1);assert s!=size-1;v=(1<<(s+1))-1;v=((v>>r)|(v<<(size-r)))&((1<<size)-1)
 return sum(v<<j for j in range(0,width,size))
def capture(a,b):
 raw=IMAGE.read(a,b-a);dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);ii=list(dc.disasm(raw,a));assert len(ii)*4==len(raw)
 return {'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()};fs.update({n:capture(a,b)for n,(a,b)in CUTS.items()})
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;isa=[];cmps=[];liveins={};census={}
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);ii=list(dc.disasm(raw,int(f['start'],16)));assert len(ii)*4==len(raw);seen=set();live=[];control=[]
  for i in ii:
   m=i.mnemonic;p=split(i.op_str);w=int.from_bytes(i.bytes,'little');width=64 if w>>31 else 32;writes={i.reg_name(r)for r in i.regs_access()[1]};assert 'sp'not in writes
   if m=='cmp':
    bad=sorted(v for v in writes if re.fullmatch('[wx][0-9]+',v))
    if bad:cmps.append({'site':hex(i.address),'Capstone_GPR_writes':bad,'architectural_GPR_writes':[]})
   args=p if m in['str','strb','strh','cmp','braa']else p[1:]+([p[0]]if m=='movk'else[])
   for arg in args:
    for r in re.findall(r'\b[wx][0-9]+\b',arg):
     if r[1:]not in seen and r not in{v['register']for v in live}:live.append({'register':r,'first_read':hex(i.address)})
   if m not in['str','strb','strh','cmp','braa']:seen.add(p[0][1:])
   row=None
   if m=='ubfiz':
    assert w&0x7f800000==0x53000000 and(w>>22)&1==w>>31;r=(w>>16)&63;s=(w>>10)&63;l,k=int(p[2][1:],0),int(p[3][1:],0);assert(l,k)==((width-r)%width,s+1);assert[int(x[1:])for x in p[:2]]==[w&31,(w>>5)&31];row={'kind':m,'width_bits':width,'immr':r,'imms':s}
   elif m=='lsr'and not p[-1].startswith('#'):
    assert w&0x7fe0fc00==0x1ac02400 and[int(x[1:])for x in p]==[w&31,(w>>5)&31,(w>>16)&31];row={'kind':'register_lsr','width_bits':width,'shift_mask':width-1}
   elif m=='ror':
    assert w&0x7fa00000==0x13800000 and(w>>22)&1==w>>31 and(w>>5)&31==(w>>16)&31==int(p[1][1:])and w&31==int(p[0][1:])and(w>>10)&63==int(p[2][1:],0);row={'kind':'ROR_EXTR_alias','width_bits':width,'rotate_bits':(w>>10)&63}
   elif m=='eor'and len(p)==4 and p[3].startswith('ror'):
    assert w&0x7f200000==0x4a000000 and(w>>22)&3==3 and[int(x[1:])for x in p[:3]]==[w&31,(w>>5)&31,(w>>16)&31]and(w>>10)&63==int(p[3].split('#')[1],0);row={'kind':'EOR_rotated_operand','width_bits':width,'rotate_bits':(w>>10)&63}
   elif m=='eon':
    assert w&0x7f200000==0x4a200000 and(w>>22)&3==0 and(w>>10)&63==0 and[int(x[1:])for x in p]==[w&31,(w>>5)&31,(w>>16)&31];row={'kind':'EON','width_bits':width,'complement_after_shift':True}
   elif m in['and','orr']and p[2].startswith('#'):
    assert w&0x7f800000=={'and':0x12000000,'orr':0x32000000}[m]and w&31==int(p[0][1:])and(w>>5)&31==int(p[1][1:])and logical_mask(w)==int(p[2][1:],0);row={'kind':'logical_immediate','operation':m,'width_bits':width,'mask':hex(logical_mask(w))}
   elif m=='strh':
    off=int(p[1].split('#')[1].strip(']'),0)if'#'in p[1]else 0;assert w&0xffc00000==0x79000000 and w&31==31 and(w>>5)&31==20 and((w>>10)&4095)*2==off;row={'kind':'zero_halfword_store','width_bits':16,'LOCAL_offset':off}
   if row:isa.append({'site':hex(i.address),'bytes':i.bytes.hex(),**row})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert control==(['braa']if n in BLOCKS else[]);liveins[n]=live;census[n]=dict(collections.Counter(i.mnemonic for i in ii))
 edges=[];slots=set()
 for n,indices in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix in indices:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and(w>>32)&65535==mod and not(w>>48&7);slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex()})
 saved=[]
 for ix,mod in SAVED_CONTINUATIONS:
  slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and(w>>32)&65535==mod and not(w>>48&7);slots.add(slot);saved.append({'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 call=capture(0x1009bb53c,0x1009bb544);assert[(i['mnemonic'],i['operands'])for i in call['instructions']]==[('mov','x17, #0x2220'),('blraa','x8, x17')];slot=TABLE+8*0xce18;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==0x2220 and FIXUPS[slot]['target']==0x100d03348;slots.add(slot)
 rec=[]
 for name in LINEAGE:
  for label,f in json.loads(read(ROOT/(name+'_source.json')))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'source':name+'_source.json','fragment':label,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 wrapper=json.loads(read(ROOT/'daemon_mode_one_adapter_source.json'))['fragments']['wrapper'];prefix_raw=IMAGE.read(0x1009bb3b0,0x1009bb534-0x1009bb3b0);prefix_instructions=list(dc.disasm(prefix_raw,0x1009bb3b0));protected={t+str(j)for j in[21,25,26,28,30]for t in['x','w']}
 assert len(prefix_instructions)==97 and all(not protected&{i.reg_name(r)for r in i.regs_access()[1]}for i in prefix_instructions)
 assert not any(i.mnemonic in['bl','blr','blraa','blrab']for i in prefix_instructions)
 seed_preservation={'start':'0x1009bb3b0','end':'0x1009bb534','instructions':97,'bytes':len(prefix_raw),'sha256':h(prefix_raw),'preserved_registers':sorted(protected),'intervening_calls':0,'source':'daemon_mode_one_adapter_source.json/fragments/wrapper'}
 ptr=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_bindings':len(edges),'saved_continuation_bindings':len(saved),'pointer_records':len(ptr),'ISA_decodes_checked':len(isa),'comparison_role_corrections':len(cmps),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'internal_call_bytes_checked':8,'wrapper_prefix_seed_preservation_instructions':97,'SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'image_name':SOURCE.name,'image_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in DEPS},'fragments':fs,'branch_edges':edges,'saved_continuations':saved,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups(slots),'internal_adapter_call':call,'wrapper_prefix_seed_preservation':seed_preservation,'ISA_decode_checks':isa,'comparison_role_corrections':cmps,'operand_based_GPR_first_reads':liveins,'mnemonic_census':census,'prior_recaptures':rec,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
