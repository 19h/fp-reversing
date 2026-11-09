#!/usr/bin/env python3
"""Original source and bounded syntactic candidate censuses. Frame offsets and
nearby pool biases identify candidates, not complete writers or native phases.
O(text words+captured bytes) time and retained-output space; no IDB mutation.
"""
import json,struct,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from recover_daemon_iokit_census import text_section

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def span(n,a,z):
 b=IMAGE.read(a,z-a);return{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]}
def main():
 A,N=text_section();raw=IMAGE.read(A,N);words=list(struct.iter_unpack('<I',raw));slots={0x26d0:[],0x24a8:[],0x26b0:[]};biases={k:[]for k in['keys','field','payload']};adrps=[]
 patterns={label:(0x92800000|((lo-1)<<5),0xf2a00000|(hi<<5))for label,lo,hi in [('keys',0xe51a,0xf8e9),('field',0x3e0e,0x88e6),('payload',0x3ada,0xff9e)]}
 for j,(w,)in enumerate(words):
  pc=A+j*4
  for off,hits in slots.items():
   if w&0xffffffe0==0xf94003e0|((off//8)<<10):hits.append(span('candidate_'+hex(pc),pc,pc+36))
  for label,(first,second)in patterns.items():
   if w&0xffffffe0==first and j+1<len(words)and words[j+1][0]&0xffffffe0==second and w&31==words[j+1][0]&31:biases[label].append(span('bias_'+label,pc,pc+16))
  if w&0x9f000000==0x90000000:
   imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm;page=(pc&~4095)+(imm<<12)
   if page in[0x1010c6000,0x1010c9000]:
    ins=list(CS.disasm(IMAGE.read(pc,8),pc));adrps.append({'pc':hex(pc),'page':hex(page),'next_mnemonic':ins[1].mnemonic,'next_operands':ins[1].op_str})
 spans=[]
 for name,a,z in [('input_pack',0x1009d0198,0x1009d0308),('unmask_phase',0x1009f0120,0x1009f0130),('unmask_word',0x1009f0154,0x1009f0170),('word_store',0x100975790,0x100975794),('outer_entry',0x1008bf64c,0x1008bf6f0),('outer_predicate',0x100bb01e8,0x100bb0248),('outer_advance',0x10096928c,0x1009692cc),('tag_match',0x100b0c638,0x100b0c674),('inner_count_gate',0x100963c9c,0x100963cf0),('inner_init',0x100b252e8,0x100b25384),('inner_base_gate',0x10094cbb8,0x10094cbec),('inner_key_gate',0x10095e930,0x10095e970),('candidate_malloc320',0x100ac7cf8,0x100ac7d94),('candidate_malloc_variable',0x100acec04,0x100acece0),('candidate_key_initializer10',0x100bb2418,0x100bb24ac),('candidate_key_clear_A',0x100a466ec,0x100a46754),('candidate_key_clear_B',0x100b11d40,0x100b11dac),('candidate_payload_clear',0x100b280dc,0x100b28100),('inner_predicate',0x1008bb504,0x1008bb53c),('inner_advance',0x100839154,0x100839198),('inner_index_store',0x100b328a8,0x100b328d8),('object_pointer_gate',0x100c744b0,0x100c744f4),('object_header_gate',0x1009e2e1c,0x1009e2e58),('object_equal_field',0x100b31ce4,0x100b31d10),('object_unequal_field',0x100a2ae1c,0x100a2ae54),('object_d8_field',0x100c70c9c,0x100c70cb4),('object_head_unlink',0x100a264d0,0x100a264f8)]:spans.append(span(name,a,z))
 prior=Path('/Users/___/Downloads/fpx/analysis/pool_sites_final.json');old=json.loads(prior.read_text());wanted={0x1010c67a8,0x1010c67d0,0x1010c9288};priorhits=[x for x in old if x.get('target')in wanted]
 deps=['daemon_receive_tools.py','recover_daemon_iokit_census.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'text_address':hex(A),'text_size_bytes':N,'text_sha256':hashlib.sha256(raw).hexdigest(),'spans':spans,'literal_LDR_Xn_SP_census':{hex(k):{'scope':'Aligned unsigned-immediate LDR Xn,[SP,#offset] only; aliases,paired/unscaled loads,SP changes and phase ownership excluded.','matches':v}for k,v in slots.items()},'bias_MOVN_MOVK_census':{'scope':'Adjacent MOVN64 low16/MOVK64 high16 in original text; same destination register; other constant constructions excluded.','patterns':{k:[hex(a),hex(b)]for k,(a,b)in patterns.items()},'matches':biases},'direct_ADRP_page_census':{'scope':'Original aligned ADRP to the two requested pages; immediate next instruction only. Not a complete global-reference scan.','matches':adrps},'saved_annotation_search':{'path':str(prior),'sha256':sha(prior),'entries':len(old),'exact_target_matches':priorhits,'native_complete_writer_graph':False},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_source.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'frame_slot_candidates':{hex(k):len(v)for k,v in slots.items()},'bias_candidates':{k:len(v)for k,v in biases.items()},'ADRP_page_candidates':len(adrps)}),flush=True)
if __name__=='__main__':main()
