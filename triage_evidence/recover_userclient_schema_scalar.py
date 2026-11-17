#!/usr/bin/env python3
"""Freeze schema header, scalar output and caller status interfaces.
O(B+I+inherited custody) construction/space; no native execution or IDB change.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_schema_search as Parent
P='userclient_schema_scalar'
SCOPE='Conditional original-source protected schema header/scalar reader and saved caller return. Native admission/PAC/ownership, application field meaning, packet-layer identity and matched ADID/daemon/kext transport remain outside the claims.'
SPANS={'schema_tag_return':(0xfffffe000a638e68,0xfffffe000a638ebc),'schema_type_decode':(0xfffffe000a63930c,0xfffffe000a6393c8),'schema_type_return':(0xfffffe000a63a2b0,0xfffffe000a63a33c),'schema_length_bridge':(0xfffffe000a637128,0xfffffe000a637138),'schema_body_extent':(0xfffffe000a638b84,0xfffffe000a638c04),'schema_caller_status':(0xfffffe000a636728,0xfffffe000a63677c)}
BRANCHES=Parent.BRANCHES|{0xfffffe000a63713c:Parent.BRANCHES[0xfffffe000a63713c]+[0x1a2,0x15b],0xfffffe000a638e74:[0x252],0xfffffe000a63932c:[0x28],0xfffffe000a63a330:[0x22e],0xfffffe000a63712c:[0xe07]}
SPANS.update({'schema_type_gate':(0xfffffe000a638c04,0xfffffe000a638c50),'schema_scalar_request':(0xfffffe000a638c50,0xfffffe000a638cbc),'schema_other_type':(0xfffffe000a63abdc,0xfffffe000a63abf4),'schema_short_body':(0xfffffe000a63abf4,0xfffffe000a63ac18),'schema_scalar_return':(0xfffffe000a63ac18,0xfffffe000a63ac38),'schema_commit_cursor':(0xfffffe000a63ac38,0xfffffe000a63ac94),'schema_scalar_output':(0xfffffe000a63ac94,0xfffffe000a63acd0)})
SPANS['schema_commit_entry']=(0xfffffe000a63ac38,0xfffffe000a63ac3c)
SPANS['schema_commit_cursor']=(0xfffffe000a63ac3c,0xfffffe000a63ac94)
BRANCHES.update({0xfffffe000a638bf8:[0x483,0x487],0xfffffe000a638c44:[0x487,0x565],0xfffffe000a638cb0:[0x22e],0xfffffe000a63ac04:[0x3d8],0xfffffe000a63ac2c:[0x680],0xfffffe000a63ac7c:[0x3d8,0x8ef],0xfffffe000a63acbc:[0x3d8],0xfffffe000a636760:[0x80f,0xc06]})
BRANCHES[0xfffffe000a63713c]=BRANCHES[0xfffffe000a63713c]+[0x19a]
RETAGS=Parent.RETAGS
DIRECT=Parent.Parent.DIRECT|{0xfffffe000a638c14:('b.ne',0xfffffe000a63abdc),0xfffffe000a63abe4:('b.eq',0xfffffe000a63ac3c),0xfffffe000a63abf0:('b.eq',0xfffffe000a63ac3c)}
FALSE=[n for n in Parent.FALSE if n!='kernel_schema_field_decoding_established']+['native_schema_scalar_decoding_established']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_schema_search_checks.json'));assert prior==Parent.build();spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 names=set(prior['dependencies'])|{'recover_userclient_schema_search.py','audit_userclient_schema_search.py','userclient_schema_search_checks.json','userclient_schema_search_audit.json'}
 base=dict(prior);base.pop('kernel_schema_field_decoding_established',None)
 return {**base,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'lookup_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(prior['predecessor_states']),'bank_input_cases':256},'conditional_schema_u32_decoding_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
