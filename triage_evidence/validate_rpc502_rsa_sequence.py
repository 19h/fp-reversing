#!/usr/bin/env python3
"""Independent complete exponent/precomputation order and alias observations.

Reads preserved source-only profiles;does not execute target instructions.
O(calls*limbs) record work plus bounded modular exponentiation. Complements
full fresh worker/row verifier rather than changing its published inputs.
"""
import hashlib,json,struct
from pathlib import Path
from rpc502_startup_tools import unpack,certificate_view
from rpc502_rsa_models import integer_arg,integer_at,memory
ROOT=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'rpc502_rsa_profiles.json').read_text());checks=json.loads((ROOT/'rpc502_rsa_checks.json').read_text());assert checks['all_checks_pass'];root=certificate_view((ROOT/'rpc502_startup_root.der').read_bytes());key=certificate_view((ROOT/'rpc502_startup_key_services.der').read_bytes());assertions=0;summaries=[];aliases=0;precomp_points=0
 def check(v,label):
  nonlocal assertions
  assert v,label;assertions+=1
 for w in p['cases']:
  r=unpack(w);groups=[]
  for call in r['montgomery_calls']:
   rec=call['entry_record'];kind=call['kind'];n=integer_arg(rec,32 if kind=='square'else 8)['value']
   if not groups or groups[-1][0][0]!=n:groups.append([])
   groups[-1].append((n,call))
  for gi,group in enumerate(groups):
   check(len(group)==32,'complete32-call exponent group');N=group[0][0];R=1<<2048;S=int((key if gi==0 else certificate_view(bytes.fromhex(w['case']['body_hex'])))['signature_hex'],16);check(N==int((root if gi==0 else key)['modulus_hex'],16),'actual group modulus')
   for j,(_,call)in enumerate(group):
    rec=call['entry_record'];after=call['returned_record'];kind=call['kind'];a=integer_arg(rec,24);b=a if kind=='square'else integer_arg(rec,40);out=integer_arg(after,16)
    if j<11:expected=('square',(pow(2,1<<j,N)*R)%N,(pow(2,1<<j,N)*R)%N,(pow(2,1<<(j+1),N)*R)%N)
    elif j==11:expected=('product',R*R%N,S,S*R%N)
    elif j==12:expected=('square',R%N,R%N,R%N)
    elif j==13:expected=('product',R%N,S*R%N,S*R%N)
    elif j<30:expected=('square',pow(S,1<<(j-14),N)*R%N,pow(S,1<<(j-14),N)*R%N,pow(S,1<<(j-13),N)*R%N)
    elif j==30:expected=('product',pow(S,65536,N)*R%N,S*R%N,pow(S,65537,N)*R%N)
    else:expected=('product',pow(S,65537,N)*R%N,1,pow(S,65537,N))
    check((kind,a['value'],b['value'],out['value'])==expected,'complete independent exponent/precompute order')
    if kind=='square':check(out['address']==a['address'],'observed in-place square');aliases+=1
    ctx=int.from_bytes(bytes.fromhex(rec['prefix96_hex'])[:8],'little');cb=memory(rec,ctx,20);check(cb==memory(after,ctx,20),'selected context header unchanged by actual call')
    if j<11:
     pp=struct.unpack_from('<Q',cb,8)[0];check(integer_at(rec,pp)['value']==a['value']and integer_at(after,pp)['value']==out['value'],'actual context precomputation pointer tracks repeated square');precomp_points+=1
   summaries.append({'case':w['case']['label'],'group_index':gi,'calls':len(group),'precompute_squares':11,'public_exponent_squares':17,'products':4,'exponent':65537})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_rsa_profiles.json','rpc502_rsa_checks.json','rpc502_rsa_models.py','rpc502_startup_tools.py']},'verified_counts':{'assertions':assertions,'complete_groups':len(summaries),'calls':sum(e['calls']for e in summaries),'observed_in_place_squares':aliases,'context_precomputation_points':precomp_points},'group_summaries':summaries,'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc502_rsa_sequence_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
