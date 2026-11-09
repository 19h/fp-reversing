#!/usr/bin/env python3
"""Verify the two corrected query summary flags against the complete draft.

Reconstruct the preceding draft profile and producer byte-for-byte using
explicit inverse edits and pinned SHA-256 identities. O(profile bytes) time
and space. Source execution events and every other result field stay equal.
No target executes; only this new correction record is written.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
OLD_PROBE_SHA='a8539b4afc9288dc45fcc700b46925e1df487e48be2122a190eca2e972c5355d'
OLD_PROFILE_SHA='f8b9b459a9c501cd577b22923fc4982b835f371207323b7712cfbbd0bb113f30'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=ROOT/'probe_lskd_readback.py';source=p.read_text();new="native_object_free_executed=False)\n  if self.wrapper_return is not None:r.update(source_execution_wrapper_returned=True,source_query_success_executed=self.publication is not None and self.wrapper_return['registers31'][0]=='0x0')\n  return r";old='native_object_free_executed=False);return r';assert source.count(new)==1;assert hashlib.sha256(source.replace(new,old).encode()).hexdigest()==OLD_PROBE_SHA
 profile=ROOT/'lskd_readback_profiles.json';data=json.loads(profile.read_text());assert data['generator_sha256']==sha(p);changed=[]
 for j,r in enumerate(data['cases']):
  if r['input'].get('caller')=='query':
   assert r['query_method_return_executed']and r['query_wrapper_return']['registers31'][0]=='0x0'
   for key in['source_execution_wrapper_returned','source_query_success_executed']:assert r[key]is True;r[key]=False;changed.append({'case_index':j,'field':key,'draft':False,'corrected':True})
 assert len(changed)==24;data['generator_sha256']=OLD_PROBE_SHA;assert hashlib.sha256((json.dumps(data,indent=2)+'\n').encode()).hexdigest()==OLD_PROFILE_SHA
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{p.name:sha(p),profile.name:sha(profile)},'draft_producer_sha256':OLD_PROBE_SHA,'draft_profile_sha256':OLD_PROFILE_SHA,'corrected_flags':changed,'profile_cases_with_identical_source_events_and_other_fields':len(data['cases']),'complete_draft_reconstruction_matches':True,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_readback_flag_correction.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'corrected_flags':24,'source_and_other_profile_fields_unchanged_cases':343,'draft_byte_reconstruction_pass':True}),flush=True)
if __name__=='__main__':main()
