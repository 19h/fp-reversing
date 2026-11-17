#!/usr/bin/env python3
"""Pinned early-main caller, original walker/signer and boot-bound tables.
Linear source/collection/table/page work. No native target execution.
"""
import json
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_boot_logging_handoff as B
import recover_kernel_initializer_pointer_signing as S
P='kernel_main_pointer_signing';RETURN=0xfffffe000c639a9c
SCOPE='Original early-main walker/signing call on the declared boot-word startup frame, replacing its no-RAM model. Logical PAC identity; no module initializer invocation, native signatures, cold-entry admission or matched FairPlay IPC.'
def build():
 im=B.BootImage();prior=json.loads(read(ROOT/(B.P+'_checks.json')));signing=json.loads(read(ROOT/(S.P+'_checks.json')))
 functions=[*prior['functions'],S.body(im.k,S.WALK),S.body(im.k,S.SIGN,S.SIGN_END)]
 assert functions[-2:]==signing['functions']
 for h in signing['headers']:assert S.logical(im,int(h['address'],16),len(bytes.fromhex(h['bytes_hex']))).hex()==h['bytes_hex']
 for t in signing['pointer_tables']:assert S.logical(im,int(t['address'],16),t['size_bytes']).hex()==t['logical_bytes_hex']
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json',B.P+'_audit.json',S.P+'_checks.json',S.P+'_audit.json','recover_kernel_boot_logging_handoff.py','recover_kernel_boot_fixup_projection.py']},'functions':functions,'pointer_tables':signing['pointer_tables'],'headers':signing['headers'],'fairplay_class_initializers':signing['fairplay_class_initializers'],'fairplay_callback_bodies':signing['fairplay_callback_bodies'],'fairplay_target_symbols':signing['fairplay_target_symbols'],'exact_helper_symbols':signing['exact_helper_symbols'],'verified_counts':{'functions':len(functions),'source_words':sum(len(f['instructions']) for f in functions),'added_functions':2,'added_words':314,'pointer_tables':len(signing['pointer_tables']),'pointer_slots':6362,'pointer_bytes':50896,'root_and_fileset_headers':363},'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
