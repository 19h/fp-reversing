#!/usr/bin/env python3
"""Recapture source and producer lineage for the69 word-loop lookup roles."""
import copy,json
from recover_daemon_mode_one_lookup_bounds import ROOT,FLAGS,build as parent_build
from recover_daemon_mode_one_digit_maps import build as maps_build
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_mode_one_lookup_roles'
SCOPE='All69 byte lookup families in the selected48-round word extension,conditional on source entry/frame and preserved producer-table contracts. Source-linked typed induction and local SMT algebra;complete word recurrence,algorithm identity,caller publication and native daemon-kext exchange remain unknown.'
DEPS=['daemon_mode_one_lookup_bounds_source.json','daemon_mode_one_lookup_bounds_checks.json','daemon_mode_one_digit_maps_source.json','daemon_mode_one_digit_maps_checks.json','daemon_mode_one_carry_table_checks.json','daemon_mode_one_state_materialization_checks.json','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_plane_consumer_checks.json','daemon_mode_one_word_schedule_checks.json']
def build():
 old=parent_build();assert old==json.loads(read(ROOT/DEPS[0]));maps=maps_build();assert maps==json.loads(read(ROOT/DEPS[2]));s=copy.deepcopy(old)
 s.update(generator_sha256=sha(__file__),static_scope=SCOPE,parent_source_sha256=sha(ROOT/DEPS[0]),parent_checks_sha256=sha(ROOT/DEPS[1]),producer_source=maps)
 s['dependencies'].update({n:sha(ROOT/n)for n in DEPS})
 return s
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
