#!/usr/bin/env python3
"""Validate the sidecar increment and refresh only the owned artifact manifest.

Original inputs, external dump.md and IDBs are never written. Runtime target
operations remain outside this verifier. Time O(total artifact bytes + links);
space bounded by the largest loaded JSON/report plus manifest entries.
"""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1<<20):h.update(chunk)
    return h.hexdigest()


def entry(path):
    return {'path':str(path.relative_to(BASE)),'size_bytes':path.stat().st_size,'sha256':sha(path)}


def main():
    old=json.loads((ROOT/'interface_manifest.json').read_text())
    for row in old['inputs_preserved']:
        path=BASE/row['path']
        assert path.stat().st_size==row['size_bytes'] and sha(path)==row['sha256'],path
    # Published producers/artifacts are frozen; verify retained outputs only.
    contract=json.loads((ROOT/'rpc502_sidecar_contracts.json').read_text())
    quality={
      'scope':'Sidecar/state/file-ABI increment only; full interface goal remains active and incomplete.',
      'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
      'QG2':{'status':'pass','evidence':'Report S1-S7 include dependent results and falsification probes.'},
      'QG3':{'status':'pass_for_increment','evidence':'State/path/next-file ABI covered; full_goal_complete=false.'},
      'QG4':{'status':'pass','evidence':'u32/u64/signed32 arithmetic, byte extents, SDK compile and complexity explicit.'},
      'QG5':{'status':'pass','evidence':'State, stack, split, VMM/CoreKE and descriptor-zero cases separated; native gaps explicit.'},
      'QG6':{'status':'pass','evidence':'Original byte/import/fixup, IDB, SDK, solver and finite-case provenance separated.'},
      'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table included.'},
      'verified_counts':{'native_ranges':len(contract['ranges']),'proofs_unsat':len(contract['proofs']),
        'encoder_inputs':len(contract['encoder_exhaustive_256']),'path_profiles':len(contract['profiles']),
        'io_profiles':len(contract['io_profiles']),'import_banks_256':len(contract['io_banks_exhaustive_256']),
        'metadata_profiles':len(contract['metadata_profiles']),
        'live_ida_ranges':contract['live_ida']['matching_ranges'],'sdk_compile_exit':contract['sdk_compile']['exit_code']},
      'native_target_executed':False,'target_host_operations_executed':False,'idb_mutated':False,
      'inputs_preserved':old['inputs_preserved'],'full_goal_complete':False}
    assert json.loads((ROOT/'rpc502_sidecar_quality_gates.json').read_text())==quality
    reports={BASE/r['path'] for r in old['files'] if '/' not in r['path'] and r['path'].endswith('.md')}
    reports.add(BASE/'rpc502_sidecar_report.md')
    if (BASE/'kernel_membership_removal_report.md').exists():reports.add(BASE/'kernel_membership_removal_report.md')
    if (BASE/'kernel_iokit_open_report.md').exists():reports.add(BASE/'kernel_iokit_open_report.md')
    if (BASE/'iokit_connection_lifecycle_report.md').exists():reports.add(BASE/'iokit_connection_lifecycle_report.md')
    if (BASE/'iokit_structure_arguments_report.md').exists():reports.add(BASE/'iokit_structure_arguments_report.md')
    if (BASE/'iokit_filter_policy_report.md').exists():reports.add(BASE/'iokit_filter_policy_report.md')
    if (BASE/'iokit_async_contract_report.md').exists():reports.add(BASE/'iokit_async_contract_report.md')
    if (BASE/'rpc700_publication_report.md').exists():reports.add(BASE/'rpc700_publication_report.md')
    if (BASE/'managed_fairplay_bridge_report.md').exists():reports.add(BASE/'managed_fairplay_bridge_report.md')
    if (BASE/'managed_adapter_dispatch_report.md').exists():reports.add(BASE/'managed_adapter_dispatch_report.md')
    if (BASE/'host_special_registration_report.md').exists():reports.add(BASE/'host_special_registration_report.md')
    if (BASE/'launchd_variant_binding_report.md').exists():reports.add(BASE/'launchd_variant_binding_report.md')
    if (BASE/'launchd_service_endpoint_report.md').exists():reports.add(BASE/'launchd_service_endpoint_report.md')
    if (BASE/'bootstrap_checkin_handoff_report.md').exists():reports.add(BASE/'bootstrap_checkin_handoff_report.md')
    if (BASE/'launchd_audit_context_report.md').exists():reports.add(BASE/'launchd_audit_context_report.md')
    if (BASE/'port_destroyed_return_report.md').exists():reports.add(BASE/'port_destroyed_return_report.md')
    if (BASE/'receive_name_guard_report.md').exists():reports.add(BASE/'receive_name_guard_report.md')
    if (BASE/'coalition_service_gate_report.md').exists():reports.add(BASE/'coalition_service_gate_report.md')
    if (BASE/'endpoint_job_lifecycle_report.md').exists():reports.add(BASE/'endpoint_job_lifecycle_report.md')
    if (BASE/'job_factory_lineage_report.md').exists():reports.add(BASE/'job_factory_lineage_report.md')
    if (BASE/'exclaves_notification_contract_report.md').exists():reports.add(BASE/'exclaves_notification_contract_report.md')
    if (BASE/'spawn_conclave_abi_report.md').exists():reports.add(BASE/'spawn_conclave_abi_report.md')
    if (BASE/'spawn_port_actions_report.md').exists():reports.add(BASE/'spawn_port_actions_report.md')
    if (BASE/'registered_port_consumers_report.md').exists():reports.add(BASE/'registered_port_consumers_report.md')
    if (BASE/'initializer_programvars_report.md').exists():reports.add(BASE/'initializer_programvars_report.md')
    if (BASE/'kernel_args_environment_report.md').exists():reports.add(BASE/'kernel_args_environment_report.md')
    if (BASE/'rpc700_endpoint_inventory_report.md').exists():reports.add(BASE/'rpc700_endpoint_inventory_report.md')
    if (BASE/'daemon_xpc_listener_report.md').exists():reports.add(BASE/'daemon_xpc_listener_report.md')
    if (BASE/'daemon_xpc_payload_report.md').exists():reports.add(BASE/'daemon_xpc_payload_report.md')
    if (BASE/'daemon_xpc_records_report.md').exists():reports.add(BASE/'daemon_xpc_records_report.md')
    if (BASE/'daemon_xpc_iteration_report.md').exists():reports.add(BASE/'daemon_xpc_iteration_report.md')
    if (BASE/'daemon_xpc_core_bridge_report.md').exists():reports.add(BASE/'daemon_xpc_core_bridge_report.md')
    if (BASE/'daemon_xpc_reply_lifecycle_report.md').exists():reports.add(BASE/'daemon_xpc_reply_lifecycle_report.md')
    if (BASE/'xpc_reply_transport_report.md').exists():reports.add(BASE/'xpc_reply_transport_report.md')
    if (BASE/'xpc_receive_context_report.md').exists():reports.add(BASE/'xpc_receive_context_report.md')
    if (BASE/'xpc_resource_lifecycle_report.md').exists():reports.add(BASE/'xpc_resource_lifecycle_report.md')
    if (BASE/'xpc_transaction_controls_report.md').exists():reports.add(BASE/'xpc_transaction_controls_report.md')
    if (BASE/'daemon_xpc_error_outputs_report.md').exists():reports.add(BASE/'daemon_xpc_error_outputs_report.md')
    if (BASE/'daemon_output_publication_report.md').exists():reports.add(BASE/'daemon_output_publication_report.md')
    if (BASE/'daemon_list_output_report.md').exists():reports.add(BASE/'daemon_list_output_report.md')
    if (BASE/'daemon_record_stream_report.md').exists():reports.add(BASE/'daemon_record_stream_report.md')
    if (BASE/'daemon_payload_codec_report.md').exists():reports.add(BASE/'daemon_payload_codec_report.md')
    if (BASE/'daemon_header_codec_report.md').exists():reports.add(BASE/'daemon_header_codec_report.md')
    if (BASE/'daemon_constructor_inputs_report.md').exists():reports.add(BASE/'daemon_constructor_inputs_report.md')
    if (BASE/'daemon_constructor_lookup_report.md').exists():reports.add(BASE/'daemon_constructor_lookup_report.md')
    if (BASE/'daemon_typed_scalar_report.md').exists():reports.add(BASE/'daemon_typed_scalar_report.md')
    if (BASE/'daemon_constructor_failure_report.md').exists():reports.add(BASE/'daemon_constructor_failure_report.md')
    if (BASE/'daemon_constructor_bank_origins_report.md').exists():reports.add(BASE/'daemon_constructor_bank_origins_report.md')
    if (BASE/'daemon_constructor_callers_report.md').exists():reports.add(BASE/'daemon_constructor_callers_report.md')
    if (BASE/'daemon_collection_retirement_report.md').exists():reports.add(BASE/'daemon_collection_retirement_report.md')
    if (BASE/'daemon_builder_owner_join_report.md').exists():reports.add(BASE/'daemon_builder_owner_join_report.md')
    if (BASE/'daemon_scalar_field_population_report.md').exists():reports.add(BASE/'daemon_scalar_field_population_report.md')
    if (BASE/'daemon_helper_result_residue_report.md').exists():reports.add(BASE/'daemon_helper_result_residue_report.md')
    if (BASE/'daemon_existing_scalar_reader_report.md').exists():reports.add(BASE/'daemon_existing_scalar_reader_report.md')
    if (BASE/'daemon_reader_context_footprint_report.md').exists():reports.add(BASE/'daemon_reader_context_footprint_report.md')
    if (BASE/'daemon_reader_stack_epoch_report.md').exists():reports.add(BASE/'daemon_reader_stack_epoch_report.md')
    if (BASE/'daemon_context_input_producers_report.md').exists():reports.add(BASE/'daemon_context_input_producers_report.md')
    if (BASE/'daemon_reader_extent_families_report.md').exists():reports.add(BASE/'daemon_reader_extent_families_report.md')
    if (BASE/'daemon_reader_typed_dispatch_report.md').exists():reports.add(BASE/'daemon_reader_typed_dispatch_report.md')
    if (BASE/'daemon_reader_value_consumers_report.md').exists():reports.add(BASE/'daemon_reader_value_consumers_report.md')
    if (BASE/'daemon_reader_container_origins_report.md').exists():reports.add(BASE/'daemon_reader_container_origins_report.md')
    if (BASE/'daemon_reader_record_headers_report.md').exists():reports.add(BASE/'daemon_reader_record_headers_report.md')
    if (BASE/'daemon_reader_record_payloads_report.md').exists():reports.add(BASE/'daemon_reader_record_payloads_report.md')
    if (BASE/'daemon_service_cf_lifecycle_report.md').exists():reports.add(BASE/'daemon_service_cf_lifecycle_report.md')
    if (BASE/'cf_mach_port_retirement_report.md').exists():reports.add(BASE/'cf_mach_port_retirement_report.md')
    if (BASE/'daemon_cf_descriptor_bridge_report.md').exists():reports.add(BASE/'daemon_cf_descriptor_bridge_report.md')
    if (BASE/'cf_public_runloop_report.md').exists():reports.add(BASE/'cf_public_runloop_report.md')
    if (BASE/'cf_source0_scheduler_report.md').exists():reports.add(BASE/'cf_source0_scheduler_report.md')
    if (BASE/'cf_descriptor_source_factory_report.md').exists():reports.add(BASE/'cf_descriptor_source_factory_report.md')
    if (BASE/'daemon_descriptor_source_report.md').exists():reports.add(BASE/'daemon_descriptor_source_report.md')
    if (BASE/'cf_source_wake_callers_report.md').exists():reports.add(BASE/'cf_source_wake_callers_report.md')
    if (BASE/'kernel_wake_send_ingress_report.md').exists():reports.add(BASE/'kernel_wake_send_ingress_report.md')
    if (BASE/'cf_wake_send_wrapper_report.md').exists():reports.add(BASE/'cf_wake_send_wrapper_report.md')
    if (BASE/'cf_runloop_wake_port_report.md').exists():reports.add(BASE/'cf_runloop_wake_port_report.md')
    if (BASE/'kernel_timer_expiration_delivery_report.md').exists():reports.add(BASE/'kernel_timer_expiration_delivery_report.md')
    if (BASE/'kernel_timer_port_create_report.md').exists():reports.add(BASE/'kernel_timer_port_create_report.md')
    if (BASE/'kernel_root_port_construct_report.md').exists():reports.add(BASE/'kernel_root_port_construct_report.md')
    if (BASE/'cf_control_port_dispatch_report.md').exists():reports.add(BASE/'cf_control_port_dispatch_report.md')
    if (BASE/'cf_mode_construction_report.md').exists():reports.add(BASE/'cf_mode_construction_report.md')
    if (BASE/'kernel_portset_delivery_report.md').exists():reports.add(BASE/'kernel_portset_delivery_report.md')
    if (BASE/'cf_source_scheduling_report.md').exists():reports.add(BASE/'cf_source_scheduling_report.md')
    if (BASE/'cf_runloop_handoff_report.md').exists():reports.add(BASE/'cf_runloop_handoff_report.md')
    if (BASE/'dispatch_voucher_hooks_report.md').exists():reports.add(BASE/'dispatch_voucher_hooks_report.md')
    if (BASE/'cf_receive_voucher_report.md').exists():reports.add(BASE/'cf_receive_voucher_report.md')
    if (BASE/'cf_daemon_request_report.md').exists():reports.add(BASE/'cf_daemon_request_report.md')
    if (BASE/'daemon_request_application_report.md').exists():reports.add(BASE/'daemon_request_application_report.md')
    if (BASE/'daemon_request_consumption_report.md').exists():reports.add(BASE/'daemon_request_consumption_report.md')
    if (BASE/'kernel_request_delivery_report.md').exists():reports.add(BASE/'kernel_request_delivery_report.md')
    if (BASE/'kernel_request_copyin_report.md').exists():reports.add(BASE/'kernel_request_copyin_report.md')
    if (BASE/'kernel_request_receive_report.md').exists():reports.add(BASE/'kernel_request_receive_report.md')
    if (BASE/'kernel_rpc_request_report.md').exists():reports.add(BASE/'kernel_rpc_request_report.md')
    if (BASE/'kernel_special_reply_report.md').exists():reports.add(BASE/'kernel_special_reply_report.md')
    if (BASE/'kernel_reply_namespace_report.md').exists():reports.add(BASE/'kernel_reply_namespace_report.md')
    if (BASE/'kernel_receive_copyout_report.md').exists():reports.add(BASE/'kernel_receive_copyout_report.md')
    if (BASE/'kernel_receive_continuation_report.md').exists():reports.add(BASE/'kernel_receive_continuation_report.md')
    if (BASE/'kernel_waitq_enqueue_report.md').exists():reports.add(BASE/'kernel_waitq_enqueue_report.md')
    if (BASE/'kernel_waitq_receiver_report.md').exists():reports.add(BASE/'kernel_waitq_receiver_report.md')
    if (BASE/'kernel_kmsg_queue_report.md').exists():reports.add(BASE/'kernel_kmsg_queue_report.md')
    if (BASE/'kernel_cache_gate_report.md').exists():reports.add(BASE/'kernel_cache_gate_report.md')
    if (BASE/'kernel_zone_refill_report.md').exists():reports.add(BASE/'kernel_zone_refill_report.md')
    if (BASE/'kernel_zone_startup_report.md').exists():reports.add(BASE/'kernel_zone_startup_report.md')
    if (BASE/'kernel_kmsg_allocation_report.md').exists():reports.add(BASE/'kernel_kmsg_allocation_report.md')
    if (BASE/'kernel_notification_send_report.md').exists():reports.add(BASE/'kernel_notification_send_report.md')
    if (BASE/'kernel_send_right_lifecycle_report.md').exists():reports.add(BASE/'kernel_send_right_lifecycle_report.md')
    if (BASE/'kext_vm_copyout_bridge_report.md').exists():reports.add(BASE/'kext_vm_copyout_bridge_report.md')
    if (BASE/'kernel_range_fallback_report.md').exists():reports.add(BASE/'kernel_range_fallback_report.md')
    if (BASE/'kernel_range_resolver_report.md').exists():reports.add(BASE/'kernel_range_resolver_report.md')
    if (BASE/'kernel_map_store_init_report.md').exists():reports.add(BASE/'kernel_map_store_init_report.md')
    if (BASE/'kernel_type2_copyout_report.md').exists():reports.add(BASE/'kernel_type2_copyout_report.md')
    if (BASE/'kernel_vm_entry_copy_report.md').exists():reports.add(BASE/'kernel_vm_entry_copy_report.md')
    if (BASE/'kernel_vm_range_cursor_report.md').exists():reports.add(BASE/'kernel_vm_range_cursor_report.md')
    if (BASE/'rpc502_vm_handoff_report.md').exists():reports.add(BASE/'rpc502_vm_handoff_report.md')
    if (BASE/'iorpc_binary_parser_report.md').exists():reports.add(BASE/'iorpc_binary_parser_report.md')
    if (BASE/'iorpc_ool_serialization_report.md').exists():reports.add(BASE/'iorpc_ool_serialization_report.md')
    if (BASE/'iorpc_object_conversion_report.md').exists():reports.add(BASE/'iorpc_object_conversion_report.md')
    if (BASE/'iorpc_remote_report.md').exists():reports.add(BASE/'iorpc_remote_report.md')
    if (BASE/'platform_iorpc_report.md').exists():reports.add(BASE/'platform_iorpc_report.md')
    if (BASE/'aes_platform_gate_report.md').exists():reports.add(BASE/'aes_platform_gate_report.md')
    if (BASE/'aes_quantum_binding_report.md').exists():reports.add(BASE/'aes_quantum_binding_report.md')
    if (BASE/'aes_hardware_job_report.md').exists():reports.add(BASE/'aes_hardware_job_report.md')
    if (BASE/'aes_synchronous_wait_report.md').exists():reports.add(BASE/'aes_synchronous_wait_report.md')
    if (BASE/'aes_carrier_initialization_report.md').exists():reports.add(BASE/'aes_carrier_initialization_report.md')
    if (BASE/'aes_completion_contract_report.md').exists():reports.add(BASE/'aes_completion_contract_report.md')
    if (BASE/'aes_provider_queue_report.md').exists():reports.add(BASE/'aes_provider_queue_report.md')
    if (BASE/'aes_command_pool_report.md').exists():reports.add(BASE/'aes_command_pool_report.md')
    if (BASE/'workloop_gate_attachment_report.md').exists():reports.add(BASE/'workloop_gate_attachment_report.md')
    if (BASE/'aes_command_gate_report.md').exists():reports.add(BASE/'aes_command_gate_report.md')
    if (BASE/'kext_startup_hardware_bridge_report.md').exists():reports.add(BASE/'kext_startup_hardware_bridge_report.md')
    if (BASE/'kext_provider_initialize_report.md').exists():reports.add(BASE/'kext_provider_initialize_report.md')
    if (BASE/'kext_constructor_reply_state_report.md').exists():reports.add(BASE/'kext_constructor_reply_state_report.md')
    if (BASE/'kext_constructor_request_report.md').exists():reports.add(BASE/'kext_constructor_request_report.md')
    if (BASE/'kext_context_retirement_report.md').exists():reports.add(BASE/'kext_context_retirement_report.md')
    if (BASE/'kext_page_context_report.md').exists():reports.add(BASE/'kext_page_context_report.md')
    if (BASE/'kext_security_record_report.md').exists():reports.add(BASE/'kext_security_record_report.md')
    if (BASE/'kext_mapped_cleanup_report.md').exists():reports.add(BASE/'kext_mapped_cleanup_report.md')
    if (BASE/'kernel_task_map_report.md').exists():reports.add(BASE/'kernel_task_map_report.md')
    if (BASE/'kernel_copyin_policy_report.md').exists():reports.add(BASE/'kernel_copyin_policy_report.md')
    if (BASE/'rpc502_reply_copyin_report.md').exists():reports.add(BASE/'rpc502_reply_copyin_report.md')
    if (BASE/'kernel_reply_copyout_report.md').exists():reports.add(BASE/'kernel_reply_copyout_report.md')
    if (BASE/'rpc502_reply_bridge_report.md').exists():reports.add(BASE/'rpc502_reply_bridge_report.md')
    if (BASE/'rpc502_receive_bridge_report.md').exists():reports.add(BASE/'rpc502_receive_bridge_report.md')
    if (BASE/'kernel_receive_delivery_report.md').exists():reports.add(BASE/'kernel_receive_delivery_report.md')
    if (BASE/'kernel_queue_receive_report.md').exists():reports.add(BASE/'kernel_queue_receive_report.md')
    if (BASE/'kernel_queue_send_report.md').exists():reports.add(BASE/'kernel_queue_send_report.md')
    if (BASE/'kernel_reply_send_report.md').exists():reports.add(BASE/'kernel_reply_send_report.md')
    if (BASE/'kernel_vm_mig_report.md').exists():reports.add(BASE/'kernel_vm_mig_report.md')
    if (BASE/'daemon_vm_cleanup_report.md').exists():reports.add(BASE/'daemon_vm_cleanup_report.md')
    if (BASE/'daemon_client_object_report.md').exists():reports.add(BASE/'daemon_client_object_report.md')
    if (BASE/'daemon_boolean_chain_report.md').exists():reports.add(BASE/'daemon_boolean_chain_report.md')
    if (BASE/'daemon_secondary_string_report.md').exists():reports.add(BASE/'daemon_secondary_string_report.md')
    if (BASE/'daemon_secondary_result_report.md').exists():reports.add(BASE/'daemon_secondary_result_report.md')
    if (BASE/'daemon_entitlement_flow_report.md').exists():reports.add(BASE/'daemon_entitlement_flow_report.md')
    if (BASE/'daemon_entitlement_result_report.md').exists():reports.add(BASE/'daemon_entitlement_result_report.md')
    if (BASE/'daemon_record40_consumer_report.md').exists():reports.add(BASE/'daemon_record40_consumer_report.md')
    if (BASE/'daemon_mig_handover_report.md').exists():reports.add(BASE/'daemon_mig_handover_report.md')
    if (BASE/'daemon_operation_heads_report.md').exists():reports.add(BASE/'daemon_operation_heads_report.md')
    if (BASE/'daemon_core_dispatch_report.md').exists():reports.add(BASE/'daemon_core_dispatch_report.md')
    if (BASE/'daemon_shared_roots_report.md').exists():reports.add(BASE/'daemon_shared_roots_report.md')
    if (BASE/'daemon_aux_callers_report.md').exists():reports.add(BASE/'daemon_aux_callers_report.md')
    if (BASE/'daemon_output_base_report.md').exists():reports.add(BASE/'daemon_output_base_report.md')
    if (BASE/'daemon_cleanup_return_report.md').exists():reports.add(BASE/'daemon_cleanup_return_report.md')
    if (BASE/'daemon_arena_lifetime_report.md').exists():reports.add(BASE/'daemon_arena_lifetime_report.md')
    if (BASE/'daemon_arena_consumer_report.md').exists():reports.add(BASE/'daemon_arena_consumer_report.md')
    if (BASE/'daemon_arena_list_report.md').exists():reports.add(BASE/'daemon_arena_list_report.md')
    if (BASE/'daemon_record720_spill_report.md').exists():reports.add(BASE/'daemon_record720_spill_report.md')
    if (BASE/'daemon_record720_fields_report.md').exists():reports.add(BASE/'daemon_record720_fields_report.md')
    if (BASE/'daemon_record720_fingerprint_report.md').exists():reports.add(BASE/'daemon_record720_fingerprint_report.md')
    if (BASE/'daemon_record720_release_report.md').exists():reports.add(BASE/'daemon_record720_release_report.md')
    if (BASE/'daemon_record720_handoff_report.md').exists():reports.add(BASE/'daemon_record720_handoff_report.md')
    if (BASE/'daemon_record720_report.md').exists():reports.add(BASE/'daemon_record720_report.md')
    if (BASE/'daemon_cache_publication_report.md').exists():reports.add(BASE/'daemon_cache_publication_report.md')
    if (BASE/'daemon_digest_completion_report.md').exists():reports.add(BASE/'daemon_digest_completion_report.md')
    if (BASE/'daemon_digest_output_report.md').exists():reports.add(BASE/'daemon_digest_output_report.md')
    if (BASE/'daemon_sha1_core_report.md').exists():reports.add(BASE/'daemon_sha1_core_report.md')
    if (BASE/'daemon_compression_frame_report.md').exists():reports.add(BASE/'daemon_compression_frame_report.md')
    if (BASE/'daemon_digest_conventions_report.md').exists():reports.add(BASE/'daemon_digest_conventions_report.md')
    if (BASE/'daemon_digest_routes_report.md').exists():reports.add(BASE/'daemon_digest_routes_report.md')
    if (BASE/'daemon_identity_cache_report.md').exists():reports.add(BASE/'daemon_identity_cache_report.md')
    if (BASE/'daemon_cache36_report.md').exists():reports.add(BASE/'daemon_cache36_report.md')
    if (BASE/'daemon_object_clock_report.md').exists():reports.add(BASE/'daemon_object_clock_report.md')
    if (BASE/'daemon_object_initialization_report.md').exists():reports.add(BASE/'daemon_object_initialization_report.md')
    if (BASE/'daemon_creation_predecessors_report.md').exists():reports.add(BASE/'daemon_creation_predecessors_report.md')
    if (BASE/'daemon_object_creation_report.md').exists():reports.add(BASE/'daemon_object_creation_report.md')
    if (BASE/'daemon_object_consumers_report.md').exists():reports.add(BASE/'daemon_object_consumers_report.md')
    if (BASE/'daemon_registry_lookup_report.md').exists():reports.add(BASE/'daemon_registry_lookup_report.md')
    if (BASE/'daemon_mode471c_lifecycle_report.md').exists():reports.add(BASE/'daemon_mode471c_lifecycle_report.md')
    if (BASE/'rpc502_mapping_report.md').exists():reports.add(BASE/'rpc502_mapping_report.md')
    if (BASE/'user_trap_interface_report.md').exists():reports.add(BASE/'user_trap_interface_report.md')
    if (BASE/'kernel_dispatch_report.md').exists():reports.add(BASE/'kernel_dispatch_report.md')
    if (BASE/'kernel_namespace_report.md').exists():reports.add(BASE/'kernel_namespace_report.md')
    if (BASE/'cf_receive_report.md').exists():reports.add(BASE/'cf_receive_report.md')
    if (BASE/'daemon_registration_report.md').exists():reports.add(BASE/'daemon_registration_report.md')
    if (BASE/'created_port_report.md').exists():reports.add(BASE/'created_port_report.md')
    if (BASE/'arcade_subscription_report.md').exists():reports.add(BASE/'arcade_subscription_report.md')
    if (BASE/'arcade_service_report.md').exists():reports.add(BASE/'arcade_service_report.md')
    if (BASE/'arcade_reply_report.md').exists():reports.add(BASE/'arcade_reply_report.md')
    if (BASE/'arcade_policy_report.md').exists():reports.add(BASE/'arcade_policy_report.md')
    if (BASE/'arcade_receipt_report.md').exists():reports.add(BASE/'arcade_receipt_report.md')
    if (BASE/'appstore_repair_report.md').exists():reports.add(BASE/'appstore_repair_report.md')
    if (BASE/'appstore_receiver_report.md').exists():reports.add(BASE/'appstore_receiver_report.md')
    if (BASE/'appstore_events_report.md').exists():reports.add(BASE/'appstore_events_report.md')
    if (BASE/'ams_core_report.md').exists():reports.add(BASE/'ams_core_report.md')
    if (BASE/'corefp_exports_report.md').exists():reports.add(BASE/'corefp_exports_report.md')
    if (BASE/'corefp_lookup_report.md').exists():reports.add(BASE/'corefp_lookup_report.md')
    if (BASE/'corefp_client_paths_report.md').exists():reports.add(BASE/'corefp_client_paths_report.md')
    if (BASE/'adid_receiver_report.md').exists():reports.add(BASE/'adid_receiver_report.md')
    if (BASE/'adid_startup_report.md').exists():reports.add(BASE/'adid_startup_report.md')
    if (BASE/'adid_request_report.md').exists():reports.add(BASE/'adid_request_report.md')
    if (BASE/'adid_context_report.md').exists():reports.add(BASE/'adid_context_report.md')
    if (BASE/'adid_iokit_report.md').exists():reports.add(BASE/'adid_iokit_report.md')
    if (BASE/'adid_iokit_caller_report.md').exists():reports.add(BASE/'adid_iokit_caller_report.md')
    if (BASE/'adid_driver_dispatch_report.md').exists():reports.add(BASE/'adid_driver_dispatch_report.md')
    if (BASE/'adid_context_gate_report.md').exists():reports.add(BASE/'adid_context_gate_report.md')
    if (BASE/'adid_state_producer_report.md').exists():reports.add(BASE/'adid_state_producer_report.md')
    if (BASE/'adid_context_lookup_report.md').exists():reports.add(BASE/'adid_context_lookup_report.md')
    if (BASE/'adid_record_lifecycle_report.md').exists():reports.add(BASE/'adid_record_lifecycle_report.md')
    if (BASE/'adid_command_dispatch_report.md').exists():reports.add(BASE/'adid_command_dispatch_report.md')
    if (BASE/'adid_avp_packet_report.md').exists():reports.add(BASE/'adid_avp_packet_report.md')
    if (BASE/'akd_adid_client_report.md').exists():reports.add(BASE/'akd_adid_client_report.md')
    if (BASE/'adid_notification_report.md').exists():reports.add(BASE/'adid_notification_report.md')
    if (BASE/'notify_ipc_report.md').exists():reports.add(BASE/'notify_ipc_report.md')
    if (BASE/'notifyd_admission_report.md').exists():reports.add(BASE/'notifyd_admission_report.md')
    if (BASE/'notifyd_policy_report.md').exists():reports.add(BASE/'notifyd_policy_report.md')
    if (BASE/'notifyd_monitor_report.md').exists():reports.add(BASE/'notifyd_monitor_report.md')
    if (BASE/'rpc502_parser_report.md').exists():reports.add(BASE/'rpc502_parser_report.md')
    if (BASE/'rpc502_supplemental_report.md').exists():reports.add(BASE/'rpc502_supplemental_report.md')
    if (BASE/'rpc502_certificate_report.md').exists():reports.add(BASE/'rpc502_certificate_report.md')
    if (BASE/'rpc502_startup_report.md').exists():reports.add(BASE/'rpc502_startup_report.md')
    if (BASE/'rpc502_auth_report.md').exists():reports.add(BASE/'rpc502_auth_report.md')
    for name in ['rpc502_rsa_report.md','rpc502_policy_report.md','rpc502_late_report.md','rpc502_padding_report.md','rpc502_ownership_report.md','rpc502_cleanup_report.md','rpc700_namespace_report.md','kext_close_report.md','kext_cold_init_report.md','kext_buffer_report.md','kext_aes_handoff_report.md','kext_aes_dispatch_report.md','sample_descriptor_report.md','sample_caller_report.md','sample_state_report.md','sample_transfer_report.md','carrier_control_report.md','sample_lock_report.md','rw_lifecycle_report.md','iolib_group_report.md','legacy_stack_report.md','legacy_tlv_report.md','lskd_request_report.md','lskd_fields_report.md','lskd_execute_report.md','lskd_response_report.md','lskd_consumer_report.md','lskd_handlers_report.md','lskd_values_report.md','lskd_readback_report.md','lskd_continuations_report.md','lskd_state_report.md','lskd_lookup_report.md','lskd_objects_report.md','lskd_writers_report.md','lskd_core_workspace_report.md','lskd_core_input_report.md','lskd_input_buffers_report.md','daemon_iokit_census_report.md','daemon_query_state_report.md','daemon_query_fallback_report.md','daemon_iokit_objects_report.md','daemon_iokit_class_report.md']:
        if (BASE/name).exists():reports.add(BASE/name)
    assert len(reports)>=18 and BASE/'dump.md' not in reports and BASE/'analysis.md' not in reports
    if (BASE/'daemon_iokit_sync_report.md').exists():reports.add(BASE/'daemon_iokit_sync_report.md')
    if (BASE/'daemon_iokit_errors_report.md').exists():reports.add(BASE/'daemon_iokit_errors_report.md')
    if (BASE/'daemon_iokit_callers_report.md').exists():reports.add(BASE/'daemon_iokit_callers_report.md')
    if (BASE/'daemon_rwlock_lifecycle_report.md').exists():reports.add(BASE/'daemon_rwlock_lifecycle_report.md')
    if (BASE/'daemon_frame_entry_report.md').exists():reports.add(BASE/'daemon_frame_entry_report.md')
    if (BASE/'daemon_arena_entry_report.md').exists():reports.add(BASE/'daemon_arena_entry_report.md')
    if (BASE/'daemon_arena_storage_report.md').exists():reports.add(BASE/'daemon_arena_storage_report.md')
    if (BASE/'daemon_context_transfer_report.md').exists():reports.add(BASE/'daemon_context_transfer_report.md')
    if (BASE/'daemon_entropy_return_report.md').exists():reports.add(BASE/'daemon_entropy_return_report.md')
    if (BASE/'daemon_seed_material_report.md').exists():reports.add(BASE/'daemon_seed_material_report.md')
    if (BASE/'daemon_prng_output_report.md').exists():reports.add(BASE/'daemon_prng_output_report.md')
    if (BASE/'daemon_buffer_consumer_report.md').exists():reports.add(BASE/'daemon_buffer_consumer_report.md')
    if (BASE/'daemon_global_state_report.md').exists():reports.add(BASE/'daemon_global_state_report.md')
    if (BASE/'daemon_callback_revisit_report.md').exists():reports.add(BASE/'daemon_callback_revisit_report.md')
    if (BASE/'daemon_context_lock_report.md').exists():reports.add(BASE/'daemon_context_lock_report.md')
    if (BASE/'daemon_descriptor_readers_report.md').exists():reports.add(BASE/'daemon_descriptor_readers_report.md')
    if (BASE/'daemon_descriptor_producers_report.md').exists():reports.add(BASE/'daemon_descriptor_producers_report.md')
    links=0
    unavailable_external=[]
    for path in sorted(reports):
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',path.read_text()):
            raw=raw.strip('<>')
            if re.match(r'^[a-zA-Z][\w+.-]*://',raw) or raw.startswith('#'):continue
            name=raw.split('#',1)[0]
            target=Path(name) if name.startswith('/') else path.parent/name
            if not target.exists():
                # Preserve this historical primary-source citation after the SDK update.
                sdk=json.loads((ROOT/'kernel_root_port_construct_source.json').read_text())['SDK_context']
                assert path.name=='kernel_root_port_construct_report.md' and name==sdk['path'],(path,name)
                assert sdk['sha256']=='959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185'
                installed=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX27.2.sdk/usr/include/mach/port.h')
                current_sha=sha(installed)
                assert current_sha!=sdk['sha256']
                unavailable_external.append({'report':path.name,'path':name,'historical_sha256':sdk['sha256'],
                    'status':'historical_external_reference_unavailable','installed_comparison_path':str(installed),
                    'installed_comparison_sha256':current_sha,'equivalence_established':False})
            links+=1
    evidence=[p for p in ROOT.iterdir() if p.is_file() and p.name!='interface_manifest.json']
    json_count=0
    for path in evidence:
        if path.suffix=='.json':json.loads(path.read_text());json_count+=1
    owned=reports|{p for p in BASE.glob('fairplay_*.py')}|set(evidence)
    manifest={'created_utc':datetime.now(timezone.utc).isoformat(),'goal_status':'active',
       'inputs_preserved':old['inputs_preserved'],
       'scope_note':'Owned reports/scripts and direct evidence; external dump.md preserved/excluded. Current case sets are scoped by their contract files; earlier exploratory snapshots are historical.',
       'validation':{'reports':len(reports),'local_markdown_links':links,'direct_json_files':json_count,
                     'unavailable_external_primary_references':unavailable_external,
                     'sidecar_increment_checks':quality['verified_counts']},
       'files':[entry(p) for p in sorted(owned)]}
    if (ROOT/'rpc502_mapping_quality_gates.json').exists():
        mapping_quality=json.loads((ROOT/'rpc502_mapping_quality_gates.json').read_text())
        manifest['validation']['mapping_increment_checks']=mapping_quality['verified_counts']
    if (ROOT/'user_trap_quality_gates.json').exists():
        trap_quality=json.loads((ROOT/'user_trap_quality_gates.json').read_text())
        manifest['validation']['user_trap_increment_checks']=trap_quality['verified_counts']
    if (ROOT/'kernel_dispatch_quality_gates.json').exists():
        dispatch_quality=json.loads((ROOT/'kernel_dispatch_quality_gates.json').read_text())
        manifest['validation']['kernel_dispatch_increment_checks']=dispatch_quality['verified_counts']
    if (ROOT/'kernel_namespace_quality_gates.json').exists():
        namespace_quality=json.loads((ROOT/'kernel_namespace_quality_gates.json').read_text())
        manifest['validation']['kernel_namespace_increment_checks']=namespace_quality['verified_counts']
    if (ROOT/'cf_receive_quality_gates.json').exists():
        cf_quality=json.loads((ROOT/'cf_receive_quality_gates.json').read_text())
        manifest['validation']['cf_receive_increment_checks']=cf_quality['verified_counts']
    if (ROOT/'daemon_registration_quality_gates.json').exists():
        registration_quality=json.loads((ROOT/'daemon_registration_quality_gates.json').read_text())
        manifest['validation']['daemon_registration_increment_checks']=registration_quality['verified_counts']
    if (ROOT/'created_port_quality_gates.json').exists():
        created_quality=json.loads((ROOT/'created_port_quality_gates.json').read_text())
        manifest['validation']['created_port_increment_checks']=created_quality['verified_counts']
    if (ROOT/'arcade_subscription_quality_gates.json').exists():
        subscription_quality=json.loads((ROOT/'arcade_subscription_quality_gates.json').read_text())
        manifest['validation']['arcade_subscription_increment_checks']=subscription_quality['verified_counts']
    if (ROOT/'arcade_xpc_quality_gates.json').exists():
        xpc_quality=json.loads((ROOT/'arcade_xpc_quality_gates.json').read_text())
        manifest['validation']['arcade_xpc_increment_checks']=xpc_quality['verified_counts']
    if (ROOT/'arcade_policy_quality_gates.json').exists():
        policy_quality=json.loads((ROOT/'arcade_policy_quality_gates.json').read_text())
        manifest['validation']['arcade_policy_increment_checks']=policy_quality['verified_counts']
    if (ROOT/'arcade_receipt_quality_gates.json').exists():
        receipt_quality=json.loads((ROOT/'arcade_receipt_quality_gates.json').read_text())
        manifest['validation']['arcade_receipt_increment_checks']=receipt_quality['verified_counts']
    if (ROOT/'appstore_agent_quality_gates.json').exists():
        agent_quality=json.loads((ROOT/'appstore_agent_quality_gates.json').read_text())
        manifest['validation']['appstore_receiver_increment_checks']=agent_quality['verified_counts']
    if (ROOT/'appstore_events_quality_gates.json').exists():
        events_quality=json.loads((ROOT/'appstore_events_quality_gates.json').read_text())
        manifest['validation']['appstore_events_increment_checks']=events_quality['verified_counts']
    if (ROOT/'ams_core_quality_gates.json').exists():
        core_quality=json.loads((ROOT/'ams_core_quality_gates.json').read_text())
        manifest['validation']['ams_core_increment_checks']=core_quality['verified_counts']
    if (ROOT/'corefp_exports_quality_gates.json').exists():
        exports_quality=json.loads((ROOT/'corefp_exports_quality_gates.json').read_text())
        manifest['validation']['corefp_exports_increment_checks']=exports_quality['verified_counts']
    if (ROOT/'corefp_lookup_quality_gates.json').exists():
        lookup_quality=json.loads((ROOT/'corefp_lookup_quality_gates.json').read_text())
        manifest['validation']['corefp_lookup_increment_checks']=lookup_quality['verified_counts']
    if (ROOT/'corefp_client_paths_quality_gates.json').exists():
        paths_quality=json.loads((ROOT/'corefp_client_paths_quality_gates.json').read_text())
        manifest['validation']['corefp_client_paths_increment_checks']=paths_quality['verified_counts']
    if (ROOT/'adid_receiver_quality_gates.json').exists():
        adid_quality=json.loads((ROOT/'adid_receiver_quality_gates.json').read_text())
        manifest['validation']['adid_receiver_increment_checks']=adid_quality['verified_counts']
    if (ROOT/'adid_startup_quality_gates.json').exists():
        startup_quality=json.loads((ROOT/'adid_startup_quality_gates.json').read_text())
        manifest['validation']['adid_startup_increment_checks']=startup_quality['verified_counts']
    if (ROOT/'adid_request_quality_gates.json').exists():
        request_quality=json.loads((ROOT/'adid_request_quality_gates.json').read_text())
        manifest['validation']['adid_request_increment_checks']=request_quality['verified_counts']
    if (ROOT/'adid_context_quality_gates.json').exists():
        context_quality=json.loads((ROOT/'adid_context_quality_gates.json').read_text())
        manifest['validation']['adid_context_increment_checks']=context_quality['verified_counts']
    if (ROOT/'adid_iokit_quality_gates.json').exists():
        iokit_quality=json.loads((ROOT/'adid_iokit_quality_gates.json').read_text())
        manifest['validation']['adid_iokit_increment_checks']=iokit_quality['verified_counts']
    if (ROOT/'adid_iokit_caller_quality_gates.json').exists():
        caller_quality=json.loads((ROOT/'adid_iokit_caller_quality_gates.json').read_text())
        manifest['validation']['adid_iokit_caller_increment_checks']=caller_quality['verified_counts']
    if (ROOT/'adid_driver_dispatch_quality_gates.json').exists():
        driver_dispatch_quality=json.loads((ROOT/'adid_driver_dispatch_quality_gates.json').read_text())
        manifest['validation']['adid_driver_dispatch_increment_checks']=driver_dispatch_quality['verified_counts']
    if (ROOT/'adid_context_gate_quality_gates.json').exists():
        context_gate_quality=json.loads((ROOT/'adid_context_gate_quality_gates.json').read_text())
        manifest['validation']['adid_context_gate_increment_checks']=context_gate_quality['verified_counts']
    if (ROOT/'adid_state_producer_quality_gates.json').exists():
        state_producer_quality=json.loads((ROOT/'adid_state_producer_quality_gates.json').read_text())
        manifest['validation']['adid_state_producer_increment_checks']=state_producer_quality['verified_counts']
    if (ROOT/'adid_context_lookup_quality_gates.json').exists():
        context_lookup_quality=json.loads((ROOT/'adid_context_lookup_quality_gates.json').read_text())
        manifest['validation']['adid_context_lookup_increment_checks']=context_lookup_quality['verified_counts']
    if (ROOT/'adid_record_lifecycle_quality_gates.json').exists():
        record_lifecycle_quality=json.loads((ROOT/'adid_record_lifecycle_quality_gates.json').read_text())
        manifest['validation']['adid_record_lifecycle_increment_checks']=record_lifecycle_quality['verified_counts']
    if (ROOT/'adid_command_dispatch_quality_gates.json').exists():
        command_dispatch_quality=json.loads((ROOT/'adid_command_dispatch_quality_gates.json').read_text())
        manifest['validation']['adid_command_dispatch_increment_checks']=command_dispatch_quality['verified_counts']
    if (ROOT/'adid_avp_packet_quality_gates.json').exists():
        avp_packet_quality=json.loads((ROOT/'adid_avp_packet_quality_gates.json').read_text())
        manifest['validation']['adid_avp_packet_increment_checks']=avp_packet_quality['verified_counts']
    if (ROOT/'akd_adid_quality_gates.json').exists():
        akd_quality=json.loads((ROOT/'akd_adid_quality_gates.json').read_text())
        manifest['validation']['akd_adid_increment_checks']=akd_quality['verified_counts']
    if (ROOT/'adid_notification_quality_gates.json').exists():
        notification_quality=json.loads((ROOT/'adid_notification_quality_gates.json').read_text())
        manifest['validation']['adid_notification_increment_checks']=notification_quality['verified_counts']
    if (ROOT/'notify_ipc_quality_gates.json').exists():
        notify_quality=json.loads((ROOT/'notify_ipc_quality_gates.json').read_text())
        manifest['validation']['notify_ipc_increment_checks']=notify_quality['verified_counts']
    if (ROOT/'notifyd_admission_quality_gates.json').exists():
        admission_quality=json.loads((ROOT/'notifyd_admission_quality_gates.json').read_text())
        manifest['validation']['notifyd_admission_increment_checks']=admission_quality['verified_counts']
    if (ROOT/'notifyd_policy_quality_gates.json').exists():
        policy_quality=json.loads((ROOT/'notifyd_policy_quality_gates.json').read_text())
        manifest['validation']['notifyd_policy_increment_checks']=policy_quality['verified_counts']
    if (ROOT/'notifyd_monitor_quality_gates.json').exists():
        monitor_quality=json.loads((ROOT/'notifyd_monitor_quality_gates.json').read_text())
        manifest['validation']['notifyd_monitor_increment_checks']=monitor_quality['verified_counts']
    if (ROOT/'rpc502_parser_quality_gates.json').exists():
        parser_quality=json.loads((ROOT/'rpc502_parser_quality_gates.json').read_text())
        manifest['validation']['rpc502_parser_increment_checks']=parser_quality['verified_counts']
    if (ROOT/'rpc502_supp_quality_gates.json').exists():
        supp_quality=json.loads((ROOT/'rpc502_supp_quality_gates.json').read_text())
        manifest['validation']['rpc502_supp_increment_checks']=supp_quality['verified_counts']
        manifest['validation']['rpc502_supp_candidate_body_checks']=supp_quality['candidate_body_verified_counts']
    if (ROOT/'rpc502_certificate_quality_gates.json').exists():
        certificate_quality=json.loads((ROOT/'rpc502_certificate_quality_gates.json').read_text())
        manifest['validation']['rpc502_certificate_increment_checks']=certificate_quality['verified_counts']
    if (ROOT/'rpc502_startup_quality_gates.json').exists():
        rpc_startup_quality=json.loads((ROOT/'rpc502_startup_quality_gates.json').read_text())
        manifest['validation']['rpc502_startup_increment_checks']=rpc_startup_quality['verified_counts']
    if (ROOT/'rpc502_auth_quality_gates.json').exists():
        rpc_auth_quality=json.loads((ROOT/'rpc502_auth_quality_gates.json').read_text())
        manifest['validation']['rpc502_auth_increment_checks']=rpc_auth_quality['verified_counts']
    if (ROOT/'rpc502_rsa_quality_gates.json').exists():
        arithmetic_quality=json.loads((ROOT/'rpc502_rsa_quality_gates.json').read_text())
        manifest['validation']['rpc502_rsa_increment_checks']=arithmetic_quality['verified_counts']
        manifest['validation']['rpc502_policy_increment_checks']=arithmetic_quality['policy_verified_counts']
    if (ROOT/'rpc502_late_quality_gates.json').exists():
        late_quality=json.loads((ROOT/'rpc502_late_quality_gates.json').read_text())
        manifest['validation']['rpc502_late_increment_checks']=late_quality['verified_counts']
        manifest['validation']['rpc502_late_nonzero_checks']=late_quality['nonzero_verified_counts']
        manifest['validation']['rpc502_late_reuse_checks']=late_quality['reuse_verified_counts']
    if (ROOT/'rw_lifecycle_quality_gates.json').exists():
        rw_lifecycle_quality=json.loads((ROOT/'rw_lifecycle_quality_gates.json').read_text())
        manifest['validation']['rw_lifecycle_increment_checks']=rw_lifecycle_quality['verified_counts']
    if (ROOT/'sample_lock_quality_gates.json').exists():
        sample_lock_quality=json.loads((ROOT/'sample_lock_quality_gates.json').read_text())
        manifest['validation']['sample_lock_increment_checks']=sample_lock_quality['verified_counts']
    if (ROOT/'carrier_control_quality_gates.json').exists():
        carrier_quality=json.loads((ROOT/'carrier_control_quality_gates.json').read_text())
        manifest['validation']['carrier_control_increment_checks']=carrier_quality['verified_counts']
    if (ROOT/'sample_transfer_quality_gates.json').exists():
        transfer_quality=json.loads((ROOT/'sample_transfer_quality_gates.json').read_text())
        manifest['validation']['sample_transfer_increment_checks']=transfer_quality['verified_counts']
    if (ROOT/'sample_state_quality_gates.json').exists():
        state_quality=json.loads((ROOT/'sample_state_quality_gates.json').read_text())
        manifest['validation']['sample_state_increment_checks']=state_quality['verified_counts']
    if (ROOT/'sample_caller_quality_gates.json').exists():
        caller_quality=json.loads((ROOT/'sample_caller_quality_gates.json').read_text())
        manifest['validation']['sample_caller_increment_checks']=caller_quality['verified_counts']
    if (ROOT/'sample_descriptor_quality_gates.json').exists():
        media_quality=json.loads((ROOT/'sample_descriptor_quality_gates.json').read_text())
        manifest['validation']['sample_descriptor_increment_checks']=media_quality['verified_counts']
    if (ROOT/'kext_aes_dispatch_quality_gates.json').exists():
        dispatch_quality=json.loads((ROOT/'kext_aes_dispatch_quality_gates.json').read_text())
        manifest['validation']['kext_aes_dispatch_increment_checks']=dispatch_quality['verified_counts']
    if (ROOT/'kext_aes_handoff_quality_gates.json').exists():
        handoff_quality=json.loads((ROOT/'kext_aes_handoff_quality_gates.json').read_text())
        manifest['validation']['kext_aes_handoff_increment_checks']=handoff_quality['verified_counts']
    if (ROOT/'kext_buffer_quality_gates.json').exists():
        buffer_quality=json.loads((ROOT/'kext_buffer_quality_gates.json').read_text())
        manifest['validation']['kext_buffer_increment_checks']=buffer_quality['verified_counts']
    if (ROOT/'kext_cold_init_quality_gates.json').exists():
        cold_quality=json.loads((ROOT/'kext_cold_init_quality_gates.json').read_text())
        manifest['validation']['kext_cold_init_increment_checks']=cold_quality['verified_counts']
    if (ROOT/'kext_close_quality_gates.json').exists():
        close_quality=json.loads((ROOT/'kext_close_quality_gates.json').read_text())
        manifest['validation']['kext_close_increment_checks']=close_quality['verified_counts']
    if (ROOT/'rpc700_namespace_quality_gates.json').exists():
        rpc700_quality=json.loads((ROOT/'rpc700_namespace_quality_gates.json').read_text())
        manifest['validation']['rpc700_namespace_increment_checks']=rpc700_quality['verified_counts']
    if (ROOT/'rpc502_cleanup_quality_gates.json').exists():
        cleanup_quality=json.loads((ROOT/'rpc502_cleanup_quality_gates.json').read_text())
        manifest['validation']['rpc502_cleanup_increment_checks']=cleanup_quality['verified_counts']
    if (ROOT/'rpc502_ownership_quality_gates.json').exists():
        ownership_quality=json.loads((ROOT/'rpc502_ownership_quality_gates.json').read_text())
        manifest['validation']['rpc502_ownership_increment_checks']=ownership_quality['verified_counts']
    if (ROOT/'rpc502_padding_quality_gates.json').exists():
        padding_quality=json.loads((ROOT/'rpc502_padding_quality_gates.json').read_text())
        manifest['validation']['rpc502_padding_increment_checks']=padding_quality['verified_counts']
    if (ROOT/'iolib_group_quality_gates.json').exists():
        group_quality=json.loads((ROOT/'iolib_group_quality_gates.json').read_text())
        manifest['validation']['iolib_group_increment_checks']=group_quality['verified_counts']
    if (ROOT/'legacy_stack_quality_gates.json').exists():
        stack_quality=json.loads((ROOT/'legacy_stack_quality_gates.json').read_text())
        manifest['validation']['legacy_stack_increment_checks']=stack_quality['verified_counts']
    if (ROOT/'legacy_tlv_quality_gates.json').exists():
        tlv_quality=json.loads((ROOT/'legacy_tlv_quality_gates.json').read_text())
        manifest['validation']['legacy_tlv_increment_checks']=tlv_quality['verified_counts']
    if (ROOT/'lskd_request_quality_gates.json').exists():
        lskd_quality=json.loads((ROOT/'lskd_request_quality_gates.json').read_text())
        manifest['validation']['lskd_request_increment_checks']=lskd_quality['verified_counts']
    if (ROOT/'lskd_fields_quality_gates.json').exists():
        fields_quality=json.loads((ROOT/'lskd_fields_quality_gates.json').read_text())
        manifest['validation']['lskd_fields_increment_checks']=fields_quality['verified_counts']
    if (ROOT/'lskd_execute_quality_gates.json').exists():
        execute_quality=json.loads((ROOT/'lskd_execute_quality_gates.json').read_text())
        manifest['validation']['lskd_execute_increment_checks']=execute_quality['verified_counts']
    if (ROOT/'lskd_response_quality_gates.json').exists():
        response_quality=json.loads((ROOT/'lskd_response_quality_gates.json').read_text())
        manifest['validation']['lskd_response_increment_checks']=response_quality['verified_counts']
    if (ROOT/'lskd_consumer_quality_gates.json').exists():
        consumer_quality=json.loads((ROOT/'lskd_consumer_quality_gates.json').read_text())
        manifest['validation']['lskd_consumer_increment_checks']=consumer_quality['verified_counts']
    if (ROOT/'lskd_handlers_quality_gates.json').exists():
        handlers_quality=json.loads((ROOT/'lskd_handlers_quality_gates.json').read_text())
        manifest['validation']['lskd_handlers_increment_checks']=handlers_quality['verified_counts']
    if (ROOT/'lskd_values_quality_gates.json').exists():
        values_quality=json.loads((ROOT/'lskd_values_quality_gates.json').read_text())
        manifest['validation']['lskd_values_increment_checks']=values_quality['verified_counts']
    if (ROOT/'lskd_readback_quality_gates.json').exists():
        readback_quality=json.loads((ROOT/'lskd_readback_quality_gates.json').read_text())
        manifest['validation']['lskd_readback_increment_checks']=readback_quality['verified_counts']
    if (ROOT/'lskd_continuations_quality_gates.json').exists():
        continuations_quality=json.loads((ROOT/'lskd_continuations_quality_gates.json').read_text())
        manifest['validation']['lskd_continuations_increment_checks']=continuations_quality['verified_counts']
    if (ROOT/'lskd_state_quality_gates.json').exists():
        lookup_state_quality=json.loads((ROOT/'lskd_state_quality_gates.json').read_text())
        manifest['validation']['lskd_state_increment_checks']=lookup_state_quality['verified_counts']
    if (ROOT/'lskd_lookup_quality_gates.json').exists():
        lookup_quality=json.loads((ROOT/'lskd_lookup_quality_gates.json').read_text())
        manifest['validation']['lskd_lookup_increment_checks']=lookup_quality['verified_counts']
    if (ROOT/'lskd_objects_quality_gates.json').exists():
        objects_quality=json.loads((ROOT/'lskd_objects_quality_gates.json').read_text())
        manifest['validation']['lskd_objects_increment_checks']=objects_quality['verified_counts']
    if (ROOT/'lskd_writers_quality_gates.json').exists():
        writers_quality=json.loads((ROOT/'lskd_writers_quality_gates.json').read_text())
        manifest['validation']['lskd_writers_increment_checks']=writers_quality['verified_counts']
    if (ROOT/'lskd_core_workspace_quality_gates.json').exists():
        core_workspace_quality=json.loads((ROOT/'lskd_core_workspace_quality_gates.json').read_text())
        manifest['validation']['lskd_core_workspace_increment_checks']=core_workspace_quality['verified_counts']
    if (ROOT/'lskd_core_input_quality_gates.json').exists():
        core_input_quality=json.loads((ROOT/'lskd_core_input_quality_gates.json').read_text())
        manifest['validation']['lskd_core_input_increment_checks']=core_input_quality['verified_counts']
        manifest['validation']['lskd_core_input_caller_checks']=core_input_quality['caller_verified_counts']
    if (ROOT/'lskd_input_buffers_quality_gates.json').exists():
        input_buffers_quality=json.loads((ROOT/'lskd_input_buffers_quality_gates.json').read_text())
        manifest['validation']['lskd_input_buffers_increment_checks']=input_buffers_quality['verified_counts']
    if (ROOT/'daemon_iokit_census_quality_gates.json').exists():
        daemon_iokit_census_quality=json.loads((ROOT/'daemon_iokit_census_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_census_increment_checks']=daemon_iokit_census_quality['verified_counts']
    if (ROOT/'daemon_query_state_quality_gates.json').exists():
        query_state_quality=json.loads((ROOT/'daemon_query_state_quality_gates.json').read_text())
        manifest['validation']['daemon_query_state_increment_checks']=query_state_quality['verified_counts']
    if (ROOT/'daemon_query_fallback_quality_gates.json').exists():
        query_fallback_quality=json.loads((ROOT/'daemon_query_fallback_quality_gates.json').read_text())
        manifest['validation']['daemon_query_fallback_increment_checks']=query_fallback_quality['verified_counts']
    if (ROOT/'daemon_iokit_objects_quality_gates.json').exists():
        iokit_objects_quality=json.loads((ROOT/'daemon_iokit_objects_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_objects_increment_checks']=iokit_objects_quality['verified_counts']
    if (ROOT/'daemon_iokit_class_quality_gates.json').exists():
        iokit_class_quality=json.loads((ROOT/'daemon_iokit_class_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_class_increment_checks']=iokit_class_quality['verified_counts']
    if (ROOT/'daemon_iokit_sync_quality_gates.json').exists():
        iokit_sync_quality=json.loads((ROOT/'daemon_iokit_sync_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_sync_increment_checks']=iokit_sync_quality['verified_counts']
    if (ROOT/'daemon_iokit_errors_quality_gates.json').exists():
        iokit_errors_quality=json.loads((ROOT/'daemon_iokit_errors_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_errors_increment_checks']=iokit_errors_quality['verified_counts']
    if (ROOT/'daemon_iokit_callers_quality_gates.json').exists():
        iokit_callers_quality=json.loads((ROOT/'daemon_iokit_callers_quality_gates.json').read_text())
        manifest['validation']['daemon_iokit_callers_increment_checks']=iokit_callers_quality['verified_counts']
    if (ROOT/'daemon_rwlock_lifecycle_quality_gates.json').exists():
        rwlock_lifecycle_quality=json.loads((ROOT/'daemon_rwlock_lifecycle_quality_gates.json').read_text())
        manifest['validation']['daemon_rwlock_lifecycle_increment_checks']=rwlock_lifecycle_quality['verified_counts']
    if (ROOT/'daemon_frame_entry_quality_gates.json').exists():
        frame_entry_quality=json.loads((ROOT/'daemon_frame_entry_quality_gates.json').read_text())
        manifest['validation']['daemon_frame_entry_increment_checks']=frame_entry_quality['verified_counts']
    if (ROOT/'daemon_arena_entry_quality_gates.json').exists():
        arena_entry_quality=json.loads((ROOT/'daemon_arena_entry_quality_gates.json').read_text())
        manifest['validation']['daemon_arena_entry_increment_checks']=arena_entry_quality['verified_counts']
    if (ROOT/'daemon_arena_storage_quality_gates.json').exists():
        arena_storage_quality=json.loads((ROOT/'daemon_arena_storage_quality_gates.json').read_text())
        manifest['validation']['daemon_arena_storage_increment_checks']=arena_storage_quality['verified_counts']
    if (ROOT/'daemon_context_transfer_quality_gates.json').exists():
        context_transfer_quality=json.loads((ROOT/'daemon_context_transfer_quality_gates.json').read_text())
        manifest['validation']['daemon_context_transfer_increment_checks']=context_transfer_quality['verified_counts']
        manifest['validation']['daemon_context_transfer_A64_checks']=context_transfer_quality['independent_A64_totals']
    if (ROOT/'daemon_entropy_return_quality_gates.json').exists():
        entropy_return_quality=json.loads((ROOT/'daemon_entropy_return_quality_gates.json').read_text())
        manifest['validation']['daemon_entropy_return_increment_checks']=entropy_return_quality['verified_counts']
        manifest['validation']['daemon_entropy_return_A64_checks']=entropy_return_quality['independent_A64_totals']
    if (ROOT/'daemon_seed_material_quality_gates.json').exists():
        seed_material_quality=json.loads((ROOT/'daemon_seed_material_quality_gates.json').read_text())
        manifest['validation']['daemon_seed_material_increment_checks']=seed_material_quality['verified_counts']
        manifest['validation']['daemon_seed_material_A64_checks']=seed_material_quality['independent_A64_totals']
    if (ROOT/'daemon_prng_output_quality_gates.json').exists():
        prng_output_quality=json.loads((ROOT/'daemon_prng_output_quality_gates.json').read_text())
        manifest['validation']['daemon_prng_output_increment_checks']=prng_output_quality['verified_counts']
        manifest['validation']['daemon_prng_output_A64_checks']=prng_output_quality['independent_A64_totals']
    if (ROOT/'daemon_buffer_consumer_quality_gates.json').exists():
        buffer_consumer_quality=json.loads((ROOT/'daemon_buffer_consumer_quality_gates.json').read_text())
        manifest['validation']['daemon_buffer_consumer_increment_checks']=buffer_consumer_quality['verified_counts']
        manifest['validation']['daemon_buffer_consumer_dynamic_A64_checks']=buffer_consumer_quality['dynamic_A64_totals']
    if (ROOT/'daemon_global_state_quality_gates.json').exists():
        global_state_quality=json.loads((ROOT/'daemon_global_state_quality_gates.json').read_text())
        manifest['validation']['daemon_global_state_increment_checks']=global_state_quality['verified_counts']
    if (ROOT/'daemon_callback_revisit_quality_gates.json').exists():
        callback_revisit_quality=json.loads((ROOT/'daemon_callback_revisit_quality_gates.json').read_text())
        manifest['validation']['daemon_callback_revisit_increment_checks']=callback_revisit_quality['verified_counts']
        manifest['validation']['daemon_callback_revisit_A64_checks']=callback_revisit_quality['independent_A64_totals']
    if (ROOT/'daemon_context_lock_quality_gates.json').exists():
        context_lock_quality=json.loads((ROOT/'daemon_context_lock_quality_gates.json').read_text())
        manifest['validation']['daemon_context_lock_increment_checks']=context_lock_quality['verified_counts']
        manifest['validation']['daemon_context_lock_A64_checks']=context_lock_quality['independent_A64_totals']
    if (ROOT/'daemon_descriptor_readers_quality_gates.json').exists():
        descriptor_readers_quality=json.loads((ROOT/'daemon_descriptor_readers_quality_gates.json').read_text())
        manifest['validation']['daemon_descriptor_readers_increment_checks']=descriptor_readers_quality['verified_counts']
        manifest['validation']['daemon_descriptor_readers_A64_checks']=descriptor_readers_quality['independent_A64_totals']
    if (ROOT/'daemon_descriptor_producers_quality_gates.json').exists():
        descriptor_producers_quality=json.loads((ROOT/'daemon_descriptor_producers_quality_gates.json').read_text())
        manifest['validation']['daemon_descriptor_producers_increment_checks']=descriptor_producers_quality['verified_counts']
        manifest['validation']['daemon_descriptor_producers_A64_checks']=descriptor_producers_quality['independent_A64_totals']
    if (ROOT/'daemon_mode471c_lifecycle_quality_gates.json').exists():
        mode471c_quality=json.loads((ROOT/'daemon_mode471c_lifecycle_quality_gates.json').read_text())
        manifest['validation']['daemon_mode471c_lifecycle_increment_checks']=mode471c_quality['verified_counts']
        manifest['validation']['daemon_mode471c_lifecycle_A64_checks']=mode471c_quality['independent_A64_totals']
    if (ROOT/'daemon_registry_lookup_quality_gates.json').exists():
        registry_quality=json.loads((ROOT/'daemon_registry_lookup_quality_gates.json').read_text())
        manifest['validation']['daemon_registry_lookup_increment_checks']=registry_quality['verified_counts']
        manifest['validation']['daemon_registry_lookup_A64_checks']=registry_quality['independent_A64_totals']
    if (ROOT/'daemon_object_consumers_quality_gates.json').exists():
        object_consumers_quality=json.loads((ROOT/'daemon_object_consumers_quality_gates.json').read_text())
        manifest['validation']['daemon_object_consumers_increment_checks']=object_consumers_quality['verified_counts']
        manifest['validation']['daemon_object_consumers_A64_checks']=object_consumers_quality['independent_A64_totals']
    if (ROOT/'daemon_object_creation_quality_gates.json').exists():
        object_creation_quality=json.loads((ROOT/'daemon_object_creation_quality_gates.json').read_text())
        manifest['validation']['daemon_object_creation_increment_checks']=object_creation_quality['verified_counts']
        manifest['validation']['daemon_object_creation_A64_checks']=object_creation_quality['independent_A64_totals']
    if (ROOT/'daemon_creation_predecessors_quality_gates.json').exists():
        creation_predecessors_quality=json.loads((ROOT/'daemon_creation_predecessors_quality_gates.json').read_text())
        manifest['validation']['daemon_creation_predecessors_increment_checks']=creation_predecessors_quality['verified_counts']
        manifest['validation']['daemon_creation_predecessors_A64_checks']=creation_predecessors_quality['independent_A64_totals']
    if (ROOT/'daemon_object_initialization_quality_gates.json').exists():
        object_initialization_quality=json.loads((ROOT/'daemon_object_initialization_quality_gates.json').read_text())
        manifest['validation']['daemon_object_initialization_increment_checks']=object_initialization_quality['verified_counts']
        manifest['validation']['daemon_object_initialization_A64_checks']=object_initialization_quality['independent_A64_totals']
    if (ROOT/'daemon_object_clock_quality_gates.json').exists():
        object_clock_quality=json.loads((ROOT/'daemon_object_clock_quality_gates.json').read_text())
        manifest['validation']['daemon_object_clock_increment_checks']=object_clock_quality['verified_counts']
        manifest['validation']['daemon_object_clock_A64_checks']=object_clock_quality['independent_A64_totals']
    if (ROOT/'daemon_cache36_quality_gates.json').exists():
        cache36_quality=json.loads((ROOT/'daemon_cache36_quality_gates.json').read_text())
        manifest['validation']['daemon_cache36_increment_checks']=cache36_quality['verified_counts']
        manifest['validation']['daemon_cache36_A64_checks']=cache36_quality['independent_A64_totals']
    if (ROOT/'daemon_identity_cache_quality_gates.json').exists():
        identity_cache_quality=json.loads((ROOT/'daemon_identity_cache_quality_gates.json').read_text())
        manifest['validation']['daemon_identity_cache_increment_checks']=identity_cache_quality['verified_counts']
        manifest['validation']['daemon_identity_cache_A64_checks']=identity_cache_quality['independent_A64_totals']
    if (ROOT/'daemon_digest_routes_quality_gates.json').exists():
        digest_routes_quality=json.loads((ROOT/'daemon_digest_routes_quality_gates.json').read_text())
        manifest['validation']['daemon_digest_routes_increment_checks']=digest_routes_quality['verified_counts']
        manifest['validation']['daemon_digest_routes_A64_checks']=digest_routes_quality['independent_A64_totals']
    if (ROOT/'daemon_digest_conventions_quality_gates.json').exists():
        digest_conventions_quality=json.loads((ROOT/'daemon_digest_conventions_quality_gates.json').read_text())
        manifest['validation']['daemon_digest_conventions_increment_checks']=digest_conventions_quality['verified_counts']
        manifest['validation']['daemon_digest_conventions_A64_checks']=digest_conventions_quality['independent_A64_totals']
    if (ROOT/'daemon_compression_frame_quality_gates.json').exists():
        compression_frame_quality=json.loads((ROOT/'daemon_compression_frame_quality_gates.json').read_text())
        manifest['validation']['daemon_compression_frame_increment_checks']=compression_frame_quality['verified_counts']
        manifest['validation']['daemon_compression_frame_A64_checks']=compression_frame_quality['independent_A64_totals']
    if (ROOT/'daemon_sha1_core_quality_gates.json').exists():
        sha1_core_quality=json.loads((ROOT/'daemon_sha1_core_quality_gates.json').read_text())
        manifest['validation']['daemon_sha1_core_increment_checks']=sha1_core_quality['verified_counts']
        manifest['validation']['daemon_sha1_core_A64_checks']=sha1_core_quality['independent_A64_totals']
    if (ROOT/'daemon_digest_output_quality_gates.json').exists():
        digest_output_quality=json.loads((ROOT/'daemon_digest_output_quality_gates.json').read_text())
        manifest['validation']['daemon_digest_output_increment_checks']=digest_output_quality['verified_counts']
        manifest['validation']['daemon_digest_output_A64_checks']=digest_output_quality['independent_A64_totals']
    if (ROOT/'daemon_digest_completion_quality_gates.json').exists():
        digest_completion_quality=json.loads((ROOT/'daemon_digest_completion_quality_gates.json').read_text())
        manifest['validation']['daemon_digest_completion_increment_checks']=digest_completion_quality['verified_counts']
        manifest['validation']['daemon_digest_completion_A64_checks']=digest_completion_quality['independent_A64_totals']
    if (ROOT/'daemon_cache_publication_quality_gates.json').exists():
        cache_publication_quality=json.loads((ROOT/'daemon_cache_publication_quality_gates.json').read_text())
        manifest['validation']['daemon_cache_publication_increment_checks']=cache_publication_quality['verified_counts']
        manifest['validation']['daemon_cache_publication_A64_checks']=cache_publication_quality['independent_A64_totals']
        manifest['validation']['daemon_cache_relocation_checks']=cache_publication_quality['relocation_verified_counts']
    if (ROOT/'daemon_record720_quality_gates.json').exists():
        record720_quality=json.loads((ROOT/'daemon_record720_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_increment_checks']=record720_quality['verified_counts']
        manifest['validation']['daemon_record720_A64_totals']=record720_quality['A64_totals']
    if (ROOT/'daemon_record720_handoff_quality_gates.json').exists():
        handoff720_quality=json.loads((ROOT/'daemon_record720_handoff_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_handoff_increment_checks']=handoff720_quality['verified_counts']
        manifest['validation']['daemon_record720_handoff_A64_totals']=handoff720_quality['independent_A64_totals']
    if (ROOT/'daemon_record720_release_quality_gates.json').exists():
        release720_quality=json.loads((ROOT/'daemon_record720_release_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_release_increment_checks']=release720_quality['verified_counts']
        manifest['validation']['daemon_record720_release_A64_totals']=release720_quality['independent_A64_totals']
    if (ROOT/'daemon_record720_fingerprint_quality_gates.json').exists():
        fingerprint720_quality=json.loads((ROOT/'daemon_record720_fingerprint_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_fingerprint_increment_checks']=fingerprint720_quality['verified_counts']
        manifest['validation']['daemon_record720_fingerprint_A64_totals']=fingerprint720_quality['independent_A64_totals']
    if (ROOT/'daemon_record720_fields_quality_gates.json').exists():
        fields720_quality=json.loads((ROOT/'daemon_record720_fields_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_fields_increment_checks']=fields720_quality['verified_counts']
        manifest['validation']['daemon_record720_fields_A64_totals']=fields720_quality['independent_A64_totals']
    if (ROOT/'daemon_record720_spill_quality_gates.json').exists():
        spill720_quality=json.loads((ROOT/'daemon_record720_spill_quality_gates.json').read_text())
        manifest['validation']['daemon_record720_spill_increment_checks']=spill720_quality['verified_counts']
        manifest['validation']['daemon_record720_spill_witness_totals']=spill720_quality['independent_witness_totals']
    if (ROOT/'daemon_arena_list_quality_gates.json').exists():
        arena_list_quality=json.loads((ROOT/'daemon_arena_list_quality_gates.json').read_text())
        manifest['validation']['daemon_arena_list_increment_checks']=arena_list_quality['verified_counts']
        manifest['validation']['daemon_arena_list_witness_totals']=arena_list_quality['independent_witness_totals']
    if (ROOT/'daemon_arena_consumer_quality_gates.json').exists():
        arena_consumer_quality=json.loads((ROOT/'daemon_arena_consumer_quality_gates.json').read_text())
        manifest['validation']['daemon_arena_consumer_increment_checks']=arena_consumer_quality['verified_counts']
        manifest['validation']['daemon_arena_consumer_A64_totals']=arena_consumer_quality['independent_A64_totals']
    if (ROOT/'rpc502_receive_bridge_quality_gates.json').exists():
        receive_bridge_quality=json.loads((ROOT/'rpc502_receive_bridge_quality_gates.json').read_text())
        manifest['validation']['rpc502_receive_bridge_increment_checks']=receive_bridge_quality['verified_counts']
        manifest['validation']['rpc502_receive_bridge_kernel_A64_totals']=receive_bridge_quality['independent_kernel_A64_totals']
        manifest['validation']['rpc502_receive_bridge_daemon_A64_totals']=receive_bridge_quality['independent_daemon_A64_totals']
    if (ROOT/'kernel_receive_delivery_quality_gates.json').exists():
        receive_delivery_quality=json.loads((ROOT/'kernel_receive_delivery_quality_gates.json').read_text())
        manifest['validation']['kernel_receive_delivery_increment_checks']=receive_delivery_quality['verified_counts']
        manifest['validation']['kernel_receive_delivery_A64_totals']=receive_delivery_quality['independent_A64_totals']
    if (ROOT/'kernel_queue_receive_quality_gates.json').exists():
        queue_receive_quality=json.loads((ROOT/'kernel_queue_receive_quality_gates.json').read_text())
        manifest['validation']['kernel_queue_receive_increment_checks']=queue_receive_quality['verified_counts']
        manifest['validation']['kernel_queue_receive_A64_totals']=queue_receive_quality['independent_A64_totals']
    if (ROOT/'kernel_queue_send_quality_gates.json').exists():
        queue_send_quality=json.loads((ROOT/'kernel_queue_send_quality_gates.json').read_text())
        manifest['validation']['kernel_queue_send_increment_checks']=queue_send_quality['verified_counts']
        manifest['validation']['kernel_queue_send_A64_totals']=queue_send_quality['independent_A64_totals']
        manifest['validation']['kernel_queue_send_consumer_joins']=queue_send_quality['consumer_joins']
    if (ROOT/'kernel_reply_send_quality_gates.json').exists():
        reply_send_quality=json.loads((ROOT/'kernel_reply_send_quality_gates.json').read_text())
        manifest['validation']['kernel_reply_send_increment_checks']=reply_send_quality['verified_counts']
        manifest['validation']['kernel_reply_send_A64_totals']=reply_send_quality['independent_A64_totals']
    if (ROOT/'kernel_vm_mig_quality_gates.json').exists():
        kernel_vm_mig_quality=json.loads((ROOT/'kernel_vm_mig_quality_gates.json').read_text())
        manifest['validation']['kernel_vm_mig_increment_checks']=kernel_vm_mig_quality['verified_counts']
        manifest['validation']['kernel_vm_mig_A64_totals']=kernel_vm_mig_quality['independent_A64_totals']
    if (ROOT/'daemon_vm_cleanup_quality_gates.json').exists():
        vm_cleanup_quality=json.loads((ROOT/'daemon_vm_cleanup_quality_gates.json').read_text())
        manifest['validation']['daemon_vm_cleanup_increment_checks']=vm_cleanup_quality['verified_counts']
        manifest['validation']['daemon_vm_cleanup_A64_totals']=vm_cleanup_quality['independent_A64_totals']
        manifest['validation']['daemon_vm_cleanup_cache_A64_totals']=vm_cleanup_quality['independent_cache_A64_totals']
    if (ROOT/'daemon_client_object_quality_gates.json').exists():
        client_object_quality=json.loads((ROOT/'daemon_client_object_quality_gates.json').read_text())
        manifest['validation']['daemon_client_object_increment_checks']=client_object_quality['verified_counts']
        manifest['validation']['daemon_client_object_A64_totals']=client_object_quality['independent_A64_totals']
    if (ROOT/'daemon_boolean_chain_quality_gates.json').exists():
        boolean_chain_quality=json.loads((ROOT/'daemon_boolean_chain_quality_gates.json').read_text())
        manifest['validation']['daemon_boolean_chain_increment_checks']=boolean_chain_quality['verified_counts']
        manifest['validation']['daemon_boolean_chain_A64_totals']=boolean_chain_quality['independent_A64_totals']
    if (ROOT/'daemon_secondary_string_quality_gates.json').exists():
        secondary_string_quality=json.loads((ROOT/'daemon_secondary_string_quality_gates.json').read_text())
        manifest['validation']['daemon_secondary_string_increment_checks']=secondary_string_quality['verified_counts']
        manifest['validation']['daemon_secondary_string_A64_totals']=secondary_string_quality['independent_A64_totals']
        manifest['validation']['daemon_secondary_string_host_libc_reference_executed']=True
    if (ROOT/'daemon_secondary_result_quality_gates.json').exists():
        secondary_result_quality=json.loads((ROOT/'daemon_secondary_result_quality_gates.json').read_text())
        manifest['validation']['daemon_secondary_result_increment_checks']=secondary_result_quality['verified_counts']
        manifest['validation']['daemon_secondary_result_A64_totals']=secondary_result_quality['independent_A64_totals']
    if (ROOT/'daemon_entitlement_flow_quality_gates.json').exists():
        entitlement_flow_quality=json.loads((ROOT/'daemon_entitlement_flow_quality_gates.json').read_text())
        manifest['validation']['daemon_entitlement_flow_increment_checks']=entitlement_flow_quality['verified_counts']
        manifest['validation']['daemon_entitlement_flow_A64_totals']=entitlement_flow_quality['independent_A64_totals']
    if (ROOT/'daemon_entitlement_result_quality_gates.json').exists():
        entitlement_result_quality=json.loads((ROOT/'daemon_entitlement_result_quality_gates.json').read_text())
        manifest['validation']['daemon_entitlement_result_increment_checks']=entitlement_result_quality['verified_counts']
        manifest['validation']['daemon_entitlement_result_A64_totals']=entitlement_result_quality['independent_A64_totals']
    if (ROOT/'daemon_record40_consumer_quality_gates.json').exists():
        record40_consumer_quality=json.loads((ROOT/'daemon_record40_consumer_quality_gates.json').read_text())
        manifest['validation']['daemon_record40_consumer_increment_checks']=record40_consumer_quality['verified_counts']
        manifest['validation']['daemon_record40_consumer_A64_totals']=record40_consumer_quality['independent_A64_totals']
    if (ROOT/'daemon_mig_handover_quality_gates.json').exists():
        mig_handover_quality=json.loads((ROOT/'daemon_mig_handover_quality_gates.json').read_text())
        manifest['validation']['daemon_mig_handover_increment_checks']=mig_handover_quality['verified_counts']
        manifest['validation']['daemon_mig_handover_A64_totals']=mig_handover_quality['independent_A64_totals']
    if (ROOT/'daemon_operation_heads_quality_gates.json').exists():
        operation_heads_quality=json.loads((ROOT/'daemon_operation_heads_quality_gates.json').read_text())
        manifest['validation']['daemon_operation_heads_increment_checks']=operation_heads_quality['verified_counts']
        manifest['validation']['daemon_operation_heads_A64_totals']=operation_heads_quality['independent_A64_totals']
    if (ROOT/'daemon_core_dispatch_quality_gates.json').exists():
        core_dispatch_quality=json.loads((ROOT/'daemon_core_dispatch_quality_gates.json').read_text())
        manifest['validation']['daemon_core_dispatch_increment_checks']=core_dispatch_quality['verified_counts']
        manifest['validation']['daemon_core_dispatch_A64_totals']=core_dispatch_quality['independent_A64_totals']
    if (ROOT/'daemon_shared_roots_quality_gates.json').exists():
        shared_roots_quality=json.loads((ROOT/'daemon_shared_roots_quality_gates.json').read_text())
        manifest['validation']['daemon_shared_roots_increment_checks']=shared_roots_quality['verified_counts']
        manifest['validation']['daemon_shared_roots_A64_totals']=shared_roots_quality['independent_A64_totals']
    if (ROOT/'daemon_aux_callers_quality_gates.json').exists():
        aux_callers_quality=json.loads((ROOT/'daemon_aux_callers_quality_gates.json').read_text())
        manifest['validation']['daemon_aux_callers_increment_checks']=aux_callers_quality['verified_counts']
        manifest['validation']['daemon_aux_callers_A64_totals']=aux_callers_quality['independent_A64_totals']
    if (ROOT/'daemon_output_base_quality_gates.json').exists():
        output_base_quality=json.loads((ROOT/'daemon_output_base_quality_gates.json').read_text())
        manifest['validation']['daemon_output_base_increment_checks']=output_base_quality['verified_counts']
        manifest['validation']['daemon_output_base_A64_totals']=output_base_quality['independent_A64_totals']
    if (ROOT/'daemon_cleanup_return_quality_gates.json').exists():
        cleanup_return_quality=json.loads((ROOT/'daemon_cleanup_return_quality_gates.json').read_text())
        manifest['validation']['daemon_cleanup_return_increment_checks']=cleanup_return_quality['verified_counts']
        manifest['validation']['daemon_cleanup_return_A64_totals']=cleanup_return_quality['independent_A64_totals']
    if (ROOT/'daemon_arena_lifetime_quality_gates.json').exists():
        arena_lifetime_quality=json.loads((ROOT/'daemon_arena_lifetime_quality_gates.json').read_text())
        manifest['validation']['daemon_arena_lifetime_increment_checks']=arena_lifetime_quality['verified_counts']
        manifest['validation']['daemon_arena_lifetime_A64_totals']=arena_lifetime_quality['independent_A64_totals']
    if (ROOT/'rpc502_reply_bridge_quality_gates.json').exists():
        reply_bridge_quality=json.loads((ROOT/'rpc502_reply_bridge_quality_gates.json').read_text())
        manifest['validation']['rpc502_reply_bridge_increment_checks']=reply_bridge_quality['verified_counts']
        manifest['validation']['rpc502_reply_bridge_A64_totals']=reply_bridge_quality['independent_A64_replay']
    if (ROOT/'kernel_reply_copyout_quality_gates.json').exists():
        reply_copyout_quality=json.loads((ROOT/'kernel_reply_copyout_quality_gates.json').read_text())
        manifest['validation']['kernel_reply_copyout_increment_checks']=reply_copyout_quality['verified_counts']
        manifest['validation']['kernel_reply_copyout_A64_totals']=reply_copyout_quality['independent_A64_replay']
    if (ROOT/'rpc502_reply_copyin_quality_gates.json').exists():
        reply_copyin_quality=json.loads((ROOT/'rpc502_reply_copyin_quality_gates.json').read_text())
        manifest['validation']['rpc502_reply_copyin_increment_checks']=reply_copyin_quality['verified_counts']
        manifest['validation']['rpc502_reply_copyin_A64_totals']=reply_copyin_quality['independent_A64_replay']
    if (ROOT/'kernel_copyin_policy_quality_gates.json').exists():
        copyin_policy_quality=json.loads((ROOT/'kernel_copyin_policy_quality_gates.json').read_text())
        manifest['validation']['kernel_copyin_policy_increment_checks']=copyin_policy_quality['verified_counts']
        manifest['validation']['kernel_copyin_policy_A64_totals']=copyin_policy_quality['independent_A64_replay']
    if (ROOT/'cf_public_runloop_quality_gates.json').exists():
        public_quality=json.loads((ROOT/'cf_public_runloop_quality_gates.json').read_text())
        manifest['validation']['cf_public_runloop_increment_checks']=public_quality['verified_counts']
        manifest['validation']['cf_public_runloop_CF_totals']=public_quality['independent_CF_replay']
        manifest['validation']['cf_public_runloop_daemon_totals']=public_quality['independent_daemon_replay']
    if (ROOT/'cf_source0_scheduler_quality_gates.json').exists():
        scheduler_quality=json.loads((ROOT/'cf_source0_scheduler_quality_gates.json').read_text())
        manifest['validation']['cf_source0_scheduler_increment_checks']=scheduler_quality['verified_counts']
        manifest['validation']['cf_source0_scheduler_CF_totals']=scheduler_quality['independent_CF_replay']
        manifest['validation']['cf_source0_scheduler_daemon_totals']=scheduler_quality['independent_daemon_replay']
    if (ROOT/'cf_descriptor_source_factory_quality_gates.json').exists():
        factory_quality=json.loads((ROOT/'cf_descriptor_source_factory_quality_gates.json').read_text())
        manifest['validation']['cf_descriptor_source_factory_increment_checks']=factory_quality['verified_counts']
        manifest['validation']['cf_descriptor_source_factory_CF_totals']=factory_quality['independent_CF_replay']
        manifest['validation']['cf_descriptor_source_factory_daemon_totals']=factory_quality['independent_daemon_replay']
    if (ROOT/'daemon_descriptor_source_quality_gates.json').exists():
        descriptor_quality=json.loads((ROOT/'daemon_descriptor_source_quality_gates.json').read_text())
        manifest['validation']['daemon_descriptor_source_increment_checks']=descriptor_quality['verified_counts']
        manifest['validation']['daemon_descriptor_source_daemon_totals']=descriptor_quality['independent_daemon_replay']
        manifest['validation']['daemon_descriptor_source_CF_totals']=descriptor_quality['independent_CF_replay']
    if (ROOT/'cf_source_wake_callers_quality_gates.json').exists():
        source_wake_quality=json.loads((ROOT/'cf_source_wake_callers_quality_gates.json').read_text())
        manifest['validation']['cf_source_wake_callers_increment_checks']=source_wake_quality['verified_counts']
        manifest['validation']['cf_source_wake_callers_CF_totals']=source_wake_quality['independent_CF_replay']
        manifest['validation']['cf_source_wake_callers_downstream_totals']=source_wake_quality['fresh_downstream_kernel_replay']
        manifest['validation']['cf_source_wake_callers_startup_totals']=source_wake_quality['fresh_timer_startup_replay']
    if (ROOT/'kernel_wake_send_ingress_quality_gates.json').exists():
        wake_ingress_quality=json.loads((ROOT/'kernel_wake_send_ingress_quality_gates.json').read_text())
        manifest['validation']['kernel_wake_send_ingress_increment_checks']=wake_ingress_quality['verified_counts']
        manifest['validation']['kernel_wake_send_ingress_A64_totals']=wake_ingress_quality['independent_A64_replay']
        manifest['validation']['kernel_wake_send_ingress_CF_totals']=wake_ingress_quality['independent_CF_replay']
        manifest['validation']['kernel_wake_send_ingress_startup_totals']=wake_ingress_quality['fresh_timer_startup_replay']
        manifest['validation']['kernel_wake_send_ingress_producer_totals']=wake_ingress_quality['fresh_CF_producer_replay']
    if (ROOT/'cf_wake_send_wrapper_quality_gates.json').exists():
        send_wrapper_quality=json.loads((ROOT/'cf_wake_send_wrapper_quality_gates.json').read_text())
        manifest['validation']['cf_wake_send_wrapper_increment_checks']=send_wrapper_quality['verified_counts']
        manifest['validation']['cf_wake_send_wrapper_A64_totals']=send_wrapper_quality['independent_A64_replay']
        manifest['validation']['cf_wake_send_wrapper_CF_totals']=send_wrapper_quality['independent_CF_replay']
        manifest['validation']['cf_wake_send_wrapper_startup_totals']=send_wrapper_quality['fresh_timer_startup_replay']
        manifest['validation']['cf_wake_send_wrapper_factory_totals']=send_wrapper_quality['fresh_CF_factory_replay']
    if (ROOT/'cf_runloop_wake_port_quality_gates.json').exists():
        wake_quality=json.loads((ROOT/'cf_runloop_wake_port_quality_gates.json').read_text())
        manifest['validation']['cf_runloop_wake_port_increment_checks']=wake_quality['verified_counts']
        manifest['validation']['cf_runloop_wake_port_A64_totals']=wake_quality['independent_A64_replay']
        manifest['validation']['cf_runloop_wake_port_CF_totals']=wake_quality['independent_CF_replay']
        manifest['validation']['cf_runloop_wake_port_startup_totals']=wake_quality['fresh_timer_startup_replay']
    if (ROOT/'kernel_timer_expiration_delivery_quality_gates.json').exists():
        expiration_quality=json.loads((ROOT/'kernel_timer_expiration_delivery_quality_gates.json').read_text())
        manifest['validation']['kernel_timer_expiration_delivery_increment_checks']=expiration_quality['verified_counts']
        manifest['validation']['kernel_timer_expiration_delivery_A64_totals']=expiration_quality['independent_A64_replay']
        manifest['validation']['kernel_timer_expiration_delivery_CF_totals']=expiration_quality['independent_CF_replay']
        manifest['validation']['kernel_timer_expiration_delivery_startup_totals']=expiration_quality['fresh_timer_startup_replay']
    if (ROOT/'kernel_timer_port_create_quality_gates.json').exists():
        timer_quality=json.loads((ROOT/'kernel_timer_port_create_quality_gates.json').read_text())
        manifest['validation']['kernel_timer_port_create_increment_checks']=timer_quality['verified_counts']
        manifest['validation']['kernel_timer_port_create_A64_totals']=timer_quality['independent_A64_replay']
        manifest['validation']['kernel_timer_port_create_CF_totals']=timer_quality['independent_CF_replay']
        manifest['validation']['kernel_timer_port_create_startup_totals']=timer_quality['independent_startup_replay']
    if (ROOT/'kernel_root_port_construct_quality_gates.json').exists():
        root_quality=json.loads((ROOT/'kernel_root_port_construct_quality_gates.json').read_text())
        manifest['validation']['kernel_root_port_construct_increment_checks']=root_quality['verified_counts']
        manifest['validation']['kernel_root_port_construct_A64_totals']=root_quality['independent_A64_replay']
        manifest['validation']['kernel_root_port_construct_CF_totals']=root_quality['independent_CF_replay']
    if (ROOT/'cf_control_port_dispatch_quality_gates.json').exists():
        control_quality=json.loads((ROOT/'cf_control_port_dispatch_quality_gates.json').read_text())
        manifest['validation']['cf_control_port_dispatch_increment_checks']=control_quality['verified_counts']
        manifest['validation']['cf_control_port_dispatch_A64_totals']=control_quality['independent_A64_replay']
        manifest['validation']['cf_control_port_dispatch_kernel_totals']=control_quality['fresh_kernel_replay']
        manifest['validation']['cf_control_port_dispatch_mode_totals']=control_quality['fresh_mode_replay']
    if (ROOT/'cf_mode_construction_quality_gates.json').exists():
        mode_quality=json.loads((ROOT/'cf_mode_construction_quality_gates.json').read_text())
        manifest['validation']['cf_mode_construction_increment_checks']=mode_quality['verified_counts']
        manifest['validation']['cf_mode_construction_A64_totals']=mode_quality['independent_A64_replay']
        manifest['validation']['cf_mode_construction_kernel_totals']=mode_quality['fresh_kernel_replay']
    if (ROOT/'kernel_portset_delivery_quality_gates.json').exists():
        portset_quality=json.loads((ROOT/'kernel_portset_delivery_quality_gates.json').read_text())
        manifest['validation']['kernel_portset_delivery_increment_checks']=portset_quality['verified_counts']
        manifest['validation']['kernel_portset_delivery_A64_totals']=portset_quality['independent_A64_replay']
        manifest['validation']['kernel_portset_delivery_CF_totals']=portset_quality['independent_CF_replay']
    if (ROOT/'cf_source_scheduling_quality_gates.json').exists():
        scheduling_quality=json.loads((ROOT/'cf_source_scheduling_quality_gates.json').read_text())
        manifest['validation']['cf_source_scheduling_increment_checks']=scheduling_quality['verified_counts']
        manifest['validation']['cf_source_scheduling_A64_totals']=scheduling_quality['independent_A64_replay']
    if (ROOT/'cf_runloop_handoff_quality_gates.json').exists():
        runloop_quality=json.loads((ROOT/'cf_runloop_handoff_quality_gates.json').read_text())
        manifest['validation']['cf_runloop_handoff_increment_checks']=runloop_quality['verified_counts']
        manifest['validation']['cf_runloop_handoff_A64_totals']=runloop_quality['independent_A64_replay']
    if (ROOT/'dispatch_voucher_hooks_quality_gates.json').exists():
        dispatch_hooks_quality=json.loads((ROOT/'dispatch_voucher_hooks_quality_gates.json').read_text())
        manifest['validation']['dispatch_voucher_hooks_increment_checks']=dispatch_hooks_quality['verified_counts']
        manifest['validation']['dispatch_voucher_hooks_A64_totals']=dispatch_hooks_quality['independent_A64_replay']
    if (ROOT/'cf_receive_voucher_quality_gates.json').exists():
        receive_voucher_quality=json.loads((ROOT/'cf_receive_voucher_quality_gates.json').read_text())
        manifest['validation']['cf_receive_voucher_increment_checks']=receive_voucher_quality['verified_counts']
        manifest['validation']['cf_receive_voucher_A64_totals']=receive_voucher_quality['independent_A64_replay']
    if (ROOT/'cf_daemon_request_quality_gates.json').exists():
        cf_daemon_quality=json.loads((ROOT/'cf_daemon_request_quality_gates.json').read_text())
        manifest['validation']['cf_daemon_request_increment_checks']=cf_daemon_quality['verified_counts']
        manifest['validation']['cf_daemon_request_A64_totals']=cf_daemon_quality['independent_A64_replay']
    if (ROOT/'daemon_request_application_quality_gates.json').exists():
        application_quality=json.loads((ROOT/'daemon_request_application_quality_gates.json').read_text())
        manifest['validation']['daemon_request_application_increment_checks']=application_quality['verified_counts']
        manifest['validation']['daemon_request_application_A64_totals']=application_quality['independent_A64_replay']
    if (ROOT/'daemon_request_consumption_quality_gates.json').exists():
        daemon_request_quality=json.loads((ROOT/'daemon_request_consumption_quality_gates.json').read_text())
        manifest['validation']['daemon_request_consumption_increment_checks']=daemon_request_quality['verified_counts']
        manifest['validation']['daemon_request_consumption_A64_totals']=daemon_request_quality['independent_A64_replay']
    if (ROOT/'kernel_request_delivery_quality_gates.json').exists():
        request_delivery_quality=json.loads((ROOT/'kernel_request_delivery_quality_gates.json').read_text())
        manifest['validation']['kernel_request_delivery_increment_checks']=request_delivery_quality['verified_counts']
        manifest['validation']['kernel_request_delivery_A64_totals']=request_delivery_quality['independent_A64_replay']
    if (ROOT/'kernel_request_copyin_quality_gates.json').exists():
        request_copyin_quality=json.loads((ROOT/'kernel_request_copyin_quality_gates.json').read_text())
        manifest['validation']['kernel_request_copyin_increment_checks']=request_copyin_quality['verified_counts']
        manifest['validation']['kernel_request_copyin_A64_totals']=request_copyin_quality['independent_A64_replay']
    if (ROOT/'kernel_request_receive_quality_gates.json').exists():
        request_receive_quality=json.loads((ROOT/'kernel_request_receive_quality_gates.json').read_text())
        manifest['validation']['kernel_request_receive_increment_checks']=request_receive_quality['verified_counts']
        manifest['validation']['kernel_request_receive_A64_totals']=request_receive_quality['independent_A64_replay']
    if (ROOT/'kernel_rpc_request_quality_gates.json').exists():
        rpc_request_quality=json.loads((ROOT/'kernel_rpc_request_quality_gates.json').read_text())
        manifest['validation']['kernel_rpc_request_increment_checks']=rpc_request_quality['verified_counts']
        manifest['validation']['kernel_rpc_request_A64_totals']=rpc_request_quality['independent_A64_replay']
    if (ROOT/'kernel_special_reply_quality_gates.json').exists():
        special_reply_quality=json.loads((ROOT/'kernel_special_reply_quality_gates.json').read_text())
        manifest['validation']['kernel_special_reply_increment_checks']=special_reply_quality['verified_counts']
        manifest['validation']['kernel_special_reply_A64_totals']=special_reply_quality['independent_A64_replay']
    if (ROOT/'kernel_reply_namespace_quality_gates.json').exists():
        reply_namespace_quality=json.loads((ROOT/'kernel_reply_namespace_quality_gates.json').read_text())
        manifest['validation']['kernel_reply_namespace_increment_checks']=reply_namespace_quality['verified_counts']
        manifest['validation']['kernel_reply_namespace_A64_totals']=reply_namespace_quality['independent_A64_replay']
    if (ROOT/'kernel_receive_copyout_quality_gates.json').exists():
        receive_copyout_quality=json.loads((ROOT/'kernel_receive_copyout_quality_gates.json').read_text())
        manifest['validation']['kernel_receive_copyout_increment_checks']=receive_copyout_quality['verified_counts']
        manifest['validation']['kernel_receive_copyout_A64_totals']=receive_copyout_quality['independent_A64_replay']
    if (ROOT/'kernel_receive_continuation_quality_gates.json').exists():
        receive_continuation_quality=json.loads((ROOT/'kernel_receive_continuation_quality_gates.json').read_text())
        manifest['validation']['kernel_receive_continuation_increment_checks']=receive_continuation_quality['verified_counts']
        manifest['validation']['kernel_receive_continuation_A64_totals']=receive_continuation_quality['independent_A64_replay']
    if (ROOT/'kernel_waitq_enqueue_quality_gates.json').exists():
        waitq_enqueue_quality=json.loads((ROOT/'kernel_waitq_enqueue_quality_gates.json').read_text())
        manifest['validation']['kernel_waitq_enqueue_increment_checks']=waitq_enqueue_quality['verified_counts']
        manifest['validation']['kernel_waitq_enqueue_A64_totals']=waitq_enqueue_quality['independent_A64_replay']
    if (ROOT/'kernel_waitq_receiver_quality_gates.json').exists():
        waitq_receiver_quality=json.loads((ROOT/'kernel_waitq_receiver_quality_gates.json').read_text())
        manifest['validation']['kernel_waitq_receiver_increment_checks']=waitq_receiver_quality['verified_counts']
        manifest['validation']['kernel_waitq_receiver_A64_totals']=waitq_receiver_quality['independent_A64_replay']
    if (ROOT/'kernel_kmsg_queue_quality_gates.json').exists():
        kmsg_queue_quality=json.loads((ROOT/'kernel_kmsg_queue_quality_gates.json').read_text())
        manifest['validation']['kernel_kmsg_queue_increment_checks']=kmsg_queue_quality['verified_counts']
        manifest['validation']['kernel_kmsg_queue_A64_totals']=kmsg_queue_quality['independent_A64_replay']
    if (ROOT/'kernel_cache_gate_quality_gates.json').exists():
        cache_gate_quality=json.loads((ROOT/'kernel_cache_gate_quality_gates.json').read_text())
        manifest['validation']['kernel_cache_gate_increment_checks']=cache_gate_quality['verified_counts']
        manifest['validation']['kernel_cache_gate_A64_totals']=cache_gate_quality['independent_A64_replay']
    if (ROOT/'kernel_zone_refill_quality_gates.json').exists():
        zone_refill_quality=json.loads((ROOT/'kernel_zone_refill_quality_gates.json').read_text())
        manifest['validation']['kernel_zone_refill_increment_checks']=zone_refill_quality['verified_counts']
        manifest['validation']['kernel_zone_refill_A64_totals']=zone_refill_quality['independent_A64_replay']
    if (ROOT/'kernel_zone_startup_quality_gates.json').exists():
        zone_startup_quality=json.loads((ROOT/'kernel_zone_startup_quality_gates.json').read_text())
        manifest['validation']['kernel_zone_startup_increment_checks']=zone_startup_quality['verified_counts']
        manifest['validation']['kernel_zone_startup_A64_totals']=zone_startup_quality['independent_A64_replay']
    if (ROOT/'kernel_kmsg_allocation_quality_gates.json').exists():
        kmsg_allocation_quality=json.loads((ROOT/'kernel_kmsg_allocation_quality_gates.json').read_text())
        manifest['validation']['kernel_kmsg_allocation_increment_checks']=kmsg_allocation_quality['verified_counts']
        manifest['validation']['kernel_kmsg_allocation_A64_totals']=kmsg_allocation_quality['independent_A64_replay']
    if (ROOT/'kernel_notification_send_quality_gates.json').exists():
        notification_send_quality=json.loads((ROOT/'kernel_notification_send_quality_gates.json').read_text())
        manifest['validation']['kernel_notification_send_increment_checks']=notification_send_quality['verified_counts']
        manifest['validation']['kernel_notification_send_A64_totals']=notification_send_quality['independent_A64_replay']
    if (ROOT/'kernel_send_right_lifecycle_quality_gates.json').exists():
        send_lifecycle_quality=json.loads((ROOT/'kernel_send_right_lifecycle_quality_gates.json').read_text())
        manifest['validation']['kernel_send_right_lifecycle_increment_checks']=send_lifecycle_quality['verified_counts']
        manifest['validation']['kernel_send_right_lifecycle_A64_totals']=send_lifecycle_quality['independent_A64_replay']
    if (ROOT/'kext_vm_copyout_bridge_quality_gates.json').exists():
        copyout_bridge_quality=json.loads((ROOT/'kext_vm_copyout_bridge_quality_gates.json').read_text())
        manifest['validation']['kext_vm_copyout_bridge_increment_checks']=copyout_bridge_quality['verified_counts']
        manifest['validation']['kext_vm_copyout_bridge_A64_totals']=copyout_bridge_quality['independent_A64_replay']
    if (ROOT/'kernel_range_fallback_quality_gates.json').exists():
        range_fallback_quality=json.loads((ROOT/'kernel_range_fallback_quality_gates.json').read_text())
        manifest['validation']['kernel_range_fallback_increment_checks']=range_fallback_quality['verified_counts']
        manifest['validation']['kernel_range_fallback_A64_totals']=range_fallback_quality['independent_A64_replay']
    if (ROOT/'kernel_range_resolver_quality_gates.json').exists():
        range_resolver_quality=json.loads((ROOT/'kernel_range_resolver_quality_gates.json').read_text())
        manifest['validation']['kernel_range_resolver_increment_checks']=range_resolver_quality['verified_counts']
        manifest['validation']['kernel_range_resolver_A64_totals']=range_resolver_quality['independent_A64_replay']
    if (ROOT/'kernel_map_store_init_quality_gates.json').exists():
        map_store_init_quality=json.loads((ROOT/'kernel_map_store_init_quality_gates.json').read_text())
        manifest['validation']['kernel_map_store_init_increment_checks']=map_store_init_quality['verified_counts']
        manifest['validation']['kernel_map_store_init_A64_totals']=map_store_init_quality['independent_A64_replay']
    if (ROOT/'kernel_type2_copyout_quality_gates.json').exists():
        type2_copyout_quality=json.loads((ROOT/'kernel_type2_copyout_quality_gates.json').read_text())
        manifest['validation']['kernel_type2_copyout_increment_checks']=type2_copyout_quality['verified_counts']
        manifest['validation']['kernel_type2_copyout_A64_totals']=type2_copyout_quality['independent_A64_replay']
    if (ROOT/'kernel_vm_entry_copy_quality_gates.json').exists():
        vm_entry_copy_quality=json.loads((ROOT/'kernel_vm_entry_copy_quality_gates.json').read_text())
        manifest['validation']['kernel_vm_entry_copy_increment_checks']=vm_entry_copy_quality['verified_counts']
        manifest['validation']['kernel_vm_entry_copy_A64_totals']=vm_entry_copy_quality['independent_A64_replay']
    if (ROOT/'kernel_vm_range_cursor_quality_gates.json').exists():
        vm_range_cursor_quality=json.loads((ROOT/'kernel_vm_range_cursor_quality_gates.json').read_text())
        manifest['validation']['kernel_vm_range_cursor_increment_checks']=vm_range_cursor_quality['verified_counts']
        manifest['validation']['kernel_vm_range_cursor_A64_totals']=vm_range_cursor_quality['independent_A64_replay']
    if (ROOT/'rpc502_vm_handoff_quality_gates.json').exists():
        vm_handoff_quality=json.loads((ROOT/'rpc502_vm_handoff_quality_gates.json').read_text())
        manifest['validation']['rpc502_vm_handoff_increment_checks']=vm_handoff_quality['verified_counts']
        manifest['validation']['rpc502_vm_handoff_A64_totals']=vm_handoff_quality['independent_A64_replay']
    if (ROOT/'iorpc_binary_parser_quality_gates.json').exists():
        binary_parser_quality=json.loads((ROOT/'iorpc_binary_parser_quality_gates.json').read_text())
        manifest['validation']['iorpc_binary_parser_increment_checks']=binary_parser_quality['verified_counts']
        manifest['validation']['iorpc_binary_parser_A64_totals']=binary_parser_quality['independent_A64_replay']
    if (ROOT/'iorpc_ool_serialization_quality_gates.json').exists():
        ool_serialization_quality=json.loads((ROOT/'iorpc_ool_serialization_quality_gates.json').read_text())
        manifest['validation']['iorpc_ool_serialization_increment_checks']=ool_serialization_quality['verified_counts']
        manifest['validation']['iorpc_ool_serialization_A64_totals']=ool_serialization_quality['independent_A64_replay']
    if (ROOT/'iorpc_object_conversion_quality_gates.json').exists():
        object_conversion_quality=json.loads((ROOT/'iorpc_object_conversion_quality_gates.json').read_text())
        manifest['validation']['iorpc_object_conversion_increment_checks']=object_conversion_quality['verified_counts']
        manifest['validation']['iorpc_object_conversion_A64_totals']=object_conversion_quality['independent_A64_replay']
    if (ROOT/'iorpc_remote_quality_gates.json').exists():
        remote_rpc_quality=json.loads((ROOT/'iorpc_remote_quality_gates.json').read_text())
        manifest['validation']['iorpc_remote_increment_checks']=remote_rpc_quality['verified_counts']
        manifest['validation']['iorpc_remote_A64_totals']=remote_rpc_quality['independent_A64_replay']
    if (ROOT/'platform_iorpc_quality_gates.json').exists():
        platform_rpc_quality=json.loads((ROOT/'platform_iorpc_quality_gates.json').read_text())
        manifest['validation']['platform_iorpc_increment_checks']=platform_rpc_quality['verified_counts']
        manifest['validation']['platform_iorpc_A64_totals']=platform_rpc_quality['independent_A64_replay']
    if (ROOT/'aes_platform_gate_quality_gates.json').exists():
        aes_platform_quality=json.loads((ROOT/'aes_platform_gate_quality_gates.json').read_text())
        manifest['validation']['aes_platform_gate_increment_checks']=aes_platform_quality['verified_counts']
        manifest['validation']['aes_platform_gate_A64_totals']=aes_platform_quality['independent_A64_replay']
    if (ROOT/'aes_quantum_binding_quality_gates.json').exists():
        aes_binding_quality=json.loads((ROOT/'aes_quantum_binding_quality_gates.json').read_text())
        manifest['validation']['aes_quantum_binding_increment_checks']=aes_binding_quality['verified_counts']
        manifest['validation']['aes_quantum_binding_A64_totals']=aes_binding_quality['independent_A64_replay']
    if (ROOT/'aes_hardware_job_quality_gates.json').exists():
        aes_jobs_quality=json.loads((ROOT/'aes_hardware_job_quality_gates.json').read_text())
        manifest['validation']['aes_hardware_job_increment_checks']=aes_jobs_quality['verified_counts']
        manifest['validation']['aes_hardware_job_A64_totals']=aes_jobs_quality['independent_A64_replay']
    if (ROOT/'aes_synchronous_wait_quality_gates.json').exists():
        aes_sync_quality=json.loads((ROOT/'aes_synchronous_wait_quality_gates.json').read_text())
        manifest['validation']['aes_synchronous_wait_increment_checks']=aes_sync_quality['verified_counts']
        manifest['validation']['aes_synchronous_wait_A64_totals']=aes_sync_quality['independent_A64_replay']
    if (ROOT/'aes_carrier_initialization_quality_gates.json').exists():
        aes_carrier_quality=json.loads((ROOT/'aes_carrier_initialization_quality_gates.json').read_text())
        manifest['validation']['aes_carrier_initialization_increment_checks']=aes_carrier_quality['verified_counts']
        manifest['validation']['aes_carrier_initialization_A64_totals']=aes_carrier_quality['independent_A64_replay']
    if (ROOT/'aes_completion_contract_quality_gates.json').exists():
        aes_completion_quality=json.loads((ROOT/'aes_completion_contract_quality_gates.json').read_text())
        manifest['validation']['aes_completion_contract_increment_checks']=aes_completion_quality['verified_counts']
        manifest['validation']['aes_completion_contract_A64_totals']=aes_completion_quality['independent_A64_replay']
    if (ROOT/'aes_provider_queue_quality_gates.json').exists():
        aes_provider_quality=json.loads((ROOT/'aes_provider_queue_quality_gates.json').read_text())
        manifest['validation']['aes_provider_queue_increment_checks']=aes_provider_quality['verified_counts']
        manifest['validation']['aes_provider_queue_A64_totals']=aes_provider_quality['independent_A64_replay']
    if (ROOT/'aes_command_pool_quality_gates.json').exists():
        aes_pool_quality=json.loads((ROOT/'aes_command_pool_quality_gates.json').read_text())
        manifest['validation']['aes_command_pool_increment_checks']=aes_pool_quality['verified_counts']
        manifest['validation']['aes_command_pool_A64_totals']=aes_pool_quality['independent_A64_replay']
    if (ROOT/'workloop_gate_attachment_quality_gates.json').exists():
        workloop_attachment_quality=json.loads((ROOT/'workloop_gate_attachment_quality_gates.json').read_text())
        manifest['validation']['workloop_gate_attachment_increment_checks']=workloop_attachment_quality['verified_counts']
        manifest['validation']['workloop_gate_attachment_A64_totals']=workloop_attachment_quality['independent_A64_replay']
    if (ROOT/'aes_command_gate_quality_gates.json').exists():
        aes_gate_quality=json.loads((ROOT/'aes_command_gate_quality_gates.json').read_text())
        manifest['validation']['aes_command_gate_increment_checks']=aes_gate_quality['verified_counts']
        manifest['validation']['aes_command_gate_A64_totals']=aes_gate_quality['independent_A64_replay']
    if (ROOT/'kext_startup_hardware_bridge_quality_gates.json').exists():
        startup_hardware_quality=json.loads((ROOT/'kext_startup_hardware_bridge_quality_gates.json').read_text())
        manifest['validation']['kext_startup_hardware_bridge_increment_checks']=startup_hardware_quality['verified_counts']
        manifest['validation']['kext_startup_hardware_bridge_A64_totals']=startup_hardware_quality['independent_A64_replay']
    if (ROOT/'kext_provider_initialize_quality_gates.json').exists():
        provider_initialize_quality=json.loads((ROOT/'kext_provider_initialize_quality_gates.json').read_text())
        manifest['validation']['kext_provider_initialize_increment_checks']=provider_initialize_quality['verified_counts']
        manifest['validation']['kext_provider_initialize_A64_totals']=provider_initialize_quality['independent_A64_replay']
    if (ROOT/'kext_constructor_reply_state_quality_gates.json').exists():
        constructor_reply_state_quality=json.loads((ROOT/'kext_constructor_reply_state_quality_gates.json').read_text())
        manifest['validation']['kext_constructor_reply_state_increment_checks']=constructor_reply_state_quality['verified_counts']
        manifest['validation']['kext_constructor_reply_state_A64_totals']=constructor_reply_state_quality['independent_A64_replay']
    if (ROOT/'kext_constructor_request_quality_gates.json').exists():
        constructor_request_quality=json.loads((ROOT/'kext_constructor_request_quality_gates.json').read_text())
        manifest['validation']['kext_constructor_request_increment_checks']=constructor_request_quality['verified_counts']
        manifest['validation']['kext_constructor_request_A64_totals']=constructor_request_quality['independent_A64_replay']
    if (ROOT/'kext_context_retirement_quality_gates.json').exists():
        context_retirement_quality=json.loads((ROOT/'kext_context_retirement_quality_gates.json').read_text())
        manifest['validation']['kext_context_retirement_increment_checks']=context_retirement_quality['verified_counts']
        manifest['validation']['kext_context_retirement_A64_totals']=context_retirement_quality['independent_A64_replay']
    if (ROOT/'kext_page_context_quality_gates.json').exists():
        page_context_quality=json.loads((ROOT/'kext_page_context_quality_gates.json').read_text())
        manifest['validation']['kext_page_context_increment_checks']=page_context_quality['verified_counts']
        manifest['validation']['kext_page_context_A64_totals']=page_context_quality['independent_A64_replay']
    if (ROOT/'kext_security_record_quality_gates.json').exists():
        security_record_quality=json.loads((ROOT/'kext_security_record_quality_gates.json').read_text())
        manifest['validation']['kext_security_record_increment_checks']=security_record_quality['verified_counts']
        manifest['validation']['kext_security_record_A64_totals']=security_record_quality['independent_A64_replay']
    if (ROOT/'kext_mapped_cleanup_quality_gates.json').exists():
        mapped_cleanup_quality=json.loads((ROOT/'kext_mapped_cleanup_quality_gates.json').read_text())
        manifest['validation']['kext_mapped_cleanup_increment_checks']=mapped_cleanup_quality['verified_counts']
        manifest['validation']['kext_mapped_cleanup_A64_totals']=mapped_cleanup_quality['independent_A64_replay']
    if (ROOT/'kernel_task_map_quality_gates.json').exists():
        task_map_quality=json.loads((ROOT/'kernel_task_map_quality_gates.json').read_text())
        manifest['validation']['kernel_task_map_increment_checks']=task_map_quality['verified_counts']
        manifest['validation']['kernel_task_map_A64_totals']=task_map_quality['independent_A64_replay']
    if (ROOT/'daemon_cf_descriptor_bridge_quality_gates.json').exists():
        bridge_quality=json.loads((ROOT/'daemon_cf_descriptor_bridge_quality_gates.json').read_text())
        manifest['validation']['daemon_cf_descriptor_bridge_increment_checks']=bridge_quality['verified_counts']
        manifest['validation']['daemon_cf_descriptor_bridge_combined_totals']=bridge_quality['independent_combined_replay']
    if (ROOT/'cf_mach_port_retirement_quality_gates.json').exists():
        retirement_quality=json.loads((ROOT/'cf_mach_port_retirement_quality_gates.json').read_text())
        manifest['validation']['cf_mach_port_retirement_increment_checks']=retirement_quality['verified_counts']
        manifest['validation']['cf_mach_port_retirement_repeat_semantic_totals']=retirement_quality['repeat_and_independent_semantic_checks']
    if (ROOT/'daemon_service_cf_lifecycle_quality_gates.json').exists():
        service_lifecycle_quality=json.loads((ROOT/'daemon_service_cf_lifecycle_quality_gates.json').read_text())
        manifest['validation']['daemon_service_cf_lifecycle_increment_checks']=service_lifecycle_quality['verified_counts']
        manifest['validation']['daemon_service_cf_lifecycle_repeat_service_totals']=service_lifecycle_quality['repeat_and_independent_service_checks']
    if (ROOT/'kernel_membership_removal_quality_gates.json').exists():
        membership_removal_quality=json.loads((ROOT/'kernel_membership_removal_quality_gates.json').read_text())
        manifest['validation']['kernel_membership_removal_increment_checks']=membership_removal_quality['verified_counts']
        manifest['validation']['kernel_membership_removal_static_scope']=membership_removal_quality['static_scope']
    if (ROOT/'kernel_iokit_open_quality_gates.json').exists():
        open_quality=json.loads((ROOT/'kernel_iokit_open_quality_gates.json').read_text())
        manifest['validation']['kernel_iokit_open_increment_checks']=open_quality['verified_counts']
        manifest['validation']['kernel_iokit_open_static_scope']=open_quality['static_scope']
    if (ROOT/'iokit_connection_lifecycle_quality_gates.json').exists():
        connection_quality=json.loads((ROOT/'iokit_connection_lifecycle_quality_gates.json').read_text())
        manifest['validation']['iokit_connection_lifecycle_increment_checks']=connection_quality['verified_counts']
        manifest['validation']['iokit_connection_lifecycle_static_scope']=connection_quality['static_scope']
    if (ROOT/'iokit_structure_arguments_quality_gates.json').exists():
        structure_quality=json.loads((ROOT/'iokit_structure_arguments_quality_gates.json').read_text())
        manifest['validation']['iokit_structure_arguments_increment_checks']=structure_quality['verified_counts']
        manifest['validation']['iokit_structure_arguments_static_scope']=structure_quality['static_scope']
    if (ROOT/'iokit_filter_policy_quality_gates.json').exists():
        filter_quality=json.loads((ROOT/'iokit_filter_policy_quality_gates.json').read_text())
        manifest['validation']['iokit_filter_policy_increment_checks']=filter_quality['verified_counts']
        manifest['validation']['iokit_filter_policy_static_scope']=filter_quality['static_scope']
    if (ROOT/'iokit_async_contract_quality_gates.json').exists():
        async_quality=json.loads((ROOT/'iokit_async_contract_quality_gates.json').read_text())
        manifest['validation']['iokit_async_contract_increment_checks']=async_quality['verified_counts']
        manifest['validation']['iokit_async_contract_static_scope']=async_quality['static_scope']
    if (ROOT/'rpc700_publication_quality_gates.json').exists():
        publication_quality=json.loads((ROOT/'rpc700_publication_quality_gates.json').read_text())
        manifest['validation']['rpc700_publication_increment_checks']=publication_quality['verified_counts']
        manifest['validation']['rpc700_publication_static_scope']=publication_quality['static_scope']
    if (ROOT/'managed_fairplay_bridge_quality_gates.json').exists():
        managed_bridge_quality=json.loads((ROOT/'managed_fairplay_bridge_quality_gates.json').read_text())
        manifest['validation']['managed_fairplay_bridge_increment_checks']=managed_bridge_quality['verified_counts']
        manifest['validation']['managed_fairplay_bridge_static_scope']=managed_bridge_quality['static_scope']
    if (ROOT/'managed_adapter_dispatch_quality_gates.json').exists():
        adapter_dispatch_quality=json.loads((ROOT/'managed_adapter_dispatch_quality_gates.json').read_text())
        manifest['validation']['managed_adapter_dispatch_increment_checks']=adapter_dispatch_quality['verified_counts']
        manifest['validation']['managed_adapter_dispatch_static_scope']=adapter_dispatch_quality['static_scope']
    if (ROOT/'host_special_registration_quality_gates.json').exists():
        special_registration_quality=json.loads((ROOT/'host_special_registration_quality_gates.json').read_text())
        manifest['validation']['host_special_registration_increment_checks']=special_registration_quality['verified_counts']
        manifest['validation']['host_special_registration_static_scope']=special_registration_quality['static_scope']
    if (ROOT/'launchd_variant_binding_quality_gates.json').exists():
        variant_binding_quality=json.loads((ROOT/'launchd_variant_binding_quality_gates.json').read_text())
        manifest['validation']['launchd_variant_binding_increment_checks']=variant_binding_quality['verified_counts']
        manifest['validation']['launchd_variant_binding_static_scope']=variant_binding_quality['static_scope']
    if (ROOT/'launchd_service_endpoint_quality_gates.json').exists():
        service_endpoint_quality=json.loads((ROOT/'launchd_service_endpoint_quality_gates.json').read_text())
        manifest['validation']['launchd_service_endpoint_increment_checks']=service_endpoint_quality['verified_counts']
        manifest['validation']['launchd_service_endpoint_static_scope']=service_endpoint_quality['static_scope']
    if (ROOT/'bootstrap_checkin_handoff_quality_gates.json').exists():
        checkin_handoff_quality=json.loads((ROOT/'bootstrap_checkin_handoff_quality_gates.json').read_text())
        manifest['validation']['bootstrap_checkin_handoff_increment_checks']=checkin_handoff_quality['verified_counts']
        manifest['validation']['bootstrap_checkin_handoff_static_scope']=checkin_handoff_quality['static_scope']
    if (ROOT/'launchd_audit_context_quality_gates.json').exists():
        audit_context_quality=json.loads((ROOT/'launchd_audit_context_quality_gates.json').read_text())
        manifest['validation']['launchd_audit_context_increment_checks']=audit_context_quality['verified_counts']
        manifest['validation']['launchd_audit_context_static_scope']=audit_context_quality['static_scope']
    if (ROOT/'port_destroyed_return_quality_gates.json').exists():
        destroyed_return_quality=json.loads((ROOT/'port_destroyed_return_quality_gates.json').read_text())
        manifest['validation']['port_destroyed_return_increment_checks']=destroyed_return_quality['verified_counts']
        manifest['validation']['port_destroyed_return_static_scope']=destroyed_return_quality['static_scope']
    if (ROOT/'receive_name_guard_quality_gates.json').exists():
        receive_guard_quality=json.loads((ROOT/'receive_name_guard_quality_gates.json').read_text())
        manifest['validation']['receive_name_guard_increment_checks']=receive_guard_quality['verified_counts']
        manifest['validation']['receive_name_guard_static_scope']=receive_guard_quality['static_scope']
    if (ROOT/'coalition_service_gate_quality_gates.json').exists():
        coalition_gate_quality=json.loads((ROOT/'coalition_service_gate_quality_gates.json').read_text())
        manifest['validation']['coalition_service_gate_increment_checks']=coalition_gate_quality['verified_counts']
        manifest['validation']['coalition_service_gate_static_scope']=coalition_gate_quality['static_scope']
    if (ROOT/'endpoint_job_lifecycle_quality_gates.json').exists():
        endpoint_lifecycle_quality=json.loads((ROOT/'endpoint_job_lifecycle_quality_gates.json').read_text())
        manifest['validation']['endpoint_job_lifecycle_increment_checks']=endpoint_lifecycle_quality['verified_counts']
        manifest['validation']['endpoint_job_lifecycle_static_scope']=endpoint_lifecycle_quality['static_scope']
    if (ROOT/'job_factory_lineage_quality_gates.json').exists():
        job_lineage_quality=json.loads((ROOT/'job_factory_lineage_quality_gates.json').read_text())
        manifest['validation']['job_factory_lineage_increment_checks']=job_lineage_quality['verified_counts']
        manifest['validation']['job_factory_lineage_static_scope']=job_lineage_quality['static_scope']
    if (ROOT/'exclaves_notification_contract_quality_gates.json').exists():
        exclaves_notification_quality=json.loads((ROOT/'exclaves_notification_contract_quality_gates.json').read_text())
        manifest['validation']['exclaves_notification_contract_increment_checks']=exclaves_notification_quality['verified_counts']
        manifest['validation']['exclaves_notification_contract_static_scope']=exclaves_notification_quality['static_scope']
    if (ROOT/'spawn_conclave_abi_quality_gates.json').exists():
        spawn_quality=json.loads((ROOT/'spawn_conclave_abi_quality_gates.json').read_text())
        manifest['validation']['spawn_conclave_abi_increment_checks']=spawn_quality['verified_counts']
        manifest['validation']['spawn_conclave_abi_static_scope']=spawn_quality['static_scope']
    if (ROOT/'spawn_port_actions_quality_gates.json').exists():
        spawn_ports_quality=json.loads((ROOT/'spawn_port_actions_quality_gates.json').read_text())
        manifest['validation']['spawn_port_actions_increment_checks']=spawn_ports_quality['verified_counts']
        manifest['validation']['spawn_port_actions_static_scope']=spawn_ports_quality['static_scope']
    if (ROOT/'registered_port_consumers_quality_gates.json').exists():
        registered_consumers_quality=json.loads((ROOT/'registered_port_consumers_quality_gates.json').read_text())
        manifest['validation']['registered_port_consumers_increment_checks']=registered_consumers_quality['verified_counts']
        manifest['validation']['registered_port_consumers_static_scope']=registered_consumers_quality['static_scope']
    if (ROOT/'initializer_programvars_quality_gates.json').exists():
        initializer_vars_quality=json.loads((ROOT/'initializer_programvars_quality_gates.json').read_text())
        manifest['validation']['initializer_programvars_increment_checks']=initializer_vars_quality['verified_counts']
        manifest['validation']['initializer_programvars_static_scope']=initializer_vars_quality['static_scope']
    if (ROOT/'kernel_args_environment_quality_gates.json').exists():
        kernel_args_quality=json.loads((ROOT/'kernel_args_environment_quality_gates.json').read_text())
        manifest['validation']['kernel_args_environment_increment_checks']=kernel_args_quality['verified_counts']
        manifest['validation']['kernel_args_environment_static_scope']=kernel_args_quality['static_scope']
    if (ROOT/'rpc700_endpoint_inventory_quality_gates.json').exists():
        endpoint_inventory_quality=json.loads((ROOT/'rpc700_endpoint_inventory_quality_gates.json').read_text())
        manifest['validation']['rpc700_endpoint_inventory_increment_checks']=endpoint_inventory_quality['verified_counts']
        manifest['validation']['rpc700_endpoint_inventory_static_scope']=endpoint_inventory_quality['static_scope']
        manifest['validation']['rpc700_endpoint_inventory_native_observation_scope']=endpoint_inventory_quality['native_observation_scope']
    if (ROOT/'daemon_xpc_listener_quality_gates.json').exists():
        daemon_listener_quality=json.loads((ROOT/'daemon_xpc_listener_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_listener_increment_checks']=daemon_listener_quality['verified_counts']
        manifest['validation']['daemon_xpc_listener_static_scope']=daemon_listener_quality['static_scope']
    if (ROOT/'daemon_xpc_payload_quality_gates.json').exists():
        daemon_payload_quality=json.loads((ROOT/'daemon_xpc_payload_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_payload_increment_checks']=daemon_payload_quality['verified_counts']
        manifest['validation']['daemon_xpc_payload_static_scope']=daemon_payload_quality['static_scope']
    if (ROOT/'daemon_xpc_records_quality_gates.json').exists():
        daemon_records_quality=json.loads((ROOT/'daemon_xpc_records_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_records_increment_checks']=daemon_records_quality['verified_counts']
        manifest['validation']['daemon_xpc_records_static_scope']=daemon_records_quality['static_scope']
    if (ROOT/'daemon_xpc_iteration_quality_gates.json').exists():
        daemon_iteration_quality=json.loads((ROOT/'daemon_xpc_iteration_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_iteration_increment_checks']=daemon_iteration_quality['verified_counts']
        manifest['validation']['daemon_xpc_iteration_static_scope']=daemon_iteration_quality['static_scope']
    if (ROOT/'daemon_xpc_core_bridge_quality_gates.json').exists():
        daemon_core_bridge_quality=json.loads((ROOT/'daemon_xpc_core_bridge_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_core_bridge_increment_checks']=daemon_core_bridge_quality['verified_counts']
        manifest['validation']['daemon_xpc_core_bridge_static_scope']=daemon_core_bridge_quality['static_scope']
    if (ROOT/'daemon_xpc_reply_lifecycle_quality_gates.json').exists():
        daemon_reply_lifecycle_quality=json.loads((ROOT/'daemon_xpc_reply_lifecycle_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_reply_lifecycle_increment_checks']=daemon_reply_lifecycle_quality['verified_counts']
        manifest['validation']['daemon_xpc_reply_lifecycle_static_scope']=daemon_reply_lifecycle_quality['static_scope']
    if (ROOT/'xpc_reply_transport_quality_gates.json').exists():
        xpc_transport_quality=json.loads((ROOT/'xpc_reply_transport_quality_gates.json').read_text())
        manifest['validation']['xpc_reply_transport_increment_checks']=xpc_transport_quality['verified_counts']
        manifest['validation']['xpc_reply_transport_static_scope']=xpc_transport_quality['static_scope']
    if (ROOT/'xpc_receive_context_quality_gates.json').exists():
        xpc_receive_quality=json.loads((ROOT/'xpc_receive_context_quality_gates.json').read_text())
        manifest['validation']['xpc_receive_context_increment_checks']=xpc_receive_quality['verified_counts']
        manifest['validation']['xpc_receive_context_static_scope']=xpc_receive_quality['static_scope']
    if (ROOT/'xpc_resource_lifecycle_quality_gates.json').exists():
        xpc_resource_quality=json.loads((ROOT/'xpc_resource_lifecycle_quality_gates.json').read_text())
        manifest['validation']['xpc_resource_lifecycle_increment_checks']=xpc_resource_quality['verified_counts']
        manifest['validation']['xpc_resource_lifecycle_static_scope']=xpc_resource_quality['static_scope']
    if (ROOT/'xpc_transaction_controls_quality_gates.json').exists():
        xpc_transaction_quality=json.loads((ROOT/'xpc_transaction_controls_quality_gates.json').read_text())
        manifest['validation']['xpc_transaction_controls_increment_checks']=xpc_transaction_quality['verified_counts']
        manifest['validation']['xpc_transaction_controls_static_scope']=xpc_transaction_quality['static_scope']
    if (ROOT/'daemon_xpc_error_outputs_quality_gates.json').exists():
        daemon_error_outputs_quality=json.loads((ROOT/'daemon_xpc_error_outputs_quality_gates.json').read_text())
        manifest['validation']['daemon_xpc_error_outputs_increment_checks']=daemon_error_outputs_quality['verified_counts']
        manifest['validation']['daemon_xpc_error_outputs_static_scope']=daemon_error_outputs_quality['static_scope']
    if (ROOT/'daemon_output_publication_quality_gates.json').exists():
        daemon_output_publication_quality=json.loads((ROOT/'daemon_output_publication_quality_gates.json').read_text())
        manifest['validation']['daemon_output_publication_increment_checks']=daemon_output_publication_quality['verified_counts']
        manifest['validation']['daemon_output_publication_static_scope']=daemon_output_publication_quality['static_scope']
    if (ROOT/'daemon_list_output_quality_gates.json').exists():
        daemon_list_output_quality=json.loads((ROOT/'daemon_list_output_quality_gates.json').read_text())
        manifest['validation']['daemon_list_output_increment_checks']=daemon_list_output_quality['verified_counts']
        manifest['validation']['daemon_list_output_static_scope']=daemon_list_output_quality['static_scope']
    if (ROOT/'daemon_record_stream_quality_gates.json').exists():
        record_stream_quality=json.loads((ROOT/'daemon_record_stream_quality_gates.json').read_text())
        manifest['validation']['daemon_record_stream_increment_checks']=record_stream_quality['verified_counts']
        manifest['validation']['daemon_record_stream_static_scope']=record_stream_quality['static_scope']
    if (ROOT/'daemon_payload_codec_quality_gates.json').exists():
        payload_codec_quality=json.loads((ROOT/'daemon_payload_codec_quality_gates.json').read_text())
        manifest['validation']['daemon_payload_codec_increment_checks']=payload_codec_quality['verified_counts']
        manifest['validation']['daemon_payload_codec_static_scope']=payload_codec_quality['static_scope']
    if (ROOT/'daemon_header_codec_quality_gates.json').exists():
        header_codec_quality=json.loads((ROOT/'daemon_header_codec_quality_gates.json').read_text())
        manifest['validation']['daemon_header_codec_increment_checks']=header_codec_quality['verified_counts']
        manifest['validation']['daemon_header_codec_static_scope']=header_codec_quality['static_scope']
    if (ROOT/'daemon_constructor_inputs_quality_gates.json').exists():
        constructor_inputs_quality=json.loads((ROOT/'daemon_constructor_inputs_quality_gates.json').read_text())
        manifest['validation']['daemon_constructor_inputs_increment_checks']=constructor_inputs_quality['verified_counts']
        manifest['validation']['daemon_constructor_inputs_static_scope']=constructor_inputs_quality['static_scope']
    if (ROOT/'daemon_constructor_lookup_quality_gates.json').exists():
        constructor_lookup_quality=json.loads((ROOT/'daemon_constructor_lookup_quality_gates.json').read_text())
        manifest['validation']['daemon_constructor_lookup_increment_checks']=constructor_lookup_quality['verified_counts']
        manifest['validation']['daemon_constructor_lookup_static_scope']=constructor_lookup_quality['static_scope']
    if (ROOT/'daemon_typed_scalar_quality_gates.json').exists():
        typed_scalar_quality=json.loads((ROOT/'daemon_typed_scalar_quality_gates.json').read_text())
        manifest['validation']['daemon_typed_scalar_increment_checks']=typed_scalar_quality['verified_counts']
        manifest['validation']['daemon_typed_scalar_static_scope']=typed_scalar_quality['static_scope']
    if (ROOT/'daemon_constructor_failure_quality_gates.json').exists():
        constructor_failure_quality=json.loads((ROOT/'daemon_constructor_failure_quality_gates.json').read_text())
        manifest['validation']['daemon_constructor_failure_increment_checks']=constructor_failure_quality['verified_counts']
        manifest['validation']['daemon_constructor_failure_static_scope']=constructor_failure_quality['static_scope']
    if (ROOT/'daemon_constructor_bank_origins_quality_gates.json').exists():
        constructor_bank_origins_quality=json.loads((ROOT/'daemon_constructor_bank_origins_quality_gates.json').read_text())
        manifest['validation']['daemon_constructor_bank_origins_increment_checks']=constructor_bank_origins_quality['verified_counts']
        manifest['validation']['daemon_constructor_bank_origins_static_scope']=constructor_bank_origins_quality['static_scope']
    if (ROOT/'daemon_constructor_callers_quality_gates.json').exists():
        constructor_callers_quality=json.loads((ROOT/'daemon_constructor_callers_quality_gates.json').read_text())
        manifest['validation']['daemon_constructor_callers_increment_checks']=constructor_callers_quality['verified_counts']
        manifest['validation']['daemon_constructor_callers_static_scope']=constructor_callers_quality['static_scope']
    if (ROOT/'daemon_collection_retirement_quality_gates.json').exists():
        collection_retirement_quality=json.loads((ROOT/'daemon_collection_retirement_quality_gates.json').read_text())
        manifest['validation']['daemon_collection_retirement_increment_checks']=collection_retirement_quality['verified_counts']
        manifest['validation']['daemon_collection_retirement_static_scope']=collection_retirement_quality['static_scope']
    if (ROOT/'daemon_builder_owner_join_quality_gates.json').exists():
        builder_owner_join_quality=json.loads((ROOT/'daemon_builder_owner_join_quality_gates.json').read_text())
        manifest['validation']['daemon_builder_owner_join_increment_checks']=builder_owner_join_quality['verified_counts']
        manifest['validation']['daemon_builder_owner_join_static_scope']=builder_owner_join_quality['static_scope']
    if (ROOT/'daemon_scalar_field_population_quality_gates.json').exists():
        scalar_field_population_quality=json.loads((ROOT/'daemon_scalar_field_population_quality_gates.json').read_text())
        manifest['validation']['daemon_scalar_field_population_increment_checks']=scalar_field_population_quality['verified_counts']
        manifest['validation']['daemon_scalar_field_population_static_scope']=scalar_field_population_quality['static_scope']
    if (ROOT/'daemon_helper_result_residue_quality_gates.json').exists():
        helper_result_residue_quality=json.loads((ROOT/'daemon_helper_result_residue_quality_gates.json').read_text())
        manifest['validation']['daemon_helper_result_residue_increment_checks']=helper_result_residue_quality['verified_counts']
        manifest['validation']['daemon_helper_result_residue_static_scope']=helper_result_residue_quality['static_scope']
    if (ROOT/'daemon_existing_scalar_reader_quality_gates.json').exists():
        existing_scalar_reader_quality=json.loads((ROOT/'daemon_existing_scalar_reader_quality_gates.json').read_text())
        manifest['validation']['daemon_existing_scalar_reader_increment_checks']=existing_scalar_reader_quality['verified_counts']
        manifest['validation']['daemon_existing_scalar_reader_static_scope']=existing_scalar_reader_quality['static_scope']
    if (ROOT/'daemon_reader_context_footprint_quality_gates.json').exists():
        reader_context_footprint_quality=json.loads((ROOT/'daemon_reader_context_footprint_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_context_footprint_increment_checks']=reader_context_footprint_quality['verified_counts']
        manifest['validation']['daemon_reader_context_footprint_static_scope']=reader_context_footprint_quality['static_scope']
    if (ROOT/'daemon_reader_stack_epoch_quality_gates.json').exists():
        reader_stack_epoch_quality=json.loads((ROOT/'daemon_reader_stack_epoch_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_stack_epoch_increment_checks']=reader_stack_epoch_quality['verified_counts']
        manifest['validation']['daemon_reader_stack_epoch_static_scope']=reader_stack_epoch_quality['static_scope']
    if (ROOT/'daemon_context_input_producers_quality_gates.json').exists():
        context_input_producers_quality=json.loads((ROOT/'daemon_context_input_producers_quality_gates.json').read_text())
        manifest['validation']['daemon_context_input_producers_increment_checks']=context_input_producers_quality['verified_counts']
        manifest['validation']['daemon_context_input_producers_static_scope']=context_input_producers_quality['static_scope']
    if (ROOT/'daemon_reader_extent_families_quality_gates.json').exists():
        reader_extent_families_quality=json.loads((ROOT/'daemon_reader_extent_families_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_extent_families_increment_checks']=reader_extent_families_quality['verified_counts']
        manifest['validation']['daemon_reader_extent_families_static_scope']=reader_extent_families_quality['static_scope']
    if (ROOT/'daemon_reader_typed_dispatch_quality_gates.json').exists():
        reader_typed_dispatch_quality=json.loads((ROOT/'daemon_reader_typed_dispatch_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_typed_dispatch_increment_checks']=reader_typed_dispatch_quality['verified_counts']
        manifest['validation']['daemon_reader_typed_dispatch_static_scope']=reader_typed_dispatch_quality['static_scope']
    if (ROOT/'daemon_reader_value_consumers_quality_gates.json').exists():
        reader_value_consumers_quality=json.loads((ROOT/'daemon_reader_value_consumers_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_value_consumers_increment_checks']=reader_value_consumers_quality['verified_counts']
        manifest['validation']['daemon_reader_value_consumers_static_scope']=reader_value_consumers_quality['static_scope']
    if (ROOT/'daemon_reader_container_origins_quality_gates.json').exists():
        reader_container_origins_quality=json.loads((ROOT/'daemon_reader_container_origins_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_container_origins_increment_checks']=reader_container_origins_quality['verified_counts']
        manifest['validation']['daemon_reader_container_origins_static_scope']=reader_container_origins_quality['static_scope']
    if (ROOT/'daemon_reader_record_headers_quality_gates.json').exists():
        reader_record_headers_quality=json.loads((ROOT/'daemon_reader_record_headers_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_record_headers_increment_checks']=reader_record_headers_quality['verified_counts']
        manifest['validation']['daemon_reader_record_headers_static_scope']=reader_record_headers_quality['static_scope']
    if (ROOT/'daemon_reader_record_payloads_quality_gates.json').exists():
        reader_record_payloads_quality=json.loads((ROOT/'daemon_reader_record_payloads_quality_gates.json').read_text())
        manifest['validation']['daemon_reader_record_payloads_increment_checks']=reader_record_payloads_quality['verified_counts']
        manifest['validation']['daemon_reader_record_payloads_static_scope']=reader_record_payloads_quality['static_scope']
    (ROOT/'interface_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    check=json.loads((ROOT/'interface_manifest.json').read_text())
    for row in check['files']:
        path=BASE/row['path'];assert sha(path)==row['sha256'] and path.stat().st_size==row['size_bytes']
    print(json.dumps({'owned_artifacts':len(check['files']),**check['validation'],
                      'original_inputs_preserved':len(check['inputs_preserved']),'goal_status':'active'}))


if __name__=='__main__':main()
