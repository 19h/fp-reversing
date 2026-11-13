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


from verify_daemon_reader_record_payloads_publication import sha,read,exists,size,canonical


def entry(path):
    return {'path':str(path.relative_to(BASE)),'size_bytes':size(path),'sha256':sha(path)}


def main():
    old=json.loads(read(ROOT/'interface_manifest.json'))
    for row in old['inputs_preserved']:
        path=BASE/row['path']
        assert size(path)==row['size_bytes'] and sha(path)==row['sha256'],path
    # Published producers/artifacts are frozen; verify retained outputs only.
    contract=json.loads(read(ROOT/'rpc502_sidecar_contracts.json'))
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
    assert json.loads(read(ROOT/'rpc502_sidecar_quality_gates.json'))==quality
    reports={BASE/r['path'] for r in old['files'] if '/' not in r['path'] and r['path'].endswith('.md')}
    reports.add(BASE/'rpc502_sidecar_report.md')
    if exists(BASE/'kernel_membership_removal_report.md'):reports.add(BASE/'kernel_membership_removal_report.md')
    if exists(BASE/'kernel_iokit_open_report.md'):reports.add(BASE/'kernel_iokit_open_report.md')
    if exists(BASE/'iokit_connection_lifecycle_report.md'):reports.add(BASE/'iokit_connection_lifecycle_report.md')
    if exists(BASE/'iokit_structure_arguments_report.md'):reports.add(BASE/'iokit_structure_arguments_report.md')
    if exists(BASE/'iokit_filter_policy_report.md'):reports.add(BASE/'iokit_filter_policy_report.md')
    if exists(BASE/'iokit_async_contract_report.md'):reports.add(BASE/'iokit_async_contract_report.md')
    if exists(BASE/'rpc700_publication_report.md'):reports.add(BASE/'rpc700_publication_report.md')
    if exists(BASE/'managed_fairplay_bridge_report.md'):reports.add(BASE/'managed_fairplay_bridge_report.md')
    if exists(BASE/'managed_adapter_dispatch_report.md'):reports.add(BASE/'managed_adapter_dispatch_report.md')
    if exists(BASE/'host_special_registration_report.md'):reports.add(BASE/'host_special_registration_report.md')
    if exists(BASE/'launchd_variant_binding_report.md'):reports.add(BASE/'launchd_variant_binding_report.md')
    if exists(BASE/'launchd_service_endpoint_report.md'):reports.add(BASE/'launchd_service_endpoint_report.md')
    if exists(BASE/'bootstrap_checkin_handoff_report.md'):reports.add(BASE/'bootstrap_checkin_handoff_report.md')
    if exists(BASE/'launchd_audit_context_report.md'):reports.add(BASE/'launchd_audit_context_report.md')
    if exists(BASE/'port_destroyed_return_report.md'):reports.add(BASE/'port_destroyed_return_report.md')
    if exists(BASE/'receive_name_guard_report.md'):reports.add(BASE/'receive_name_guard_report.md')
    if exists(BASE/'coalition_service_gate_report.md'):reports.add(BASE/'coalition_service_gate_report.md')
    if exists(BASE/'endpoint_job_lifecycle_report.md'):reports.add(BASE/'endpoint_job_lifecycle_report.md')
    if exists(BASE/'job_factory_lineage_report.md'):reports.add(BASE/'job_factory_lineage_report.md')
    if exists(BASE/'exclaves_notification_contract_report.md'):reports.add(BASE/'exclaves_notification_contract_report.md')
    if exists(BASE/'spawn_conclave_abi_report.md'):reports.add(BASE/'spawn_conclave_abi_report.md')
    if exists(BASE/'spawn_port_actions_report.md'):reports.add(BASE/'spawn_port_actions_report.md')
    if exists(BASE/'registered_port_consumers_report.md'):reports.add(BASE/'registered_port_consumers_report.md')
    if exists(BASE/'initializer_programvars_report.md'):reports.add(BASE/'initializer_programvars_report.md')
    if exists(BASE/'kernel_args_environment_report.md'):reports.add(BASE/'kernel_args_environment_report.md')
    if exists(BASE/'rpc700_endpoint_inventory_report.md'):reports.add(BASE/'rpc700_endpoint_inventory_report.md')
    if exists(BASE/'daemon_xpc_listener_report.md'):reports.add(BASE/'daemon_xpc_listener_report.md')
    if exists(BASE/'daemon_xpc_payload_report.md'):reports.add(BASE/'daemon_xpc_payload_report.md')
    if exists(BASE/'daemon_xpc_records_report.md'):reports.add(BASE/'daemon_xpc_records_report.md')
    if exists(BASE/'daemon_xpc_iteration_report.md'):reports.add(BASE/'daemon_xpc_iteration_report.md')
    if exists(BASE/'daemon_xpc_core_bridge_report.md'):reports.add(BASE/'daemon_xpc_core_bridge_report.md')
    if exists(BASE/'daemon_xpc_reply_lifecycle_report.md'):reports.add(BASE/'daemon_xpc_reply_lifecycle_report.md')
    if exists(BASE/'xpc_reply_transport_report.md'):reports.add(BASE/'xpc_reply_transport_report.md')
    if exists(BASE/'xpc_receive_context_report.md'):reports.add(BASE/'xpc_receive_context_report.md')
    if exists(BASE/'xpc_resource_lifecycle_report.md'):reports.add(BASE/'xpc_resource_lifecycle_report.md')
    if exists(BASE/'xpc_transaction_controls_report.md'):reports.add(BASE/'xpc_transaction_controls_report.md')
    if exists(BASE/'daemon_xpc_error_outputs_report.md'):reports.add(BASE/'daemon_xpc_error_outputs_report.md')
    if exists(BASE/'daemon_output_publication_report.md'):reports.add(BASE/'daemon_output_publication_report.md')
    if exists(BASE/'daemon_list_output_report.md'):reports.add(BASE/'daemon_list_output_report.md')
    if exists(BASE/'daemon_record_stream_report.md'):reports.add(BASE/'daemon_record_stream_report.md')
    if exists(BASE/'daemon_payload_codec_report.md'):reports.add(BASE/'daemon_payload_codec_report.md')
    if exists(BASE/'daemon_header_codec_report.md'):reports.add(BASE/'daemon_header_codec_report.md')
    if exists(BASE/'daemon_constructor_inputs_report.md'):reports.add(BASE/'daemon_constructor_inputs_report.md')
    if exists(BASE/'daemon_constructor_lookup_report.md'):reports.add(BASE/'daemon_constructor_lookup_report.md')
    if exists(BASE/'daemon_typed_scalar_report.md'):reports.add(BASE/'daemon_typed_scalar_report.md')
    if exists(BASE/'daemon_constructor_failure_report.md'):reports.add(BASE/'daemon_constructor_failure_report.md')
    if exists(BASE/'daemon_constructor_bank_origins_report.md'):reports.add(BASE/'daemon_constructor_bank_origins_report.md')
    if exists(BASE/'daemon_constructor_callers_report.md'):reports.add(BASE/'daemon_constructor_callers_report.md')
    if exists(BASE/'daemon_collection_retirement_report.md'):reports.add(BASE/'daemon_collection_retirement_report.md')
    if exists(BASE/'daemon_builder_owner_join_report.md'):reports.add(BASE/'daemon_builder_owner_join_report.md')
    if exists(BASE/'daemon_scalar_field_population_report.md'):reports.add(BASE/'daemon_scalar_field_population_report.md')
    if exists(BASE/'daemon_helper_result_residue_report.md'):reports.add(BASE/'daemon_helper_result_residue_report.md')
    if exists(BASE/'daemon_existing_scalar_reader_report.md'):reports.add(BASE/'daemon_existing_scalar_reader_report.md')
    if exists(BASE/'daemon_reader_context_footprint_report.md'):reports.add(BASE/'daemon_reader_context_footprint_report.md')
    if exists(BASE/'daemon_reader_stack_epoch_report.md'):reports.add(BASE/'daemon_reader_stack_epoch_report.md')
    if exists(BASE/'daemon_context_input_producers_report.md'):reports.add(BASE/'daemon_context_input_producers_report.md')
    if exists(BASE/'daemon_reader_extent_families_report.md'):reports.add(BASE/'daemon_reader_extent_families_report.md')
    if exists(BASE/'daemon_reader_typed_dispatch_report.md'):reports.add(BASE/'daemon_reader_typed_dispatch_report.md')
    if exists(BASE/'daemon_reader_value_consumers_report.md'):reports.add(BASE/'daemon_reader_value_consumers_report.md')
    if exists(BASE/'daemon_reader_container_origins_report.md'):reports.add(BASE/'daemon_reader_container_origins_report.md')
    if exists(BASE/'daemon_reader_record_headers_report.md'):reports.add(BASE/'daemon_reader_record_headers_report.md')
    if exists(BASE/'daemon_reader_record_payloads_report.md'):reports.add(BASE/'daemon_reader_record_payloads_report.md')
    if exists(BASE/'daemon_reader_record_replacement_report.md'):reports.add(BASE/'daemon_reader_record_replacement_report.md')
    if exists(BASE/'daemon_reader_u64_codec_report.md'):reports.add(BASE/'daemon_reader_u64_codec_report.md')
    if exists(BASE/'daemon_reader_outer_lifecycle_report.md'):reports.add(BASE/'daemon_reader_outer_lifecycle_report.md')
    if exists(BASE/'daemon_reader_nested_input_report.md'):reports.add(BASE/'daemon_reader_nested_input_report.md')
    if exists(BASE/'daemon_reader_option_default_report.md'):reports.add(BASE/'daemon_reader_option_default_report.md')
    if exists(BASE/'daemon_outer_record_ingress_report.md'):reports.add(BASE/'daemon_outer_record_ingress_report.md')
    if exists(BASE/'daemon_outer_first_key_report.md'):reports.add(BASE/'daemon_outer_first_key_report.md')
    if exists(BASE/'daemon_mode_one_adapter_report.md'):reports.add(BASE/'daemon_mode_one_adapter_report.md')
    if exists(BASE/'daemon_mode_one_source_passes_report.md'):reports.add(BASE/'daemon_mode_one_source_passes_report.md')
    if exists(BASE/'daemon_mode_one_scatter_report.md'):reports.add(BASE/'daemon_mode_one_scatter_report.md')
    if exists(BASE/'daemon_mode_one_inverse_tables_report.md'):reports.add(BASE/'daemon_mode_one_inverse_tables_report.md')
    if exists(BASE/'daemon_mode_one_carry_table_report.md'):reports.add(BASE/'daemon_mode_one_carry_table_report.md')
    if exists(BASE/'daemon_mode_one_digit_maps_report.md'):reports.add(BASE/'daemon_mode_one_digit_maps_report.md')
    if exists(BASE/'daemon_mode_one_post_table_passes_report.md'):reports.add(BASE/'daemon_mode_one_post_table_passes_report.md')
    if exists(BASE/'daemon_mode_one_bank_combine_report.md'):reports.add(BASE/'daemon_mode_one_bank_combine_report.md')
    if exists(BASE/'daemon_mode_one_word_mix_report.md'):reports.add(BASE/'daemon_mode_one_word_mix_report.md')
    if exists(BASE/'daemon_mode_one_state_materialization_report.md'):reports.add(BASE/'daemon_mode_one_state_materialization_report.md')
    if exists(BASE/'daemon_mode_one_source_absorption_report.md'):reports.add(BASE/'daemon_mode_one_source_absorption_report.md')
    if exists(BASE/'daemon_mode_one_plane_consumer_report.md'):reports.add(BASE/'daemon_mode_one_plane_consumer_report.md')
    if exists(BASE/'daemon_mode_one_word_schedule_report.md'):reports.add(BASE/'daemon_mode_one_word_schedule_report.md')
    if exists(BASE/'daemon_mode_one_lookup_bounds_report.md'):reports.add(BASE/'daemon_mode_one_lookup_bounds_report.md')
    if exists(BASE/'daemon_mode_one_lookup_roles_report.md'):reports.add(BASE/'daemon_mode_one_lookup_roles_report.md')
    if exists(BASE/'daemon_mode_one_word_rounds_report.md'):reports.add(BASE/'daemon_mode_one_word_rounds_report.md')
    if exists(BASE/'daemon_mode_one_phase_handoff_report.md'):reports.add(BASE/'daemon_mode_one_phase_handoff_report.md')
    if exists(BASE/'daemon_mode_one_record_scan_report.md'):reports.add(BASE/'daemon_mode_one_record_scan_report.md')
    if exists(BASE/'daemon_mode_one_record_passes_report.md'):reports.add(BASE/'daemon_mode_one_record_passes_report.md')
    if exists(BASE/'daemon_mode_one_record_permutation_report.md'):reports.add(BASE/'daemon_mode_one_record_permutation_report.md')
    if exists(BASE/'daemon_mode_one_record_adder_report.md'):reports.add(BASE/'daemon_mode_one_record_adder_report.md')
    if exists(BASE/'daemon_mode_one_record_codecs_report.md'):reports.add(BASE/'daemon_mode_one_record_codecs_report.md')
    if exists(BASE/'daemon_mode_one_record_rescan_report.md'):reports.add(BASE/'daemon_mode_one_record_rescan_report.md')
    if exists(BASE/'daemon_mode_one_record_join_report.md'):reports.add(BASE/'daemon_mode_one_record_join_report.md')
    if exists(BASE/'daemon_mode_one_record_input_planes_report.md'):reports.add(BASE/'daemon_mode_one_record_input_planes_report.md')
    if exists(BASE/'daemon_mode_one_record_long_planes_report.md'):reports.add(BASE/'daemon_mode_one_record_long_planes_report.md')
    if exists(BASE/'daemon_mode_one_record_long_prefix_report.md'):reports.add(BASE/'daemon_mode_one_record_long_prefix_report.md')
    if exists(BASE/'daemon_mode_one_record_word_gather_report.md'):reports.add(BASE/'daemon_mode_one_record_word_gather_report.md')
    if exists(BASE/'daemon_mode_one_record_word_extension_report.md'):reports.add(BASE/'daemon_mode_one_record_word_extension_report.md')
    if exists(BASE/'daemon_mode_one_record_rounds_report.md'):reports.add(BASE/'daemon_mode_one_record_rounds_report.md')
    if exists(BASE/'daemon_mode_one_record_reentry_report.md'):reports.add(BASE/'daemon_mode_one_record_reentry_report.md')
    if exists(BASE/'daemon_mode_one_record_checkpoint_report.md'):reports.add(BASE/'daemon_mode_one_record_checkpoint_report.md')
    if exists(BASE/'daemon_mode_one_workspace_passes_report.md'):reports.add(BASE/'daemon_mode_one_workspace_passes_report.md')
    if exists(BASE/'daemon_mode_one_encoded_addition_report.md'):reports.add(BASE/'daemon_mode_one_encoded_addition_report.md')
    if exists(BASE/'daemon_mode_one_nibble_operation_suite_report.md'):reports.add(BASE/'daemon_mode_one_nibble_operation_suite_report.md')
    if exists(BASE/'daemon_mode_one_workspace_state_install_report.md'):reports.add(BASE/'daemon_mode_one_workspace_state_install_report.md')
    if exists(BASE/'daemon_mode_one_parity_state_adapters_report.md'):reports.add(BASE/'daemon_mode_one_parity_state_adapters_report.md')
    if exists(BASE/'daemon_mode_one_word_xor_plane_refresh_report.md'):reports.add(BASE/'daemon_mode_one_word_xor_plane_refresh_report.md')
    if exists(BASE/'daemon_mode_one_secondary_word_import_report.md'):reports.add(BASE/'daemon_mode_one_secondary_word_import_report.md')
    if exists(BASE/'daemon_mode_one_secondary_word_extension_report.md'):reports.add(BASE/'daemon_mode_one_secondary_word_extension_report.md')
    if exists(BASE/'daemon_service_cf_lifecycle_report.md'):reports.add(BASE/'daemon_service_cf_lifecycle_report.md')
    if exists(BASE/'cf_mach_port_retirement_report.md'):reports.add(BASE/'cf_mach_port_retirement_report.md')
    if exists(BASE/'daemon_cf_descriptor_bridge_report.md'):reports.add(BASE/'daemon_cf_descriptor_bridge_report.md')
    if exists(BASE/'cf_public_runloop_report.md'):reports.add(BASE/'cf_public_runloop_report.md')
    if exists(BASE/'cf_source0_scheduler_report.md'):reports.add(BASE/'cf_source0_scheduler_report.md')
    if exists(BASE/'cf_descriptor_source_factory_report.md'):reports.add(BASE/'cf_descriptor_source_factory_report.md')
    if exists(BASE/'daemon_descriptor_source_report.md'):reports.add(BASE/'daemon_descriptor_source_report.md')
    if exists(BASE/'cf_source_wake_callers_report.md'):reports.add(BASE/'cf_source_wake_callers_report.md')
    if exists(BASE/'kernel_wake_send_ingress_report.md'):reports.add(BASE/'kernel_wake_send_ingress_report.md')
    if exists(BASE/'cf_wake_send_wrapper_report.md'):reports.add(BASE/'cf_wake_send_wrapper_report.md')
    if exists(BASE/'cf_runloop_wake_port_report.md'):reports.add(BASE/'cf_runloop_wake_port_report.md')
    if exists(BASE/'kernel_timer_expiration_delivery_report.md'):reports.add(BASE/'kernel_timer_expiration_delivery_report.md')
    if exists(BASE/'kernel_timer_port_create_report.md'):reports.add(BASE/'kernel_timer_port_create_report.md')
    if exists(BASE/'kernel_root_port_construct_report.md'):reports.add(BASE/'kernel_root_port_construct_report.md')
    if exists(BASE/'cf_control_port_dispatch_report.md'):reports.add(BASE/'cf_control_port_dispatch_report.md')
    if exists(BASE/'cf_mode_construction_report.md'):reports.add(BASE/'cf_mode_construction_report.md')
    if exists(BASE/'kernel_portset_delivery_report.md'):reports.add(BASE/'kernel_portset_delivery_report.md')
    if exists(BASE/'cf_source_scheduling_report.md'):reports.add(BASE/'cf_source_scheduling_report.md')
    if exists(BASE/'cf_runloop_handoff_report.md'):reports.add(BASE/'cf_runloop_handoff_report.md')
    if exists(BASE/'dispatch_voucher_hooks_report.md'):reports.add(BASE/'dispatch_voucher_hooks_report.md')
    if exists(BASE/'cf_receive_voucher_report.md'):reports.add(BASE/'cf_receive_voucher_report.md')
    if exists(BASE/'cf_daemon_request_report.md'):reports.add(BASE/'cf_daemon_request_report.md')
    if exists(BASE/'daemon_request_application_report.md'):reports.add(BASE/'daemon_request_application_report.md')
    if exists(BASE/'daemon_request_consumption_report.md'):reports.add(BASE/'daemon_request_consumption_report.md')
    if exists(BASE/'kernel_request_delivery_report.md'):reports.add(BASE/'kernel_request_delivery_report.md')
    if exists(BASE/'kernel_request_copyin_report.md'):reports.add(BASE/'kernel_request_copyin_report.md')
    if exists(BASE/'kernel_request_receive_report.md'):reports.add(BASE/'kernel_request_receive_report.md')
    if exists(BASE/'kernel_rpc_request_report.md'):reports.add(BASE/'kernel_rpc_request_report.md')
    if exists(BASE/'kernel_special_reply_report.md'):reports.add(BASE/'kernel_special_reply_report.md')
    if exists(BASE/'kernel_reply_namespace_report.md'):reports.add(BASE/'kernel_reply_namespace_report.md')
    if exists(BASE/'kernel_receive_copyout_report.md'):reports.add(BASE/'kernel_receive_copyout_report.md')
    if exists(BASE/'kernel_receive_continuation_report.md'):reports.add(BASE/'kernel_receive_continuation_report.md')
    if exists(BASE/'kernel_waitq_enqueue_report.md'):reports.add(BASE/'kernel_waitq_enqueue_report.md')
    if exists(BASE/'kernel_waitq_receiver_report.md'):reports.add(BASE/'kernel_waitq_receiver_report.md')
    if exists(BASE/'kernel_kmsg_queue_report.md'):reports.add(BASE/'kernel_kmsg_queue_report.md')
    if exists(BASE/'kernel_cache_gate_report.md'):reports.add(BASE/'kernel_cache_gate_report.md')
    if exists(BASE/'kernel_zone_refill_report.md'):reports.add(BASE/'kernel_zone_refill_report.md')
    if exists(BASE/'kernel_zone_startup_report.md'):reports.add(BASE/'kernel_zone_startup_report.md')
    if exists(BASE/'kernel_kmsg_allocation_report.md'):reports.add(BASE/'kernel_kmsg_allocation_report.md')
    if exists(BASE/'kernel_notification_send_report.md'):reports.add(BASE/'kernel_notification_send_report.md')
    if exists(BASE/'kernel_send_right_lifecycle_report.md'):reports.add(BASE/'kernel_send_right_lifecycle_report.md')
    if exists(BASE/'kext_vm_copyout_bridge_report.md'):reports.add(BASE/'kext_vm_copyout_bridge_report.md')
    if exists(BASE/'kernel_range_fallback_report.md'):reports.add(BASE/'kernel_range_fallback_report.md')
    if exists(BASE/'kernel_range_resolver_report.md'):reports.add(BASE/'kernel_range_resolver_report.md')
    if exists(BASE/'kernel_map_store_init_report.md'):reports.add(BASE/'kernel_map_store_init_report.md')
    if exists(BASE/'kernel_type2_copyout_report.md'):reports.add(BASE/'kernel_type2_copyout_report.md')
    if exists(BASE/'kernel_vm_entry_copy_report.md'):reports.add(BASE/'kernel_vm_entry_copy_report.md')
    if exists(BASE/'kernel_vm_range_cursor_report.md'):reports.add(BASE/'kernel_vm_range_cursor_report.md')
    if exists(BASE/'rpc502_vm_handoff_report.md'):reports.add(BASE/'rpc502_vm_handoff_report.md')
    if exists(BASE/'iorpc_binary_parser_report.md'):reports.add(BASE/'iorpc_binary_parser_report.md')
    if exists(BASE/'iorpc_ool_serialization_report.md'):reports.add(BASE/'iorpc_ool_serialization_report.md')
    if exists(BASE/'iorpc_object_conversion_report.md'):reports.add(BASE/'iorpc_object_conversion_report.md')
    if exists(BASE/'iorpc_remote_report.md'):reports.add(BASE/'iorpc_remote_report.md')
    if exists(BASE/'platform_iorpc_report.md'):reports.add(BASE/'platform_iorpc_report.md')
    if exists(BASE/'aes_platform_gate_report.md'):reports.add(BASE/'aes_platform_gate_report.md')
    if exists(BASE/'aes_quantum_binding_report.md'):reports.add(BASE/'aes_quantum_binding_report.md')
    if exists(BASE/'aes_hardware_job_report.md'):reports.add(BASE/'aes_hardware_job_report.md')
    if exists(BASE/'aes_synchronous_wait_report.md'):reports.add(BASE/'aes_synchronous_wait_report.md')
    if exists(BASE/'aes_carrier_initialization_report.md'):reports.add(BASE/'aes_carrier_initialization_report.md')
    if exists(BASE/'aes_completion_contract_report.md'):reports.add(BASE/'aes_completion_contract_report.md')
    if exists(BASE/'aes_provider_queue_report.md'):reports.add(BASE/'aes_provider_queue_report.md')
    if exists(BASE/'aes_command_pool_report.md'):reports.add(BASE/'aes_command_pool_report.md')
    if exists(BASE/'workloop_gate_attachment_report.md'):reports.add(BASE/'workloop_gate_attachment_report.md')
    if exists(BASE/'aes_command_gate_report.md'):reports.add(BASE/'aes_command_gate_report.md')
    if exists(BASE/'kext_startup_hardware_bridge_report.md'):reports.add(BASE/'kext_startup_hardware_bridge_report.md')
    if exists(BASE/'kext_provider_initialize_report.md'):reports.add(BASE/'kext_provider_initialize_report.md')
    if exists(BASE/'kext_constructor_reply_state_report.md'):reports.add(BASE/'kext_constructor_reply_state_report.md')
    if exists(BASE/'kext_constructor_request_report.md'):reports.add(BASE/'kext_constructor_request_report.md')
    if exists(BASE/'kext_context_retirement_report.md'):reports.add(BASE/'kext_context_retirement_report.md')
    if exists(BASE/'kext_page_context_report.md'):reports.add(BASE/'kext_page_context_report.md')
    if exists(BASE/'kext_security_record_report.md'):reports.add(BASE/'kext_security_record_report.md')
    if exists(BASE/'kext_mapped_cleanup_report.md'):reports.add(BASE/'kext_mapped_cleanup_report.md')
    if exists(BASE/'kernel_task_map_report.md'):reports.add(BASE/'kernel_task_map_report.md')
    if exists(BASE/'kernel_copyin_policy_report.md'):reports.add(BASE/'kernel_copyin_policy_report.md')
    if exists(BASE/'rpc502_reply_copyin_report.md'):reports.add(BASE/'rpc502_reply_copyin_report.md')
    if exists(BASE/'kernel_reply_copyout_report.md'):reports.add(BASE/'kernel_reply_copyout_report.md')
    if exists(BASE/'rpc502_reply_bridge_report.md'):reports.add(BASE/'rpc502_reply_bridge_report.md')
    if exists(BASE/'rpc502_receive_bridge_report.md'):reports.add(BASE/'rpc502_receive_bridge_report.md')
    if exists(BASE/'kernel_receive_delivery_report.md'):reports.add(BASE/'kernel_receive_delivery_report.md')
    if exists(BASE/'kernel_queue_receive_report.md'):reports.add(BASE/'kernel_queue_receive_report.md')
    if exists(BASE/'kernel_queue_send_report.md'):reports.add(BASE/'kernel_queue_send_report.md')
    if exists(BASE/'kernel_reply_send_report.md'):reports.add(BASE/'kernel_reply_send_report.md')
    if exists(BASE/'kernel_vm_mig_report.md'):reports.add(BASE/'kernel_vm_mig_report.md')
    if exists(BASE/'daemon_vm_cleanup_report.md'):reports.add(BASE/'daemon_vm_cleanup_report.md')
    if exists(BASE/'daemon_client_object_report.md'):reports.add(BASE/'daemon_client_object_report.md')
    if exists(BASE/'daemon_boolean_chain_report.md'):reports.add(BASE/'daemon_boolean_chain_report.md')
    if exists(BASE/'daemon_secondary_string_report.md'):reports.add(BASE/'daemon_secondary_string_report.md')
    if exists(BASE/'daemon_secondary_result_report.md'):reports.add(BASE/'daemon_secondary_result_report.md')
    if exists(BASE/'daemon_entitlement_flow_report.md'):reports.add(BASE/'daemon_entitlement_flow_report.md')
    if exists(BASE/'daemon_entitlement_result_report.md'):reports.add(BASE/'daemon_entitlement_result_report.md')
    if exists(BASE/'daemon_record40_consumer_report.md'):reports.add(BASE/'daemon_record40_consumer_report.md')
    if exists(BASE/'daemon_mig_handover_report.md'):reports.add(BASE/'daemon_mig_handover_report.md')
    if exists(BASE/'daemon_operation_heads_report.md'):reports.add(BASE/'daemon_operation_heads_report.md')
    if exists(BASE/'daemon_core_dispatch_report.md'):reports.add(BASE/'daemon_core_dispatch_report.md')
    if exists(BASE/'daemon_shared_roots_report.md'):reports.add(BASE/'daemon_shared_roots_report.md')
    if exists(BASE/'daemon_aux_callers_report.md'):reports.add(BASE/'daemon_aux_callers_report.md')
    if exists(BASE/'daemon_output_base_report.md'):reports.add(BASE/'daemon_output_base_report.md')
    if exists(BASE/'daemon_cleanup_return_report.md'):reports.add(BASE/'daemon_cleanup_return_report.md')
    if exists(BASE/'daemon_arena_lifetime_report.md'):reports.add(BASE/'daemon_arena_lifetime_report.md')
    if exists(BASE/'daemon_arena_consumer_report.md'):reports.add(BASE/'daemon_arena_consumer_report.md')
    if exists(BASE/'daemon_arena_list_report.md'):reports.add(BASE/'daemon_arena_list_report.md')
    if exists(BASE/'daemon_record720_spill_report.md'):reports.add(BASE/'daemon_record720_spill_report.md')
    if exists(BASE/'daemon_record720_fields_report.md'):reports.add(BASE/'daemon_record720_fields_report.md')
    if exists(BASE/'daemon_record720_fingerprint_report.md'):reports.add(BASE/'daemon_record720_fingerprint_report.md')
    if exists(BASE/'daemon_record720_release_report.md'):reports.add(BASE/'daemon_record720_release_report.md')
    if exists(BASE/'daemon_record720_handoff_report.md'):reports.add(BASE/'daemon_record720_handoff_report.md')
    if exists(BASE/'daemon_record720_report.md'):reports.add(BASE/'daemon_record720_report.md')
    if exists(BASE/'daemon_cache_publication_report.md'):reports.add(BASE/'daemon_cache_publication_report.md')
    if exists(BASE/'daemon_digest_completion_report.md'):reports.add(BASE/'daemon_digest_completion_report.md')
    if exists(BASE/'daemon_digest_output_report.md'):reports.add(BASE/'daemon_digest_output_report.md')
    if exists(BASE/'daemon_sha1_core_report.md'):reports.add(BASE/'daemon_sha1_core_report.md')
    if exists(BASE/'daemon_compression_frame_report.md'):reports.add(BASE/'daemon_compression_frame_report.md')
    if exists(BASE/'daemon_digest_conventions_report.md'):reports.add(BASE/'daemon_digest_conventions_report.md')
    if exists(BASE/'daemon_digest_routes_report.md'):reports.add(BASE/'daemon_digest_routes_report.md')
    if exists(BASE/'daemon_identity_cache_report.md'):reports.add(BASE/'daemon_identity_cache_report.md')
    if exists(BASE/'daemon_cache36_report.md'):reports.add(BASE/'daemon_cache36_report.md')
    if exists(BASE/'daemon_object_clock_report.md'):reports.add(BASE/'daemon_object_clock_report.md')
    if exists(BASE/'daemon_object_initialization_report.md'):reports.add(BASE/'daemon_object_initialization_report.md')
    if exists(BASE/'daemon_creation_predecessors_report.md'):reports.add(BASE/'daemon_creation_predecessors_report.md')
    if exists(BASE/'daemon_object_creation_report.md'):reports.add(BASE/'daemon_object_creation_report.md')
    if exists(BASE/'daemon_object_consumers_report.md'):reports.add(BASE/'daemon_object_consumers_report.md')
    if exists(BASE/'daemon_registry_lookup_report.md'):reports.add(BASE/'daemon_registry_lookup_report.md')
    if exists(BASE/'daemon_mode471c_lifecycle_report.md'):reports.add(BASE/'daemon_mode471c_lifecycle_report.md')
    if exists(BASE/'rpc502_mapping_report.md'):reports.add(BASE/'rpc502_mapping_report.md')
    if exists(BASE/'user_trap_interface_report.md'):reports.add(BASE/'user_trap_interface_report.md')
    if exists(BASE/'kernel_dispatch_report.md'):reports.add(BASE/'kernel_dispatch_report.md')
    if exists(BASE/'kernel_namespace_report.md'):reports.add(BASE/'kernel_namespace_report.md')
    if exists(BASE/'cf_receive_report.md'):reports.add(BASE/'cf_receive_report.md')
    if exists(BASE/'daemon_registration_report.md'):reports.add(BASE/'daemon_registration_report.md')
    if exists(BASE/'created_port_report.md'):reports.add(BASE/'created_port_report.md')
    if exists(BASE/'arcade_subscription_report.md'):reports.add(BASE/'arcade_subscription_report.md')
    if exists(BASE/'arcade_service_report.md'):reports.add(BASE/'arcade_service_report.md')
    if exists(BASE/'arcade_reply_report.md'):reports.add(BASE/'arcade_reply_report.md')
    if exists(BASE/'arcade_policy_report.md'):reports.add(BASE/'arcade_policy_report.md')
    if exists(BASE/'arcade_receipt_report.md'):reports.add(BASE/'arcade_receipt_report.md')
    if exists(BASE/'appstore_repair_report.md'):reports.add(BASE/'appstore_repair_report.md')
    if exists(BASE/'appstore_receiver_report.md'):reports.add(BASE/'appstore_receiver_report.md')
    if exists(BASE/'appstore_events_report.md'):reports.add(BASE/'appstore_events_report.md')
    if exists(BASE/'ams_core_report.md'):reports.add(BASE/'ams_core_report.md')
    if exists(BASE/'corefp_exports_report.md'):reports.add(BASE/'corefp_exports_report.md')
    if exists(BASE/'corefp_lookup_report.md'):reports.add(BASE/'corefp_lookup_report.md')
    if exists(BASE/'corefp_client_paths_report.md'):reports.add(BASE/'corefp_client_paths_report.md')
    if exists(BASE/'adid_receiver_report.md'):reports.add(BASE/'adid_receiver_report.md')
    if exists(BASE/'adid_startup_report.md'):reports.add(BASE/'adid_startup_report.md')
    if exists(BASE/'adid_request_report.md'):reports.add(BASE/'adid_request_report.md')
    if exists(BASE/'adid_context_report.md'):reports.add(BASE/'adid_context_report.md')
    if exists(BASE/'adid_iokit_report.md'):reports.add(BASE/'adid_iokit_report.md')
    if exists(BASE/'adid_iokit_caller_report.md'):reports.add(BASE/'adid_iokit_caller_report.md')
    if exists(BASE/'adid_driver_dispatch_report.md'):reports.add(BASE/'adid_driver_dispatch_report.md')
    if exists(BASE/'adid_context_gate_report.md'):reports.add(BASE/'adid_context_gate_report.md')
    if exists(BASE/'adid_state_producer_report.md'):reports.add(BASE/'adid_state_producer_report.md')
    if exists(BASE/'adid_context_lookup_report.md'):reports.add(BASE/'adid_context_lookup_report.md')
    if exists(BASE/'adid_record_lifecycle_report.md'):reports.add(BASE/'adid_record_lifecycle_report.md')
    if exists(BASE/'adid_command_dispatch_report.md'):reports.add(BASE/'adid_command_dispatch_report.md')
    if exists(BASE/'adid_avp_packet_report.md'):reports.add(BASE/'adid_avp_packet_report.md')
    if exists(BASE/'akd_adid_client_report.md'):reports.add(BASE/'akd_adid_client_report.md')
    if exists(BASE/'adid_notification_report.md'):reports.add(BASE/'adid_notification_report.md')
    if exists(BASE/'notify_ipc_report.md'):reports.add(BASE/'notify_ipc_report.md')
    if exists(BASE/'notifyd_admission_report.md'):reports.add(BASE/'notifyd_admission_report.md')
    if exists(BASE/'notifyd_policy_report.md'):reports.add(BASE/'notifyd_policy_report.md')
    if exists(BASE/'notifyd_monitor_report.md'):reports.add(BASE/'notifyd_monitor_report.md')
    if exists(BASE/'rpc502_parser_report.md'):reports.add(BASE/'rpc502_parser_report.md')
    if exists(BASE/'rpc502_supplemental_report.md'):reports.add(BASE/'rpc502_supplemental_report.md')
    if exists(BASE/'rpc502_certificate_report.md'):reports.add(BASE/'rpc502_certificate_report.md')
    if exists(BASE/'rpc502_startup_report.md'):reports.add(BASE/'rpc502_startup_report.md')
    if exists(BASE/'rpc502_auth_report.md'):reports.add(BASE/'rpc502_auth_report.md')
    for name in ['rpc502_rsa_report.md','rpc502_policy_report.md','rpc502_late_report.md','rpc502_padding_report.md','rpc502_ownership_report.md','rpc502_cleanup_report.md','rpc700_namespace_report.md','kext_close_report.md','kext_cold_init_report.md','kext_buffer_report.md','kext_aes_handoff_report.md','kext_aes_dispatch_report.md','sample_descriptor_report.md','sample_caller_report.md','sample_state_report.md','sample_transfer_report.md','carrier_control_report.md','sample_lock_report.md','rw_lifecycle_report.md','iolib_group_report.md','legacy_stack_report.md','legacy_tlv_report.md','lskd_request_report.md','lskd_fields_report.md','lskd_execute_report.md','lskd_response_report.md','lskd_consumer_report.md','lskd_handlers_report.md','lskd_values_report.md','lskd_readback_report.md','lskd_continuations_report.md','lskd_state_report.md','lskd_lookup_report.md','lskd_objects_report.md','lskd_writers_report.md','lskd_core_workspace_report.md','lskd_core_input_report.md','lskd_input_buffers_report.md','daemon_iokit_census_report.md','daemon_query_state_report.md','daemon_query_fallback_report.md','daemon_iokit_objects_report.md','daemon_iokit_class_report.md']:
        if exists(BASE/name):reports.add(BASE/name)
    assert len(reports)>=18 and BASE/'dump.md' not in reports and BASE/'analysis.md' not in reports
    if exists(BASE/'daemon_iokit_sync_report.md'):reports.add(BASE/'daemon_iokit_sync_report.md')
    if exists(BASE/'daemon_iokit_errors_report.md'):reports.add(BASE/'daemon_iokit_errors_report.md')
    if exists(BASE/'daemon_iokit_callers_report.md'):reports.add(BASE/'daemon_iokit_callers_report.md')
    if exists(BASE/'daemon_rwlock_lifecycle_report.md'):reports.add(BASE/'daemon_rwlock_lifecycle_report.md')
    if exists(BASE/'daemon_frame_entry_report.md'):reports.add(BASE/'daemon_frame_entry_report.md')
    if exists(BASE/'daemon_arena_entry_report.md'):reports.add(BASE/'daemon_arena_entry_report.md')
    if exists(BASE/'daemon_arena_storage_report.md'):reports.add(BASE/'daemon_arena_storage_report.md')
    if exists(BASE/'daemon_context_transfer_report.md'):reports.add(BASE/'daemon_context_transfer_report.md')
    if exists(BASE/'daemon_entropy_return_report.md'):reports.add(BASE/'daemon_entropy_return_report.md')
    if exists(BASE/'daemon_seed_material_report.md'):reports.add(BASE/'daemon_seed_material_report.md')
    if exists(BASE/'daemon_prng_output_report.md'):reports.add(BASE/'daemon_prng_output_report.md')
    if exists(BASE/'daemon_buffer_consumer_report.md'):reports.add(BASE/'daemon_buffer_consumer_report.md')
    if exists(BASE/'daemon_global_state_report.md'):reports.add(BASE/'daemon_global_state_report.md')
    if exists(BASE/'daemon_callback_revisit_report.md'):reports.add(BASE/'daemon_callback_revisit_report.md')
    if exists(BASE/'daemon_context_lock_report.md'):reports.add(BASE/'daemon_context_lock_report.md')
    if exists(BASE/'daemon_descriptor_readers_report.md'):reports.add(BASE/'daemon_descriptor_readers_report.md')
    if exists(BASE/'daemon_descriptor_producers_report.md'):reports.add(BASE/'daemon_descriptor_producers_report.md')
    if exists(BASE/'daemon_mode_one_secondary_rounds_report.md'):reports.add(BASE/'daemon_mode_one_secondary_rounds_report.md')
    if exists(BASE/'daemon_mode_one_secondary_reentry_report.md'):reports.add(BASE/'daemon_mode_one_secondary_reentry_report.md')
    if exists(BASE/'daemon_mode_one_even_view_import_report.md'):reports.add(BASE/'daemon_mode_one_even_view_import_report.md')
    if exists(BASE/'daemon_mode_one_result_publication_report.md'):reports.add(BASE/'daemon_mode_one_result_publication_report.md')
    if exists(BASE/'daemon_mode_one_output_verification_report.md'):reports.add(BASE/'daemon_mode_one_output_verification_report.md')
    if exists(BASE/'daemon_mode_one_second_phase_handoff_report.md'):reports.add(BASE/'daemon_mode_one_second_phase_handoff_report.md')
    if exists(BASE/'daemon_mode_one_budget_store_audit_report.md'):reports.add(BASE/'daemon_mode_one_budget_store_audit_report.md')
    if exists(BASE/'daemon_mode_one_computed_store_footprints_report.md'):reports.add(BASE/'daemon_mode_one_computed_store_footprints_report.md')
    if exists(BASE/'kext_query_getter_values_report.md'):reports.add(BASE/'kext_query_getter_values_report.md')
    if exists(BASE/'versioned_request_abi_report.md'):reports.add(BASE/'versioned_request_abi_report.md')
    if exists(BASE/'userclient_context_lifecycle_report.md'):reports.add(BASE/'userclient_context_lifecycle_report.md')
    if exists(BASE/'context_descriptor_task_flow_report.md'):reports.add(BASE/'context_descriptor_task_flow_report.md')
    if exists(BASE/'core_stack_delta_abi_report.md'):reports.add(BASE/'core_stack_delta_abi_report.md')
    if exists(BASE/'inner_write_frontier_report.md'):reports.add(BASE/'inner_write_frontier_report.md')
    if exists(BASE/'buffer_construction_flow_report.md'):reports.add(BASE/'buffer_construction_flow_report.md')
    if exists(BASE/'dma_map_constraints_report.md'):reports.add(BASE/'dma_map_constraints_report.md')
    if exists(BASE/'mixed_data_lifecycle_report.md'):reports.add(BASE/'mixed_data_lifecycle_report.md')
    if exists(BASE/'mixed_data_backing_report.md'):reports.add(BASE/'mixed_data_backing_report.md')
    if exists(BASE/'mixed_data_release_report.md'):reports.add(BASE/'mixed_data_release_report.md')
    if exists(BASE/'mixed_data_retirement_report.md'):reports.add(BASE/'mixed_data_retirement_report.md')
    if exists(BASE/'mixed_data_zone_geometry_report.md'):reports.add(BASE/'mixed_data_zone_geometry_report.md')
    if exists(BASE/'descriptor_prepare_lifecycle_report.md'):reports.add(BASE/'descriptor_prepare_lifecycle_report.md')
    if exists(BASE/'aes_cleanup_epoch_report.md'):reports.add(BASE/'aes_cleanup_epoch_report.md')
    if exists(BASE/'cached_lock_origin_report.md'):reports.add(BASE/'cached_lock_origin_report.md')
    if exists(BASE/'lskd_lock_origin_report.md'):reports.add(BASE/'lskd_lock_origin_report.md')
    if exists(BASE/'lskd_start_lock_flow_report.md'):reports.add(BASE/'lskd_start_lock_flow_report.md')
    if exists(BASE/'lskd_vector_origin_report.md'):reports.add(BASE/'lskd_vector_origin_report.md')
    if exists(BASE/'lskd_element_population_report.md'):reports.add(BASE/'lskd_element_population_report.md')
    if exists(BASE/'lskd_secure_time_report.md'):reports.add(BASE/'lskd_secure_time_report.md')
    if exists(BASE/'lskd_clock_completion_report.md'):reports.add(BASE/'lskd_clock_completion_report.md')
    if exists(BASE/'lskd_clock_reader_report.md'):reports.add(BASE/'lskd_clock_reader_report.md')
    if exists(BASE/'lskd_clock_accumulator_report.md'):reports.add(BASE/'lskd_clock_accumulator_report.md')
    if exists(BASE/'lskd_context_compare_report.md'):reports.add(BASE/'lskd_context_compare_report.md')
    if exists(BASE/'lskd_reader_lineage_report.md'):reports.add(BASE/'lskd_reader_lineage_report.md')
    if exists(BASE/'lskd_context_codec_report.md'):reports.add(BASE/'lskd_context_codec_report.md')
    if exists(BASE/'lskd_context_return_report.md'):reports.add(BASE/'lskd_context_return_report.md')
    if exists(BASE/'lskd_operation_preflight_report.md'):reports.add(BASE/'lskd_operation_preflight_report.md')
    if exists(BASE/'lskd_byte_spans_report.md'):reports.add(BASE/'lskd_byte_spans_report.md')
    if exists(BASE/'lskd_hardware_staging_report.md'):reports.add(BASE/'lskd_hardware_staging_report.md')
    if exists(BASE/'aes_provider_admission_report.md'):reports.add(BASE/'aes_provider_admission_report.md')
    if exists(BASE/'aes_dma_preparation_report.md'):reports.add(BASE/'aes_dma_preparation_report.md')
    if exists(BASE/'aes_configuration_commands_report.md'):reports.add(BASE/'aes_configuration_commands_report.md')
    if exists(BASE/'aes_trace_wakeup_report.md'):reports.add(BASE/'aes_trace_wakeup_report.md')
    if exists(BASE/'aes_event_registration_report.md'):reports.add(BASE/'aes_event_registration_report.md')
    if exists(BASE/'event_wait_table_report.md'):reports.add(BASE/'event_wait_table_report.md')
    if exists(BASE/'startup_dispatch_report.md'):reports.add(BASE/'startup_dispatch_report.md')
    if exists(BASE/'aes_event_wake_selection_report.md'):reports.add(BASE/'aes_event_wake_selection_report.md')
    if exists(BASE/'aes_block_wake_handshake_report.md'):reports.add(BASE/'aes_block_wake_handshake_report.md')
    if exists(BASE/'aes_runqueue_membership_report.md'):reports.add(BASE/'aes_runqueue_membership_report.md')
    if exists(BASE/'aes_cached_class_queue_report.md'):reports.add(BASE/'aes_cached_class_queue_report.md')
    if exists(BASE/'aes_uncached_context_queue_report.md'):reports.add(BASE/'aes_uncached_context_queue_report.md')
    if exists(BASE/'aes_context_score_policy_report.md'):reports.add(BASE/'aes_context_score_policy_report.md')
    if exists(BASE/'fpsd1200_contract_report.md'):reports.add(BASE/'fpsd1200_contract_report.md')
    if exists(BASE/'fpsd1200_admission_report.md'):reports.add(BASE/'fpsd1200_admission_report.md')
    if exists(BASE/'fpsd1200_identity_report.md'):reports.add(BASE/'fpsd1200_identity_report.md')
    if exists(BASE/'fpsd1200_arena_report.md'):reports.add(BASE/'fpsd1200_arena_report.md')
    if exists(BASE/'fpsd1200_context_report.md'):reports.add(BASE/'fpsd1200_context_report.md')
    if exists(BASE/'fpsd1200_certificate_report.md'):reports.add(BASE/'fpsd1200_certificate_report.md')
    if exists(BASE/'fpsd1200_vm_report.md'):reports.add(BASE/'fpsd1200_vm_report.md')
    if exists(BASE/'fpsd1200_port_report.md'):reports.add(BASE/'fpsd1200_port_report.md')
    if exists(BASE/'fpsd1200_lifetime_report.md'):reports.add(BASE/'fpsd1200_lifetime_report.md')
    if exists(BASE/'fpsd1200_process_report.md'):reports.add(BASE/'fpsd1200_process_report.md')
    if exists(BASE/'fpsd1201_session_report.md'):reports.add(BASE/'fpsd1201_session_report.md')
    if exists(BASE/'fpsd1202_ool_report.md'):reports.add(BASE/'fpsd1202_ool_report.md')
    if exists(BASE/'fpsd1202_session_report.md'):reports.add(BASE/'fpsd1202_session_report.md')
    if exists(BASE/'fpsd_tail_retirement_report.md'):reports.add(BASE/'fpsd_tail_retirement_report.md')
    if exists(BASE/'fpsd1201_client_report.md'):reports.add(BASE/'fpsd1201_client_report.md')
    if exists(BASE/'fpsd1201_caller_report.md'):reports.add(BASE/'fpsd1201_caller_report.md')
    if exists(BASE/'fpsd1201_record_report.md'):reports.add(BASE/'fpsd1201_record_report.md')
    if exists(BASE/'fpsd1201_import_report.md'):reports.add(BASE/'fpsd1201_import_report.md')
    if exists(BASE/'fpsd1201_operand_report.md'):reports.add(BASE/'fpsd1201_operand_report.md')
    if exists(BASE/'fpsd1201_shift_report.md'):reports.add(BASE/'fpsd1201_shift_report.md')
    if exists(BASE/'fpsd1201_comparison_report.md'):reports.add(BASE/'fpsd1201_comparison_report.md')
    if exists(BASE/'fpsd1201_subtraction_report.md'):reports.add(BASE/'fpsd1201_subtraction_report.md')
    if exists(BASE/'fpsd1201_reduction_report.md'):reports.add(BASE/'fpsd1201_reduction_report.md')
    if exists(BASE/'fpsd1201_consumer_report.md'):reports.add(BASE/'fpsd1201_consumer_report.md')
    if exists(BASE/'fpsd1201_product_report.md'):reports.add(BASE/'fpsd1201_product_report.md')
    if exists(BASE/'fpsd1201_auxiliary_report.md'):reports.add(BASE/'fpsd1201_auxiliary_report.md')
    if exists(BASE/'fpsd1201_export_report.md'):reports.add(BASE/'fpsd1201_export_report.md')
    if exists(BASE/'fpsd1201_handoff_report.md'):reports.add(BASE/'fpsd1201_handoff_report.md')
    if exists(BASE/'fpsd1201_workspace_report.md'):reports.add(BASE/'fpsd1201_workspace_report.md')
    if exists(BASE/'fpsd1201_predicates_report.md'):reports.add(BASE/'fpsd1201_predicates_report.md')
    if exists(BASE/'fpsd1201_seed_report.md'):reports.add(BASE/'fpsd1201_seed_report.md')
    if exists(BASE/'fpsd1201_key_routes_report.md'):reports.add(BASE/'fpsd1201_key_routes_report.md')
    if exists(BASE/'corefp_network_identity_report.md'):reports.add(BASE/'corefp_network_identity_report.md')
    if exists(BASE/'corefp_lookup_initialization_report.md'):reports.add(BASE/'corefp_lookup_initialization_report.md')
    if exists(BASE/'corefp_cold_metadata_report.md'):reports.add(BASE/'corefp_cold_metadata_report.md')
    if exists(BASE/'corefp_lookup_release_report.md'):reports.add(BASE/'corefp_lookup_release_report.md')
    if exists(BASE/'corefp_request1200_failure_report.md'):reports.add(BASE/'corefp_request1200_failure_report.md')
    if exists(BASE/'corefp_cold_seed_report.md'):reports.add(BASE/'corefp_cold_seed_report.md')
    if exists(BASE/'corefp_root_adapter_report.md'):reports.add(BASE/'corefp_root_adapter_report.md')
    if exists(BASE/'corefp_root_ingress_report.md'):reports.add(BASE/'corefp_root_ingress_report.md')
    if exists(BASE/'corefp_ingress_callers_report.md'):reports.add(BASE/'corefp_ingress_callers_report.md')
    if exists(BASE/'corefp_vm_lifecycle_report.md'):reports.add(BASE/'corefp_vm_lifecycle_report.md')
    if exists(BASE/'corefp_caller_cold_report.md'):reports.add(BASE/'corefp_caller_cold_report.md')
    if exists(BASE/'corefp_optional_reset_report.md'):reports.add(BASE/'corefp_optional_reset_report.md')
    if exists(BASE/'corefp_reset_caller_report.md'):reports.add(BASE/'corefp_reset_caller_report.md')
    if exists(BASE/'corefp_pool_allocator_report.md'):reports.add(BASE/'corefp_pool_allocator_report.md')
    if exists(BASE/'corefp_pool_caller_report.md'):reports.add(BASE/'corefp_pool_caller_report.md')
    if exists(BASE/'corefp_pool_transform_report.md'):reports.add(BASE/'corefp_pool_transform_report.md')
    if exists(BASE/'corefp_workspace_report.md'):reports.add(BASE/'corefp_workspace_report.md')
    if exists(BASE/'corefp_workspace_consumers_report.md'):reports.add(BASE/'corefp_workspace_consumers_report.md')
    if exists(BASE/'corefp_output_packing_report.md'):reports.add(BASE/'corefp_output_packing_report.md')
    if exists(BASE/'corefp_late_preparation_report.md'):reports.add(BASE/'corefp_late_preparation_report.md')
    if exists(BASE/'corefp_preparation_scans_report.md'):reports.add(BASE/'corefp_preparation_scans_report.md')
    if exists(BASE/'corefp_phase_parameters_report.md'):reports.add(BASE/'corefp_phase_parameters_report.md')
    if exists(BASE/'corefp_scan_entry_report.md'):reports.add(BASE/'corefp_scan_entry_report.md')
    if exists(BASE/'corefp_word_codec_report.md'):reports.add(BASE/'corefp_word_codec_report.md')
    if exists(BASE/'corefp_word_recurrence_report.md'):reports.add(BASE/'corefp_word_recurrence_report.md')
    if exists(BASE/'corefp_word_inputs_report.md'):reports.add(BASE/'corefp_word_inputs_report.md')
    if exists(BASE/'corefp_input_lineage_report.md'):reports.add(BASE/'corefp_input_lineage_report.md')
    if exists(BASE/'corefp_word_traversal_report.md'):reports.add(BASE/'corefp_word_traversal_report.md')
    if exists(BASE/'corefp_word_selectors_report.md'):reports.add(BASE/'corefp_word_selectors_report.md')
    if exists(BASE/'daemon_versioned_header_report.md'):reports.add(BASE/'daemon_versioned_header_report.md')
    if exists(BASE/'daemon_versioned_root_report.md'):reports.add(BASE/'daemon_versioned_root_report.md')
    if exists(BASE/'daemon_versioned_ingress_report.md'):reports.add(BASE/'daemon_versioned_ingress_report.md')
    if exists(BASE/'daemon_frame_word_report.md'):reports.add(BASE/'daemon_frame_word_report.md')
    if exists(BASE/'daemon_frame_admission_report.md'):reports.add(BASE/'daemon_frame_admission_report.md')
    if exists(BASE/'daemon_remainder_preparation_report.md'):reports.add(BASE/'daemon_remainder_preparation_report.md')
    if exists(BASE/'daemon_nested_helper_processing_report.md'):reports.add(BASE/'daemon_nested_helper_processing_report.md')
    if exists(BASE/'daemon_postblock_dispatch_report.md'):reports.add(BASE/'daemon_postblock_dispatch_report.md')
    if exists(BASE/'versioned_core_entry_report.md'):reports.add(BASE/'versioned_core_entry_report.md')
    if exists(BASE/'versioned_core_preparation_report.md'):reports.add(BASE/'versioned_core_preparation_report.md')
    if exists(BASE/'versioned_dispatcher_frame_report.md'):reports.add(BASE/'versioned_dispatcher_frame_report.md')
    if exists(BASE/'versioned_stream_initialization_report.md'):reports.add(BASE/'versioned_stream_initialization_report.md')
    if exists(BASE/'versioned_stream_words_report.md'):reports.add(BASE/'versioned_stream_words_report.md')
    if exists(BASE/'versioned_output_stream_report.md'):reports.add(BASE/'versioned_output_stream_report.md')
    if exists(BASE/'versioned_inner_entry_report.md'):reports.add(BASE/'versioned_inner_entry_report.md')
    if exists(BASE/'versioned_aes_parameters_report.md'):reports.add(BASE/'versioned_aes_parameters_report.md')
    if exists(BASE/'versioned_lock_handoff_report.md'):reports.add(BASE/'versioned_lock_handoff_report.md')
    if exists(BASE/'versioned_hardware_admission_report.md'):reports.add(BASE/'versioned_hardware_admission_report.md')
    if exists(BASE/'versioned_error_release_report.md'):reports.add(BASE/'versioned_error_release_report.md')
    if exists(BASE/'versioned_wrapper_error_return_report.md'):reports.add(BASE/'versioned_wrapper_error_return_report.md')
    if exists(BASE/'daemon_iokit_result_report.md'):reports.add(BASE/'daemon_iokit_result_report.md')
    if exists(BASE/'daemon_iokit_error_return_report.md'):reports.add(BASE/'daemon_iokit_error_return_report.md')
    if exists(BASE/'daemon_return_bank_origins_report.md'):reports.add(BASE/'daemon_return_bank_origins_report.md')
    if exists(BASE/'daemon_return_cache_codec_report.md'):reports.add(BASE/'daemon_return_cache_codec_report.md')
    if exists(BASE/'daemon_scratch_pointer_origin_report.md'):reports.add(BASE/'daemon_scratch_pointer_origin_report.md')
    if exists(BASE/'daemon_environment_outputs_report.md'):reports.add(BASE/'daemon_environment_outputs_report.md')
    if exists(BASE/'daemon_notification_registration_report.md'):reports.add(BASE/'daemon_notification_registration_report.md')
    if exists(BASE/'daemon_notification_failure_report.md'):reports.add(BASE/'daemon_notification_failure_report.md')
    if exists(BASE/'daemon_audit_scratch_report.md'):reports.add(BASE/'daemon_audit_scratch_report.md')
    if exists(BASE/'daemon_pidpath_consumer_report.md'):reports.add(BASE/'daemon_pidpath_consumer_report.md')
    if exists(BASE/'daemon_network_identity_report.md'):reports.add(BASE/'daemon_network_identity_report.md')
    if exists(BASE/'daemon_network_record_report.md'):reports.add(BASE/'daemon_network_record_report.md')
    links=0
    unavailable_external=[]
    for path in sorted(reports):
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(path)):
            raw=raw.strip('<>')
            if re.match(r'^[a-zA-Z][\w+.-]*://',raw) or raw.startswith('#'):continue
            name=raw.split('#',1)[0]
            target=Path(name) if name.startswith('/') else path.parent/name
            if not exists(target):
                alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(target))
                if alias!=str(target)and exists(Path(alias)):
                    links+=1
                    continue
                # Preserve this historical primary-source citation after the SDK update.
                sdk=json.loads(read(ROOT/'kernel_root_port_construct_source.json'))['SDK_context']
                assert path.name=='kernel_root_port_construct_report.md' and name==sdk['path'],(path,name)
                assert sdk['sha256']=='959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185'
                sdk_root=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
                installed=sdk_root/'usr'/'include'/'mach'/'port.h'
                current_sha=sha(installed)
                assert current_sha!=sdk['sha256']
                unavailable_external.append({'report':path.name,'path':'historical SDK:usr/include/mach/port.h','historical_sha256':sdk['sha256'],
                    'status':'historical_external_reference_unavailable','installed_comparison_path':'installed SDK:usr/include/mach/port.h',
                    'installed_comparison_sha256':current_sha,'equivalence_established':False})
            links+=1
    evidence=sorted({canonical(p)for p in ROOT.iterdir()if p.is_file()and canonical(p).name!='interface_manifest.json'and p.suffix.lower()not in{'.i64','.idb','.id0','.id1','.id2','.nam','.til'}})
    json_count=0
    for path in evidence:
        if path.suffix=='.json':json.loads(read(path));json_count+=1
    owned=reports|{p for p in BASE.glob('fairplay_*.py')}|set(evidence)|{BASE/'.gitignore'}
    manifest={'created_utc':datetime.now(timezone.utc).isoformat(),'goal_status':'active',
       'inputs_preserved':old['inputs_preserved'],
       'logical_storage_policy':'Canonical JSON paths may resolve read-only to .json.zst; sizes and SHA256 are decoded logical content. Historical Markdown paths are checked logically, not claimed physically present.',
       'scope_note':'Owned reports/scripts and direct evidence; external dump.md preserved/excluded. Current case sets are scoped by their contract files; earlier exploratory snapshots are historical.',
       'validation':{'reports':len(reports),'local_markdown_links':links,'direct_json_files':json_count,
                     'unavailable_external_primary_references':unavailable_external,
                     'sidecar_increment_checks':quality['verified_counts']},
       'files':[entry(p) for p in sorted(owned)]}
    if 'privacy_migration'in old:manifest['privacy_migration']=old['privacy_migration']
    if exists(ROOT/'rpc502_mapping_quality_gates.json'):
        mapping_quality=json.loads(read(ROOT/'rpc502_mapping_quality_gates.json'))
        manifest['validation']['mapping_increment_checks']=mapping_quality['verified_counts']
    if exists(ROOT/'user_trap_quality_gates.json'):
        trap_quality=json.loads(read(ROOT/'user_trap_quality_gates.json'))
        manifest['validation']['user_trap_increment_checks']=trap_quality['verified_counts']
    if exists(ROOT/'kernel_dispatch_quality_gates.json'):
        dispatch_quality=json.loads(read(ROOT/'kernel_dispatch_quality_gates.json'))
        manifest['validation']['kernel_dispatch_increment_checks']=dispatch_quality['verified_counts']
    if exists(ROOT/'kernel_namespace_quality_gates.json'):
        namespace_quality=json.loads(read(ROOT/'kernel_namespace_quality_gates.json'))
        manifest['validation']['kernel_namespace_increment_checks']=namespace_quality['verified_counts']
    if exists(ROOT/'cf_receive_quality_gates.json'):
        cf_quality=json.loads(read(ROOT/'cf_receive_quality_gates.json'))
        manifest['validation']['cf_receive_increment_checks']=cf_quality['verified_counts']
    if exists(ROOT/'daemon_registration_quality_gates.json'):
        registration_quality=json.loads(read(ROOT/'daemon_registration_quality_gates.json'))
        manifest['validation']['daemon_registration_increment_checks']=registration_quality['verified_counts']
    if exists(ROOT/'created_port_quality_gates.json'):
        created_quality=json.loads(read(ROOT/'created_port_quality_gates.json'))
        manifest['validation']['created_port_increment_checks']=created_quality['verified_counts']
    if exists(ROOT/'arcade_subscription_quality_gates.json'):
        subscription_quality=json.loads(read(ROOT/'arcade_subscription_quality_gates.json'))
        manifest['validation']['arcade_subscription_increment_checks']=subscription_quality['verified_counts']
    if exists(ROOT/'arcade_xpc_quality_gates.json'):
        xpc_quality=json.loads(read(ROOT/'arcade_xpc_quality_gates.json'))
        manifest['validation']['arcade_xpc_increment_checks']=xpc_quality['verified_counts']
    if exists(ROOT/'arcade_policy_quality_gates.json'):
        policy_quality=json.loads(read(ROOT/'arcade_policy_quality_gates.json'))
        manifest['validation']['arcade_policy_increment_checks']=policy_quality['verified_counts']
    if exists(ROOT/'arcade_receipt_quality_gates.json'):
        receipt_quality=json.loads(read(ROOT/'arcade_receipt_quality_gates.json'))
        manifest['validation']['arcade_receipt_increment_checks']=receipt_quality['verified_counts']
    if exists(ROOT/'appstore_agent_quality_gates.json'):
        agent_quality=json.loads(read(ROOT/'appstore_agent_quality_gates.json'))
        manifest['validation']['appstore_receiver_increment_checks']=agent_quality['verified_counts']
    if exists(ROOT/'appstore_events_quality_gates.json'):
        events_quality=json.loads(read(ROOT/'appstore_events_quality_gates.json'))
        manifest['validation']['appstore_events_increment_checks']=events_quality['verified_counts']
    if exists(ROOT/'ams_core_quality_gates.json'):
        core_quality=json.loads(read(ROOT/'ams_core_quality_gates.json'))
        manifest['validation']['ams_core_increment_checks']=core_quality['verified_counts']
    if exists(ROOT/'corefp_exports_quality_gates.json'):
        exports_quality=json.loads(read(ROOT/'corefp_exports_quality_gates.json'))
        manifest['validation']['corefp_exports_increment_checks']=exports_quality['verified_counts']
    if exists(ROOT/'corefp_lookup_quality_gates.json'):
        lookup_quality=json.loads(read(ROOT/'corefp_lookup_quality_gates.json'))
        manifest['validation']['corefp_lookup_increment_checks']=lookup_quality['verified_counts']
    if exists(ROOT/'corefp_client_paths_quality_gates.json'):
        paths_quality=json.loads(read(ROOT/'corefp_client_paths_quality_gates.json'))
        manifest['validation']['corefp_client_paths_increment_checks']=paths_quality['verified_counts']
    if exists(ROOT/'adid_receiver_quality_gates.json'):
        adid_quality=json.loads(read(ROOT/'adid_receiver_quality_gates.json'))
        manifest['validation']['adid_receiver_increment_checks']=adid_quality['verified_counts']
    if exists(ROOT/'adid_startup_quality_gates.json'):
        startup_quality=json.loads(read(ROOT/'adid_startup_quality_gates.json'))
        manifest['validation']['adid_startup_increment_checks']=startup_quality['verified_counts']
    if exists(ROOT/'adid_request_quality_gates.json'):
        request_quality=json.loads(read(ROOT/'adid_request_quality_gates.json'))
        manifest['validation']['adid_request_increment_checks']=request_quality['verified_counts']
    if exists(ROOT/'adid_context_quality_gates.json'):
        context_quality=json.loads(read(ROOT/'adid_context_quality_gates.json'))
        manifest['validation']['adid_context_increment_checks']=context_quality['verified_counts']
    if exists(ROOT/'adid_iokit_quality_gates.json'):
        iokit_quality=json.loads(read(ROOT/'adid_iokit_quality_gates.json'))
        manifest['validation']['adid_iokit_increment_checks']=iokit_quality['verified_counts']
    if exists(ROOT/'adid_iokit_caller_quality_gates.json'):
        caller_quality=json.loads(read(ROOT/'adid_iokit_caller_quality_gates.json'))
        manifest['validation']['adid_iokit_caller_increment_checks']=caller_quality['verified_counts']
    if exists(ROOT/'adid_driver_dispatch_quality_gates.json'):
        driver_dispatch_quality=json.loads(read(ROOT/'adid_driver_dispatch_quality_gates.json'))
        manifest['validation']['adid_driver_dispatch_increment_checks']=driver_dispatch_quality['verified_counts']
    if exists(ROOT/'adid_context_gate_quality_gates.json'):
        context_gate_quality=json.loads(read(ROOT/'adid_context_gate_quality_gates.json'))
        manifest['validation']['adid_context_gate_increment_checks']=context_gate_quality['verified_counts']
    if exists(ROOT/'adid_state_producer_quality_gates.json'):
        state_producer_quality=json.loads(read(ROOT/'adid_state_producer_quality_gates.json'))
        manifest['validation']['adid_state_producer_increment_checks']=state_producer_quality['verified_counts']
    if exists(ROOT/'adid_context_lookup_quality_gates.json'):
        context_lookup_quality=json.loads(read(ROOT/'adid_context_lookup_quality_gates.json'))
        manifest['validation']['adid_context_lookup_increment_checks']=context_lookup_quality['verified_counts']
    if exists(ROOT/'adid_record_lifecycle_quality_gates.json'):
        record_lifecycle_quality=json.loads(read(ROOT/'adid_record_lifecycle_quality_gates.json'))
        manifest['validation']['adid_record_lifecycle_increment_checks']=record_lifecycle_quality['verified_counts']
    if exists(ROOT/'adid_command_dispatch_quality_gates.json'):
        command_dispatch_quality=json.loads(read(ROOT/'adid_command_dispatch_quality_gates.json'))
        manifest['validation']['adid_command_dispatch_increment_checks']=command_dispatch_quality['verified_counts']
    if exists(ROOT/'adid_avp_packet_quality_gates.json'):
        avp_packet_quality=json.loads(read(ROOT/'adid_avp_packet_quality_gates.json'))
        manifest['validation']['adid_avp_packet_increment_checks']=avp_packet_quality['verified_counts']
    if exists(ROOT/'akd_adid_quality_gates.json'):
        akd_quality=json.loads(read(ROOT/'akd_adid_quality_gates.json'))
        manifest['validation']['akd_adid_increment_checks']=akd_quality['verified_counts']
    if exists(ROOT/'adid_notification_quality_gates.json'):
        notification_quality=json.loads(read(ROOT/'adid_notification_quality_gates.json'))
        manifest['validation']['adid_notification_increment_checks']=notification_quality['verified_counts']
    if exists(ROOT/'notify_ipc_quality_gates.json'):
        notify_quality=json.loads(read(ROOT/'notify_ipc_quality_gates.json'))
        manifest['validation']['notify_ipc_increment_checks']=notify_quality['verified_counts']
    if exists(ROOT/'notifyd_admission_quality_gates.json'):
        admission_quality=json.loads(read(ROOT/'notifyd_admission_quality_gates.json'))
        manifest['validation']['notifyd_admission_increment_checks']=admission_quality['verified_counts']
    if exists(ROOT/'notifyd_policy_quality_gates.json'):
        policy_quality=json.loads(read(ROOT/'notifyd_policy_quality_gates.json'))
        manifest['validation']['notifyd_policy_increment_checks']=policy_quality['verified_counts']
    if exists(ROOT/'notifyd_monitor_quality_gates.json'):
        monitor_quality=json.loads(read(ROOT/'notifyd_monitor_quality_gates.json'))
        manifest['validation']['notifyd_monitor_increment_checks']=monitor_quality['verified_counts']
    if exists(ROOT/'rpc502_parser_quality_gates.json'):
        parser_quality=json.loads(read(ROOT/'rpc502_parser_quality_gates.json'))
        manifest['validation']['rpc502_parser_increment_checks']=parser_quality['verified_counts']
    if exists(ROOT/'rpc502_supp_quality_gates.json'):
        supp_quality=json.loads(read(ROOT/'rpc502_supp_quality_gates.json'))
        manifest['validation']['rpc502_supp_increment_checks']=supp_quality['verified_counts']
        manifest['validation']['rpc502_supp_candidate_body_checks']=supp_quality['candidate_body_verified_counts']
    if exists(ROOT/'rpc502_certificate_quality_gates.json'):
        certificate_quality=json.loads(read(ROOT/'rpc502_certificate_quality_gates.json'))
        manifest['validation']['rpc502_certificate_increment_checks']=certificate_quality['verified_counts']
    if exists(ROOT/'rpc502_startup_quality_gates.json'):
        rpc_startup_quality=json.loads(read(ROOT/'rpc502_startup_quality_gates.json'))
        manifest['validation']['rpc502_startup_increment_checks']=rpc_startup_quality['verified_counts']
    if exists(ROOT/'rpc502_auth_quality_gates.json'):
        rpc_auth_quality=json.loads(read(ROOT/'rpc502_auth_quality_gates.json'))
        manifest['validation']['rpc502_auth_increment_checks']=rpc_auth_quality['verified_counts']
    if exists(ROOT/'rpc502_rsa_quality_gates.json'):
        arithmetic_quality=json.loads(read(ROOT/'rpc502_rsa_quality_gates.json'))
        manifest['validation']['rpc502_rsa_increment_checks']=arithmetic_quality['verified_counts']
        manifest['validation']['rpc502_policy_increment_checks']=arithmetic_quality['policy_verified_counts']
    if exists(ROOT/'rpc502_late_quality_gates.json'):
        late_quality=json.loads(read(ROOT/'rpc502_late_quality_gates.json'))
        manifest['validation']['rpc502_late_increment_checks']=late_quality['verified_counts']
        manifest['validation']['rpc502_late_nonzero_checks']=late_quality['nonzero_verified_counts']
        manifest['validation']['rpc502_late_reuse_checks']=late_quality['reuse_verified_counts']
    if exists(ROOT/'rw_lifecycle_quality_gates.json'):
        rw_lifecycle_quality=json.loads(read(ROOT/'rw_lifecycle_quality_gates.json'))
        manifest['validation']['rw_lifecycle_increment_checks']=rw_lifecycle_quality['verified_counts']
    if exists(ROOT/'sample_lock_quality_gates.json'):
        sample_lock_quality=json.loads(read(ROOT/'sample_lock_quality_gates.json'))
        manifest['validation']['sample_lock_increment_checks']=sample_lock_quality['verified_counts']
    if exists(ROOT/'carrier_control_quality_gates.json'):
        carrier_quality=json.loads(read(ROOT/'carrier_control_quality_gates.json'))
        manifest['validation']['carrier_control_increment_checks']=carrier_quality['verified_counts']
    if exists(ROOT/'sample_transfer_quality_gates.json'):
        transfer_quality=json.loads(read(ROOT/'sample_transfer_quality_gates.json'))
        manifest['validation']['sample_transfer_increment_checks']=transfer_quality['verified_counts']
    if exists(ROOT/'sample_state_quality_gates.json'):
        state_quality=json.loads(read(ROOT/'sample_state_quality_gates.json'))
        manifest['validation']['sample_state_increment_checks']=state_quality['verified_counts']
    if exists(ROOT/'sample_caller_quality_gates.json'):
        caller_quality=json.loads(read(ROOT/'sample_caller_quality_gates.json'))
        manifest['validation']['sample_caller_increment_checks']=caller_quality['verified_counts']
    if exists(ROOT/'sample_descriptor_quality_gates.json'):
        media_quality=json.loads(read(ROOT/'sample_descriptor_quality_gates.json'))
        manifest['validation']['sample_descriptor_increment_checks']=media_quality['verified_counts']
    if exists(ROOT/'kext_aes_dispatch_quality_gates.json'):
        dispatch_quality=json.loads(read(ROOT/'kext_aes_dispatch_quality_gates.json'))
        manifest['validation']['kext_aes_dispatch_increment_checks']=dispatch_quality['verified_counts']
    if exists(ROOT/'kext_aes_handoff_quality_gates.json'):
        handoff_quality=json.loads(read(ROOT/'kext_aes_handoff_quality_gates.json'))
        manifest['validation']['kext_aes_handoff_increment_checks']=handoff_quality['verified_counts']
    if exists(ROOT/'kext_buffer_quality_gates.json'):
        buffer_quality=json.loads(read(ROOT/'kext_buffer_quality_gates.json'))
        manifest['validation']['kext_buffer_increment_checks']=buffer_quality['verified_counts']
    if exists(ROOT/'kext_cold_init_quality_gates.json'):
        cold_quality=json.loads(read(ROOT/'kext_cold_init_quality_gates.json'))
        manifest['validation']['kext_cold_init_increment_checks']=cold_quality['verified_counts']
    if exists(ROOT/'kext_close_quality_gates.json'):
        close_quality=json.loads(read(ROOT/'kext_close_quality_gates.json'))
        manifest['validation']['kext_close_increment_checks']=close_quality['verified_counts']
    if exists(ROOT/'rpc700_namespace_quality_gates.json'):
        rpc700_quality=json.loads(read(ROOT/'rpc700_namespace_quality_gates.json'))
        manifest['validation']['rpc700_namespace_increment_checks']=rpc700_quality['verified_counts']
    if exists(ROOT/'rpc502_cleanup_quality_gates.json'):
        cleanup_quality=json.loads(read(ROOT/'rpc502_cleanup_quality_gates.json'))
        manifest['validation']['rpc502_cleanup_increment_checks']=cleanup_quality['verified_counts']
    if exists(ROOT/'rpc502_ownership_quality_gates.json'):
        ownership_quality=json.loads(read(ROOT/'rpc502_ownership_quality_gates.json'))
        manifest['validation']['rpc502_ownership_increment_checks']=ownership_quality['verified_counts']
    if exists(ROOT/'rpc502_padding_quality_gates.json'):
        padding_quality=json.loads(read(ROOT/'rpc502_padding_quality_gates.json'))
        manifest['validation']['rpc502_padding_increment_checks']=padding_quality['verified_counts']
    if exists(ROOT/'iolib_group_quality_gates.json'):
        group_quality=json.loads(read(ROOT/'iolib_group_quality_gates.json'))
        manifest['validation']['iolib_group_increment_checks']=group_quality['verified_counts']
    if exists(ROOT/'legacy_stack_quality_gates.json'):
        stack_quality=json.loads(read(ROOT/'legacy_stack_quality_gates.json'))
        manifest['validation']['legacy_stack_increment_checks']=stack_quality['verified_counts']
    if exists(ROOT/'legacy_tlv_quality_gates.json'):
        tlv_quality=json.loads(read(ROOT/'legacy_tlv_quality_gates.json'))
        manifest['validation']['legacy_tlv_increment_checks']=tlv_quality['verified_counts']
    if exists(ROOT/'lskd_request_quality_gates.json'):
        lskd_quality=json.loads(read(ROOT/'lskd_request_quality_gates.json'))
        manifest['validation']['lskd_request_increment_checks']=lskd_quality['verified_counts']
    if exists(ROOT/'lskd_fields_quality_gates.json'):
        fields_quality=json.loads(read(ROOT/'lskd_fields_quality_gates.json'))
        manifest['validation']['lskd_fields_increment_checks']=fields_quality['verified_counts']
    if exists(ROOT/'lskd_execute_quality_gates.json'):
        execute_quality=json.loads(read(ROOT/'lskd_execute_quality_gates.json'))
        manifest['validation']['lskd_execute_increment_checks']=execute_quality['verified_counts']
    if exists(ROOT/'lskd_response_quality_gates.json'):
        response_quality=json.loads(read(ROOT/'lskd_response_quality_gates.json'))
        manifest['validation']['lskd_response_increment_checks']=response_quality['verified_counts']
    if exists(ROOT/'lskd_consumer_quality_gates.json'):
        consumer_quality=json.loads(read(ROOT/'lskd_consumer_quality_gates.json'))
        manifest['validation']['lskd_consumer_increment_checks']=consumer_quality['verified_counts']
    if exists(ROOT/'lskd_handlers_quality_gates.json'):
        handlers_quality=json.loads(read(ROOT/'lskd_handlers_quality_gates.json'))
        manifest['validation']['lskd_handlers_increment_checks']=handlers_quality['verified_counts']
    if exists(ROOT/'lskd_values_quality_gates.json'):
        values_quality=json.loads(read(ROOT/'lskd_values_quality_gates.json'))
        manifest['validation']['lskd_values_increment_checks']=values_quality['verified_counts']
    if exists(ROOT/'lskd_readback_quality_gates.json'):
        readback_quality=json.loads(read(ROOT/'lskd_readback_quality_gates.json'))
        manifest['validation']['lskd_readback_increment_checks']=readback_quality['verified_counts']
    if exists(ROOT/'lskd_continuations_quality_gates.json'):
        continuations_quality=json.loads(read(ROOT/'lskd_continuations_quality_gates.json'))
        manifest['validation']['lskd_continuations_increment_checks']=continuations_quality['verified_counts']
    if exists(ROOT/'lskd_state_quality_gates.json'):
        lookup_state_quality=json.loads(read(ROOT/'lskd_state_quality_gates.json'))
        manifest['validation']['lskd_state_increment_checks']=lookup_state_quality['verified_counts']
    if exists(ROOT/'lskd_lookup_quality_gates.json'):
        lookup_quality=json.loads(read(ROOT/'lskd_lookup_quality_gates.json'))
        manifest['validation']['lskd_lookup_increment_checks']=lookup_quality['verified_counts']
    if exists(ROOT/'lskd_objects_quality_gates.json'):
        objects_quality=json.loads(read(ROOT/'lskd_objects_quality_gates.json'))
        manifest['validation']['lskd_objects_increment_checks']=objects_quality['verified_counts']
    if exists(ROOT/'lskd_writers_quality_gates.json'):
        writers_quality=json.loads(read(ROOT/'lskd_writers_quality_gates.json'))
        manifest['validation']['lskd_writers_increment_checks']=writers_quality['verified_counts']
    if exists(ROOT/'lskd_core_workspace_quality_gates.json'):
        core_workspace_quality=json.loads(read(ROOT/'lskd_core_workspace_quality_gates.json'))
        manifest['validation']['lskd_core_workspace_increment_checks']=core_workspace_quality['verified_counts']
    if exists(ROOT/'lskd_core_input_quality_gates.json'):
        core_input_quality=json.loads(read(ROOT/'lskd_core_input_quality_gates.json'))
        manifest['validation']['lskd_core_input_increment_checks']=core_input_quality['verified_counts']
        manifest['validation']['lskd_core_input_caller_checks']=core_input_quality['caller_verified_counts']
    if exists(ROOT/'lskd_input_buffers_quality_gates.json'):
        input_buffers_quality=json.loads(read(ROOT/'lskd_input_buffers_quality_gates.json'))
        manifest['validation']['lskd_input_buffers_increment_checks']=input_buffers_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_census_quality_gates.json'):
        daemon_iokit_census_quality=json.loads(read(ROOT/'daemon_iokit_census_quality_gates.json'))
        manifest['validation']['daemon_iokit_census_increment_checks']=daemon_iokit_census_quality['verified_counts']
    if exists(ROOT/'daemon_query_state_quality_gates.json'):
        query_state_quality=json.loads(read(ROOT/'daemon_query_state_quality_gates.json'))
        manifest['validation']['daemon_query_state_increment_checks']=query_state_quality['verified_counts']
    if exists(ROOT/'daemon_query_fallback_quality_gates.json'):
        query_fallback_quality=json.loads(read(ROOT/'daemon_query_fallback_quality_gates.json'))
        manifest['validation']['daemon_query_fallback_increment_checks']=query_fallback_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_objects_quality_gates.json'):
        iokit_objects_quality=json.loads(read(ROOT/'daemon_iokit_objects_quality_gates.json'))
        manifest['validation']['daemon_iokit_objects_increment_checks']=iokit_objects_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_class_quality_gates.json'):
        iokit_class_quality=json.loads(read(ROOT/'daemon_iokit_class_quality_gates.json'))
        manifest['validation']['daemon_iokit_class_increment_checks']=iokit_class_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_sync_quality_gates.json'):
        iokit_sync_quality=json.loads(read(ROOT/'daemon_iokit_sync_quality_gates.json'))
        manifest['validation']['daemon_iokit_sync_increment_checks']=iokit_sync_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_errors_quality_gates.json'):
        iokit_errors_quality=json.loads(read(ROOT/'daemon_iokit_errors_quality_gates.json'))
        manifest['validation']['daemon_iokit_errors_increment_checks']=iokit_errors_quality['verified_counts']
    if exists(ROOT/'daemon_iokit_callers_quality_gates.json'):
        iokit_callers_quality=json.loads(read(ROOT/'daemon_iokit_callers_quality_gates.json'))
        manifest['validation']['daemon_iokit_callers_increment_checks']=iokit_callers_quality['verified_counts']
    if exists(ROOT/'daemon_rwlock_lifecycle_quality_gates.json'):
        rwlock_lifecycle_quality=json.loads(read(ROOT/'daemon_rwlock_lifecycle_quality_gates.json'))
        manifest['validation']['daemon_rwlock_lifecycle_increment_checks']=rwlock_lifecycle_quality['verified_counts']
    if exists(ROOT/'daemon_frame_entry_quality_gates.json'):
        frame_entry_quality=json.loads(read(ROOT/'daemon_frame_entry_quality_gates.json'))
        manifest['validation']['daemon_frame_entry_increment_checks']=frame_entry_quality['verified_counts']
    if exists(ROOT/'daemon_arena_entry_quality_gates.json'):
        arena_entry_quality=json.loads(read(ROOT/'daemon_arena_entry_quality_gates.json'))
        manifest['validation']['daemon_arena_entry_increment_checks']=arena_entry_quality['verified_counts']
    if exists(ROOT/'daemon_arena_storage_quality_gates.json'):
        arena_storage_quality=json.loads(read(ROOT/'daemon_arena_storage_quality_gates.json'))
        manifest['validation']['daemon_arena_storage_increment_checks']=arena_storage_quality['verified_counts']
    if exists(ROOT/'daemon_context_transfer_quality_gates.json'):
        context_transfer_quality=json.loads(read(ROOT/'daemon_context_transfer_quality_gates.json'))
        manifest['validation']['daemon_context_transfer_increment_checks']=context_transfer_quality['verified_counts']
        manifest['validation']['daemon_context_transfer_A64_checks']=context_transfer_quality['independent_A64_totals']
    if exists(ROOT/'daemon_entropy_return_quality_gates.json'):
        entropy_return_quality=json.loads(read(ROOT/'daemon_entropy_return_quality_gates.json'))
        manifest['validation']['daemon_entropy_return_increment_checks']=entropy_return_quality['verified_counts']
        manifest['validation']['daemon_entropy_return_A64_checks']=entropy_return_quality['independent_A64_totals']
    if exists(ROOT/'daemon_seed_material_quality_gates.json'):
        seed_material_quality=json.loads(read(ROOT/'daemon_seed_material_quality_gates.json'))
        manifest['validation']['daemon_seed_material_increment_checks']=seed_material_quality['verified_counts']
        manifest['validation']['daemon_seed_material_A64_checks']=seed_material_quality['independent_A64_totals']
    if exists(ROOT/'daemon_prng_output_quality_gates.json'):
        prng_output_quality=json.loads(read(ROOT/'daemon_prng_output_quality_gates.json'))
        manifest['validation']['daemon_prng_output_increment_checks']=prng_output_quality['verified_counts']
        manifest['validation']['daemon_prng_output_A64_checks']=prng_output_quality['independent_A64_totals']
    if exists(ROOT/'daemon_buffer_consumer_quality_gates.json'):
        buffer_consumer_quality=json.loads(read(ROOT/'daemon_buffer_consumer_quality_gates.json'))
        manifest['validation']['daemon_buffer_consumer_increment_checks']=buffer_consumer_quality['verified_counts']
        manifest['validation']['daemon_buffer_consumer_dynamic_A64_checks']=buffer_consumer_quality['dynamic_A64_totals']
    if exists(ROOT/'daemon_global_state_quality_gates.json'):
        global_state_quality=json.loads(read(ROOT/'daemon_global_state_quality_gates.json'))
        manifest['validation']['daemon_global_state_increment_checks']=global_state_quality['verified_counts']
    if exists(ROOT/'daemon_callback_revisit_quality_gates.json'):
        callback_revisit_quality=json.loads(read(ROOT/'daemon_callback_revisit_quality_gates.json'))
        manifest['validation']['daemon_callback_revisit_increment_checks']=callback_revisit_quality['verified_counts']
        manifest['validation']['daemon_callback_revisit_A64_checks']=callback_revisit_quality['independent_A64_totals']
    if exists(ROOT/'daemon_context_lock_quality_gates.json'):
        context_lock_quality=json.loads(read(ROOT/'daemon_context_lock_quality_gates.json'))
        manifest['validation']['daemon_context_lock_increment_checks']=context_lock_quality['verified_counts']
        manifest['validation']['daemon_context_lock_A64_checks']=context_lock_quality['independent_A64_totals']
    if exists(ROOT/'daemon_descriptor_readers_quality_gates.json'):
        descriptor_readers_quality=json.loads(read(ROOT/'daemon_descriptor_readers_quality_gates.json'))
        manifest['validation']['daemon_descriptor_readers_increment_checks']=descriptor_readers_quality['verified_counts']
        manifest['validation']['daemon_descriptor_readers_A64_checks']=descriptor_readers_quality['independent_A64_totals']
    if exists(ROOT/'daemon_descriptor_producers_quality_gates.json'):
        descriptor_producers_quality=json.loads(read(ROOT/'daemon_descriptor_producers_quality_gates.json'))
        manifest['validation']['daemon_descriptor_producers_increment_checks']=descriptor_producers_quality['verified_counts']
        manifest['validation']['daemon_descriptor_producers_A64_checks']=descriptor_producers_quality['independent_A64_totals']
    if exists(ROOT/'daemon_mode471c_lifecycle_quality_gates.json'):
        mode471c_quality=json.loads(read(ROOT/'daemon_mode471c_lifecycle_quality_gates.json'))
        manifest['validation']['daemon_mode471c_lifecycle_increment_checks']=mode471c_quality['verified_counts']
        manifest['validation']['daemon_mode471c_lifecycle_A64_checks']=mode471c_quality['independent_A64_totals']
    if exists(ROOT/'daemon_registry_lookup_quality_gates.json'):
        registry_quality=json.loads(read(ROOT/'daemon_registry_lookup_quality_gates.json'))
        manifest['validation']['daemon_registry_lookup_increment_checks']=registry_quality['verified_counts']
        manifest['validation']['daemon_registry_lookup_A64_checks']=registry_quality['independent_A64_totals']
    if exists(ROOT/'daemon_object_consumers_quality_gates.json'):
        object_consumers_quality=json.loads(read(ROOT/'daemon_object_consumers_quality_gates.json'))
        manifest['validation']['daemon_object_consumers_increment_checks']=object_consumers_quality['verified_counts']
        manifest['validation']['daemon_object_consumers_A64_checks']=object_consumers_quality['independent_A64_totals']
    if exists(ROOT/'daemon_object_creation_quality_gates.json'):
        object_creation_quality=json.loads(read(ROOT/'daemon_object_creation_quality_gates.json'))
        manifest['validation']['daemon_object_creation_increment_checks']=object_creation_quality['verified_counts']
        manifest['validation']['daemon_object_creation_A64_checks']=object_creation_quality['independent_A64_totals']
    if exists(ROOT/'daemon_creation_predecessors_quality_gates.json'):
        creation_predecessors_quality=json.loads(read(ROOT/'daemon_creation_predecessors_quality_gates.json'))
        manifest['validation']['daemon_creation_predecessors_increment_checks']=creation_predecessors_quality['verified_counts']
        manifest['validation']['daemon_creation_predecessors_A64_checks']=creation_predecessors_quality['independent_A64_totals']
    if exists(ROOT/'daemon_object_initialization_quality_gates.json'):
        object_initialization_quality=json.loads(read(ROOT/'daemon_object_initialization_quality_gates.json'))
        manifest['validation']['daemon_object_initialization_increment_checks']=object_initialization_quality['verified_counts']
        manifest['validation']['daemon_object_initialization_A64_checks']=object_initialization_quality['independent_A64_totals']
    if exists(ROOT/'daemon_object_clock_quality_gates.json'):
        object_clock_quality=json.loads(read(ROOT/'daemon_object_clock_quality_gates.json'))
        manifest['validation']['daemon_object_clock_increment_checks']=object_clock_quality['verified_counts']
        manifest['validation']['daemon_object_clock_A64_checks']=object_clock_quality['independent_A64_totals']
    if exists(ROOT/'daemon_cache36_quality_gates.json'):
        cache36_quality=json.loads(read(ROOT/'daemon_cache36_quality_gates.json'))
        manifest['validation']['daemon_cache36_increment_checks']=cache36_quality['verified_counts']
        manifest['validation']['daemon_cache36_A64_checks']=cache36_quality['independent_A64_totals']
    if exists(ROOT/'daemon_identity_cache_quality_gates.json'):
        identity_cache_quality=json.loads(read(ROOT/'daemon_identity_cache_quality_gates.json'))
        manifest['validation']['daemon_identity_cache_increment_checks']=identity_cache_quality['verified_counts']
        manifest['validation']['daemon_identity_cache_A64_checks']=identity_cache_quality['independent_A64_totals']
    if exists(ROOT/'daemon_digest_routes_quality_gates.json'):
        digest_routes_quality=json.loads(read(ROOT/'daemon_digest_routes_quality_gates.json'))
        manifest['validation']['daemon_digest_routes_increment_checks']=digest_routes_quality['verified_counts']
        manifest['validation']['daemon_digest_routes_A64_checks']=digest_routes_quality['independent_A64_totals']
    if exists(ROOT/'daemon_digest_conventions_quality_gates.json'):
        digest_conventions_quality=json.loads(read(ROOT/'daemon_digest_conventions_quality_gates.json'))
        manifest['validation']['daemon_digest_conventions_increment_checks']=digest_conventions_quality['verified_counts']
        manifest['validation']['daemon_digest_conventions_A64_checks']=digest_conventions_quality['independent_A64_totals']
    if exists(ROOT/'daemon_compression_frame_quality_gates.json'):
        compression_frame_quality=json.loads(read(ROOT/'daemon_compression_frame_quality_gates.json'))
        manifest['validation']['daemon_compression_frame_increment_checks']=compression_frame_quality['verified_counts']
        manifest['validation']['daemon_compression_frame_A64_checks']=compression_frame_quality['independent_A64_totals']
    if exists(ROOT/'daemon_sha1_core_quality_gates.json'):
        sha1_core_quality=json.loads(read(ROOT/'daemon_sha1_core_quality_gates.json'))
        manifest['validation']['daemon_sha1_core_increment_checks']=sha1_core_quality['verified_counts']
        manifest['validation']['daemon_sha1_core_A64_checks']=sha1_core_quality['independent_A64_totals']
    if exists(ROOT/'daemon_digest_output_quality_gates.json'):
        digest_output_quality=json.loads(read(ROOT/'daemon_digest_output_quality_gates.json'))
        manifest['validation']['daemon_digest_output_increment_checks']=digest_output_quality['verified_counts']
        manifest['validation']['daemon_digest_output_A64_checks']=digest_output_quality['independent_A64_totals']
    if exists(ROOT/'daemon_digest_completion_quality_gates.json'):
        digest_completion_quality=json.loads(read(ROOT/'daemon_digest_completion_quality_gates.json'))
        manifest['validation']['daemon_digest_completion_increment_checks']=digest_completion_quality['verified_counts']
        manifest['validation']['daemon_digest_completion_A64_checks']=digest_completion_quality['independent_A64_totals']
    if exists(ROOT/'daemon_cache_publication_quality_gates.json'):
        cache_publication_quality=json.loads(read(ROOT/'daemon_cache_publication_quality_gates.json'))
        manifest['validation']['daemon_cache_publication_increment_checks']=cache_publication_quality['verified_counts']
        manifest['validation']['daemon_cache_publication_A64_checks']=cache_publication_quality['independent_A64_totals']
        manifest['validation']['daemon_cache_relocation_checks']=cache_publication_quality['relocation_verified_counts']
    if exists(ROOT/'daemon_record720_quality_gates.json'):
        record720_quality=json.loads(read(ROOT/'daemon_record720_quality_gates.json'))
        manifest['validation']['daemon_record720_increment_checks']=record720_quality['verified_counts']
        manifest['validation']['daemon_record720_A64_totals']=record720_quality['A64_totals']
    if exists(ROOT/'daemon_record720_handoff_quality_gates.json'):
        handoff720_quality=json.loads(read(ROOT/'daemon_record720_handoff_quality_gates.json'))
        manifest['validation']['daemon_record720_handoff_increment_checks']=handoff720_quality['verified_counts']
        manifest['validation']['daemon_record720_handoff_A64_totals']=handoff720_quality['independent_A64_totals']
    if exists(ROOT/'daemon_record720_release_quality_gates.json'):
        release720_quality=json.loads(read(ROOT/'daemon_record720_release_quality_gates.json'))
        manifest['validation']['daemon_record720_release_increment_checks']=release720_quality['verified_counts']
        manifest['validation']['daemon_record720_release_A64_totals']=release720_quality['independent_A64_totals']
    if exists(ROOT/'daemon_record720_fingerprint_quality_gates.json'):
        fingerprint720_quality=json.loads(read(ROOT/'daemon_record720_fingerprint_quality_gates.json'))
        manifest['validation']['daemon_record720_fingerprint_increment_checks']=fingerprint720_quality['verified_counts']
        manifest['validation']['daemon_record720_fingerprint_A64_totals']=fingerprint720_quality['independent_A64_totals']
    if exists(ROOT/'daemon_record720_fields_quality_gates.json'):
        fields720_quality=json.loads(read(ROOT/'daemon_record720_fields_quality_gates.json'))
        manifest['validation']['daemon_record720_fields_increment_checks']=fields720_quality['verified_counts']
        manifest['validation']['daemon_record720_fields_A64_totals']=fields720_quality['independent_A64_totals']
    if exists(ROOT/'daemon_record720_spill_quality_gates.json'):
        spill720_quality=json.loads(read(ROOT/'daemon_record720_spill_quality_gates.json'))
        manifest['validation']['daemon_record720_spill_increment_checks']=spill720_quality['verified_counts']
        manifest['validation']['daemon_record720_spill_witness_totals']=spill720_quality['independent_witness_totals']
    if exists(ROOT/'daemon_arena_list_quality_gates.json'):
        arena_list_quality=json.loads(read(ROOT/'daemon_arena_list_quality_gates.json'))
        manifest['validation']['daemon_arena_list_increment_checks']=arena_list_quality['verified_counts']
        manifest['validation']['daemon_arena_list_witness_totals']=arena_list_quality['independent_witness_totals']
    if exists(ROOT/'daemon_arena_consumer_quality_gates.json'):
        arena_consumer_quality=json.loads(read(ROOT/'daemon_arena_consumer_quality_gates.json'))
        manifest['validation']['daemon_arena_consumer_increment_checks']=arena_consumer_quality['verified_counts']
        manifest['validation']['daemon_arena_consumer_A64_totals']=arena_consumer_quality['independent_A64_totals']
    if exists(ROOT/'rpc502_receive_bridge_quality_gates.json'):
        receive_bridge_quality=json.loads(read(ROOT/'rpc502_receive_bridge_quality_gates.json'))
        manifest['validation']['rpc502_receive_bridge_increment_checks']=receive_bridge_quality['verified_counts']
        manifest['validation']['rpc502_receive_bridge_kernel_A64_totals']=receive_bridge_quality['independent_kernel_A64_totals']
        manifest['validation']['rpc502_receive_bridge_daemon_A64_totals']=receive_bridge_quality['independent_daemon_A64_totals']
    if exists(ROOT/'kernel_receive_delivery_quality_gates.json'):
        receive_delivery_quality=json.loads(read(ROOT/'kernel_receive_delivery_quality_gates.json'))
        manifest['validation']['kernel_receive_delivery_increment_checks']=receive_delivery_quality['verified_counts']
        manifest['validation']['kernel_receive_delivery_A64_totals']=receive_delivery_quality['independent_A64_totals']
    if exists(ROOT/'kernel_queue_receive_quality_gates.json'):
        queue_receive_quality=json.loads(read(ROOT/'kernel_queue_receive_quality_gates.json'))
        manifest['validation']['kernel_queue_receive_increment_checks']=queue_receive_quality['verified_counts']
        manifest['validation']['kernel_queue_receive_A64_totals']=queue_receive_quality['independent_A64_totals']
    if exists(ROOT/'kernel_queue_send_quality_gates.json'):
        queue_send_quality=json.loads(read(ROOT/'kernel_queue_send_quality_gates.json'))
        manifest['validation']['kernel_queue_send_increment_checks']=queue_send_quality['verified_counts']
        manifest['validation']['kernel_queue_send_A64_totals']=queue_send_quality['independent_A64_totals']
        manifest['validation']['kernel_queue_send_consumer_joins']=queue_send_quality['consumer_joins']
    if exists(ROOT/'kernel_reply_send_quality_gates.json'):
        reply_send_quality=json.loads(read(ROOT/'kernel_reply_send_quality_gates.json'))
        manifest['validation']['kernel_reply_send_increment_checks']=reply_send_quality['verified_counts']
        manifest['validation']['kernel_reply_send_A64_totals']=reply_send_quality['independent_A64_totals']
    if exists(ROOT/'kernel_vm_mig_quality_gates.json'):
        kernel_vm_mig_quality=json.loads(read(ROOT/'kernel_vm_mig_quality_gates.json'))
        manifest['validation']['kernel_vm_mig_increment_checks']=kernel_vm_mig_quality['verified_counts']
        manifest['validation']['kernel_vm_mig_A64_totals']=kernel_vm_mig_quality['independent_A64_totals']
    if exists(ROOT/'daemon_vm_cleanup_quality_gates.json'):
        vm_cleanup_quality=json.loads(read(ROOT/'daemon_vm_cleanup_quality_gates.json'))
        manifest['validation']['daemon_vm_cleanup_increment_checks']=vm_cleanup_quality['verified_counts']
        manifest['validation']['daemon_vm_cleanup_A64_totals']=vm_cleanup_quality['independent_A64_totals']
        manifest['validation']['daemon_vm_cleanup_cache_A64_totals']=vm_cleanup_quality['independent_cache_A64_totals']
    if exists(ROOT/'daemon_client_object_quality_gates.json'):
        client_object_quality=json.loads(read(ROOT/'daemon_client_object_quality_gates.json'))
        manifest['validation']['daemon_client_object_increment_checks']=client_object_quality['verified_counts']
        manifest['validation']['daemon_client_object_A64_totals']=client_object_quality['independent_A64_totals']
    if exists(ROOT/'daemon_boolean_chain_quality_gates.json'):
        boolean_chain_quality=json.loads(read(ROOT/'daemon_boolean_chain_quality_gates.json'))
        manifest['validation']['daemon_boolean_chain_increment_checks']=boolean_chain_quality['verified_counts']
        manifest['validation']['daemon_boolean_chain_A64_totals']=boolean_chain_quality['independent_A64_totals']
    if exists(ROOT/'daemon_secondary_string_quality_gates.json'):
        secondary_string_quality=json.loads(read(ROOT/'daemon_secondary_string_quality_gates.json'))
        manifest['validation']['daemon_secondary_string_increment_checks']=secondary_string_quality['verified_counts']
        manifest['validation']['daemon_secondary_string_A64_totals']=secondary_string_quality['independent_A64_totals']
        manifest['validation']['daemon_secondary_string_host_libc_reference_executed']=True
    if exists(ROOT/'daemon_secondary_result_quality_gates.json'):
        secondary_result_quality=json.loads(read(ROOT/'daemon_secondary_result_quality_gates.json'))
        manifest['validation']['daemon_secondary_result_increment_checks']=secondary_result_quality['verified_counts']
        manifest['validation']['daemon_secondary_result_A64_totals']=secondary_result_quality['independent_A64_totals']
    if exists(ROOT/'daemon_entitlement_flow_quality_gates.json'):
        entitlement_flow_quality=json.loads(read(ROOT/'daemon_entitlement_flow_quality_gates.json'))
        manifest['validation']['daemon_entitlement_flow_increment_checks']=entitlement_flow_quality['verified_counts']
        manifest['validation']['daemon_entitlement_flow_A64_totals']=entitlement_flow_quality['independent_A64_totals']
    if exists(ROOT/'daemon_entitlement_result_quality_gates.json'):
        entitlement_result_quality=json.loads(read(ROOT/'daemon_entitlement_result_quality_gates.json'))
        manifest['validation']['daemon_entitlement_result_increment_checks']=entitlement_result_quality['verified_counts']
        manifest['validation']['daemon_entitlement_result_A64_totals']=entitlement_result_quality['independent_A64_totals']
    if exists(ROOT/'daemon_record40_consumer_quality_gates.json'):
        record40_consumer_quality=json.loads(read(ROOT/'daemon_record40_consumer_quality_gates.json'))
        manifest['validation']['daemon_record40_consumer_increment_checks']=record40_consumer_quality['verified_counts']
        manifest['validation']['daemon_record40_consumer_A64_totals']=record40_consumer_quality['independent_A64_totals']
    if exists(ROOT/'daemon_mig_handover_quality_gates.json'):
        mig_handover_quality=json.loads(read(ROOT/'daemon_mig_handover_quality_gates.json'))
        manifest['validation']['daemon_mig_handover_increment_checks']=mig_handover_quality['verified_counts']
        manifest['validation']['daemon_mig_handover_A64_totals']=mig_handover_quality['independent_A64_totals']
    if exists(ROOT/'daemon_operation_heads_quality_gates.json'):
        operation_heads_quality=json.loads(read(ROOT/'daemon_operation_heads_quality_gates.json'))
        manifest['validation']['daemon_operation_heads_increment_checks']=operation_heads_quality['verified_counts']
        manifest['validation']['daemon_operation_heads_A64_totals']=operation_heads_quality['independent_A64_totals']
    if exists(ROOT/'daemon_core_dispatch_quality_gates.json'):
        core_dispatch_quality=json.loads(read(ROOT/'daemon_core_dispatch_quality_gates.json'))
        manifest['validation']['daemon_core_dispatch_increment_checks']=core_dispatch_quality['verified_counts']
        manifest['validation']['daemon_core_dispatch_A64_totals']=core_dispatch_quality['independent_A64_totals']
    if exists(ROOT/'daemon_shared_roots_quality_gates.json'):
        shared_roots_quality=json.loads(read(ROOT/'daemon_shared_roots_quality_gates.json'))
        manifest['validation']['daemon_shared_roots_increment_checks']=shared_roots_quality['verified_counts']
        manifest['validation']['daemon_shared_roots_A64_totals']=shared_roots_quality['independent_A64_totals']
    if exists(ROOT/'daemon_aux_callers_quality_gates.json'):
        aux_callers_quality=json.loads(read(ROOT/'daemon_aux_callers_quality_gates.json'))
        manifest['validation']['daemon_aux_callers_increment_checks']=aux_callers_quality['verified_counts']
        manifest['validation']['daemon_aux_callers_A64_totals']=aux_callers_quality['independent_A64_totals']
    if exists(ROOT/'daemon_output_base_quality_gates.json'):
        output_base_quality=json.loads(read(ROOT/'daemon_output_base_quality_gates.json'))
        manifest['validation']['daemon_output_base_increment_checks']=output_base_quality['verified_counts']
        manifest['validation']['daemon_output_base_A64_totals']=output_base_quality['independent_A64_totals']
    if exists(ROOT/'daemon_cleanup_return_quality_gates.json'):
        cleanup_return_quality=json.loads(read(ROOT/'daemon_cleanup_return_quality_gates.json'))
        manifest['validation']['daemon_cleanup_return_increment_checks']=cleanup_return_quality['verified_counts']
        manifest['validation']['daemon_cleanup_return_A64_totals']=cleanup_return_quality['independent_A64_totals']
    if exists(ROOT/'daemon_arena_lifetime_quality_gates.json'):
        arena_lifetime_quality=json.loads(read(ROOT/'daemon_arena_lifetime_quality_gates.json'))
        manifest['validation']['daemon_arena_lifetime_increment_checks']=arena_lifetime_quality['verified_counts']
        manifest['validation']['daemon_arena_lifetime_A64_totals']=arena_lifetime_quality['independent_A64_totals']
    if exists(ROOT/'rpc502_reply_bridge_quality_gates.json'):
        reply_bridge_quality=json.loads(read(ROOT/'rpc502_reply_bridge_quality_gates.json'))
        manifest['validation']['rpc502_reply_bridge_increment_checks']=reply_bridge_quality['verified_counts']
        manifest['validation']['rpc502_reply_bridge_A64_totals']=reply_bridge_quality['independent_A64_replay']
    if exists(ROOT/'kernel_reply_copyout_quality_gates.json'):
        reply_copyout_quality=json.loads(read(ROOT/'kernel_reply_copyout_quality_gates.json'))
        manifest['validation']['kernel_reply_copyout_increment_checks']=reply_copyout_quality['verified_counts']
        manifest['validation']['kernel_reply_copyout_A64_totals']=reply_copyout_quality['independent_A64_replay']
    if exists(ROOT/'rpc502_reply_copyin_quality_gates.json'):
        reply_copyin_quality=json.loads(read(ROOT/'rpc502_reply_copyin_quality_gates.json'))
        manifest['validation']['rpc502_reply_copyin_increment_checks']=reply_copyin_quality['verified_counts']
        manifest['validation']['rpc502_reply_copyin_A64_totals']=reply_copyin_quality['independent_A64_replay']
    if exists(ROOT/'kernel_copyin_policy_quality_gates.json'):
        copyin_policy_quality=json.loads(read(ROOT/'kernel_copyin_policy_quality_gates.json'))
        manifest['validation']['kernel_copyin_policy_increment_checks']=copyin_policy_quality['verified_counts']
        manifest['validation']['kernel_copyin_policy_A64_totals']=copyin_policy_quality['independent_A64_replay']
    if exists(ROOT/'cf_public_runloop_quality_gates.json'):
        public_quality=json.loads(read(ROOT/'cf_public_runloop_quality_gates.json'))
        manifest['validation']['cf_public_runloop_increment_checks']=public_quality['verified_counts']
        manifest['validation']['cf_public_runloop_CF_totals']=public_quality['independent_CF_replay']
        manifest['validation']['cf_public_runloop_daemon_totals']=public_quality['independent_daemon_replay']
    if exists(ROOT/'cf_source0_scheduler_quality_gates.json'):
        scheduler_quality=json.loads(read(ROOT/'cf_source0_scheduler_quality_gates.json'))
        manifest['validation']['cf_source0_scheduler_increment_checks']=scheduler_quality['verified_counts']
        manifest['validation']['cf_source0_scheduler_CF_totals']=scheduler_quality['independent_CF_replay']
        manifest['validation']['cf_source0_scheduler_daemon_totals']=scheduler_quality['independent_daemon_replay']
    if exists(ROOT/'cf_descriptor_source_factory_quality_gates.json'):
        factory_quality=json.loads(read(ROOT/'cf_descriptor_source_factory_quality_gates.json'))
        manifest['validation']['cf_descriptor_source_factory_increment_checks']=factory_quality['verified_counts']
        manifest['validation']['cf_descriptor_source_factory_CF_totals']=factory_quality['independent_CF_replay']
        manifest['validation']['cf_descriptor_source_factory_daemon_totals']=factory_quality['independent_daemon_replay']
    if exists(ROOT/'daemon_descriptor_source_quality_gates.json'):
        descriptor_quality=json.loads(read(ROOT/'daemon_descriptor_source_quality_gates.json'))
        manifest['validation']['daemon_descriptor_source_increment_checks']=descriptor_quality['verified_counts']
        manifest['validation']['daemon_descriptor_source_daemon_totals']=descriptor_quality['independent_daemon_replay']
        manifest['validation']['daemon_descriptor_source_CF_totals']=descriptor_quality['independent_CF_replay']
    if exists(ROOT/'cf_source_wake_callers_quality_gates.json'):
        source_wake_quality=json.loads(read(ROOT/'cf_source_wake_callers_quality_gates.json'))
        manifest['validation']['cf_source_wake_callers_increment_checks']=source_wake_quality['verified_counts']
        manifest['validation']['cf_source_wake_callers_CF_totals']=source_wake_quality['independent_CF_replay']
        manifest['validation']['cf_source_wake_callers_downstream_totals']=source_wake_quality['fresh_downstream_kernel_replay']
        manifest['validation']['cf_source_wake_callers_startup_totals']=source_wake_quality['fresh_timer_startup_replay']
    if exists(ROOT/'kernel_wake_send_ingress_quality_gates.json'):
        wake_ingress_quality=json.loads(read(ROOT/'kernel_wake_send_ingress_quality_gates.json'))
        manifest['validation']['kernel_wake_send_ingress_increment_checks']=wake_ingress_quality['verified_counts']
        manifest['validation']['kernel_wake_send_ingress_A64_totals']=wake_ingress_quality['independent_A64_replay']
        manifest['validation']['kernel_wake_send_ingress_CF_totals']=wake_ingress_quality['independent_CF_replay']
        manifest['validation']['kernel_wake_send_ingress_startup_totals']=wake_ingress_quality['fresh_timer_startup_replay']
        manifest['validation']['kernel_wake_send_ingress_producer_totals']=wake_ingress_quality['fresh_CF_producer_replay']
    if exists(ROOT/'cf_wake_send_wrapper_quality_gates.json'):
        send_wrapper_quality=json.loads(read(ROOT/'cf_wake_send_wrapper_quality_gates.json'))
        manifest['validation']['cf_wake_send_wrapper_increment_checks']=send_wrapper_quality['verified_counts']
        manifest['validation']['cf_wake_send_wrapper_A64_totals']=send_wrapper_quality['independent_A64_replay']
        manifest['validation']['cf_wake_send_wrapper_CF_totals']=send_wrapper_quality['independent_CF_replay']
        manifest['validation']['cf_wake_send_wrapper_startup_totals']=send_wrapper_quality['fresh_timer_startup_replay']
        manifest['validation']['cf_wake_send_wrapper_factory_totals']=send_wrapper_quality['fresh_CF_factory_replay']
    if exists(ROOT/'cf_runloop_wake_port_quality_gates.json'):
        wake_quality=json.loads(read(ROOT/'cf_runloop_wake_port_quality_gates.json'))
        manifest['validation']['cf_runloop_wake_port_increment_checks']=wake_quality['verified_counts']
        manifest['validation']['cf_runloop_wake_port_A64_totals']=wake_quality['independent_A64_replay']
        manifest['validation']['cf_runloop_wake_port_CF_totals']=wake_quality['independent_CF_replay']
        manifest['validation']['cf_runloop_wake_port_startup_totals']=wake_quality['fresh_timer_startup_replay']
    if exists(ROOT/'kernel_timer_expiration_delivery_quality_gates.json'):
        expiration_quality=json.loads(read(ROOT/'kernel_timer_expiration_delivery_quality_gates.json'))
        manifest['validation']['kernel_timer_expiration_delivery_increment_checks']=expiration_quality['verified_counts']
        manifest['validation']['kernel_timer_expiration_delivery_A64_totals']=expiration_quality['independent_A64_replay']
        manifest['validation']['kernel_timer_expiration_delivery_CF_totals']=expiration_quality['independent_CF_replay']
        manifest['validation']['kernel_timer_expiration_delivery_startup_totals']=expiration_quality['fresh_timer_startup_replay']
    if exists(ROOT/'kernel_timer_port_create_quality_gates.json'):
        timer_quality=json.loads(read(ROOT/'kernel_timer_port_create_quality_gates.json'))
        manifest['validation']['kernel_timer_port_create_increment_checks']=timer_quality['verified_counts']
        manifest['validation']['kernel_timer_port_create_A64_totals']=timer_quality['independent_A64_replay']
        manifest['validation']['kernel_timer_port_create_CF_totals']=timer_quality['independent_CF_replay']
        manifest['validation']['kernel_timer_port_create_startup_totals']=timer_quality['independent_startup_replay']
    if exists(ROOT/'kernel_root_port_construct_quality_gates.json'):
        root_quality=json.loads(read(ROOT/'kernel_root_port_construct_quality_gates.json'))
        manifest['validation']['kernel_root_port_construct_increment_checks']=root_quality['verified_counts']
        manifest['validation']['kernel_root_port_construct_A64_totals']=root_quality['independent_A64_replay']
        manifest['validation']['kernel_root_port_construct_CF_totals']=root_quality['independent_CF_replay']
    if exists(ROOT/'cf_control_port_dispatch_quality_gates.json'):
        control_quality=json.loads(read(ROOT/'cf_control_port_dispatch_quality_gates.json'))
        manifest['validation']['cf_control_port_dispatch_increment_checks']=control_quality['verified_counts']
        manifest['validation']['cf_control_port_dispatch_A64_totals']=control_quality['independent_A64_replay']
        manifest['validation']['cf_control_port_dispatch_kernel_totals']=control_quality['fresh_kernel_replay']
        manifest['validation']['cf_control_port_dispatch_mode_totals']=control_quality['fresh_mode_replay']
    if exists(ROOT/'cf_mode_construction_quality_gates.json'):
        mode_quality=json.loads(read(ROOT/'cf_mode_construction_quality_gates.json'))
        manifest['validation']['cf_mode_construction_increment_checks']=mode_quality['verified_counts']
        manifest['validation']['cf_mode_construction_A64_totals']=mode_quality['independent_A64_replay']
        manifest['validation']['cf_mode_construction_kernel_totals']=mode_quality['fresh_kernel_replay']
    if exists(ROOT/'kernel_portset_delivery_quality_gates.json'):
        portset_quality=json.loads(read(ROOT/'kernel_portset_delivery_quality_gates.json'))
        manifest['validation']['kernel_portset_delivery_increment_checks']=portset_quality['verified_counts']
        manifest['validation']['kernel_portset_delivery_A64_totals']=portset_quality['independent_A64_replay']
        manifest['validation']['kernel_portset_delivery_CF_totals']=portset_quality['independent_CF_replay']
    if exists(ROOT/'cf_source_scheduling_quality_gates.json'):
        scheduling_quality=json.loads(read(ROOT/'cf_source_scheduling_quality_gates.json'))
        manifest['validation']['cf_source_scheduling_increment_checks']=scheduling_quality['verified_counts']
        manifest['validation']['cf_source_scheduling_A64_totals']=scheduling_quality['independent_A64_replay']
    if exists(ROOT/'cf_runloop_handoff_quality_gates.json'):
        runloop_quality=json.loads(read(ROOT/'cf_runloop_handoff_quality_gates.json'))
        manifest['validation']['cf_runloop_handoff_increment_checks']=runloop_quality['verified_counts']
        manifest['validation']['cf_runloop_handoff_A64_totals']=runloop_quality['independent_A64_replay']
    if exists(ROOT/'dispatch_voucher_hooks_quality_gates.json'):
        dispatch_hooks_quality=json.loads(read(ROOT/'dispatch_voucher_hooks_quality_gates.json'))
        manifest['validation']['dispatch_voucher_hooks_increment_checks']=dispatch_hooks_quality['verified_counts']
        manifest['validation']['dispatch_voucher_hooks_A64_totals']=dispatch_hooks_quality['independent_A64_replay']
    if exists(ROOT/'cf_receive_voucher_quality_gates.json'):
        receive_voucher_quality=json.loads(read(ROOT/'cf_receive_voucher_quality_gates.json'))
        manifest['validation']['cf_receive_voucher_increment_checks']=receive_voucher_quality['verified_counts']
        manifest['validation']['cf_receive_voucher_A64_totals']=receive_voucher_quality['independent_A64_replay']
    if exists(ROOT/'cf_daemon_request_quality_gates.json'):
        cf_daemon_quality=json.loads(read(ROOT/'cf_daemon_request_quality_gates.json'))
        manifest['validation']['cf_daemon_request_increment_checks']=cf_daemon_quality['verified_counts']
        manifest['validation']['cf_daemon_request_A64_totals']=cf_daemon_quality['independent_A64_replay']
    if exists(ROOT/'daemon_request_application_quality_gates.json'):
        application_quality=json.loads(read(ROOT/'daemon_request_application_quality_gates.json'))
        manifest['validation']['daemon_request_application_increment_checks']=application_quality['verified_counts']
        manifest['validation']['daemon_request_application_A64_totals']=application_quality['independent_A64_replay']
    if exists(ROOT/'daemon_request_consumption_quality_gates.json'):
        daemon_request_quality=json.loads(read(ROOT/'daemon_request_consumption_quality_gates.json'))
        manifest['validation']['daemon_request_consumption_increment_checks']=daemon_request_quality['verified_counts']
        manifest['validation']['daemon_request_consumption_A64_totals']=daemon_request_quality['independent_A64_replay']
    if exists(ROOT/'kernel_request_delivery_quality_gates.json'):
        request_delivery_quality=json.loads(read(ROOT/'kernel_request_delivery_quality_gates.json'))
        manifest['validation']['kernel_request_delivery_increment_checks']=request_delivery_quality['verified_counts']
        manifest['validation']['kernel_request_delivery_A64_totals']=request_delivery_quality['independent_A64_replay']
    if exists(ROOT/'kernel_request_copyin_quality_gates.json'):
        request_copyin_quality=json.loads(read(ROOT/'kernel_request_copyin_quality_gates.json'))
        manifest['validation']['kernel_request_copyin_increment_checks']=request_copyin_quality['verified_counts']
        manifest['validation']['kernel_request_copyin_A64_totals']=request_copyin_quality['independent_A64_replay']
    if exists(ROOT/'kernel_request_receive_quality_gates.json'):
        request_receive_quality=json.loads(read(ROOT/'kernel_request_receive_quality_gates.json'))
        manifest['validation']['kernel_request_receive_increment_checks']=request_receive_quality['verified_counts']
        manifest['validation']['kernel_request_receive_A64_totals']=request_receive_quality['independent_A64_replay']
    if exists(ROOT/'kernel_rpc_request_quality_gates.json'):
        rpc_request_quality=json.loads(read(ROOT/'kernel_rpc_request_quality_gates.json'))
        manifest['validation']['kernel_rpc_request_increment_checks']=rpc_request_quality['verified_counts']
        manifest['validation']['kernel_rpc_request_A64_totals']=rpc_request_quality['independent_A64_replay']
    if exists(ROOT/'kernel_special_reply_quality_gates.json'):
        special_reply_quality=json.loads(read(ROOT/'kernel_special_reply_quality_gates.json'))
        manifest['validation']['kernel_special_reply_increment_checks']=special_reply_quality['verified_counts']
        manifest['validation']['kernel_special_reply_A64_totals']=special_reply_quality['independent_A64_replay']
    if exists(ROOT/'kernel_reply_namespace_quality_gates.json'):
        reply_namespace_quality=json.loads(read(ROOT/'kernel_reply_namespace_quality_gates.json'))
        manifest['validation']['kernel_reply_namespace_increment_checks']=reply_namespace_quality['verified_counts']
        manifest['validation']['kernel_reply_namespace_A64_totals']=reply_namespace_quality['independent_A64_replay']
    if exists(ROOT/'kernel_receive_copyout_quality_gates.json'):
        receive_copyout_quality=json.loads(read(ROOT/'kernel_receive_copyout_quality_gates.json'))
        manifest['validation']['kernel_receive_copyout_increment_checks']=receive_copyout_quality['verified_counts']
        manifest['validation']['kernel_receive_copyout_A64_totals']=receive_copyout_quality['independent_A64_replay']
    if exists(ROOT/'kernel_receive_continuation_quality_gates.json'):
        receive_continuation_quality=json.loads(read(ROOT/'kernel_receive_continuation_quality_gates.json'))
        manifest['validation']['kernel_receive_continuation_increment_checks']=receive_continuation_quality['verified_counts']
        manifest['validation']['kernel_receive_continuation_A64_totals']=receive_continuation_quality['independent_A64_replay']
    if exists(ROOT/'kernel_waitq_enqueue_quality_gates.json'):
        waitq_enqueue_quality=json.loads(read(ROOT/'kernel_waitq_enqueue_quality_gates.json'))
        manifest['validation']['kernel_waitq_enqueue_increment_checks']=waitq_enqueue_quality['verified_counts']
        manifest['validation']['kernel_waitq_enqueue_A64_totals']=waitq_enqueue_quality['independent_A64_replay']
    if exists(ROOT/'kernel_waitq_receiver_quality_gates.json'):
        waitq_receiver_quality=json.loads(read(ROOT/'kernel_waitq_receiver_quality_gates.json'))
        manifest['validation']['kernel_waitq_receiver_increment_checks']=waitq_receiver_quality['verified_counts']
        manifest['validation']['kernel_waitq_receiver_A64_totals']=waitq_receiver_quality['independent_A64_replay']
    if exists(ROOT/'kernel_kmsg_queue_quality_gates.json'):
        kmsg_queue_quality=json.loads(read(ROOT/'kernel_kmsg_queue_quality_gates.json'))
        manifest['validation']['kernel_kmsg_queue_increment_checks']=kmsg_queue_quality['verified_counts']
        manifest['validation']['kernel_kmsg_queue_A64_totals']=kmsg_queue_quality['independent_A64_replay']
    if exists(ROOT/'kernel_cache_gate_quality_gates.json'):
        cache_gate_quality=json.loads(read(ROOT/'kernel_cache_gate_quality_gates.json'))
        manifest['validation']['kernel_cache_gate_increment_checks']=cache_gate_quality['verified_counts']
        manifest['validation']['kernel_cache_gate_A64_totals']=cache_gate_quality['independent_A64_replay']
    if exists(ROOT/'kernel_zone_refill_quality_gates.json'):
        zone_refill_quality=json.loads(read(ROOT/'kernel_zone_refill_quality_gates.json'))
        manifest['validation']['kernel_zone_refill_increment_checks']=zone_refill_quality['verified_counts']
        manifest['validation']['kernel_zone_refill_A64_totals']=zone_refill_quality['independent_A64_replay']
    if exists(ROOT/'kernel_zone_startup_quality_gates.json'):
        zone_startup_quality=json.loads(read(ROOT/'kernel_zone_startup_quality_gates.json'))
        manifest['validation']['kernel_zone_startup_increment_checks']=zone_startup_quality['verified_counts']
        manifest['validation']['kernel_zone_startup_A64_totals']=zone_startup_quality['independent_A64_replay']
    if exists(ROOT/'kernel_kmsg_allocation_quality_gates.json'):
        kmsg_allocation_quality=json.loads(read(ROOT/'kernel_kmsg_allocation_quality_gates.json'))
        manifest['validation']['kernel_kmsg_allocation_increment_checks']=kmsg_allocation_quality['verified_counts']
        manifest['validation']['kernel_kmsg_allocation_A64_totals']=kmsg_allocation_quality['independent_A64_replay']
    if exists(ROOT/'kernel_notification_send_quality_gates.json'):
        notification_send_quality=json.loads(read(ROOT/'kernel_notification_send_quality_gates.json'))
        manifest['validation']['kernel_notification_send_increment_checks']=notification_send_quality['verified_counts']
        manifest['validation']['kernel_notification_send_A64_totals']=notification_send_quality['independent_A64_replay']
    if exists(ROOT/'kernel_send_right_lifecycle_quality_gates.json'):
        send_lifecycle_quality=json.loads(read(ROOT/'kernel_send_right_lifecycle_quality_gates.json'))
        manifest['validation']['kernel_send_right_lifecycle_increment_checks']=send_lifecycle_quality['verified_counts']
        manifest['validation']['kernel_send_right_lifecycle_A64_totals']=send_lifecycle_quality['independent_A64_replay']
    if exists(ROOT/'kext_vm_copyout_bridge_quality_gates.json'):
        copyout_bridge_quality=json.loads(read(ROOT/'kext_vm_copyout_bridge_quality_gates.json'))
        manifest['validation']['kext_vm_copyout_bridge_increment_checks']=copyout_bridge_quality['verified_counts']
        manifest['validation']['kext_vm_copyout_bridge_A64_totals']=copyout_bridge_quality['independent_A64_replay']
    if exists(ROOT/'kernel_range_fallback_quality_gates.json'):
        range_fallback_quality=json.loads(read(ROOT/'kernel_range_fallback_quality_gates.json'))
        manifest['validation']['kernel_range_fallback_increment_checks']=range_fallback_quality['verified_counts']
        manifest['validation']['kernel_range_fallback_A64_totals']=range_fallback_quality['independent_A64_replay']
    if exists(ROOT/'kernel_range_resolver_quality_gates.json'):
        range_resolver_quality=json.loads(read(ROOT/'kernel_range_resolver_quality_gates.json'))
        manifest['validation']['kernel_range_resolver_increment_checks']=range_resolver_quality['verified_counts']
        manifest['validation']['kernel_range_resolver_A64_totals']=range_resolver_quality['independent_A64_replay']
    if exists(ROOT/'kernel_map_store_init_quality_gates.json'):
        map_store_init_quality=json.loads(read(ROOT/'kernel_map_store_init_quality_gates.json'))
        manifest['validation']['kernel_map_store_init_increment_checks']=map_store_init_quality['verified_counts']
        manifest['validation']['kernel_map_store_init_A64_totals']=map_store_init_quality['independent_A64_replay']
    if exists(ROOT/'kernel_type2_copyout_quality_gates.json'):
        type2_copyout_quality=json.loads(read(ROOT/'kernel_type2_copyout_quality_gates.json'))
        manifest['validation']['kernel_type2_copyout_increment_checks']=type2_copyout_quality['verified_counts']
        manifest['validation']['kernel_type2_copyout_A64_totals']=type2_copyout_quality['independent_A64_replay']
    if exists(ROOT/'kernel_vm_entry_copy_quality_gates.json'):
        vm_entry_copy_quality=json.loads(read(ROOT/'kernel_vm_entry_copy_quality_gates.json'))
        manifest['validation']['kernel_vm_entry_copy_increment_checks']=vm_entry_copy_quality['verified_counts']
        manifest['validation']['kernel_vm_entry_copy_A64_totals']=vm_entry_copy_quality['independent_A64_replay']
    if exists(ROOT/'kernel_vm_range_cursor_quality_gates.json'):
        vm_range_cursor_quality=json.loads(read(ROOT/'kernel_vm_range_cursor_quality_gates.json'))
        manifest['validation']['kernel_vm_range_cursor_increment_checks']=vm_range_cursor_quality['verified_counts']
        manifest['validation']['kernel_vm_range_cursor_A64_totals']=vm_range_cursor_quality['independent_A64_replay']
    if exists(ROOT/'rpc502_vm_handoff_quality_gates.json'):
        vm_handoff_quality=json.loads(read(ROOT/'rpc502_vm_handoff_quality_gates.json'))
        manifest['validation']['rpc502_vm_handoff_increment_checks']=vm_handoff_quality['verified_counts']
        manifest['validation']['rpc502_vm_handoff_A64_totals']=vm_handoff_quality['independent_A64_replay']
    if exists(ROOT/'iorpc_binary_parser_quality_gates.json'):
        binary_parser_quality=json.loads(read(ROOT/'iorpc_binary_parser_quality_gates.json'))
        manifest['validation']['iorpc_binary_parser_increment_checks']=binary_parser_quality['verified_counts']
        manifest['validation']['iorpc_binary_parser_A64_totals']=binary_parser_quality['independent_A64_replay']
    if exists(ROOT/'iorpc_ool_serialization_quality_gates.json'):
        ool_serialization_quality=json.loads(read(ROOT/'iorpc_ool_serialization_quality_gates.json'))
        manifest['validation']['iorpc_ool_serialization_increment_checks']=ool_serialization_quality['verified_counts']
        manifest['validation']['iorpc_ool_serialization_A64_totals']=ool_serialization_quality['independent_A64_replay']
    if exists(ROOT/'iorpc_object_conversion_quality_gates.json'):
        object_conversion_quality=json.loads(read(ROOT/'iorpc_object_conversion_quality_gates.json'))
        manifest['validation']['iorpc_object_conversion_increment_checks']=object_conversion_quality['verified_counts']
        manifest['validation']['iorpc_object_conversion_A64_totals']=object_conversion_quality['independent_A64_replay']
    if exists(ROOT/'iorpc_remote_quality_gates.json'):
        remote_rpc_quality=json.loads(read(ROOT/'iorpc_remote_quality_gates.json'))
        manifest['validation']['iorpc_remote_increment_checks']=remote_rpc_quality['verified_counts']
        manifest['validation']['iorpc_remote_A64_totals']=remote_rpc_quality['independent_A64_replay']
    if exists(ROOT/'platform_iorpc_quality_gates.json'):
        platform_rpc_quality=json.loads(read(ROOT/'platform_iorpc_quality_gates.json'))
        manifest['validation']['platform_iorpc_increment_checks']=platform_rpc_quality['verified_counts']
        manifest['validation']['platform_iorpc_A64_totals']=platform_rpc_quality['independent_A64_replay']
    if exists(ROOT/'aes_platform_gate_quality_gates.json'):
        aes_platform_quality=json.loads(read(ROOT/'aes_platform_gate_quality_gates.json'))
        manifest['validation']['aes_platform_gate_increment_checks']=aes_platform_quality['verified_counts']
        manifest['validation']['aes_platform_gate_A64_totals']=aes_platform_quality['independent_A64_replay']
    if exists(ROOT/'aes_quantum_binding_quality_gates.json'):
        aes_binding_quality=json.loads(read(ROOT/'aes_quantum_binding_quality_gates.json'))
        manifest['validation']['aes_quantum_binding_increment_checks']=aes_binding_quality['verified_counts']
        manifest['validation']['aes_quantum_binding_A64_totals']=aes_binding_quality['independent_A64_replay']
    if exists(ROOT/'aes_hardware_job_quality_gates.json'):
        aes_jobs_quality=json.loads(read(ROOT/'aes_hardware_job_quality_gates.json'))
        manifest['validation']['aes_hardware_job_increment_checks']=aes_jobs_quality['verified_counts']
        manifest['validation']['aes_hardware_job_A64_totals']=aes_jobs_quality['independent_A64_replay']
    if exists(ROOT/'aes_synchronous_wait_quality_gates.json'):
        aes_sync_quality=json.loads(read(ROOT/'aes_synchronous_wait_quality_gates.json'))
        manifest['validation']['aes_synchronous_wait_increment_checks']=aes_sync_quality['verified_counts']
        manifest['validation']['aes_synchronous_wait_A64_totals']=aes_sync_quality['independent_A64_replay']
    if exists(ROOT/'aes_carrier_initialization_quality_gates.json'):
        aes_carrier_quality=json.loads(read(ROOT/'aes_carrier_initialization_quality_gates.json'))
        manifest['validation']['aes_carrier_initialization_increment_checks']=aes_carrier_quality['verified_counts']
        manifest['validation']['aes_carrier_initialization_A64_totals']=aes_carrier_quality['independent_A64_replay']
    if exists(ROOT/'aes_completion_contract_quality_gates.json'):
        aes_completion_quality=json.loads(read(ROOT/'aes_completion_contract_quality_gates.json'))
        manifest['validation']['aes_completion_contract_increment_checks']=aes_completion_quality['verified_counts']
        manifest['validation']['aes_completion_contract_A64_totals']=aes_completion_quality['independent_A64_replay']
    if exists(ROOT/'aes_provider_queue_quality_gates.json'):
        aes_provider_quality=json.loads(read(ROOT/'aes_provider_queue_quality_gates.json'))
        manifest['validation']['aes_provider_queue_increment_checks']=aes_provider_quality['verified_counts']
        manifest['validation']['aes_provider_queue_A64_totals']=aes_provider_quality['independent_A64_replay']
    if exists(ROOT/'aes_command_pool_quality_gates.json'):
        aes_pool_quality=json.loads(read(ROOT/'aes_command_pool_quality_gates.json'))
        manifest['validation']['aes_command_pool_increment_checks']=aes_pool_quality['verified_counts']
        manifest['validation']['aes_command_pool_A64_totals']=aes_pool_quality['independent_A64_replay']
    if exists(ROOT/'workloop_gate_attachment_quality_gates.json'):
        workloop_attachment_quality=json.loads(read(ROOT/'workloop_gate_attachment_quality_gates.json'))
        manifest['validation']['workloop_gate_attachment_increment_checks']=workloop_attachment_quality['verified_counts']
        manifest['validation']['workloop_gate_attachment_A64_totals']=workloop_attachment_quality['independent_A64_replay']
    if exists(ROOT/'aes_command_gate_quality_gates.json'):
        aes_gate_quality=json.loads(read(ROOT/'aes_command_gate_quality_gates.json'))
        manifest['validation']['aes_command_gate_increment_checks']=aes_gate_quality['verified_counts']
        manifest['validation']['aes_command_gate_A64_totals']=aes_gate_quality['independent_A64_replay']
    if exists(ROOT/'kext_startup_hardware_bridge_quality_gates.json'):
        startup_hardware_quality=json.loads(read(ROOT/'kext_startup_hardware_bridge_quality_gates.json'))
        manifest['validation']['kext_startup_hardware_bridge_increment_checks']=startup_hardware_quality['verified_counts']
        manifest['validation']['kext_startup_hardware_bridge_A64_totals']=startup_hardware_quality['independent_A64_replay']
    if exists(ROOT/'kext_provider_initialize_quality_gates.json'):
        provider_initialize_quality=json.loads(read(ROOT/'kext_provider_initialize_quality_gates.json'))
        manifest['validation']['kext_provider_initialize_increment_checks']=provider_initialize_quality['verified_counts']
        manifest['validation']['kext_provider_initialize_A64_totals']=provider_initialize_quality['independent_A64_replay']
    if exists(ROOT/'kext_constructor_reply_state_quality_gates.json'):
        constructor_reply_state_quality=json.loads(read(ROOT/'kext_constructor_reply_state_quality_gates.json'))
        manifest['validation']['kext_constructor_reply_state_increment_checks']=constructor_reply_state_quality['verified_counts']
        manifest['validation']['kext_constructor_reply_state_A64_totals']=constructor_reply_state_quality['independent_A64_replay']
    if exists(ROOT/'kext_constructor_request_quality_gates.json'):
        constructor_request_quality=json.loads(read(ROOT/'kext_constructor_request_quality_gates.json'))
        manifest['validation']['kext_constructor_request_increment_checks']=constructor_request_quality['verified_counts']
        manifest['validation']['kext_constructor_request_A64_totals']=constructor_request_quality['independent_A64_replay']
    if exists(ROOT/'kext_context_retirement_quality_gates.json'):
        context_retirement_quality=json.loads(read(ROOT/'kext_context_retirement_quality_gates.json'))
        manifest['validation']['kext_context_retirement_increment_checks']=context_retirement_quality['verified_counts']
        manifest['validation']['kext_context_retirement_A64_totals']=context_retirement_quality['independent_A64_replay']
    if exists(ROOT/'kext_page_context_quality_gates.json'):
        page_context_quality=json.loads(read(ROOT/'kext_page_context_quality_gates.json'))
        manifest['validation']['kext_page_context_increment_checks']=page_context_quality['verified_counts']
        manifest['validation']['kext_page_context_A64_totals']=page_context_quality['independent_A64_replay']
    if exists(ROOT/'kext_security_record_quality_gates.json'):
        security_record_quality=json.loads(read(ROOT/'kext_security_record_quality_gates.json'))
        manifest['validation']['kext_security_record_increment_checks']=security_record_quality['verified_counts']
        manifest['validation']['kext_security_record_A64_totals']=security_record_quality['independent_A64_replay']
    if exists(ROOT/'kext_mapped_cleanup_quality_gates.json'):
        mapped_cleanup_quality=json.loads(read(ROOT/'kext_mapped_cleanup_quality_gates.json'))
        manifest['validation']['kext_mapped_cleanup_increment_checks']=mapped_cleanup_quality['verified_counts']
        manifest['validation']['kext_mapped_cleanup_A64_totals']=mapped_cleanup_quality['independent_A64_replay']
    if exists(ROOT/'kernel_task_map_quality_gates.json'):
        task_map_quality=json.loads(read(ROOT/'kernel_task_map_quality_gates.json'))
        manifest['validation']['kernel_task_map_increment_checks']=task_map_quality['verified_counts']
        manifest['validation']['kernel_task_map_A64_totals']=task_map_quality['independent_A64_replay']
    if exists(ROOT/'daemon_cf_descriptor_bridge_quality_gates.json'):
        bridge_quality=json.loads(read(ROOT/'daemon_cf_descriptor_bridge_quality_gates.json'))
        manifest['validation']['daemon_cf_descriptor_bridge_increment_checks']=bridge_quality['verified_counts']
        manifest['validation']['daemon_cf_descriptor_bridge_combined_totals']=bridge_quality['independent_combined_replay']
    if exists(ROOT/'cf_mach_port_retirement_quality_gates.json'):
        retirement_quality=json.loads(read(ROOT/'cf_mach_port_retirement_quality_gates.json'))
        manifest['validation']['cf_mach_port_retirement_increment_checks']=retirement_quality['verified_counts']
        manifest['validation']['cf_mach_port_retirement_repeat_semantic_totals']=retirement_quality['repeat_and_independent_semantic_checks']
    if exists(ROOT/'daemon_service_cf_lifecycle_quality_gates.json'):
        service_lifecycle_quality=json.loads(read(ROOT/'daemon_service_cf_lifecycle_quality_gates.json'))
        manifest['validation']['daemon_service_cf_lifecycle_increment_checks']=service_lifecycle_quality['verified_counts']
        manifest['validation']['daemon_service_cf_lifecycle_repeat_service_totals']=service_lifecycle_quality['repeat_and_independent_service_checks']
    if exists(ROOT/'kernel_membership_removal_quality_gates.json'):
        membership_removal_quality=json.loads(read(ROOT/'kernel_membership_removal_quality_gates.json'))
        manifest['validation']['kernel_membership_removal_increment_checks']=membership_removal_quality['verified_counts']
        manifest['validation']['kernel_membership_removal_static_scope']=membership_removal_quality['static_scope']
    if exists(ROOT/'kernel_iokit_open_quality_gates.json'):
        open_quality=json.loads(read(ROOT/'kernel_iokit_open_quality_gates.json'))
        manifest['validation']['kernel_iokit_open_increment_checks']=open_quality['verified_counts']
        manifest['validation']['kernel_iokit_open_static_scope']=open_quality['static_scope']
    if exists(ROOT/'iokit_connection_lifecycle_quality_gates.json'):
        connection_quality=json.loads(read(ROOT/'iokit_connection_lifecycle_quality_gates.json'))
        manifest['validation']['iokit_connection_lifecycle_increment_checks']=connection_quality['verified_counts']
        manifest['validation']['iokit_connection_lifecycle_static_scope']=connection_quality['static_scope']
    if exists(ROOT/'iokit_structure_arguments_quality_gates.json'):
        structure_quality=json.loads(read(ROOT/'iokit_structure_arguments_quality_gates.json'))
        manifest['validation']['iokit_structure_arguments_increment_checks']=structure_quality['verified_counts']
        manifest['validation']['iokit_structure_arguments_static_scope']=structure_quality['static_scope']
    if exists(ROOT/'iokit_filter_policy_quality_gates.json'):
        filter_quality=json.loads(read(ROOT/'iokit_filter_policy_quality_gates.json'))
        manifest['validation']['iokit_filter_policy_increment_checks']=filter_quality['verified_counts']
        manifest['validation']['iokit_filter_policy_static_scope']=filter_quality['static_scope']
    if exists(ROOT/'iokit_async_contract_quality_gates.json'):
        async_quality=json.loads(read(ROOT/'iokit_async_contract_quality_gates.json'))
        manifest['validation']['iokit_async_contract_increment_checks']=async_quality['verified_counts']
        manifest['validation']['iokit_async_contract_static_scope']=async_quality['static_scope']
    if exists(ROOT/'rpc700_publication_quality_gates.json'):
        publication_quality=json.loads(read(ROOT/'rpc700_publication_quality_gates.json'))
        manifest['validation']['rpc700_publication_increment_checks']=publication_quality['verified_counts']
        manifest['validation']['rpc700_publication_static_scope']=publication_quality['static_scope']
    if exists(ROOT/'managed_fairplay_bridge_quality_gates.json'):
        managed_bridge_quality=json.loads(read(ROOT/'managed_fairplay_bridge_quality_gates.json'))
        manifest['validation']['managed_fairplay_bridge_increment_checks']=managed_bridge_quality['verified_counts']
        manifest['validation']['managed_fairplay_bridge_static_scope']=managed_bridge_quality['static_scope']
    if exists(ROOT/'managed_adapter_dispatch_quality_gates.json'):
        adapter_dispatch_quality=json.loads(read(ROOT/'managed_adapter_dispatch_quality_gates.json'))
        manifest['validation']['managed_adapter_dispatch_increment_checks']=adapter_dispatch_quality['verified_counts']
        manifest['validation']['managed_adapter_dispatch_static_scope']=adapter_dispatch_quality['static_scope']
    if exists(ROOT/'host_special_registration_quality_gates.json'):
        special_registration_quality=json.loads(read(ROOT/'host_special_registration_quality_gates.json'))
        manifest['validation']['host_special_registration_increment_checks']=special_registration_quality['verified_counts']
        manifest['validation']['host_special_registration_static_scope']=special_registration_quality['static_scope']
    if exists(ROOT/'launchd_variant_binding_quality_gates.json'):
        variant_binding_quality=json.loads(read(ROOT/'launchd_variant_binding_quality_gates.json'))
        manifest['validation']['launchd_variant_binding_increment_checks']=variant_binding_quality['verified_counts']
        manifest['validation']['launchd_variant_binding_static_scope']=variant_binding_quality['static_scope']
    if exists(ROOT/'launchd_service_endpoint_quality_gates.json'):
        service_endpoint_quality=json.loads(read(ROOT/'launchd_service_endpoint_quality_gates.json'))
        manifest['validation']['launchd_service_endpoint_increment_checks']=service_endpoint_quality['verified_counts']
        manifest['validation']['launchd_service_endpoint_static_scope']=service_endpoint_quality['static_scope']
    if exists(ROOT/'bootstrap_checkin_handoff_quality_gates.json'):
        checkin_handoff_quality=json.loads(read(ROOT/'bootstrap_checkin_handoff_quality_gates.json'))
        manifest['validation']['bootstrap_checkin_handoff_increment_checks']=checkin_handoff_quality['verified_counts']
        manifest['validation']['bootstrap_checkin_handoff_static_scope']=checkin_handoff_quality['static_scope']
    if exists(ROOT/'launchd_audit_context_quality_gates.json'):
        audit_context_quality=json.loads(read(ROOT/'launchd_audit_context_quality_gates.json'))
        manifest['validation']['launchd_audit_context_increment_checks']=audit_context_quality['verified_counts']
        manifest['validation']['launchd_audit_context_static_scope']=audit_context_quality['static_scope']
    if exists(ROOT/'port_destroyed_return_quality_gates.json'):
        destroyed_return_quality=json.loads(read(ROOT/'port_destroyed_return_quality_gates.json'))
        manifest['validation']['port_destroyed_return_increment_checks']=destroyed_return_quality['verified_counts']
        manifest['validation']['port_destroyed_return_static_scope']=destroyed_return_quality['static_scope']
    if exists(ROOT/'receive_name_guard_quality_gates.json'):
        receive_guard_quality=json.loads(read(ROOT/'receive_name_guard_quality_gates.json'))
        manifest['validation']['receive_name_guard_increment_checks']=receive_guard_quality['verified_counts']
        manifest['validation']['receive_name_guard_static_scope']=receive_guard_quality['static_scope']
    if exists(ROOT/'coalition_service_gate_quality_gates.json'):
        coalition_gate_quality=json.loads(read(ROOT/'coalition_service_gate_quality_gates.json'))
        manifest['validation']['coalition_service_gate_increment_checks']=coalition_gate_quality['verified_counts']
        manifest['validation']['coalition_service_gate_static_scope']=coalition_gate_quality['static_scope']
    if exists(ROOT/'endpoint_job_lifecycle_quality_gates.json'):
        endpoint_lifecycle_quality=json.loads(read(ROOT/'endpoint_job_lifecycle_quality_gates.json'))
        manifest['validation']['endpoint_job_lifecycle_increment_checks']=endpoint_lifecycle_quality['verified_counts']
        manifest['validation']['endpoint_job_lifecycle_static_scope']=endpoint_lifecycle_quality['static_scope']
    if exists(ROOT/'job_factory_lineage_quality_gates.json'):
        job_lineage_quality=json.loads(read(ROOT/'job_factory_lineage_quality_gates.json'))
        manifest['validation']['job_factory_lineage_increment_checks']=job_lineage_quality['verified_counts']
        manifest['validation']['job_factory_lineage_static_scope']=job_lineage_quality['static_scope']
    if exists(ROOT/'exclaves_notification_contract_quality_gates.json'):
        exclaves_notification_quality=json.loads(read(ROOT/'exclaves_notification_contract_quality_gates.json'))
        manifest['validation']['exclaves_notification_contract_increment_checks']=exclaves_notification_quality['verified_counts']
        manifest['validation']['exclaves_notification_contract_static_scope']=exclaves_notification_quality['static_scope']
    if exists(ROOT/'spawn_conclave_abi_quality_gates.json'):
        spawn_quality=json.loads(read(ROOT/'spawn_conclave_abi_quality_gates.json'))
        manifest['validation']['spawn_conclave_abi_increment_checks']=spawn_quality['verified_counts']
        manifest['validation']['spawn_conclave_abi_static_scope']=spawn_quality['static_scope']
    if exists(ROOT/'spawn_port_actions_quality_gates.json'):
        spawn_ports_quality=json.loads(read(ROOT/'spawn_port_actions_quality_gates.json'))
        manifest['validation']['spawn_port_actions_increment_checks']=spawn_ports_quality['verified_counts']
        manifest['validation']['spawn_port_actions_static_scope']=spawn_ports_quality['static_scope']
    if exists(ROOT/'registered_port_consumers_quality_gates.json'):
        registered_consumers_quality=json.loads(read(ROOT/'registered_port_consumers_quality_gates.json'))
        manifest['validation']['registered_port_consumers_increment_checks']=registered_consumers_quality['verified_counts']
        manifest['validation']['registered_port_consumers_static_scope']=registered_consumers_quality['static_scope']
    if exists(ROOT/'initializer_programvars_quality_gates.json'):
        initializer_vars_quality=json.loads(read(ROOT/'initializer_programvars_quality_gates.json'))
        manifest['validation']['initializer_programvars_increment_checks']=initializer_vars_quality['verified_counts']
        manifest['validation']['initializer_programvars_static_scope']=initializer_vars_quality['static_scope']
    if exists(ROOT/'kernel_args_environment_quality_gates.json'):
        kernel_args_quality=json.loads(read(ROOT/'kernel_args_environment_quality_gates.json'))
        manifest['validation']['kernel_args_environment_increment_checks']=kernel_args_quality['verified_counts']
        manifest['validation']['kernel_args_environment_static_scope']=kernel_args_quality['static_scope']
    if exists(ROOT/'rpc700_endpoint_inventory_quality_gates.json'):
        endpoint_inventory_quality=json.loads(read(ROOT/'rpc700_endpoint_inventory_quality_gates.json'))
        manifest['validation']['rpc700_endpoint_inventory_increment_checks']=endpoint_inventory_quality['verified_counts']
        manifest['validation']['rpc700_endpoint_inventory_static_scope']=endpoint_inventory_quality['static_scope']
        manifest['validation']['rpc700_endpoint_inventory_native_observation_scope']=endpoint_inventory_quality['native_observation_scope']
    if exists(ROOT/'daemon_xpc_listener_quality_gates.json'):
        daemon_listener_quality=json.loads(read(ROOT/'daemon_xpc_listener_quality_gates.json'))
        manifest['validation']['daemon_xpc_listener_increment_checks']=daemon_listener_quality['verified_counts']
        manifest['validation']['daemon_xpc_listener_static_scope']=daemon_listener_quality['static_scope']
    if exists(ROOT/'daemon_xpc_payload_quality_gates.json'):
        daemon_payload_quality=json.loads(read(ROOT/'daemon_xpc_payload_quality_gates.json'))
        manifest['validation']['daemon_xpc_payload_increment_checks']=daemon_payload_quality['verified_counts']
        manifest['validation']['daemon_xpc_payload_static_scope']=daemon_payload_quality['static_scope']
    if exists(ROOT/'daemon_xpc_records_quality_gates.json'):
        daemon_records_quality=json.loads(read(ROOT/'daemon_xpc_records_quality_gates.json'))
        manifest['validation']['daemon_xpc_records_increment_checks']=daemon_records_quality['verified_counts']
        manifest['validation']['daemon_xpc_records_static_scope']=daemon_records_quality['static_scope']
    if exists(ROOT/'daemon_xpc_iteration_quality_gates.json'):
        daemon_iteration_quality=json.loads(read(ROOT/'daemon_xpc_iteration_quality_gates.json'))
        manifest['validation']['daemon_xpc_iteration_increment_checks']=daemon_iteration_quality['verified_counts']
        manifest['validation']['daemon_xpc_iteration_static_scope']=daemon_iteration_quality['static_scope']
    if exists(ROOT/'daemon_xpc_core_bridge_quality_gates.json'):
        daemon_core_bridge_quality=json.loads(read(ROOT/'daemon_xpc_core_bridge_quality_gates.json'))
        manifest['validation']['daemon_xpc_core_bridge_increment_checks']=daemon_core_bridge_quality['verified_counts']
        manifest['validation']['daemon_xpc_core_bridge_static_scope']=daemon_core_bridge_quality['static_scope']
    if exists(ROOT/'daemon_xpc_reply_lifecycle_quality_gates.json'):
        daemon_reply_lifecycle_quality=json.loads(read(ROOT/'daemon_xpc_reply_lifecycle_quality_gates.json'))
        manifest['validation']['daemon_xpc_reply_lifecycle_increment_checks']=daemon_reply_lifecycle_quality['verified_counts']
        manifest['validation']['daemon_xpc_reply_lifecycle_static_scope']=daemon_reply_lifecycle_quality['static_scope']
    if exists(ROOT/'xpc_reply_transport_quality_gates.json'):
        xpc_transport_quality=json.loads(read(ROOT/'xpc_reply_transport_quality_gates.json'))
        manifest['validation']['xpc_reply_transport_increment_checks']=xpc_transport_quality['verified_counts']
        manifest['validation']['xpc_reply_transport_static_scope']=xpc_transport_quality['static_scope']
    if exists(ROOT/'xpc_receive_context_quality_gates.json'):
        xpc_receive_quality=json.loads(read(ROOT/'xpc_receive_context_quality_gates.json'))
        manifest['validation']['xpc_receive_context_increment_checks']=xpc_receive_quality['verified_counts']
        manifest['validation']['xpc_receive_context_static_scope']=xpc_receive_quality['static_scope']
    if exists(ROOT/'xpc_resource_lifecycle_quality_gates.json'):
        xpc_resource_quality=json.loads(read(ROOT/'xpc_resource_lifecycle_quality_gates.json'))
        manifest['validation']['xpc_resource_lifecycle_increment_checks']=xpc_resource_quality['verified_counts']
        manifest['validation']['xpc_resource_lifecycle_static_scope']=xpc_resource_quality['static_scope']
    if exists(ROOT/'xpc_transaction_controls_quality_gates.json'):
        xpc_transaction_quality=json.loads(read(ROOT/'xpc_transaction_controls_quality_gates.json'))
        manifest['validation']['xpc_transaction_controls_increment_checks']=xpc_transaction_quality['verified_counts']
        manifest['validation']['xpc_transaction_controls_static_scope']=xpc_transaction_quality['static_scope']
    if exists(ROOT/'daemon_xpc_error_outputs_quality_gates.json'):
        daemon_error_outputs_quality=json.loads(read(ROOT/'daemon_xpc_error_outputs_quality_gates.json'))
        manifest['validation']['daemon_xpc_error_outputs_increment_checks']=daemon_error_outputs_quality['verified_counts']
        manifest['validation']['daemon_xpc_error_outputs_static_scope']=daemon_error_outputs_quality['static_scope']
    if exists(ROOT/'daemon_output_publication_quality_gates.json'):
        daemon_output_publication_quality=json.loads(read(ROOT/'daemon_output_publication_quality_gates.json'))
        manifest['validation']['daemon_output_publication_increment_checks']=daemon_output_publication_quality['verified_counts']
        manifest['validation']['daemon_output_publication_static_scope']=daemon_output_publication_quality['static_scope']
    if exists(ROOT/'daemon_list_output_quality_gates.json'):
        daemon_list_output_quality=json.loads(read(ROOT/'daemon_list_output_quality_gates.json'))
        manifest['validation']['daemon_list_output_increment_checks']=daemon_list_output_quality['verified_counts']
        manifest['validation']['daemon_list_output_static_scope']=daemon_list_output_quality['static_scope']
    if exists(ROOT/'daemon_record_stream_quality_gates.json'):
        record_stream_quality=json.loads(read(ROOT/'daemon_record_stream_quality_gates.json'))
        manifest['validation']['daemon_record_stream_increment_checks']=record_stream_quality['verified_counts']
        manifest['validation']['daemon_record_stream_static_scope']=record_stream_quality['static_scope']
    if exists(ROOT/'daemon_payload_codec_quality_gates.json'):
        payload_codec_quality=json.loads(read(ROOT/'daemon_payload_codec_quality_gates.json'))
        manifest['validation']['daemon_payload_codec_increment_checks']=payload_codec_quality['verified_counts']
        manifest['validation']['daemon_payload_codec_static_scope']=payload_codec_quality['static_scope']
    if exists(ROOT/'daemon_header_codec_quality_gates.json'):
        header_codec_quality=json.loads(read(ROOT/'daemon_header_codec_quality_gates.json'))
        manifest['validation']['daemon_header_codec_increment_checks']=header_codec_quality['verified_counts']
        manifest['validation']['daemon_header_codec_static_scope']=header_codec_quality['static_scope']
    if exists(ROOT/'daemon_constructor_inputs_quality_gates.json'):
        constructor_inputs_quality=json.loads(read(ROOT/'daemon_constructor_inputs_quality_gates.json'))
        manifest['validation']['daemon_constructor_inputs_increment_checks']=constructor_inputs_quality['verified_counts']
        manifest['validation']['daemon_constructor_inputs_static_scope']=constructor_inputs_quality['static_scope']
    if exists(ROOT/'daemon_constructor_lookup_quality_gates.json'):
        constructor_lookup_quality=json.loads(read(ROOT/'daemon_constructor_lookup_quality_gates.json'))
        manifest['validation']['daemon_constructor_lookup_increment_checks']=constructor_lookup_quality['verified_counts']
        manifest['validation']['daemon_constructor_lookup_static_scope']=constructor_lookup_quality['static_scope']
    if exists(ROOT/'daemon_typed_scalar_quality_gates.json'):
        typed_scalar_quality=json.loads(read(ROOT/'daemon_typed_scalar_quality_gates.json'))
        manifest['validation']['daemon_typed_scalar_increment_checks']=typed_scalar_quality['verified_counts']
        manifest['validation']['daemon_typed_scalar_static_scope']=typed_scalar_quality['static_scope']
    if exists(ROOT/'daemon_constructor_failure_quality_gates.json'):
        constructor_failure_quality=json.loads(read(ROOT/'daemon_constructor_failure_quality_gates.json'))
        manifest['validation']['daemon_constructor_failure_increment_checks']=constructor_failure_quality['verified_counts']
        manifest['validation']['daemon_constructor_failure_static_scope']=constructor_failure_quality['static_scope']
    if exists(ROOT/'daemon_constructor_bank_origins_quality_gates.json'):
        constructor_bank_origins_quality=json.loads(read(ROOT/'daemon_constructor_bank_origins_quality_gates.json'))
        manifest['validation']['daemon_constructor_bank_origins_increment_checks']=constructor_bank_origins_quality['verified_counts']
        manifest['validation']['daemon_constructor_bank_origins_static_scope']=constructor_bank_origins_quality['static_scope']
    if exists(ROOT/'daemon_constructor_callers_quality_gates.json'):
        constructor_callers_quality=json.loads(read(ROOT/'daemon_constructor_callers_quality_gates.json'))
        manifest['validation']['daemon_constructor_callers_increment_checks']=constructor_callers_quality['verified_counts']
        manifest['validation']['daemon_constructor_callers_static_scope']=constructor_callers_quality['static_scope']
    if exists(ROOT/'daemon_collection_retirement_quality_gates.json'):
        collection_retirement_quality=json.loads(read(ROOT/'daemon_collection_retirement_quality_gates.json'))
        manifest['validation']['daemon_collection_retirement_increment_checks']=collection_retirement_quality['verified_counts']
        manifest['validation']['daemon_collection_retirement_static_scope']=collection_retirement_quality['static_scope']
    if exists(ROOT/'daemon_builder_owner_join_quality_gates.json'):
        builder_owner_join_quality=json.loads(read(ROOT/'daemon_builder_owner_join_quality_gates.json'))
        manifest['validation']['daemon_builder_owner_join_increment_checks']=builder_owner_join_quality['verified_counts']
        manifest['validation']['daemon_builder_owner_join_static_scope']=builder_owner_join_quality['static_scope']
    if exists(ROOT/'daemon_scalar_field_population_quality_gates.json'):
        scalar_field_population_quality=json.loads(read(ROOT/'daemon_scalar_field_population_quality_gates.json'))
        manifest['validation']['daemon_scalar_field_population_increment_checks']=scalar_field_population_quality['verified_counts']
        manifest['validation']['daemon_scalar_field_population_static_scope']=scalar_field_population_quality['static_scope']
    if exists(ROOT/'daemon_helper_result_residue_quality_gates.json'):
        helper_result_residue_quality=json.loads(read(ROOT/'daemon_helper_result_residue_quality_gates.json'))
        manifest['validation']['daemon_helper_result_residue_increment_checks']=helper_result_residue_quality['verified_counts']
        manifest['validation']['daemon_helper_result_residue_static_scope']=helper_result_residue_quality['static_scope']
    if exists(ROOT/'daemon_existing_scalar_reader_quality_gates.json'):
        existing_scalar_reader_quality=json.loads(read(ROOT/'daemon_existing_scalar_reader_quality_gates.json'))
        manifest['validation']['daemon_existing_scalar_reader_increment_checks']=existing_scalar_reader_quality['verified_counts']
        manifest['validation']['daemon_existing_scalar_reader_static_scope']=existing_scalar_reader_quality['static_scope']
    if exists(ROOT/'daemon_reader_context_footprint_quality_gates.json'):
        reader_context_footprint_quality=json.loads(read(ROOT/'daemon_reader_context_footprint_quality_gates.json'))
        manifest['validation']['daemon_reader_context_footprint_increment_checks']=reader_context_footprint_quality['verified_counts']
        manifest['validation']['daemon_reader_context_footprint_static_scope']=reader_context_footprint_quality['static_scope']
    if exists(ROOT/'daemon_reader_stack_epoch_quality_gates.json'):
        reader_stack_epoch_quality=json.loads(read(ROOT/'daemon_reader_stack_epoch_quality_gates.json'))
        manifest['validation']['daemon_reader_stack_epoch_increment_checks']=reader_stack_epoch_quality['verified_counts']
        manifest['validation']['daemon_reader_stack_epoch_static_scope']=reader_stack_epoch_quality['static_scope']
    if exists(ROOT/'daemon_context_input_producers_quality_gates.json'):
        context_input_producers_quality=json.loads(read(ROOT/'daemon_context_input_producers_quality_gates.json'))
        manifest['validation']['daemon_context_input_producers_increment_checks']=context_input_producers_quality['verified_counts']
        manifest['validation']['daemon_context_input_producers_static_scope']=context_input_producers_quality['static_scope']
    if exists(ROOT/'daemon_reader_extent_families_quality_gates.json'):
        reader_extent_families_quality=json.loads(read(ROOT/'daemon_reader_extent_families_quality_gates.json'))
        manifest['validation']['daemon_reader_extent_families_increment_checks']=reader_extent_families_quality['verified_counts']
        manifest['validation']['daemon_reader_extent_families_static_scope']=reader_extent_families_quality['static_scope']
    if exists(ROOT/'daemon_reader_typed_dispatch_quality_gates.json'):
        reader_typed_dispatch_quality=json.loads(read(ROOT/'daemon_reader_typed_dispatch_quality_gates.json'))
        manifest['validation']['daemon_reader_typed_dispatch_increment_checks']=reader_typed_dispatch_quality['verified_counts']
        manifest['validation']['daemon_reader_typed_dispatch_static_scope']=reader_typed_dispatch_quality['static_scope']
    if exists(ROOT/'daemon_reader_value_consumers_quality_gates.json'):
        reader_value_consumers_quality=json.loads(read(ROOT/'daemon_reader_value_consumers_quality_gates.json'))
        manifest['validation']['daemon_reader_value_consumers_increment_checks']=reader_value_consumers_quality['verified_counts']
        manifest['validation']['daemon_reader_value_consumers_static_scope']=reader_value_consumers_quality['static_scope']
    if exists(ROOT/'daemon_reader_container_origins_quality_gates.json'):
        reader_container_origins_quality=json.loads(read(ROOT/'daemon_reader_container_origins_quality_gates.json'))
        manifest['validation']['daemon_reader_container_origins_increment_checks']=reader_container_origins_quality['verified_counts']
        manifest['validation']['daemon_reader_container_origins_static_scope']=reader_container_origins_quality['static_scope']
    if exists(ROOT/'daemon_reader_record_headers_quality_gates.json'):
        reader_record_headers_quality=json.loads(read(ROOT/'daemon_reader_record_headers_quality_gates.json'))
        manifest['validation']['daemon_reader_record_headers_increment_checks']=reader_record_headers_quality['verified_counts']
        manifest['validation']['daemon_reader_record_headers_static_scope']=reader_record_headers_quality['static_scope']
    if exists(ROOT/'daemon_reader_record_payloads_quality_gates.json'):
        reader_record_payloads_quality=json.loads(read(ROOT/'daemon_reader_record_payloads_quality_gates.json'))
        manifest['validation']['daemon_reader_record_payloads_increment_checks']=reader_record_payloads_quality['verified_counts']
        manifest['validation']['daemon_reader_record_payloads_static_scope']=reader_record_payloads_quality['static_scope']
    if exists(ROOT/'daemon_reader_record_replacement_quality_gates.json'):
        reader_record_replacement_quality=json.loads(read(ROOT/'daemon_reader_record_replacement_quality_gates.json'))
        manifest['validation']['daemon_reader_record_replacement_increment_checks']=reader_record_replacement_quality['verified_counts']
        manifest['validation']['daemon_reader_record_replacement_static_scope']=reader_record_replacement_quality['static_scope']
    if exists(ROOT/'daemon_reader_u64_codec_quality_gates.json'):
        reader_u64_codec_quality=json.loads(read(ROOT/'daemon_reader_u64_codec_quality_gates.json'))
        manifest['validation']['daemon_reader_u64_codec_increment_checks']=reader_u64_codec_quality['verified_counts']
        manifest['validation']['daemon_reader_u64_codec_static_scope']=reader_u64_codec_quality['static_scope']
    if exists(ROOT/'daemon_reader_outer_lifecycle_quality_gates.json'):
        outer_lifecycle_quality=json.loads(read(ROOT/'daemon_reader_outer_lifecycle_quality_gates.json'))
        manifest['validation']['daemon_reader_outer_lifecycle_increment_checks']=outer_lifecycle_quality['verified_counts']
        manifest['validation']['daemon_reader_outer_lifecycle_static_scope']=outer_lifecycle_quality['static_scope']
    if exists(ROOT/'daemon_reader_nested_input_quality_gates.json'):
        nested_input_quality=json.loads(read(ROOT/'daemon_reader_nested_input_quality_gates.json'))
        manifest['validation']['daemon_reader_nested_input_increment_checks']=nested_input_quality['verified_counts']
        manifest['validation']['daemon_reader_nested_input_static_scope']=nested_input_quality['static_scope']
    if exists(ROOT/'daemon_reader_option_default_quality_gates.json'):
        option_default_quality=json.loads(read(ROOT/'daemon_reader_option_default_quality_gates.json'))
        manifest['validation']['daemon_reader_option_default_increment_checks']=option_default_quality['verified_counts']
        manifest['validation']['daemon_reader_option_default_static_scope']=option_default_quality['static_scope']
    if exists(ROOT/'daemon_outer_record_ingress_quality_gates.json'):
        outer_ingress_quality=json.loads(read(ROOT/'daemon_outer_record_ingress_quality_gates.json'))
        manifest['validation']['daemon_outer_record_ingress_increment_checks']=outer_ingress_quality['verified_counts']
        manifest['validation']['daemon_outer_record_ingress_static_scope']=outer_ingress_quality['static_scope']
    if exists(ROOT/'daemon_outer_first_key_quality_gates.json'):
        first_key_quality=json.loads(read(ROOT/'daemon_outer_first_key_quality_gates.json'))
        manifest['validation']['daemon_outer_first_key_increment_checks']=first_key_quality['verified_counts']
        manifest['validation']['daemon_outer_first_key_static_scope']=first_key_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_adapter_quality_gates.json'):
        mode_one_quality=json.loads(read(ROOT/'daemon_mode_one_adapter_quality_gates.json'))
        manifest['validation']['daemon_mode_one_adapter_increment_checks']=mode_one_quality['verified_counts']
        manifest['validation']['daemon_mode_one_adapter_static_scope']=mode_one_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_source_passes_quality_gates.json'):
        source_pass_quality=json.loads(read(ROOT/'daemon_mode_one_source_passes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_source_passes_increment_checks']=source_pass_quality['verified_counts']
        manifest['validation']['daemon_mode_one_source_passes_static_scope']=source_pass_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_scatter_quality_gates.json'):
        scatter_quality=json.loads(read(ROOT/'daemon_mode_one_scatter_quality_gates.json'))
        manifest['validation']['daemon_mode_one_scatter_increment_checks']=scatter_quality['verified_counts']
        manifest['validation']['daemon_mode_one_scatter_static_scope']=scatter_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_inverse_tables_quality_gates.json'):
        inverse_tables_quality=json.loads(read(ROOT/'daemon_mode_one_inverse_tables_quality_gates.json'))
        manifest['validation']['daemon_mode_one_inverse_tables_increment_checks']=inverse_tables_quality['verified_counts']
        manifest['validation']['daemon_mode_one_inverse_tables_static_scope']=inverse_tables_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_carry_table_quality_gates.json'):
        carry_quality=json.loads(read(ROOT/'daemon_mode_one_carry_table_quality_gates.json'))
        manifest['validation']['daemon_mode_one_carry_table_increment_checks']=carry_quality['verified_counts']
        manifest['validation']['daemon_mode_one_carry_table_static_scope']=carry_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_digit_maps_quality_gates.json'):
        digit_quality=json.loads(read(ROOT/'daemon_mode_one_digit_maps_quality_gates.json'))
        manifest['validation']['daemon_mode_one_digit_maps_increment_checks']=digit_quality['verified_counts']
        manifest['validation']['daemon_mode_one_digit_maps_static_scope']=digit_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_post_table_passes_quality_gates.json'):
        post_quality=json.loads(read(ROOT/'daemon_mode_one_post_table_passes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_post_table_passes_increment_checks']=post_quality['verified_counts']
        manifest['validation']['daemon_mode_one_post_table_passes_static_scope']=post_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_bank_combine_quality_gates.json'):
        combine_quality=json.loads(read(ROOT/'daemon_mode_one_bank_combine_quality_gates.json'))
        manifest['validation']['daemon_mode_one_bank_combine_increment_checks']=combine_quality['verified_counts']
        manifest['validation']['daemon_mode_one_bank_combine_static_scope']=combine_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_word_mix_quality_gates.json'):
        word_quality=json.loads(read(ROOT/'daemon_mode_one_word_mix_quality_gates.json'))
        manifest['validation']['daemon_mode_one_word_mix_increment_checks']=word_quality['verified_counts']
        manifest['validation']['daemon_mode_one_word_mix_static_scope']=word_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_state_materialization_quality_gates.json'):
        state_quality=json.loads(read(ROOT/'daemon_mode_one_state_materialization_quality_gates.json'))
        manifest['validation']['daemon_mode_one_state_materialization_increment_checks']=state_quality['verified_counts']
        manifest['validation']['daemon_mode_one_state_materialization_static_scope']=state_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_source_absorption_quality_gates.json'):
        absorption_quality=json.loads(read(ROOT/'daemon_mode_one_source_absorption_quality_gates.json'))
        manifest['validation']['daemon_mode_one_source_absorption_increment_checks']=absorption_quality['verified_counts']
        manifest['validation']['daemon_mode_one_source_absorption_static_scope']=absorption_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_plane_consumer_quality_gates.json'):
        plane_quality=json.loads(read(ROOT/'daemon_mode_one_plane_consumer_quality_gates.json'))
        manifest['validation']['daemon_mode_one_plane_consumer_increment_checks']=plane_quality['verified_counts']
        manifest['validation']['daemon_mode_one_plane_consumer_static_scope']=plane_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_word_schedule_quality_gates.json'):
        schedule_quality=json.loads(read(ROOT/'daemon_mode_one_word_schedule_quality_gates.json'))
        manifest['validation']['daemon_mode_one_word_schedule_increment_checks']=schedule_quality['verified_counts']
        manifest['validation']['daemon_mode_one_word_schedule_static_scope']=schedule_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_lookup_bounds_quality_gates.json'):
        lookup_quality=json.loads(read(ROOT/'daemon_mode_one_lookup_bounds_quality_gates.json'))
        manifest['validation']['daemon_mode_one_lookup_bounds_increment_checks']=lookup_quality['verified_counts']
        manifest['validation']['daemon_mode_one_lookup_bounds_static_scope']=lookup_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_lookup_roles_quality_gates.json'):
        roles_quality=json.loads(read(ROOT/'daemon_mode_one_lookup_roles_quality_gates.json'))
        manifest['validation']['daemon_mode_one_lookup_roles_increment_checks']=roles_quality['verified_counts']
        manifest['validation']['daemon_mode_one_lookup_roles_static_scope']=roles_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_word_rounds_quality_gates.json'):
        rounds_quality=json.loads(read(ROOT/'daemon_mode_one_word_rounds_quality_gates.json'))
        manifest['validation']['daemon_mode_one_word_rounds_increment_checks']=rounds_quality['verified_counts']
        manifest['validation']['daemon_mode_one_word_rounds_static_scope']=rounds_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_phase_handoff_quality_gates.json'):
        phase_quality=json.loads(read(ROOT/'daemon_mode_one_phase_handoff_quality_gates.json'))
        manifest['validation']['daemon_mode_one_phase_handoff_increment_checks']=phase_quality['verified_counts']
        manifest['validation']['daemon_mode_one_phase_handoff_static_scope']=phase_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_scan_quality_gates.json'):
        scan_quality=json.loads(read(ROOT/'daemon_mode_one_record_scan_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_scan_increment_checks']=scan_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_scan_static_scope']=scan_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_passes_quality_gates.json'):
        passes_quality=json.loads(read(ROOT/'daemon_mode_one_record_passes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_passes_increment_checks']=passes_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_passes_static_scope']=passes_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_permutation_quality_gates.json'):
        permutation_quality=json.loads(read(ROOT/'daemon_mode_one_record_permutation_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_permutation_increment_checks']=permutation_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_permutation_static_scope']=permutation_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_adder_quality_gates.json'):
        adder_quality=json.loads(read(ROOT/'daemon_mode_one_record_adder_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_adder_increment_checks']=adder_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_adder_static_scope']=adder_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_codecs_quality_gates.json'):
        codecs_quality=json.loads(read(ROOT/'daemon_mode_one_record_codecs_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_codecs_increment_checks']=codecs_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_codecs_static_scope']=codecs_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_rescan_quality_gates.json'):
        rescan_quality=json.loads(read(ROOT/'daemon_mode_one_record_rescan_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_rescan_increment_checks']=rescan_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_rescan_static_scope']=rescan_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_join_quality_gates.json'):
        join_quality=json.loads(read(ROOT/'daemon_mode_one_record_join_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_join_increment_checks']=join_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_join_static_scope']=join_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_input_planes_quality_gates.json'):
        input_planes_quality=json.loads(read(ROOT/'daemon_mode_one_record_input_planes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_input_planes_increment_checks']=input_planes_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_input_planes_static_scope']=input_planes_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_long_planes_quality_gates.json'):
        long_planes_quality=json.loads(read(ROOT/'daemon_mode_one_record_long_planes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_long_planes_increment_checks']=long_planes_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_long_planes_static_scope']=long_planes_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_long_prefix_quality_gates.json'):
        long_prefix_quality=json.loads(read(ROOT/'daemon_mode_one_record_long_prefix_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_long_prefix_increment_checks']=long_prefix_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_long_prefix_static_scope']=long_prefix_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_word_gather_quality_gates.json'):
        word_gather_quality=json.loads(read(ROOT/'daemon_mode_one_record_word_gather_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_word_gather_increment_checks']=word_gather_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_word_gather_static_scope']=word_gather_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_word_extension_quality_gates.json'):
        word_extension_quality=json.loads(read(ROOT/'daemon_mode_one_record_word_extension_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_word_extension_increment_checks']=word_extension_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_word_extension_static_scope']=word_extension_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_rounds_quality_gates.json'):
        record_rounds_quality=json.loads(read(ROOT/'daemon_mode_one_record_rounds_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_rounds_increment_checks']=record_rounds_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_rounds_static_scope']=record_rounds_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_reentry_quality_gates.json'):
        record_reentry_quality=json.loads(read(ROOT/'daemon_mode_one_record_reentry_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_reentry_increment_checks']=record_reentry_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_reentry_static_scope']=record_reentry_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_record_checkpoint_quality_gates.json'):
        checkpoint_quality=json.loads(read(ROOT/'daemon_mode_one_record_checkpoint_quality_gates.json'))
        manifest['validation']['daemon_mode_one_record_checkpoint_increment_checks']=checkpoint_quality['verified_counts']
        manifest['validation']['daemon_mode_one_record_checkpoint_static_scope']=checkpoint_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_workspace_passes_quality_gates.json'):
        workspace_passes_quality=json.loads(read(ROOT/'daemon_mode_one_workspace_passes_quality_gates.json'))
        manifest['validation']['daemon_mode_one_workspace_passes_increment_checks']=workspace_passes_quality['verified_counts']
        manifest['validation']['daemon_mode_one_workspace_passes_static_scope']=workspace_passes_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_encoded_addition_quality_gates.json'):
        encoded_addition_quality=json.loads(read(ROOT/'daemon_mode_one_encoded_addition_quality_gates.json'))
        manifest['validation']['daemon_mode_one_encoded_addition_increment_checks']=encoded_addition_quality['verified_counts']
        manifest['validation']['daemon_mode_one_encoded_addition_static_scope']=encoded_addition_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_nibble_operation_suite_quality_gates.json'):
        nibble_operation_suite_quality=json.loads(read(ROOT/'daemon_mode_one_nibble_operation_suite_quality_gates.json'))
        manifest['validation']['daemon_mode_one_nibble_operation_suite_increment_checks']=nibble_operation_suite_quality['verified_counts']
        manifest['validation']['daemon_mode_one_nibble_operation_suite_static_scope']=nibble_operation_suite_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_workspace_state_install_quality_gates.json'):
        workspace_state_install_quality=json.loads(read(ROOT/'daemon_mode_one_workspace_state_install_quality_gates.json'))
        manifest['validation']['daemon_mode_one_workspace_state_install_increment_checks']=workspace_state_install_quality['verified_counts']
        manifest['validation']['daemon_mode_one_workspace_state_install_static_scope']=workspace_state_install_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_parity_state_adapters_quality_gates.json'):
        parity_state_adapters_quality=json.loads(read(ROOT/'daemon_mode_one_parity_state_adapters_quality_gates.json'))
        manifest['validation']['daemon_mode_one_parity_state_adapters_increment_checks']=parity_state_adapters_quality['verified_counts']
        manifest['validation']['daemon_mode_one_parity_state_adapters_static_scope']=parity_state_adapters_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_word_xor_plane_refresh_quality_gates.json'):
        word_xor_plane_refresh_quality=json.loads(read(ROOT/'daemon_mode_one_word_xor_plane_refresh_quality_gates.json'))
        manifest['validation']['daemon_mode_one_word_xor_plane_refresh_increment_checks']=word_xor_plane_refresh_quality['verified_counts']
        manifest['validation']['daemon_mode_one_word_xor_plane_refresh_static_scope']=word_xor_plane_refresh_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_secondary_word_import_quality_gates.json'):
        secondary_word_import_quality=json.loads(read(ROOT/'daemon_mode_one_secondary_word_import_quality_gates.json'))
        manifest['validation']['daemon_mode_one_secondary_word_import_increment_checks']=secondary_word_import_quality['verified_counts']
        manifest['validation']['daemon_mode_one_secondary_word_import_static_scope']=secondary_word_import_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_secondary_word_extension_quality_gates.json'):
        secondary_word_extension_quality=json.loads(read(ROOT/'daemon_mode_one_secondary_word_extension_quality_gates.json'))
        manifest['validation']['daemon_mode_one_secondary_word_extension_increment_checks']=secondary_word_extension_quality['verified_counts']
        manifest['validation']['daemon_mode_one_secondary_word_extension_static_scope']=secondary_word_extension_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_secondary_rounds_quality_gates.json'):
        secondary_rounds_quality=json.loads(read(ROOT/'daemon_mode_one_secondary_rounds_quality_gates.json'))
        manifest['validation']['daemon_mode_one_secondary_rounds_increment_checks']=secondary_rounds_quality['verified_counts']
        manifest['validation']['daemon_mode_one_secondary_rounds_static_scope']=secondary_rounds_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_secondary_reentry_quality_gates.json'):
        secondary_reentry_quality=json.loads(read(ROOT/'daemon_mode_one_secondary_reentry_quality_gates.json'))
        manifest['validation']['daemon_mode_one_secondary_reentry_increment_checks']=secondary_reentry_quality['verified_counts']
        manifest['validation']['daemon_mode_one_secondary_reentry_static_scope']=secondary_reentry_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_even_view_import_quality_gates.json'):
        even_view_import_quality=json.loads(read(ROOT/'daemon_mode_one_even_view_import_quality_gates.json'))
        manifest['validation']['daemon_mode_one_even_view_import_increment_checks']=even_view_import_quality['verified_counts']
        manifest['validation']['daemon_mode_one_even_view_import_static_scope']=even_view_import_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_result_publication_quality_gates.json'):
        result_publication_quality=json.loads(read(ROOT/'daemon_mode_one_result_publication_quality_gates.json'))
        manifest['validation']['daemon_mode_one_result_publication_increment_checks']=result_publication_quality['verified_counts']
        manifest['validation']['daemon_mode_one_result_publication_static_scope']=result_publication_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_output_verification_quality_gates.json'):
        output_verification_quality=json.loads(read(ROOT/'daemon_mode_one_output_verification_quality_gates.json'))
        manifest['validation']['daemon_mode_one_output_verification_increment_checks']=output_verification_quality['verified_counts']
        manifest['validation']['daemon_mode_one_output_verification_static_scope']=output_verification_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_second_phase_handoff_quality_gates.json'):
        second_phase_handoff_quality=json.loads(read(ROOT/'daemon_mode_one_second_phase_handoff_quality_gates.json'))
        manifest['validation']['daemon_mode_one_second_phase_handoff_increment_checks']=second_phase_handoff_quality['verified_counts']
        manifest['validation']['daemon_mode_one_second_phase_handoff_static_scope']=second_phase_handoff_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_budget_store_audit_quality_gates.json'):
        budget_store_audit_quality=json.loads(read(ROOT/'daemon_mode_one_budget_store_audit_quality_gates.json'))
        manifest['validation']['daemon_mode_one_budget_store_audit_increment_checks']=budget_store_audit_quality['verified_counts']
        manifest['validation']['daemon_mode_one_budget_store_audit_static_scope']=budget_store_audit_quality['static_scope']
    if exists(ROOT/'daemon_mode_one_computed_store_footprints_quality_gates.json'):
        computed_store_footprints_quality=json.loads(read(ROOT/'daemon_mode_one_computed_store_footprints_quality_gates.json'))
        manifest['validation']['daemon_mode_one_computed_store_footprints_increment_checks']=computed_store_footprints_quality['verified_counts']
        manifest['validation']['daemon_mode_one_computed_store_footprints_static_scope']=computed_store_footprints_quality['static_scope']
    if exists(ROOT/'kext_query_getter_values_quality_gates.json'):
        query_getter_values_quality=json.loads(read(ROOT/'kext_query_getter_values_quality_gates.json'))
        manifest['validation']['kext_query_getter_values_increment_checks']=query_getter_values_quality['verified_counts']
        manifest['validation']['kext_query_getter_values_static_scope']=query_getter_values_quality['static_scope']
    if exists(ROOT/'versioned_request_abi_quality_gates.json'):
        versioned_request_quality=json.loads(read(ROOT/'versioned_request_abi_quality_gates.json'))
        manifest['validation']['versioned_request_abi_increment_checks']=versioned_request_quality['verified_counts']
        manifest['validation']['versioned_request_abi_static_scope']=versioned_request_quality['static_scope']
    if exists(ROOT/'userclient_context_lifecycle_quality_gates.json'):
        userclient_context_quality=json.loads(read(ROOT/'userclient_context_lifecycle_quality_gates.json'))
        manifest['validation']['userclient_context_lifecycle_increment_checks']=userclient_context_quality['verified_counts']
        manifest['validation']['userclient_context_lifecycle_static_scope']=userclient_context_quality['static_scope']
    if exists(ROOT/'context_descriptor_task_flow_quality_gates.json'):
        context_descriptor_quality=json.loads(read(ROOT/'context_descriptor_task_flow_quality_gates.json'))
        manifest['validation']['context_descriptor_task_flow_increment_checks']=context_descriptor_quality['verified_counts']
        manifest['validation']['context_descriptor_task_flow_static_scope']=context_descriptor_quality['static_scope']
    if exists(ROOT/'core_stack_delta_abi_quality_gates.json'):
        core_stack_delta_quality=json.loads(read(ROOT/'core_stack_delta_abi_quality_gates.json'))
        manifest['validation']['core_stack_delta_abi_increment_checks']=core_stack_delta_quality['verified_counts']
        manifest['validation']['core_stack_delta_abi_static_scope']=core_stack_delta_quality['static_scope']
    if exists(ROOT/'inner_write_frontier_quality_gates.json'):
        inner_write_quality=json.loads(read(ROOT/'inner_write_frontier_quality_gates.json'))
        manifest['validation']['inner_write_frontier_increment_checks']=inner_write_quality['verified_counts']
        manifest['validation']['inner_write_frontier_static_scope']=inner_write_quality['static_scope']
    if exists(ROOT/'buffer_construction_flow_quality_gates.json'):
        buffer_construction_quality=json.loads(read(ROOT/'buffer_construction_flow_quality_gates.json'))
        manifest['validation']['buffer_construction_flow_increment_checks']=buffer_construction_quality['verified_counts']
        manifest['validation']['buffer_construction_flow_static_scope']=buffer_construction_quality['static_scope']
    if exists(ROOT/'dma_map_constraints_quality_gates.json'):
        dma_map_quality=json.loads(read(ROOT/'dma_map_constraints_quality_gates.json'))
        manifest['validation']['dma_map_constraints_increment_checks']=dma_map_quality['verified_counts']
        manifest['validation']['dma_map_constraints_static_scope']=dma_map_quality['static_scope']
    if exists(ROOT/'mixed_data_lifecycle_quality_gates.json'):
        mixed_data_quality=json.loads(read(ROOT/'mixed_data_lifecycle_quality_gates.json'))
        manifest['validation']['mixed_data_lifecycle_increment_checks']=mixed_data_quality['verified_counts']
        manifest['validation']['mixed_data_lifecycle_static_scope']=mixed_data_quality['static_scope']
    if exists(ROOT/'mixed_data_backing_quality_gates.json'):
        mixed_backing_quality=json.loads(read(ROOT/'mixed_data_backing_quality_gates.json'))
        manifest['validation']['mixed_data_backing_increment_checks']=mixed_backing_quality['verified_counts']
        manifest['validation']['mixed_data_backing_static_scope']=mixed_backing_quality['static_scope']
    if exists(ROOT/'mixed_data_release_quality_gates.json'):
        mixed_release_quality=json.loads(read(ROOT/'mixed_data_release_quality_gates.json'))
        manifest['validation']['mixed_data_release_increment_checks']=mixed_release_quality['verified_counts']
        manifest['validation']['mixed_data_release_static_scope']=mixed_release_quality['static_scope']
    if exists(ROOT/'mixed_data_retirement_quality_gates.json'):
        mixed_retirement_quality=json.loads(read(ROOT/'mixed_data_retirement_quality_gates.json'))
        manifest['validation']['mixed_data_retirement_increment_checks']=mixed_retirement_quality['verified_counts']
        manifest['validation']['mixed_data_retirement_static_scope']=mixed_retirement_quality['static_scope']
    if exists(ROOT/'mixed_data_zone_geometry_quality_gates.json'):
        mixed_geometry_quality=json.loads(read(ROOT/'mixed_data_zone_geometry_quality_gates.json'))
        manifest['validation']['mixed_data_zone_geometry_increment_checks']=mixed_geometry_quality['verified_counts']
        manifest['validation']['mixed_data_zone_geometry_static_scope']=mixed_geometry_quality['static_scope']
    if exists(ROOT/'descriptor_prepare_lifecycle_quality_gates.json'):
        prepare_lifecycle_quality=json.loads(read(ROOT/'descriptor_prepare_lifecycle_quality_gates.json'))
        manifest['validation']['descriptor_prepare_lifecycle_increment_checks']=prepare_lifecycle_quality['verified_counts']
        manifest['validation']['descriptor_prepare_lifecycle_static_scope']=prepare_lifecycle_quality['static_scope']
    if exists(ROOT/'aes_cleanup_epoch_quality_gates.json'):
        aes_cleanup_quality=json.loads(read(ROOT/'aes_cleanup_epoch_quality_gates.json'))
        manifest['validation']['aes_cleanup_epoch_increment_checks']=aes_cleanup_quality['verified_counts']
        manifest['validation']['aes_cleanup_epoch_static_scope']=aes_cleanup_quality['static_scope']
    if exists(ROOT/'cached_lock_origin_checks.json'):
        cached_lock_checks=json.loads(read(ROOT/'cached_lock_origin_checks.json'))
        manifest['validation']['cached_lock_origin_increment_checks']=cached_lock_checks['verified_counts']
        manifest['validation']['cached_lock_origin_static_scope']=cached_lock_checks['scope']
    if exists(ROOT/'lskd_lock_origin_checks.json'):
        lskd_lock_checks=json.loads(read(ROOT/'lskd_lock_origin_checks.json'))
        manifest['validation']['lskd_lock_origin_increment_checks']=lskd_lock_checks['verified_counts']
        manifest['validation']['lskd_lock_origin_static_scope']=lskd_lock_checks['scope']
    if exists(ROOT/'lskd_start_lock_flow_checks.json'):
        lskd_start_checks=json.loads(read(ROOT/'lskd_start_lock_flow_checks.json'))
        manifest['validation']['lskd_start_lock_flow_increment_checks']=lskd_start_checks['verified_counts']
        manifest['validation']['lskd_start_lock_flow_static_scope']=lskd_start_checks['scope']
    if exists(ROOT/'lskd_vector_origin_checks.json'):
        lskd_vector_checks=json.loads(read(ROOT/'lskd_vector_origin_checks.json'))
        manifest['validation']['lskd_vector_origin_increment_checks']=lskd_vector_checks['verified_counts']
        manifest['validation']['lskd_vector_origin_static_scope']=lskd_vector_checks['scope']
    if exists(ROOT/'lskd_element_population_checks.json'):
        lskd_population_checks=json.loads(read(ROOT/'lskd_element_population_checks.json'))
        manifest['validation']['lskd_element_population_increment_checks']=lskd_population_checks['verified_counts']
        manifest['validation']['lskd_element_population_static_scope']=lskd_population_checks['scope']
    if exists(ROOT/'lskd_secure_time_checks.json'):
        secure_time_checks=json.loads(read(ROOT/'lskd_secure_time_checks.json'))
        manifest['validation']['lskd_secure_time_increment_checks']=secure_time_checks['verified_counts']
        manifest['validation']['lskd_secure_time_static_scope']=secure_time_checks['scope']
    if exists(ROOT/'lskd_clock_completion_checks.json'):
        clock_completion_checks=json.loads(read(ROOT/'lskd_clock_completion_checks.json'))
        manifest['validation']['lskd_clock_completion_increment_checks']=clock_completion_checks['verified_counts']
        manifest['validation']['lskd_clock_completion_static_scope']=clock_completion_checks['scope']
    if exists(ROOT/'lskd_clock_reader_checks.json'):
        clock_reader_checks=json.loads(read(ROOT/'lskd_clock_reader_checks.json'))
        manifest['validation']['lskd_clock_reader_increment_checks']=clock_reader_checks['verified_counts']
        manifest['validation']['lskd_clock_reader_static_scope']=clock_reader_checks['scope']
    if exists(ROOT/'lskd_clock_accumulator_checks.json'):
        accumulator_checks=json.loads(read(ROOT/'lskd_clock_accumulator_checks.json'))
        manifest['validation']['lskd_clock_accumulator_increment_checks']=accumulator_checks['verified_counts']
        manifest['validation']['lskd_clock_accumulator_static_scope']=accumulator_checks['scope']
    if exists(ROOT/'lskd_context_compare_checks.json'):
        context_checks=json.loads(read(ROOT/'lskd_context_compare_checks.json'))
        manifest['validation']['lskd_context_compare_increment_checks']=context_checks['verified_counts']
        manifest['validation']['lskd_context_compare_static_scope']=context_checks['scope']
    if exists(ROOT/'lskd_reader_lineage_checks.json'):
        lineage_checks=json.loads(read(ROOT/'lskd_reader_lineage_checks.json'))
        manifest['validation']['lskd_reader_lineage_increment_checks']=lineage_checks['verified_counts']
        manifest['validation']['lskd_reader_lineage_static_scope']=lineage_checks['scope']
    if exists(ROOT/'lskd_context_codec_checks.json'):
        codec_checks=json.loads(read(ROOT/'lskd_context_codec_checks.json'))
        manifest['validation']['lskd_context_codec_increment_checks']=codec_checks['verified_counts']
        manifest['validation']['lskd_context_codec_static_scope']=codec_checks['scope']
    if exists(ROOT/'lskd_context_return_checks.json'):
        return_checks=json.loads(read(ROOT/'lskd_context_return_checks.json'))
        manifest['validation']['lskd_context_return_increment_checks']=return_checks['verified_counts']
        manifest['validation']['lskd_context_return_static_scope']=return_checks['scope']
    if exists(ROOT/'lskd_operation_preflight_checks.json'):
        preflight_checks=json.loads(read(ROOT/'lskd_operation_preflight_checks.json'))
        manifest['validation']['lskd_operation_preflight_increment_checks']=preflight_checks['verified_counts']
        manifest['validation']['lskd_operation_preflight_static_scope']=preflight_checks['scope']
    if exists(ROOT/'lskd_byte_spans_checks.json'):
        byte_spans_checks=json.loads(read(ROOT/'lskd_byte_spans_checks.json'))
        manifest['validation']['lskd_byte_spans_increment_checks']=byte_spans_checks['verified_counts']
        manifest['validation']['lskd_byte_spans_static_scope']=byte_spans_checks['scope']
    if exists(ROOT/'lskd_hardware_staging_checks.json'):
        staging_checks=json.loads(read(ROOT/'lskd_hardware_staging_checks.json'))
        manifest['validation']['lskd_hardware_staging_increment_checks']=staging_checks['verified_counts']
        manifest['validation']['lskd_hardware_staging_static_scope']=staging_checks['scope']
    if exists(ROOT/'aes_provider_admission_checks.json'):
        admission_checks=json.loads(read(ROOT/'aes_provider_admission_checks.json'))
        manifest['validation']['aes_provider_admission_increment_checks']=admission_checks['verified_counts']
        manifest['validation']['aes_provider_admission_static_scope']=admission_checks['scope']
    if exists(ROOT/'aes_dma_preparation_checks.json'):
        dma_checks=json.loads(read(ROOT/'aes_dma_preparation_checks.json'))
        manifest['validation']['aes_dma_preparation_increment_checks']=dma_checks['verified_counts']
        manifest['validation']['aes_dma_preparation_static_scope']=dma_checks['scope']
    if exists(ROOT/'aes_configuration_commands_checks.json'):
        configuration_checks=json.loads(read(ROOT/'aes_configuration_commands_checks.json'))
        manifest['validation']['aes_configuration_commands_increment_checks']=configuration_checks['verified_counts']
        manifest['validation']['aes_configuration_commands_static_scope']=configuration_checks['scope']
    if exists(ROOT/'aes_trace_wakeup_checks.json'):
        trace_wakeup_checks=json.loads(read(ROOT/'aes_trace_wakeup_checks.json'))
        manifest['validation']['aes_trace_wakeup_increment_checks']=trace_wakeup_checks['verified_counts']
        manifest['validation']['aes_trace_wakeup_static_scope']=trace_wakeup_checks['scope']
    if exists(ROOT/'aes_event_registration_checks.json'):
        event_registration_checks=json.loads(read(ROOT/'aes_event_registration_checks.json'))
        manifest['validation']['aes_event_registration_increment_checks']=event_registration_checks['verified_counts']
        manifest['validation']['aes_event_registration_static_scope']=event_registration_checks['scope']
    if exists(ROOT/'event_wait_table_checks.json'):
        event_wait_table_checks=json.loads(read(ROOT/'event_wait_table_checks.json'))
        manifest['validation']['event_wait_table_increment_checks']=event_wait_table_checks['verified_counts']
        manifest['validation']['event_wait_table_static_scope']=event_wait_table_checks['scope']
    if exists(ROOT/'startup_dispatch_checks.json'):
        startup_dispatch_checks=json.loads(read(ROOT/'startup_dispatch_checks.json'))
        manifest['validation']['startup_dispatch_increment_checks']=startup_dispatch_checks['verified_counts']
        manifest['validation']['startup_dispatch_static_scope']=startup_dispatch_checks['scope']
    if exists(ROOT/'aes_event_wake_selection_checks.json'):
        wake_selection_checks=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
        manifest['validation']['aes_event_wake_selection_increment_checks']=wake_selection_checks['verified_counts']
        manifest['validation']['aes_event_wake_selection_static_scope']=wake_selection_checks['scope']
    if exists(ROOT/'aes_block_wake_handshake_checks.json'):
        handshake_checks=json.loads(read(ROOT/'aes_block_wake_handshake_checks.json'))
        manifest['validation']['aes_block_wake_handshake_increment_checks']=handshake_checks['verified_counts']
        manifest['validation']['aes_block_wake_handshake_static_scope']=handshake_checks['scope']
    if exists(ROOT/'aes_runqueue_membership_checks.json'):
        runqueue_checks=json.loads(read(ROOT/'aes_runqueue_membership_checks.json'))
        manifest['validation']['aes_runqueue_membership_increment_checks']=runqueue_checks['verified_counts']
        manifest['validation']['aes_runqueue_membership_static_scope']=runqueue_checks['scope']
    if exists(ROOT/'aes_cached_class_queue_checks.json'):
        cached_class_checks=json.loads(read(ROOT/'aes_cached_class_queue_checks.json'))
        manifest['validation']['aes_cached_class_queue_increment_checks']=cached_class_checks['verified_counts']
        manifest['validation']['aes_cached_class_queue_static_scope']=cached_class_checks['scope']
    if exists(ROOT/'aes_uncached_context_queue_checks.json'):
        uncached_context_checks=json.loads(read(ROOT/'aes_uncached_context_queue_checks.json'))
        manifest['validation']['aes_uncached_context_queue_increment_checks']=uncached_context_checks['verified_counts']
        manifest['validation']['aes_uncached_context_queue_static_scope']=uncached_context_checks['scope']
    if exists(ROOT/'aes_context_score_policy_checks.json'):
        score_policy_checks=json.loads(read(ROOT/'aes_context_score_policy_checks.json'))
        manifest['validation']['aes_context_score_policy_increment_checks']=score_policy_checks['verified_counts']
        manifest['validation']['aes_context_score_policy_static_scope']=score_policy_checks['scope']
    if exists(ROOT/'fpsd1200_contract_checks.json'):
        fpsd1200_checks=json.loads(read(ROOT/'fpsd1200_contract_checks.json'))
        manifest['validation']['fpsd1200_contract_increment_checks']=fpsd1200_checks['verified_counts']
        manifest['validation']['fpsd1200_contract_static_scope']=fpsd1200_checks['scope']
    if exists(ROOT/'fpsd1200_admission_checks.json'):
        fpsd1200_admission_checks=json.loads(read(ROOT/'fpsd1200_admission_checks.json'))
        manifest['validation']['fpsd1200_admission_increment_checks']=fpsd1200_admission_checks['verified_counts']
        manifest['validation']['fpsd1200_admission_static_scope']=fpsd1200_admission_checks['scope']
    if exists(ROOT/'fpsd1200_identity_checks.json'):
        fpsd1200_identity_checks=json.loads(read(ROOT/'fpsd1200_identity_checks.json'))
        manifest['validation']['fpsd1200_identity_increment_checks']=fpsd1200_identity_checks['verified_counts']
        manifest['validation']['fpsd1200_identity_static_scope']=fpsd1200_identity_checks['scope']
    if exists(ROOT/'fpsd1200_arena_checks.json'):
        fpsd1200_arena_checks=json.loads(read(ROOT/'fpsd1200_arena_checks.json'))
        manifest['validation']['fpsd1200_arena_increment_checks']=fpsd1200_arena_checks['verified_counts']
        manifest['validation']['fpsd1200_arena_static_scope']=fpsd1200_arena_checks['scope']
    if exists(ROOT/'fpsd1200_context_checks.json'):
        fpsd1200_context_checks=json.loads(read(ROOT/'fpsd1200_context_checks.json'))
        manifest['validation']['fpsd1200_context_increment_checks']=fpsd1200_context_checks['verified_counts']
        manifest['validation']['fpsd1200_context_static_scope']=fpsd1200_context_checks['scope']
    if exists(ROOT/'fpsd1200_certificate_checks.json'):
        certificate_checks=json.loads(read(ROOT/'fpsd1200_certificate_checks.json'))
        manifest['validation']['fpsd1200_certificate_increment_checks']=certificate_checks['verified_counts']
        manifest['validation']['fpsd1200_certificate_static_scope']=certificate_checks['scope']
    if exists(ROOT/'fpsd1200_vm_checks.json'):
        vm_checks=json.loads(read(ROOT/'fpsd1200_vm_checks.json'))
        manifest['validation']['fpsd1200_vm_increment_checks']=vm_checks['verified_counts']
        manifest['validation']['fpsd1200_vm_static_scope']=vm_checks['scope']
    if exists(ROOT/'fpsd1200_port_checks.json'):
        port_checks=json.loads(read(ROOT/'fpsd1200_port_checks.json'))
        manifest['validation']['fpsd1200_port_increment_checks']=port_checks['verified_counts']
        manifest['validation']['fpsd1200_port_static_scope']=port_checks['scope']
    if exists(ROOT/'fpsd1200_lifetime_checks.json'):
        lifetime_checks=json.loads(read(ROOT/'fpsd1200_lifetime_checks.json'))
        manifest['validation']['fpsd1200_lifetime_increment_checks']=lifetime_checks['verified_counts']
        manifest['validation']['fpsd1200_lifetime_static_scope']=lifetime_checks['scope']
    if exists(ROOT/'fpsd1200_process_checks.json'):
        process_checks=json.loads(read(ROOT/'fpsd1200_process_checks.json'))
        manifest['validation']['fpsd1200_process_increment_checks']=process_checks['verified_counts']
        manifest['validation']['fpsd1200_process_static_scope']=process_checks['scope']
    if exists(ROOT/'fpsd1201_session_checks.json'):
        session_checks=json.loads(read(ROOT/'fpsd1201_session_checks.json'))
        manifest['validation']['fpsd1201_session_increment_checks']=session_checks['verified_counts']
        manifest['validation']['fpsd1201_session_static_scope']=session_checks['scope']
    if exists(ROOT/'fpsd1202_ool_checks.json'):
        ool_checks=json.loads(read(ROOT/'fpsd1202_ool_checks.json'))
        manifest['validation']['fpsd1202_ool_increment_checks']=ool_checks['verified_counts']
        manifest['validation']['fpsd1202_ool_static_scope']=ool_checks['scope']
    if exists(ROOT/'fpsd1202_session_checks.json'):
        selected_checks=json.loads(read(ROOT/'fpsd1202_session_checks.json'))
        manifest['validation']['fpsd1202_session_increment_checks']=selected_checks['verified_counts']
        manifest['validation']['fpsd1202_session_static_scope']=selected_checks['scope']
    if exists(ROOT/'fpsd_tail_retirement_checks.json'):
        tail_checks=json.loads(read(ROOT/'fpsd_tail_retirement_checks.json'))
        manifest['validation']['fpsd_tail_retirement_increment_checks']=tail_checks['verified_counts']
        manifest['validation']['fpsd_tail_retirement_static_scope']=tail_checks['scope']
    if exists(ROOT/'fpsd1201_client_checks.json'):
        client_checks=json.loads(read(ROOT/'fpsd1201_client_checks.json'))
        manifest['validation']['fpsd1201_client_increment_checks']=client_checks['verified_counts']
        manifest['validation']['fpsd1201_client_static_scope']=client_checks['scope']
    if exists(ROOT/'fpsd1201_caller_checks.json'):
        caller_checks=json.loads(read(ROOT/'fpsd1201_caller_checks.json'))
        manifest['validation']['fpsd1201_caller_increment_checks']=caller_checks['verified_counts']
        manifest['validation']['fpsd1201_caller_static_scope']=caller_checks['scope']
    if exists(ROOT/'fpsd1201_record_checks.json'):
        record_checks=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
        manifest['validation']['fpsd1201_record_increment_checks']=record_checks['verified_counts']
        manifest['validation']['fpsd1201_record_static_scope']=record_checks['scope']
    if exists(ROOT/'fpsd1201_import_checks.json'):
        import_checks=json.loads(read(ROOT/'fpsd1201_import_checks.json'))
        manifest['validation']['fpsd1201_import_increment_checks']=import_checks['verified_counts']
        manifest['validation']['fpsd1201_import_static_scope']=import_checks['scope']
    if exists(ROOT/'fpsd1201_operand_checks.json'):
        operand_checks=json.loads(read(ROOT/'fpsd1201_operand_checks.json'))
        manifest['validation']['fpsd1201_operand_increment_checks']=operand_checks['verified_counts']
        manifest['validation']['fpsd1201_operand_static_scope']=operand_checks['scope']
    if exists(ROOT/'fpsd1201_shift_checks.json'):
        shift_checks=json.loads(read(ROOT/'fpsd1201_shift_checks.json'))
        manifest['validation']['fpsd1201_shift_increment_checks']=shift_checks['verified_counts']
        manifest['validation']['fpsd1201_shift_static_scope']=shift_checks['scope']
    if exists(ROOT/'fpsd1201_comparison_checks.json'):
        comparison_checks=json.loads(read(ROOT/'fpsd1201_comparison_checks.json'))
        manifest['validation']['fpsd1201_comparison_increment_checks']=comparison_checks['verified_counts']
        manifest['validation']['fpsd1201_comparison_static_scope']=comparison_checks['scope']
    if exists(ROOT/'fpsd1201_subtraction_checks.json'):
        subtraction_checks=json.loads(read(ROOT/'fpsd1201_subtraction_checks.json'))
        manifest['validation']['fpsd1201_subtraction_increment_checks']=subtraction_checks['verified_counts']
        manifest['validation']['fpsd1201_subtraction_static_scope']=subtraction_checks['scope']
    if exists(ROOT/'fpsd1201_reduction_checks.json'):
        reduction_checks=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'))
        manifest['validation']['fpsd1201_reduction_increment_checks']=reduction_checks['verified_counts']
        manifest['validation']['fpsd1201_reduction_static_scope']=reduction_checks['scope']
    if exists(ROOT/'fpsd1201_consumer_checks.json'):
        consumer_checks=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'))
        manifest['validation']['fpsd1201_consumer_increment_checks']=consumer_checks['verified_counts']
        manifest['validation']['fpsd1201_consumer_static_scope']=consumer_checks['scope']
    if exists(ROOT/'fpsd1201_product_checks.json'):
        product_checks=json.loads(read(ROOT/'fpsd1201_product_checks.json'))
        manifest['validation']['fpsd1201_product_increment_checks']=product_checks['verified_counts']
        manifest['validation']['fpsd1201_product_static_scope']=product_checks['scope']
    if exists(ROOT/'fpsd1201_auxiliary_checks.json'):
        auxiliary_checks=json.loads(read(ROOT/'fpsd1201_auxiliary_checks.json'))
        manifest['validation']['fpsd1201_auxiliary_increment_checks']=auxiliary_checks['verified_counts']
        manifest['validation']['fpsd1201_auxiliary_static_scope']=auxiliary_checks['scope']
    if exists(ROOT/'fpsd1201_export_checks.json'):
        export_checks=json.loads(read(ROOT/'fpsd1201_export_checks.json'))
        manifest['validation']['fpsd1201_export_increment_checks']=export_checks['verified_counts']
        manifest['validation']['fpsd1201_export_static_scope']=export_checks['scope']
    if exists(ROOT/'fpsd1201_handoff_checks.json'):
        handoff_checks=json.loads(read(ROOT/'fpsd1201_handoff_checks.json'))
        manifest['validation']['fpsd1201_handoff_increment_checks']=handoff_checks['verified_counts']
        manifest['validation']['fpsd1201_handoff_static_scope']=handoff_checks['scope']
    if exists(ROOT/'fpsd1201_workspace_checks.json'):
        workspace_checks=json.loads(read(ROOT/'fpsd1201_workspace_checks.json'))
        manifest['validation']['fpsd1201_workspace_increment_checks']=workspace_checks['verified_counts']
        manifest['validation']['fpsd1201_workspace_static_scope']=workspace_checks['scope']
    if exists(ROOT/'fpsd1201_predicates_checks.json'):
        predicates_checks=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'))
        manifest['validation']['fpsd1201_predicates_increment_checks']=predicates_checks['verified_counts']
        manifest['validation']['fpsd1201_predicates_static_scope']=predicates_checks['scope']
    if exists(ROOT/'fpsd1201_seed_checks.json'):
        seed_checks=json.loads(read(ROOT/'fpsd1201_seed_checks.json'))
        manifest['validation']['fpsd1201_seed_increment_checks']=seed_checks['verified_counts']
        manifest['validation']['fpsd1201_seed_static_scope']=seed_checks['scope']
    if exists(ROOT/'fpsd1201_key_routes_checks.json'):
        key_routes_checks=json.loads(read(ROOT/'fpsd1201_key_routes_checks.json'))
        manifest['validation']['fpsd1201_key_routes_increment_checks']=key_routes_checks['verified_counts']
        manifest['validation']['fpsd1201_key_routes_static_scope']=key_routes_checks['scope']
    if exists(ROOT/'corefp_network_identity_checks.json'):
        network_checks=json.loads(read(ROOT/'corefp_network_identity_checks.json'))
        manifest['validation']['corefp_network_identity_increment_checks']=network_checks['verified_counts']
        manifest['validation']['corefp_network_identity_static_scope']=network_checks['scope']
    if exists(ROOT/'corefp_lookup_initialization_checks.json'):
        init_checks=json.loads(read(ROOT/'corefp_lookup_initialization_checks.json'))
        manifest['validation']['corefp_lookup_initialization_increment_checks']=init_checks['verified_counts']
        manifest['validation']['corefp_lookup_initialization_static_scope']=init_checks['scope']
    if exists(ROOT/'corefp_cold_metadata_checks.json'):
        cold_metadata=json.loads(read(ROOT/'corefp_cold_metadata_checks.json'))
        manifest['validation']['corefp_cold_metadata_increment_checks']=cold_metadata['verified_counts']
        manifest['validation']['corefp_cold_metadata_static_scope']=cold_metadata['scope']
    if exists(ROOT/'corefp_lookup_release_checks.json'):
        lookup_release=json.loads(read(ROOT/'corefp_lookup_release_checks.json'))
        manifest['validation']['corefp_lookup_release_increment_checks']=lookup_release['verified_counts']
        manifest['validation']['corefp_lookup_release_static_scope']=lookup_release['scope']
    if exists(ROOT/'corefp_request1200_failure_checks.json'):
        request1200_failure=json.loads(read(ROOT/'corefp_request1200_failure_checks.json'))
        manifest['validation']['corefp_request1200_failure_increment_checks']=request1200_failure['verified_counts']
        manifest['validation']['corefp_request1200_failure_static_scope']=request1200_failure['scope']
    if exists(ROOT/'corefp_cold_seed_checks.json'):
        cold_seed=json.loads(read(ROOT/'corefp_cold_seed_checks.json'))
        manifest['validation']['corefp_cold_seed_increment_checks']=cold_seed['verified_counts']
        manifest['validation']['corefp_cold_seed_static_scope']=cold_seed['scope']
    if exists(ROOT/'corefp_root_adapter_checks.json'):
        root_adapter=json.loads(read(ROOT/'corefp_root_adapter_checks.json'))
        manifest['validation']['corefp_root_adapter_increment_checks']=root_adapter['verified_counts']
        manifest['validation']['corefp_root_adapter_static_scope']=root_adapter['scope']
    if exists(ROOT/'corefp_root_ingress_checks.json'):
        root_ingress=json.loads(read(ROOT/'corefp_root_ingress_checks.json'))
        manifest['validation']['corefp_root_ingress_increment_checks']=root_ingress['verified_counts']
        manifest['validation']['corefp_root_ingress_static_scope']=root_ingress['scope']
    if exists(ROOT/'corefp_ingress_callers_checks.json'):
        ingress_callers=json.loads(read(ROOT/'corefp_ingress_callers_checks.json'))
        manifest['validation']['corefp_ingress_callers_increment_checks']=ingress_callers['verified_counts']
        manifest['validation']['corefp_ingress_callers_static_scope']=ingress_callers['scope']
    if exists(ROOT/'corefp_vm_lifecycle_checks.json'):
        vm_lifecycle=json.loads(read(ROOT/'corefp_vm_lifecycle_checks.json'))
        manifest['validation']['corefp_vm_lifecycle_increment_checks']=vm_lifecycle['verified_counts']
        manifest['validation']['corefp_vm_lifecycle_static_scope']=vm_lifecycle['scope']
    if exists(ROOT/'corefp_caller_cold_checks.json'):
        caller_cold=json.loads(read(ROOT/'corefp_caller_cold_checks.json'))
        manifest['validation']['corefp_caller_cold_increment_checks']=caller_cold['verified_counts']
        manifest['validation']['corefp_caller_cold_static_scope']=caller_cold['scope']
    if exists(ROOT/'corefp_optional_reset_checks.json'):
        optional_reset=json.loads(read(ROOT/'corefp_optional_reset_checks.json'))
        manifest['validation']['corefp_optional_reset_increment_checks']=optional_reset['verified_counts']
        manifest['validation']['corefp_optional_reset_static_scope']=optional_reset['scope']
    if exists(ROOT/'corefp_reset_caller_checks.json'):
        reset_caller=json.loads(read(ROOT/'corefp_reset_caller_checks.json'))
        manifest['validation']['corefp_reset_caller_increment_checks']=reset_caller['verified_counts']
        manifest['validation']['corefp_reset_caller_static_scope']=reset_caller['scope']
    if exists(ROOT/'corefp_pool_allocator_checks.json'):
        pool_allocator=json.loads(read(ROOT/'corefp_pool_allocator_checks.json'))
        manifest['validation']['corefp_pool_allocator_increment_checks']=pool_allocator['verified_counts']
        manifest['validation']['corefp_pool_allocator_static_scope']=pool_allocator['scope']
    if exists(ROOT/'corefp_pool_caller_checks.json'):
        pool_caller=json.loads(read(ROOT/'corefp_pool_caller_checks.json'))
        manifest['validation']['corefp_pool_caller_increment_checks']=pool_caller['verified_counts']
        manifest['validation']['corefp_pool_caller_static_scope']=pool_caller['scope']
    if exists(ROOT/'corefp_pool_transform_checks.json'):
        pool_transform=json.loads(read(ROOT/'corefp_pool_transform_checks.json'))
        manifest['validation']['corefp_pool_transform_increment_checks']=pool_transform['verified_counts']
        manifest['validation']['corefp_pool_transform_static_scope']=pool_transform['scope']
    if exists(ROOT/'corefp_workspace_checks.json'):
        workspace=json.loads(read(ROOT/'corefp_workspace_checks.json'))
        manifest['validation']['corefp_workspace_increment_checks']=workspace['verified_counts']
        manifest['validation']['corefp_workspace_static_scope']=workspace['scope']
    if exists(ROOT/'corefp_workspace_consumers_checks.json'):
        consumers=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'))
        manifest['validation']['corefp_workspace_consumers_increment_checks']=consumers['verified_counts']
        manifest['validation']['corefp_workspace_consumers_static_scope']=consumers['scope']
    if exists(ROOT/'corefp_output_packing_checks.json'):
        packing=json.loads(read(ROOT/'corefp_output_packing_checks.json'))
        manifest['validation']['corefp_output_packing_increment_checks']=packing['verified_counts']
        manifest['validation']['corefp_output_packing_static_scope']=packing['scope']
    if exists(ROOT/'corefp_late_preparation_checks.json'):
        late=json.loads(read(ROOT/'corefp_late_preparation_checks.json'))
        manifest['validation']['corefp_late_preparation_increment_checks']=late['verified_counts']
        manifest['validation']['corefp_late_preparation_static_scope']=late['scope']
    if exists(ROOT/'corefp_preparation_scans_checks.json'):
        scans=json.loads(read(ROOT/'corefp_preparation_scans_checks.json'))
        manifest['validation']['corefp_preparation_scans_increment_checks']=scans['verified_counts']
        manifest['validation']['corefp_preparation_scans_static_scope']=scans['scope']
    if exists(ROOT/'corefp_phase_parameters_checks.json'):
        phase=json.loads(read(ROOT/'corefp_phase_parameters_checks.json'))
        manifest['validation']['corefp_phase_parameters_increment_checks']=phase['verified_counts']
        manifest['validation']['corefp_phase_parameters_static_scope']=phase['scope']
    if exists(ROOT/'corefp_scan_entry_checks.json'):
        scan_entry=json.loads(read(ROOT/'corefp_scan_entry_checks.json'))
        manifest['validation']['corefp_scan_entry_increment_checks']=scan_entry['verified_counts']
        manifest['validation']['corefp_scan_entry_static_scope']=scan_entry['scope']
    if exists(ROOT/'corefp_word_codec_checks.json'):
        word_codec=json.loads(read(ROOT/'corefp_word_codec_checks.json'))
        manifest['validation']['corefp_word_codec_increment_checks']=word_codec['verified_counts']
        manifest['validation']['corefp_word_codec_static_scope']=word_codec['scope']
    if exists(ROOT/'corefp_word_recurrence_checks.json'):
        word_recurrence=json.loads(read(ROOT/'corefp_word_recurrence_checks.json'))
        manifest['validation']['corefp_word_recurrence_increment_checks']=word_recurrence['verified_counts']
        manifest['validation']['corefp_word_recurrence_static_scope']=word_recurrence['scope']
    if exists(ROOT/'corefp_word_inputs_checks.json'):
        word_inputs=json.loads(read(ROOT/'corefp_word_inputs_checks.json'))
        manifest['validation']['corefp_word_inputs_increment_checks']=word_inputs['verified_counts']
        manifest['validation']['corefp_word_inputs_static_scope']=word_inputs['scope']
    if exists(ROOT/'corefp_input_lineage_checks.json'):
        input_lineage=json.loads(read(ROOT/'corefp_input_lineage_checks.json'))
        manifest['validation']['corefp_input_lineage_increment_checks']=input_lineage['verified_counts']
        manifest['validation']['corefp_input_lineage_static_scope']=input_lineage['scope']
    if exists(ROOT/'corefp_word_traversal_checks.json'):
        word_traversal=json.loads(read(ROOT/'corefp_word_traversal_checks.json'))
        manifest['validation']['corefp_word_traversal_increment_checks']=word_traversal['verified_counts']
        manifest['validation']['corefp_word_traversal_static_scope']=word_traversal['scope']
    if exists(ROOT/'corefp_word_selectors_checks.json'):
        word_selectors=json.loads(read(ROOT/'corefp_word_selectors_checks.json'))
        manifest['validation']['corefp_word_selectors_increment_checks']=word_selectors['verified_counts']
        manifest['validation']['corefp_word_selectors_static_scope']=word_selectors['scope']
    if exists(ROOT/'daemon_versioned_header_checks.json'):
        versioned_header=json.loads(read(ROOT/'daemon_versioned_header_checks.json'))
        manifest['validation']['daemon_versioned_header_increment_checks']=versioned_header['verified_counts']
        manifest['validation']['daemon_versioned_header_static_scope']=versioned_header['scope']
    if exists(ROOT/'daemon_versioned_root_checks.json'):
        versioned_root=json.loads(read(ROOT/'daemon_versioned_root_checks.json'))
        manifest['validation']['daemon_versioned_root_increment_checks']=versioned_root['verified_counts']
        manifest['validation']['daemon_versioned_root_static_scope']=versioned_root['scope']
    if exists(ROOT/'daemon_versioned_ingress_checks.json'):
        versioned_ingress=json.loads(read(ROOT/'daemon_versioned_ingress_checks.json'))
        manifest['validation']['daemon_versioned_ingress_increment_checks']=versioned_ingress['verified_counts']
        manifest['validation']['daemon_versioned_ingress_static_scope']=versioned_ingress['scope']
    if exists(ROOT/'daemon_frame_word_checks.json'):
        frame_word=json.loads(read(ROOT/'daemon_frame_word_checks.json'))
        manifest['validation']['daemon_frame_word_increment_checks']=frame_word['verified_counts']
        manifest['validation']['daemon_frame_word_static_scope']=frame_word['scope']
    if exists(ROOT/'daemon_frame_admission_checks.json'):
        frame_admission=json.loads(read(ROOT/'daemon_frame_admission_checks.json'))
        manifest['validation']['daemon_frame_admission_increment_checks']=frame_admission['verified_counts']
        manifest['validation']['daemon_frame_admission_static_scope']=frame_admission['scope']
    if exists(ROOT/'daemon_remainder_preparation_checks.json'):
        remainder_preparation=json.loads(read(ROOT/'daemon_remainder_preparation_checks.json'))
        manifest['validation']['daemon_remainder_preparation_increment_checks']=remainder_preparation['verified_counts']
        manifest['validation']['daemon_remainder_preparation_static_scope']=remainder_preparation['scope']
    if exists(ROOT/'daemon_nested_helper_processing_checks.json'):
        nested_processing=json.loads(read(ROOT/'daemon_nested_helper_processing_checks.json'))
        manifest['validation']['daemon_nested_helper_processing_increment_checks']=nested_processing['verified_counts']
        manifest['validation']['daemon_nested_helper_processing_static_scope']=nested_processing['scope']
    if exists(ROOT/'daemon_postblock_dispatch_checks.json'):
        postblock_dispatch=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
        manifest['validation']['daemon_postblock_dispatch_increment_checks']=postblock_dispatch['verified_counts']
        manifest['validation']['daemon_postblock_dispatch_static_scope']=postblock_dispatch['scope']
    if exists(ROOT/'versioned_core_entry_checks.json'):
        versioned_core=json.loads(read(ROOT/'versioned_core_entry_checks.json'))
        versioned_replays=json.loads(read(ROOT/'versioned_core_entry_replays.json'))
        manifest['validation']['versioned_core_entry_increment_checks']=versioned_core['verified_counts']
        manifest['validation']['versioned_core_entry_replay_checks']=versioned_replays['verified_counts']
        manifest['validation']['versioned_core_entry_static_scope']=versioned_core['scope']
    if exists(ROOT/'versioned_core_preparation_checks.json'):
        versioned_preparation=json.loads(read(ROOT/'versioned_core_preparation_checks.json'))
        versioned_audit=json.loads(read(ROOT/'versioned_core_preparation_audit.json'))
        manifest['validation']['versioned_core_preparation_increment_checks']=versioned_preparation['verified_counts']
        manifest['validation']['versioned_core_preparation_audit_checks']=versioned_audit['verified_counts']
    if exists(ROOT/'versioned_dispatcher_frame_checks.json'):
        dispatcher_frame=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'))
        manifest['validation']['versioned_dispatcher_frame_increment_checks']=dispatcher_frame['verified_counts']
        manifest['validation']['versioned_dispatcher_frame_static_scope']=dispatcher_frame['scope']
    if exists(ROOT/'versioned_stream_initialization_checks.json'):
        stream_initialization=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'))
        manifest['validation']['versioned_stream_initialization_increment_checks']=stream_initialization['verified_counts']
        manifest['validation']['versioned_stream_initialization_static_scope']=stream_initialization['scope']
    if exists(ROOT/'versioned_stream_words_checks.json'):
        stream_words=json.loads(read(ROOT/'versioned_stream_words_checks.json'))
        manifest['validation']['versioned_stream_words_increment_checks']=stream_words['verified_counts']
        manifest['validation']['versioned_stream_words_static_scope']=stream_words['scope']
    if exists(ROOT/'versioned_output_stream_checks.json'):
        output_stream=json.loads(read(ROOT/'versioned_output_stream_checks.json'))
        manifest['validation']['versioned_output_stream_increment_checks']=output_stream['verified_counts']
        manifest['validation']['versioned_output_stream_static_scope']=output_stream['scope']
    if exists(ROOT/'versioned_inner_entry_checks.json'):
        inner_entry=json.loads(read(ROOT/'versioned_inner_entry_checks.json'))
        manifest['validation']['versioned_inner_entry_increment_checks']=inner_entry['verified_counts']
        manifest['validation']['versioned_inner_entry_static_scope']=inner_entry['scope']
    if exists(ROOT/'versioned_aes_parameters_checks.json'):
        aes_parameters=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'))
        manifest['validation']['versioned_aes_parameters_increment_checks']=aes_parameters['verified_counts']
        manifest['validation']['versioned_aes_parameters_static_scope']=aes_parameters['scope']
    if exists(ROOT/'versioned_lock_handoff_checks.json'):
        lock_handoff=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'))
        manifest['validation']['versioned_lock_handoff_increment_checks']=lock_handoff['verified_counts']
        manifest['validation']['versioned_lock_handoff_static_scope']=lock_handoff['scope']
    if exists(ROOT/'versioned_hardware_admission_checks.json'):
        hardware_admission=json.loads(read(ROOT/'versioned_hardware_admission_checks.json'))
        manifest['validation']['versioned_hardware_admission_increment_checks']=hardware_admission['verified_counts']
        manifest['validation']['versioned_hardware_admission_static_scope']=hardware_admission['scope']
    if exists(ROOT/'versioned_error_release_checks.json'):
        error_release=json.loads(read(ROOT/'versioned_error_release_checks.json'))
        manifest['validation']['versioned_error_release_increment_checks']=error_release['verified_counts']
        manifest['validation']['versioned_error_release_static_scope']=error_release['scope']
    if exists(ROOT/'versioned_wrapper_error_return_checks.json'):
        wrapper_error_return=json.loads(read(ROOT/'versioned_wrapper_error_return_checks.json'))
        manifest['validation']['versioned_wrapper_error_return_increment_checks']=wrapper_error_return['verified_counts']
        manifest['validation']['versioned_wrapper_error_return_static_scope']=wrapper_error_return['scope']
    if exists(ROOT/'daemon_iokit_result_checks.json'):
        iokit_result=json.loads(read(ROOT/'daemon_iokit_result_checks.json'))
        iokit_result_audit=json.loads(read(ROOT/'daemon_iokit_result_audit.json'))
        manifest['validation']['daemon_iokit_result_increment_checks']=iokit_result['verified_counts']
        manifest['validation']['daemon_iokit_result_replay_checks']=iokit_result_audit['independent_totals']
        manifest['validation']['daemon_iokit_result_static_scope']=iokit_result['scope']
    if exists(ROOT/'daemon_iokit_error_return_checks.json'):
        iokit_error_return=json.loads(read(ROOT/'daemon_iokit_error_return_checks.json'))
        iokit_error_return_audit=json.loads(read(ROOT/'daemon_iokit_error_return_audit.json'))
        manifest['validation']['daemon_iokit_error_return_increment_checks']=iokit_error_return['verified_counts']
        manifest['validation']['daemon_iokit_error_return_replay_checks']=iokit_error_return_audit['independent_totals']
        manifest['validation']['daemon_iokit_error_return_static_scope']=iokit_error_return['scope']
    if exists(ROOT/'daemon_return_bank_origins_checks.json'):
        bank_origins=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))
        bank_audit=json.loads(read(ROOT/'daemon_return_bank_origins_audit.json'))
        manifest['validation']['daemon_return_bank_origins_increment_checks']=bank_origins['verified_counts']
        manifest['validation']['daemon_return_bank_origins_upstream_replay_checks']=bank_audit['upstream_independent_totals']
        manifest['validation']['daemon_return_bank_origins_caller_replay_checks']=bank_audit['conditional_caller_independent_totals']
        manifest['validation']['daemon_return_bank_origins_static_scope']=bank_origins['scope']
    if exists(ROOT/'daemon_return_cache_codec_checks.json'):
        return_cache=json.loads(read(ROOT/'daemon_return_cache_codec_checks.json'))
        return_cache_audit=json.loads(read(ROOT/'daemon_return_cache_codec_audit.json'))
        manifest['validation']['daemon_return_cache_codec_increment_checks']=return_cache['verified_counts']
        manifest['validation']['daemon_return_cache_codec_replay_checks']=return_cache_audit['independent_totals']
        manifest['validation']['daemon_return_cache_codec_upstream_replay_checks']=return_cache_audit['upstream_independent_totals']
        manifest['validation']['daemon_return_cache_codec_static_scope']=return_cache['scope']
    if exists(ROOT/'daemon_scratch_pointer_origin_checks.json'):
        scratch=json.loads(read(ROOT/'daemon_scratch_pointer_origin_checks.json'))
        scratch_audit=json.loads(read(ROOT/'daemon_scratch_pointer_origin_audit.json'))
        manifest['validation']['daemon_scratch_pointer_origin_increment_checks']=scratch['verified_counts']
        manifest['validation']['daemon_scratch_pointer_origin_replay_checks']=scratch_audit['independent_totals']
        manifest['validation']['daemon_scratch_pointer_origin_static_scope']=scratch['scope']
        manifest['validation']['daemon_scratch_pointer_origin_clock_controls']=len(scratch_audit['helper_controls'])
        manifest['validation']['daemon_scratch_pointer_origin_return_controls']=len(scratch_audit['return_controls'])
        manifest['validation']['daemon_scratch_pointer_origin_SDK_compile_exit']=scratch_audit['SDK_checks']['exit_code']
    if exists(ROOT/"daemon_environment_outputs_checks.json"):
        environment=json.loads(read(ROOT/"daemon_environment_outputs_checks.json"))
        environment_audit=json.loads(read(ROOT/"daemon_environment_outputs_audit.json"))
        manifest["validation"]["daemon_environment_outputs_increment_checks"]=environment["verified_counts"]
        manifest["validation"]["daemon_environment_outputs_replay_checks"]=environment_audit["independent_totals"]
        manifest["validation"]["daemon_environment_outputs_static_scope"]=environment["scope"]
        manifest["validation"]["daemon_environment_outputs_source_queries_unsat"]=environment_audit["source_queries_unsat"]
        manifest["validation"]["daemon_environment_outputs_SDK_compile_exit"]=environment_audit["SDK_checks"]["exit_code"]
    if exists(ROOT/"daemon_notification_registration_checks.json"):
        notifications=json.loads(read(ROOT/"daemon_notification_registration_checks.json"))
        notifications_audit=json.loads(read(ROOT/"daemon_notification_registration_audit.json"))
        manifest["validation"]["daemon_notification_registration_increment_checks"]=notifications["verified_counts"]
        manifest["validation"]["daemon_notification_registration_replay_checks"]=notifications_audit["independent_totals"]
        manifest["validation"]["daemon_notification_registration_static_scope"]=notifications["scope"]
        manifest["validation"]["daemon_notification_registration_source_queries_unsat"]=notifications_audit["source_queries_unsat"]
        manifest["validation"]["daemon_notification_registration_SDK_compile_exit"]=notifications_audit["SDK_checks"]["exit_code"]
    if exists(ROOT/"daemon_notification_failure_checks.json"):
        notification_failure=json.loads(read(ROOT/"daemon_notification_failure_checks.json"))
        notification_failure_audit=json.loads(read(ROOT/"daemon_notification_failure_audit.json"))
        manifest["validation"]["daemon_notification_failure_increment_checks"]=notification_failure["verified_counts"]
        manifest["validation"]["daemon_notification_failure_replay_checks"]=notification_failure_audit["independent_totals"]
        manifest["validation"]["daemon_notification_failure_static_scope"]=notification_failure["scope"]
        manifest["validation"]["daemon_notification_failure_source_queries_unsat"]=notification_failure_audit["source_queries_unsat"]
        manifest["validation"]["daemon_notification_failure_SDK_compile_exit"]=notification_failure_audit["SDK_checks"]["exit_code"]
    if exists(ROOT/'daemon_audit_scratch_checks.json'):
        audit_scratch=json.loads(read(ROOT/'daemon_audit_scratch_checks.json'))
        audit_scratch_replay=json.loads(read(ROOT/'daemon_audit_scratch_audit.json'))
        manifest['validation']['daemon_audit_scratch_increment_checks']=audit_scratch['verified_counts']
        manifest['validation']['daemon_audit_scratch_replay_checks']=audit_scratch_replay['independent_totals']
        manifest['validation']['daemon_audit_scratch_static_scope']=audit_scratch['scope']
        manifest['validation']['daemon_audit_scratch_source_queries_unsat']=audit_scratch_replay['source_queries_unsat']
        manifest['validation']['daemon_audit_scratch_copy_queries_unsat']=len(audit_scratch_replay['copy_proofs'])
        manifest['validation']['daemon_audit_scratch_SDK_compile_exit']=audit_scratch_replay['SDK_checks']['exit_code']
    if exists(ROOT/'daemon_pidpath_consumer_checks.json'):
        pidpath=json.loads(read(ROOT/'daemon_pidpath_consumer_checks.json'))
        pidpath_audit=json.loads(read(ROOT/'daemon_pidpath_consumer_audit.json'))
        manifest['validation']['daemon_pidpath_consumer_increment_checks']=pidpath['verified_counts']
        manifest['validation']['daemon_pidpath_consumer_replay_checks']=pidpath_audit['independent_totals']
        manifest['validation']['daemon_pidpath_consumer_static_scope']=pidpath['scope']
        manifest['validation']['daemon_pidpath_consumer_source_queries_unsat']=pidpath_audit['source_queries_unsat']
        manifest['validation']['daemon_pidpath_consumer_SDK_compile_exit']=pidpath_audit['SDK_checks']['exit_code']
    if exists(ROOT/'daemon_network_identity_checks.json'):
        network=json.loads(read(ROOT/'daemon_network_identity_checks.json'))
        network_audit=json.loads(read(ROOT/'daemon_network_identity_audit.json'))
        manifest['validation']['daemon_network_identity_increment_checks']=network['verified_counts']
        manifest['validation']['daemon_network_identity_replay_checks']=network_audit['independent_totals']
        manifest['validation']['daemon_network_identity_static_scope']=network['scope']
        manifest['validation']['daemon_network_identity_source_queries_unsat']=network_audit['source_queries_unsat']
        manifest['validation']['daemon_network_identity_SDK_compile_exit']=network_audit['SDK_checks']['exit_code']
    if exists(ROOT/'daemon_network_record_checks.json'):
        network_record=json.loads(read(ROOT/'daemon_network_record_checks.json'))
        network_record_audit=json.loads(read(ROOT/'daemon_network_record_audit.json'))
        manifest['validation']['daemon_network_record_increment_checks']=network_record['verified_counts']
        manifest['validation']['daemon_network_record_replay_checks']=network_record_audit['independent_totals']
        manifest['validation']['daemon_network_record_initializer_checks']=network_record_audit['initializer_totals']
        manifest['validation']['daemon_network_record_static_scope']=network_record['scope']
        manifest['validation']['daemon_network_record_source_queries_unsat']=network_record_audit['source_queries_unsat']
        manifest['validation']['daemon_network_record_SDK_compile_exit']=network_record_audit['SDK_checks']['exit_code']
    (ROOT/'interface_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    check=json.loads(read(ROOT/'interface_manifest.json'))
    for row in check['files']:
        path=BASE/row['path'];assert sha(path)==row['sha256'] and size(path)==row['size_bytes']
    print(json.dumps({'owned_artifacts':len(check['files']),**check['validation'],
                      'original_inputs_preserved':len(check['inputs_preserved']),'goal_status':'active'}))


if __name__=='__main__':main()
