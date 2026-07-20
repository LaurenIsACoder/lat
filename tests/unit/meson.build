test_elfload_pagesize = executable(
  'test-elfload-pagesize',
  files('test-elfload-pagesize.c'),
  '../../linux-user/elfload-pagesize.c',
  dependencies: glib,
)

test('test-elfload-pagesize', test_elfload_pagesize)

kzt_guest_registry_test = executable(
  'kzt-guest-registry',
  files(
    'kzt/test_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-registry', kzt_guest_registry_test)

kzt_guest_registry_concurrency_test = executable(
  'kzt-guest-registry-concurrency',
  files(
    'kzt/test_guest_registry_concurrency.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-registry-concurrency', kzt_guest_registry_concurrency_test)

kzt_guest_registry_context_test = executable(
  'kzt-guest-registry-context',
  files(
    'kzt/test_guest_registry_context.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_registry_context.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-registry-context', kzt_guest_registry_context_test)

kzt_guest_library_binding_test = executable(
  'kzt-guest-library-binding',
  files(
    'kzt/test_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_LIBRARY_BINDING_TEST', '-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-library-binding', kzt_guest_library_binding_test)

kzt_guest_library_binding_teardown_test = executable(
  'kzt-guest-library-binding-teardown',
  files(
    'kzt/test_guest_library_binding_teardown.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_LIBRARY_BINDING_TEST', '-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-library-binding-teardown',
     kzt_guest_library_binding_teardown_test)

kzt_dlopen_recycle_transaction_test = executable(
  'kzt-dlopen-recycle-transaction',
  files(
    'kzt/test_dlopen_recycle_transaction.c',
    '../../target/i386/latx/context/dlopen_recycle_transaction.c',
    '../../target/i386/latx/context/elf_plt_relocation.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_LIBRARY_BINDING_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-dlopen-recycle-transaction',
     kzt_dlopen_recycle_transaction_test)

python3 = find_program('python3')
test(
  'kzt-wi382-registry-observation-source-contract',
  python3,
  args: [
    files('kzt/test_wi382_registry_observation_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi254-loader-contract',
  python3,
  args: [
    files('kzt/test_wi254_loader_contract.py'),
    meson.source_root(),
  ],
)

kzt_guest_link_map_reader_test = executable(
  'kzt-guest-link-map-reader',
  files(
    'kzt/test_guest_link_map_reader.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
  ),
  c_args: ['-DKZT_GUEST_LINK_MAP_READER_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-guest-link-map-reader', kzt_guest_link_map_reader_test)

kzt_elf_map_range_test = executable(
  'kzt-elf-map-range',
  files(
    'kzt/test_elf_map_range.c',
    '../../target/i386/latx/context/elfmap.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-elf-map-range', kzt_elf_map_range_test)

kzt_guest_dynamic_parser_test = executable(
  'kzt-guest-dynamic-parser',
  files(
    'kzt/test_guest_dynamic_parser.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-guest-dynamic-parser', kzt_guest_dynamic_parser_test)

kzt_guest_dynamic_snapshot_test = executable(
  'kzt-guest-dynamic-snapshot',
  files(
    'kzt/test_guest_dynamic_snapshot.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-dynamic-snapshot', kzt_guest_dynamic_snapshot_test)

kzt_guest_dynamic_diagnostics_test = executable(
  'kzt-guest-dynamic-diagnostics',
  files(
    'kzt/test_guest_dynamic_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_dynamic_diagnostics.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-guest-dynamic-diagnostics', kzt_guest_dynamic_diagnostics_test)

kzt_observation_adapter_test = executable(
  'kzt-observation-adapter',
  files(
    'kzt/test_observation_adapter.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
    '../../target/i386/latx/context/kzt_observation_adapter.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_dynamic_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
  ),
  c_args: [
    '-DKZT_GUEST_REGISTRY_TEST',
    '-DKZT_GUEST_LINK_MAP_READER_TEST',
    '-DKZT_GUEST_LIBRARY_BINDING_TEST',
  ],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-observation-adapter', kzt_observation_adapter_test)

kzt_registry_diagnostics_gate_test = executable(
  'kzt-registry-diagnostics-gate',
  files(
    'kzt/test_registry_diagnostics_gate.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
    '../../target/i386/latx/context/kzt_observation_adapter.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_dynamic_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
  ),
  c_args: [
    '-DCONFIG_LATX_KZT',
    '-DKZT_GUEST_REGISTRY_TEST',
    '-DKZT_GUEST_LINK_MAP_READER_TEST',
  ],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-registry-diagnostics-gate', kzt_registry_diagnostics_gate_test)

kzt_patch_planner_test = executable(
  'kzt-patch-planner',
  files(
    'kzt/test_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-patch-planner', kzt_patch_planner_test)

kzt_runtime_got_plt_candidate_test = executable(
  'kzt-runtime-got-plt-candidate',
  files(
    'kzt/test_runtime_got_plt_candidate.c',
    '../../target/i386/latx/context/kzt_runtime_got_plt_candidate.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-runtime-got-plt-candidate', kzt_runtime_got_plt_candidate_test)

kzt_runtime_candidate_enrichment_shadow_test = executable(
  'kzt-runtime-candidate-enrichment-shadow',
  files(
    'kzt/test_runtime_candidate_enrichment_shadow.c',
    '../../target/i386/latx/context/kzt_runtime_candidate_shadow.c',
    '../../target/i386/latx/context/kzt_runtime_got_plt_candidate.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test(
  'kzt-runtime-candidate-enrichment-shadow',
  kzt_runtime_candidate_enrichment_shadow_test,
)

kzt_rela_immediate_candidate_test = executable(
  'kzt-rela-immediate-candidate',
  files(
    'kzt/test_rela_immediate_candidate.c',
    '../../target/i386/latx/context/kzt_rela_immediate_candidate.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-rela-immediate-candidate', kzt_rela_immediate_candidate_test)

kzt_rela_request_enricher_test = executable(
  'kzt-rela-request-enricher',
  files(
    'kzt/test_rela_request_enricher.c',
    '../../target/i386/latx/context/kzt_rela_request_enricher.c',
    '../../target/i386/latx/context/kzt_rela_immediate_candidate.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-rela-request-enricher', kzt_rela_request_enricher_test)

kzt_wi238_structured_diagnostics_gate_test = executable(
  'kzt-wi238-structured-diagnostics-gate',
  files(
    'kzt/test_wi238_structured_diagnostics.c',
    '../../target/i386/latx/context/kzt_rela_diagnostics.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-wi238-structured-diagnostics-gate',
     kzt_wi238_structured_diagnostics_gate_test)

kzt_owner_resolver_test = executable(
  'kzt-owner-resolver',
  files(
    'kzt/test_owner_resolver.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-owner-resolver', kzt_owner_resolver_test)


kzt_patch_spike_guard_test = executable(
  'kzt-patch-spike-guard',
  files(
    'kzt/test_patch_spike_guard.c',
    'kzt/kzt_test_options.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-patch-spike-guard', kzt_patch_spike_guard_test)

kzt_patch_spike_writer_test = executable(
  'kzt-patch-spike-writer',
  files(
    'kzt/test_patch_spike_writer.c',
    'kzt/kzt_test_options.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-patch-spike-writer', kzt_patch_spike_writer_test)

kzt_wrapper_probe_test = executable(
  'kzt-wrapper-probe',
  files(
    'kzt/test_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wrapper-probe', kzt_wrapper_probe_test)

kzt_wrapper_bridge_provider_test = executable(
  'kzt-wrapper-bridge-provider',
  files(
    'kzt/test_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wrapper-bridge-provider', kzt_wrapper_bridge_provider_test)

kzt_rela_runtime_helper_chain_test = executable(
  'kzt-rela-runtime-helper-chain',
  files(
    'kzt/test_rela_runtime_helper_chain.c',
    '../../target/i386/latx/context/kzt_rela_runtime_bridge.c',
    '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_rela_request_enricher.c',
    '../../target/i386/latx/context/kzt_rela_immediate_candidate.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_bridge_exact.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-rela-runtime-helper-chain', kzt_rela_runtime_helper_chain_test)

kzt_jump_slot_route_test = executable(
  'kzt-jump-slot-route',
  files(
    'kzt/test_jump_slot_route.c',
    '../../target/i386/latx/context/kzt_jump_slot_route.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-jump-slot-route', kzt_jump_slot_route_test)

kzt_wi256_lazy_binding_test = executable(
  'kzt-wi256-lazy-binding',
  files(
    'kzt/test_wi256_lazy_binding.c',
    '../../target/i386/latx/context/kzt_lazy_binding.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wi256-lazy-binding', kzt_wi256_lazy_binding_test)

kzt_wi256_lazy_diagnostics_test = executable(
  'kzt-wi256-lazy-diagnostics',
  files(
    'kzt/test_wi256_lazy_diagnostics.c',
    '../../target/i386/latx/context/kzt_lazy_diagnostics.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wi256-lazy-diagnostics', kzt_wi256_lazy_diagnostics_test)

test(
  'kzt-wi256-lazy-diagnostics-source-contract',
  python3,
  args: [
    files('kzt/test_wi256_lazy_diagnostics_source_contract.py'),
    meson.source_root(),
  ],
)

kzt_wi256_plt_resolver_adapter_test = executable(
  'kzt-wi256-plt-resolver-adapter',
  files(
    'kzt/test_wi256_plt_resolver_adapter.c',
    '../../target/i386/latx/context/kzt_plt_resolver_adapter.c',
  ),
  c_args: ['-DKZT_PLT_RESOLVER_ADAPTER_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wi256-plt-resolver-adapter',
     kzt_wi256_plt_resolver_adapter_test)

kzt_wi256_lazy_production_bridge_test = executable(
  'kzt-wi256-lazy-production-bridge',
  files(
    'kzt/test_wi256_lazy_production_bridge.c',
    'kzt/kzt_test_options.c',
    '../../target/i386/latx/context/kzt_lazy_binding.c',
    '../../target/i386/latx/context/kzt_jump_slot_production.c',
    '../../target/i386/latx/context/kzt_jump_slot_route.c',
    '../../target/i386/latx/context/kzt_rela_runtime_bridge.c',
    '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_rela_request_enricher.c',
    '../../target/i386/latx/context/kzt_rela_diagnostics.c',
    '../../target/i386/latx/context/kzt_rela_immediate_candidate.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_runtime_got_plt_candidate.c',
    '../../target/i386/latx/context/kzt_runtime_candidate_shadow.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_bridge_exact.c',
  ),
  c_args: [
    '-DCONFIG_LATX_KZT',
    '-DKZT_GUEST_REGISTRY_TEST',
    '-DKZT_JUMP_SLOT_PRODUCTION_TEST',
  ],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-wi256-lazy-production-bridge',
     kzt_wi256_lazy_production_bridge_test)

test(
  'kzt-wi256-plt-resolver-source-contract',
  python3,
  args: [
    files('kzt/test_wi256_plt_resolver_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi237-jump-slot-route-contract',
  python3,
  args: [
    files('kzt/test_wi237_jump_slot_route_contract.py'),
    meson.source_root(),
  ],
)

kzt_wi236_enrichment_matrix_test = executable(
  'kzt-wi236-enrichment-matrix',
  files(
    'kzt/test_wi236_enrichment_matrix.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_owner_resolver.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
    '../../target/i386/latx/context/kzt_rela_immediate_candidate.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-wi236-enrichment-matrix', kzt_wi236_enrichment_matrix_test)
