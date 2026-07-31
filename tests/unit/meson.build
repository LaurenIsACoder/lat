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

test(
  'kzt-wi1009-lazy-slot-bridge-removal-contract',
  find_program('python3'),
  args: [
    files('kzt/test_wi1009_lazy_slot_bridge_context_contract.py'),
    meson.project_source_root(),
  ],
)

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

kzt_guest_registry_patch_decision_lease_test = executable(
  'kzt-guest-registry-patch-decision-lease',
  files(
    'kzt/test_guest_registry_patch_decision_lease.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-registry-patch-decision-lease',
     kzt_guest_registry_patch_decision_lease_test)

kzt_guest_registry_got_plt_injection_test = executable(
  'kzt-guest-registry-got-plt-injection',
  files(
    'kzt/test_guest_registry_got_plt_injection.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-registry-got-plt-injection',
     kzt_guest_registry_got_plt_injection_test)

kzt_per_object_got_plt_test = executable(
  'kzt-per-object-got-plt',
  files(
    'kzt/test_per_object_got_plt.c',
    '../../target/i386/latx/context/kzt_per_object_got_plt.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-per-object-got-plt', kzt_per_object_got_plt_test)

if 'x86_64-linux-user' in target_dirs
  kzt_bridge_concurrency_test = executable(
    'kzt-bridge-concurrency',
    files(
      'kzt/test_bridge_concurrency.c',
      '../../target/i386/latx/context/bridge.c',
    ),
    c_args: [
      '-DBRIDGE_TEST',
      '-DNEED_CPU_H',
      '-DCONFIG_TARGET="x86_64-linux-user-config-target.h"',
      '-DCONFIG_DEVICES="x86_64-linux-user-config-devices.h"',
    ],
    include_directories: include_directories(
      '../..',
      '../../target/i386',
      '../../linux-user/host/loongarch',
      '../../linux-user',
      '../../linux-user/x86_64',
      '../../target/i386/latx/include',
    ),
    dependencies: [dependency('threads'), cc.find_library('dl')],
  )

  test('kzt-bridge-concurrency', kzt_bridge_concurrency_test)

  kzt_bridge_atfork_fail_open_test = executable(
    'kzt-bridge-atfork-fail-open',
    files(
      'kzt/test_bridge_atfork_fail_open.c',
      'kzt/kzt_test_options.c',
      '../../target/i386/latx/context/bridge.c',
      '../../target/i386/latx/context/kzt_rela_runtime_bridge.c',
      '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
      '../../target/i386/latx/context/kzt_wrapper_probe.c',
      '../../target/i386/latx/context/kzt_bridge_exact.c',
    ),
    c_args: [
      '-DBRIDGE_TEST',
      '-DBRIDGE_TEST_ATFORK_FAIL',
      '-DCONFIG_LATX_KZT',
      '-DNEED_CPU_H',
      '-DCONFIG_TARGET="x86_64-linux-user-config-target.h"',
      '-DCONFIG_DEVICES="x86_64-linux-user-config-devices.h"',
    ],
    include_directories: include_directories(
      '../..',
      '../../target/i386',
      '../../linux-user/host/loongarch',
      '../../linux-user',
      '../../linux-user/x86_64',
      '../../target/i386/latx/include',
    ),
    dependencies: [dependency('threads'), cc.find_library('dl')],
  )

  test('kzt-bridge-atfork-fail-open', kzt_bridge_atfork_fail_open_test)

  test('kzt-bridge-atfork-diagnostics-off',
       kzt_bridge_atfork_fail_open_test, args: '--diagnostics-off')

  test(
    'kzt-wi1100-atfork-bridge-gate-source-contract',
    find_program('python3'),
    args: [
      files('kzt/test_wi1100_atfork_bridge_gate_source_contract.py'),
      meson.project_source_root(),
    ],
  )

  test('kzt-bridge-performance', kzt_bridge_concurrency_test,
       args: '--benchmark', timeout: 90, is_parallel: false)
endif

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
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
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
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: ['-DKZT_GUEST_LIBRARY_BINDING_TEST', '-DKZT_GUEST_REGISTRY_TEST'],
  include_directories: include_directories('../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-guest-library-binding-teardown',
     kzt_guest_library_binding_teardown_test)

kzt_guest_library_adapter_test = executable(
  'kzt-guest-library-adapter',
  files(
    'kzt/test_guest_library_adapter.c',
    '../../target/i386/latx/context/kzt_guest_library_adapter.c',
  ),
  c_args: [
    '-DCONFIG_LATX_KZT',
    '-DKZT_GUEST_LIBRARY_ADAPTER_TEST',
  ],
  include_directories: include_directories(
    '../..',
    '../../target/i386/latx/include',
  ),
)

test('kzt-guest-library-adapter', kzt_guest_library_adapter_test)

kzt_guest_dl_api_test = executable(
  'kzt-guest-dl-api',
  files(
    'kzt/test_guest_dl_api.c',
    '../../target/i386/latx/context/kzt_guest_dl_api.c',
    '../../target/i386/latx/context/kzt_guest_dl_init.c',
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
    '../../target/i386/latx/context/kzt_lazy_prebind_scope.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories(
    '../..',
    '../../target/i386/latx/include',
  ),
  dependencies: dependency('threads'),
)

test('kzt-guest-dl-api', kzt_guest_dl_api_test)

kzt_guest_dlclose_quiescence_test = executable(
  'kzt-guest-dlclose-quiescence',
  files(
    'kzt/test_guest_dlclose_quiescence.c',
    '../../target/i386/latx/context/kzt_guest_dl_api.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
  ),
  c_args: [
    '-DCONFIG_LATX_KZT',
    '-DKZT_GUEST_LIBRARY_BINDING_TEST',
    '-ffunction-sections',
    '-fdata-sections',
  ],
  link_args: [
    '-Wl,--gc-sections',
    '-Wl,--no-export-dynamic',
  ],
  include_directories: include_directories(
    '../..',
    '../../target/i386/latx/include',
  ),
  dependencies: dependency('threads'),
)

test('kzt-guest-dlclose-quiescence', kzt_guest_dlclose_quiescence_test)

kzt_dlopen_recycle_transaction_test = executable(
  'kzt-dlopen-recycle-transaction',
  files(
    'kzt/test_dlopen_recycle_transaction.c',
    '../../target/i386/latx/context/dlopen_recycle_transaction.c',
    '../../target/i386/latx/context/elf_plt_relocation.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
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
  'kzt-wi1021-dlerror-entry-source-contract',
  python3,
  args: [
    files('kzt/test_wi1021_dlerror_entry_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1098-thread-local-dl-state-source-contract',
  python3,
  args: [
    files('kzt/test_wi1098_thread_local_dl_state_source_contract.py'),
    meson.source_root(),
  ],
)
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

test(
  'kzt-wi600-guest-loader-gate-harness',
  python3,
  args: files('kzt/test_wi600_guest_loader_gate_harness.py'),
)

test(
  'kzt-real-guest-performance-harness',
  python3,
  args: files('kzt/test_real_guest_harness.py'),
)

test(
  'kzt-real-guest-loader-performance',
  python3,
  args: files('kzt/test_real_guest_loader_performance.py'),
)

test(
  'kzt-WI-601-real-guest-e2e-launcher',
  python3,
  args: files('kzt/test_wi601_real_guest_e2e_launcher.py'),
)

test(
  'kzt-WI-601-performance-fixture-contract',
  python3,
  args: [
    files('kzt/test_wi601_perf_fixture_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-WI-849-real-guest-preemption-launcher',
  python3,
  args: files('kzt/test_wi849_real_guest_preemption_launcher.py'),
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

kzt_guest_dynsym_lookup_test = executable(
  'kzt-guest-dynsym-lookup',
  files(
    'kzt/test_guest_dynsym_lookup.c',
    '../../target/i386/latx/context/kzt_guest_dynsym_lookup.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-guest-dynsym-lookup', kzt_guest_dynsym_lookup_test)

kzt_guest_symbol_scope_test = executable(
  'kzt-guest-symbol-scope',
  files(
    'kzt/test_guest_symbol_scope.c',
    '../../target/i386/latx/context/kzt_guest_symbol_scope.c',
    '../../target/i386/latx/context/kzt_guest_dynsym_lookup.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-guest-symbol-scope', kzt_guest_symbol_scope_test)

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
    '../../target/i386/latx/context/kzt_lazy_prebind_scope.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_dynamic_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
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
    '../../target/i386/latx/context/kzt_lazy_prebind_scope.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_dynamic_diagnostics.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
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
    'kzt/kzt_test_options.c',
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
    'kzt/kzt_test_options.c',
    '../../target/i386/latx/context/kzt_rela_stub_detector.c',
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
    'kzt/kzt_test_options.c',
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
    'kzt/kzt_test_options.c',
    '../../target/i386/latx/context/kzt_rela_runtime_bridge.c',
    '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_rela_stub_detector.c',
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

test(
  'kzt-wi601-jump-slot-single-writer-source-contract',
  python3,
  args: [
    files('kzt/test_wi601_jump_slot_single_writer_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi601-lazy-legacy-removal-source-contract',
  python3,
  args: [
    files('kzt/test_wi601_lazy_legacy_removal_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi962-guest-lifecycle-source-contract',
  python3,
  args: [
    files('kzt/test_wi962_guest_lifecycle_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi963-guest-symbol-source-contract',
  python3,
  args: [
    files('kzt/test_wi963_guest_symbol_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi973-namespace-source-contract',
  python3,
  args: [
    files('kzt/test_wi973_namespace_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi964-guest-dl-api-source-contract',
  python3,
  args: [
    files('kzt/test_wi964_guest_dl_api_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi979-guest-first-dlopen-source-contract',
  python3,
  args: [
    files('kzt/test_wi979_guest_first_dlopen_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi980-guest-first-dlclose-source-contract',
  python3,
  args: [
    files('kzt/test_wi980_guest_first_dlclose_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi602-handle-state-removal-source-contract',
  python3,
  args: [
    files('kzt/test_wi602_handle_state_removal_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi603-loader-hook-timing-source-contract',
  python3,
  args: [
    files('kzt/test_wi603_loader_hook_timing_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi603-callback-replacement-source-contract',
  python3,
  args: [
    files('kzt/test_wi603_callback_replacement_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1065-loader-hook-event-contract',
  python3,
  args: [
    files('kzt/test_wi1065_loader_hook_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1065-real-guest-hook-fixture-contract',
  python3,
  args: [
    files('kzt/test_wi1065_real_guest_hook_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1066-lazy-prebind-source-contract',
  python3,
  args: [
    files('kzt/test_wi1066_lazy_prebind_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1066-pinned-bridge-source-contract',
  python3,
  args: [
    files('kzt/test_wi1066_pinned_bridge_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1082-steady-diagnostics-source-contract',
  python3,
  args: [
    files('kzt/test_wi1082_steady_diagnostics_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1209-dlerror-bridge-fast-path-source-contract',
  python3,
  args: [
    files('kzt/test_wi1209_dlerror_bridge_fast_path_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1081-lifecycle-performance-source-contract',
  python3,
  args: [
    files('kzt/test_wi1081_lifecycle_performance_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1083-legacy-callback-removal-source-contract',
  python3,
  args: [
    files('kzt/test_wi1083_legacy_callback_removal_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1099-wrapper-provenance-source-contract',
  python3,
  args: [
    files('kzt/test_wi1099_wrapper_provenance_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1099-symbol-type-source-contract',
  python3,
  args: [
    files('kzt/test_wi1099_symbol_type_source_contract.py'),
    meson.source_root(),
  ],
)

kzt_loader_event_hook_test = executable(
  'kzt-loader-event-hook',
  files(
    'kzt/test_loader_event_hook.c',
    '../../target/i386/latx/context/kzt_loader_event_hook.c',
  ),
  c_args: ['-DKZT_LOADER_EVENT_HOOK_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-loader-event-hook', kzt_loader_event_hook_test)

kzt_lifecycle_snapshot_capacity_test = executable(
  'kzt-lifecycle-snapshot-capacity',
  files(
    'kzt/test_lifecycle_snapshot_capacity.c',
    '../../target/i386/latx/context/kzt_loader_lifecycle_snapshot.c',
    '../../target/i386/latx/context/kzt_loader_event_hook.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
  ),
  c_args: [
    '-DKZT_LOADER_EVENT_HOOK_TEST',
    '-DKZT_LOADER_LIFECYCLE_SNAPSHOT_TEST',
  ],
  include_directories: include_directories(
    '../..',
    '../../target/i386/latx/include',
  ),
  dependencies: dependency('threads'),
)

test('kzt-lifecycle-snapshot-capacity',
     kzt_lifecycle_snapshot_capacity_test)

kzt_lazy_prebind_scope_test = executable(
  'kzt-lazy-prebind-scope',
  files(
    'kzt/test_lazy_prebind_scope.c',
    '../../target/i386/latx/context/kzt_lazy_prebind_scope.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-lazy-prebind-scope', kzt_lazy_prebind_scope_test)

test(
  'kzt-wi1056-per-object-got-plt-source-contract',
  python3,
  args: [
    files('kzt/test_wi1056_per_object_got_plt_source_contract.py'),
    meson.source_root(),
  ],
)


test(
  'kzt-wi982-versioned-wrapper-selection-source-contract',
  python3,
  args: [
    files('kzt/test_wi982_versioned_wrapper_selection_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi987-guest-relocation-authority-source-contract',
  python3,
  args: [
    files('kzt/test_wi987_guest_relocation_authority_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi994-dlerror-tail-forward-source-contract',
  python3,
  args: [
    files('kzt/test_wi994_dlerror_tail_forward_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi995-lazy-direct-timing-source-contract',
  python3,
  args: [
    files('kzt/test_wi995_lazy_direct_timing_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi1007-context-resolver-source-contract',
  python3,
  args: [
    files('kzt/test_wi1007_context_resolver_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi995-lazy-bridge-translation-timing-source-contract',
  python3,
  args: [
    files('kzt/test_wi995_lazy_bridge_translation_timing_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi999-startup-observation-timing-source-contract',
  python3,
  args: [
    files('kzt/test_wi999_startup_observation_timing_source_contract.py'),
    meson.source_root(),
  ],
)

test(
  'kzt-wi999-context-init-timing-source-contract',
  python3,
  args: [
    files('kzt/test_wi999_context_init_timing_source_contract.py'),
    meson.source_root(),
  ],
)

kzt_wi256_lazy_binding_test = executable(
  'kzt-wi256-lazy-binding',
  files(
    'kzt/test_wi256_lazy_binding.c',
    '../../target/i386/latx/context/kzt_lazy_binding.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wi256-lazy-binding', kzt_wi256_lazy_binding_test)

kzt_wi837_lazy_direct_route_test = executable(
  'kzt-wi837-lazy-direct-route',
  files(
    'kzt/test_wi837_lazy_direct_route.c',
    '../../target/i386/latx/context/kzt_lazy_direct_route.c',
  ),
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-wi837-lazy-direct-route', kzt_wi837_lazy_direct_route_test)

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
    '../../target/i386/latx/context/kzt_lazy_prebind_scope.c',
    '../../target/i386/latx/context/kzt_lazy_direct_route.c',
    '../../target/i386/latx/context/kzt_jump_slot_production.c',
    '../../target/i386/latx/context/kzt_lifecycle_diagnostics.c',
    '../../target/i386/latx/context/kzt_jump_slot_route.c',
    '../../target/i386/latx/context/kzt_rela_runtime_bridge.c',
    '../../target/i386/latx/context/kzt_wrapper_bridge_provider.c',
    '../../target/i386/latx/context/kzt_wrapper_probe.c',
    '../../target/i386/latx/context/kzt_rela_stub_detector.c',
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
    '../../target/i386/latx/context/kzt_guest_registry_context.c',
    '../../target/i386/latx/context/kzt_guest_library_binding.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
    '../../target/i386/latx/context/kzt_guest_dynamic.c',
    '../../target/i386/latx/context/kzt_guest_dynsym_lookup.c',
    '../../target/i386/latx/context/kzt_guest_symbol_scope.c',
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
    'kzt/kzt_test_options.c',
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
