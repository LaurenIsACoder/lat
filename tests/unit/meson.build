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
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST', '-DKZT_GUEST_LINK_MAP_READER_TEST'],
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

kzt_patch_spike_guard_test = executable(
  'kzt-patch-spike-guard',
  files(
    'kzt/test_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-patch-spike-guard', kzt_patch_spike_guard_test)

kzt_patch_spike_writer_test = executable(
  'kzt-patch-spike-writer',
  files(
    'kzt/test_patch_spike_writer.c',
    '../../target/i386/latx/context/kzt_patch_planner.c',
    '../../target/i386/latx/context/kzt_patch_spike_guard.c',
    '../../target/i386/latx/context/kzt_patch_spike_writer.c',
  ),
  c_args: ['-DCONFIG_LATX_KZT'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
)

test('kzt-patch-spike-writer', kzt_patch_spike_writer_test)
