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


kzt_observation_adapter_test = executable(
  'kzt-observation-adapter',
  files(
    'kzt/test_observation_adapter.c',
    '../../target/i386/latx/context/kzt_guest_registry.c',
    '../../target/i386/latx/context/kzt_guest_link_map_reader.c',
    '../../target/i386/latx/context/kzt_observation_adapter.c',
  ),
  c_args: ['-DKZT_GUEST_REGISTRY_TEST', '-DKZT_GUEST_LINK_MAP_READER_TEST'],
  include_directories: include_directories('../..', '../../target/i386/latx/include'),
  dependencies: dependency('threads'),
)

test('kzt-observation-adapter', kzt_observation_adapter_test)
