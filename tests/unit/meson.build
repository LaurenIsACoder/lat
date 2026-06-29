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
