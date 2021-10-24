
if get_option('clearkey-module').disabled()
  subdir_done()
endif

dependencies = [
  dependency('gio-2.0'),
  dependency('glib-2.0'),
  dependency('gpg-error'),
  dependency('gstreamer-1.0'),
  dependency('gstreamer-base-1.0'),
  dependency('json-glib-1.0'),
  dependency('libgcrypt'),
]

sources = [
  'module.cpp',
  'session.cpp',
  'system.cpp',
]

shared_library('sparkle-cdm-clearkey', sources, dependencies: dependencies, install: true,
               install_dir : get_option('prefix') / get_option('libdir') / 'sparkle-cdm')
