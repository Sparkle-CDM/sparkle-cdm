
fs = import('fs')
inc_path = fs.parent(meson.current_build_dir())
add_project_arguments(['-I' + inc_path], language: 'cpp')

subdir('mock-module')

sparkle_cdm_sources = [
  'system.cpp',
]

sparkle_cdm_headers = [
  'open_cdm.h',
  'open_cdm_adapter.h'
]

sparkle_cdm_deps = [
  dependency('gmodule-2.0'),
  dependency('gstreamer-1.0'),
]

sparkle_cdm_lib = shared_library('ocdm',
  sparkle_cdm_sources,
  dependencies: sparkle_cdm_deps,
  install: true,
)

install_headers(sparkle_cdm_headers, subdir: join_paths('WPEFramework', 'ocdm'))

pkg = import('pkgconfig')

pkg.generate(sparkle_cdm_lib,
  description: 'Sparkle CDM library',
         name: 'thunder',
     filebase: 'thunder',
      subdirs: 'thunder',
     requires: 'glib-2.0',
)

sparkle_cdm_dep = declare_dependency(link_with: sparkle_cdm_lib)

subdir('gst')

subdir('clearkey')
