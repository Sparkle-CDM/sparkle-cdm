fs = import('fs')
inc_path = fs.parent(meson.current_source_dir())
add_project_arguments(['-I' + inc_path], language: 'cpp')

mock_lib = shared_library('sparkle-cdm-mock', ['mock.cpp'],
                          dependencies: [ dependency('gstreamer-1.0')], install: false)
