

sprkl_gst_deps = [ dependency('gstreamer-1.0'),
                   dependency('gstreamer-base-1.0'),
                   dependency('uuid'),
                   sparkle_cdm_dep,
                 ]

sprkl_gst_lib = shared_library('gstsprkl', ['decryptor.cpp', 'plugin.cpp', 'sprklcapsmeta.cpp'],
                         dependencies: sprkl_gst_deps,
                         install_dir: get_option('prefix') / get_option('libdir') / 'gstreamer-1.0',
                         install: true)

sparkle_cdm_gst_headers = []
foreach f: ['sprklcapsmeta.h', 'sprklgst.h']
  sparkle_cdm_gst_headers += 'sprkl' / f
endforeach

install_headers(sparkle_cdm_gst_headers)

pkg = import('pkgconfig')

pkg.generate(sprkl_gst_lib,
             description: 'Sparkle-CDM GStreamer library',
             name: 'sprkl-gst',
             filebase: 'sprkl-gst-1.0',
             requires: 'gstreamer-1.0',
             subdirs : ['sprkl'],
             install_dir : get_option('prefix') / get_option('libdir') / 'pkgconfig'
            )


libsinc = include_directories('.')
sprkl_gst_dep = declare_dependency(link_with : sprkl_gst_lib,
                                   include_directories : [libsinc],
                                   dependencies : sprkl_gst_deps
                                  )

meson.override_dependency('sprkl-gst-1.0', sprkl_gst_dep)
