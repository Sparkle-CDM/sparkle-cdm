
if get_option('sample-player').enabled()
  executable('sprkl-sample-player', 'sample-player.c',
             install : true,
             install_dir : get_option('prefix') / get_option('bindir'),
             dependencies : [dependency('glib-2.0'),
                             dependency('gstreamer-1.0'),
                             dependency('libsoup-3.0')])
endif
