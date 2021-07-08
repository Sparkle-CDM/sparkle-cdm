
if get_option('sample-player').enabled()
  executable('sample-player', 'sample-player.c',
             install : true,
             install_dir : get_option('prefix') / get_option('bindir'),
             dependencies : [dependency('glib-2.0'),
                             dependency('gstreamer-1.0'),
                             dependency('libsoup-2.4')])
endif
