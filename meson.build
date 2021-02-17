project('sparkle-cdm', 'cpp',
          version: '0.1.0',
    meson_version: '>= 0.55.3',
  default_options: [ 'warning_level=2',
                     'cpp_std=c++17',
                     'buildtype=debugoptimized'
                   ],
)

config_h = configuration_data()
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
config_h.set_quoted('EXTERNAL_MODULE_PATH', get_option('prefix') / get_option('libdir') / 'sparkle-cdm')

configure_file(output: 'sparkle-cdm-config.h',
        configuration: config_h)

add_project_arguments(['-I' + meson.build_root()], language: 'cpp')

subdir('src')
