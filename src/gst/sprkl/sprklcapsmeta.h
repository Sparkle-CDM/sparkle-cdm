// SPDX-License-Identifier: MIT

#pragma once

typedef struct _SprklCapsMeta SprklCapsMeta;

struct _SprklCapsMeta
{
  GstMeta meta;

  GstCaps *caps;
};

GType sprkl_caps_meta_api_get_type (void);

#define SPRKL_CAPS_META_API_TYPE (sprkl_caps_meta_api_get_type())

#define sprkl_gst_buffer_get_caps_meta(b)                               \
  ((SprklCapsMeta*)gst_buffer_get_meta ((b), SPRKL_CAPS_META_API_TYPE))

#define SPRKL_CAPS_META_INFO (sprkl_caps_meta_get_info())

const GstMetaInfo * sprkl_caps_meta_get_info (void);

SprklCapsMeta * sprkl_gst_buffer_add_caps_meta (GstBuffer * buffer, GstCaps * caps);
