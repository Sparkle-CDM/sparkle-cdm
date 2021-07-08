/*
 * Copyright 2021 Sparkle CDM Developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE X CONSORTIUM BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the sale,
 * use or other dealings in this Software without prior written
 * authorization.
 */

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
