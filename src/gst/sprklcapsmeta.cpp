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

#include <gst/gst.h>
#include "sprkl/sprklcapsmeta.h"

GType
sprkl_caps_meta_api_get_type (void)
{
  static GType type;
  static const gchar *tags[] = { NULL };

  if (g_once_init_enter (&type)) {
    GType _type = gst_meta_api_type_register ("SprklCapsMetaAPI", tags);
    g_once_init_leave (&type, _type);
  }
  return type;
}

static gboolean
sprkl_caps_meta_init (GstMeta * meta, G_GNUC_UNUSED gpointer params,
    G_GNUC_UNUSED GstBuffer * buffer)
{
  auto *sprkl_caps_meta = (SprklCapsMeta *) meta;

  sprkl_caps_meta->caps = NULL;
  return TRUE;
}

static void
sprkl_caps_meta_free (GstMeta * meta, G_GNUC_UNUSED GstBuffer * buffer)
{
  auto *sprkl_caps_meta = (SprklCapsMeta *) meta;

  if (sprkl_caps_meta->caps)
    gst_caps_unref (sprkl_caps_meta->caps);
}

static gboolean
sprkl_caps_meta_transform (GstBuffer * transbuf, GstMeta * meta,
    G_GNUC_UNUSED GstBuffer * buffer, GQuark type, gpointer data)
{
  auto *sprkl_caps_meta = (SprklCapsMeta *) meta;

  if (GST_META_TRANSFORM_IS_COPY (type)) {
    auto *copy = (GstMetaTransformCopy *) data;
    if (!copy->region) {
      /* only copy if the complete data is copied as well */
      sprkl_gst_buffer_add_caps_meta (transbuf,
          gst_caps_copy (sprkl_caps_meta->caps));
    } else {
      return FALSE;
    }
  } else {
    /* transform type not supported */
    return FALSE;
  }
  return TRUE;
}

const GstMetaInfo *
sprkl_caps_meta_get_info (void)
{
  static const GstMetaInfo *sprkl_caps_meta_info = NULL;

  if (g_once_init_enter ((GstMetaInfo **) & sprkl_caps_meta_info)) {
    const GstMetaInfo *meta =
        gst_meta_register (SPRKL_CAPS_META_API_TYPE, "SprklCapsMeta",
        sizeof (SprklCapsMeta), sprkl_caps_meta_init,
        sprkl_caps_meta_free, sprkl_caps_meta_transform);

    g_once_init_leave ((GstMetaInfo **) & sprkl_caps_meta_info,
        (GstMetaInfo *) meta);
  }
  return sprkl_caps_meta_info;
}

SprklCapsMeta *
sprkl_gst_buffer_add_caps_meta (GstBuffer * buffer, GstCaps * caps)
{
  SprklCapsMeta *meta;

  g_return_val_if_fail (GST_IS_BUFFER (buffer), NULL);
  g_return_val_if_fail (caps != NULL, NULL);

  meta =
      (SprklCapsMeta *) gst_buffer_add_meta (buffer, SPRKL_CAPS_META_INFO,
      NULL);

  meta->caps = caps;

  return meta;
}
