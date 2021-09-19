// SPDX-License-Identifier: MIT

#include "sparkle-cdm-config.h"
#include "decryptor.h"
#include <gst/gst.h>

static gboolean
plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, "sprkldecryptor", GST_RANK_PRIMARY,
      SPKL_TYPE_DECRYPTOR);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    sprkl,
    "Sparkle-CDM",
    plugin_init,
    PACKAGE_VERSION, "LGPL", "sparkle-cdm", "https://github.com/Sparkle-CDM")
