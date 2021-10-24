// SPDX-License-Identifier: MIT

#pragma once

#include "open_cdm.h"
#include <glib.h>
#include <gst/gst.h>
#include <string>

GST_DEBUG_CATEGORY_EXTERN(cdm_debug_category);

G_BEGIN_DECLS

// https://www.w3.org/TR/eme-initdata-cenc/#common-system
#define CLEARKEY_UUID "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b"
const uint8_t cencSystemId[] = { 0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02, 0xac, 0xe3, 0x3c, 0x1e, 0x52, 0xe2, 0xfb, 0x4b };
const unsigned cencSystemIdSize = sizeof(cencSystemId);

#define TRACE_MARKER GST_INFO("%s", "")
#define UNUSED_PARAM(variable) (void)variable

G_END_DECLS
