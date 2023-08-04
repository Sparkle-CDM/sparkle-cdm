// SPDX-License-Identifier: MIT

#pragma once

#include <glib.h>
#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>
#include "open_cdm.h"

G_BEGIN_DECLS

#define SPKL_TYPE_DECRYPTOR (spkl_decryptor_get_type())
#define SPKL_DECRYPTOR(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), SPKL_TYPE_DECRYPTOR, SparkleDecryptor))
#define SPKL_DECRYPTOR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), SPKL_TYPE_DECRYPTOR, SparkleDecryptorClass))

GType spkl_decryptor_get_type(void);

struct SparkleDecryptor {
    GstBaseTransform parent;

    GstEvent* protectionEvent;

    struct OpenCDMSystem* system;
    struct OpenCDMSession* session;
    struct OpenCDMSession* pending_session;
    OpenCDMSessionCallbacks sessionCallbacks;
    gboolean provisioned;
    gboolean clearBufferNotified;

    GMarkupParser markupParser;
    GMarkupParseContext *markupParseContext;
    gboolean parsingPssh;
    GBytes* pssh;
    gchar* kid;

    GMutex cdmAttachmentMutex;
    GCond cdmAttachmentCondition;
};

struct SparkleDecryptorClass {
    GstBaseTransformClass parentClass;
};

G_END_DECLS
