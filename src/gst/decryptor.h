/*
 * Copyright (c) 2021, Sparkle-CDM Developers
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
    GstCaps* currentSrcCaps;

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

    GMutex cdmAttachmentMutex;
    GCond cdmAttachmentCondition;
};

struct SparkleDecryptorClass {
    GstBaseTransformClass parentClass;
};

G_END_DECLS
