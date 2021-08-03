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

#include "decryptor.h"
#include "open_cdm_adapter.h"
#include "sprkl/sprklgst.h"

#define WIDEVINE_UUID "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"

/**
 *
 * This decryptor is meant to be used in non-web-browser applications. The
 * use-case is currently limited to:
 * - DASH
 * - Audio only (Flac, Opus, AAC)
 * - Widevine
 *
 * Media players relying on playbin should be able to make use of this
 * decryptor, that would be automatically plugged internally as required,
 * whenever an encrypted data stream has been detected by demuxers.
 *
 * The application is expected to synchronously handle GstMessages sent by the
 * decryptor. The workflow is the following:
 *
 * 0. Application should listen on the bus for synchronous `need-context`
 * messages asking for `drm-preferred-decryption-system-id` context types. For
 * now as we support only Widevine, the corresponding UUID should be set on the
 * `decryption-system-id` field of the context structure.
 *
 * 1. (optional) Parse custom ContentProtection payload that might be included
 * in the manifest. This payload is included in the `spkl-protection` structure
 * which has 2 fields: `payload` (GstBuffer) and `origin` (string, example:
 * `dash/mpd`). This can be useful for manifests that include license server
 * URLs in the ContentProtection XML, for instance. The decryptor already keeps
 * track of the init data (PSSH), so applications do not need to handle this
 * part.
 *
 * 2. Once the decryptor has received a license challenge from the underlying
 * CDM, it emits a `spkl-challenge` message, which the application needs to
 * forward to the license server. The message structure embeds the data in a
 * `challenge` GstBuffer. Application developer should refer to the
 * content-provider documentation regarding the challenge submission process.
 * For DASH this is often handled with a POST HTTPs request.
 *
 * 3. Once the license server has provided a response to the challenge request,
 * this response needs to be sent to the decryptor, using a custom downstream
 * OOB event that includes a `spkl-session-update` structure containing one
 * `message` GstBuffer field that represents the unprocessed response.
 *
 * An example player is provided, see examples/sample-player.c.
 *
 */

GST_DEBUG_CATEGORY_STATIC (spkl_decryptor_debug_category);
#define GST_CAT_DEFAULT spkl_decryptor_debug_category

static GstStaticPadTemplate sinkTemplate =
    GST_STATIC_PAD_TEMPLATE ("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
    GST_STATIC_CAPS
    ("application/x-cenc, original-media-type=(string)audio/x-flac, "
        "protection-system=(string)" WIDEVINE_UUID ";"
        "application/x-cenc, original-media-type=(string)audio/x-opus, "
        "protection-system=(string)" WIDEVINE_UUID ";"
        "application/x-cenc, original-media-type=(string)audio/mpeg, "
        "protection-system=(string)" WIDEVINE_UUID ";"));

static GstStaticPadTemplate srcTemplate =
    GST_STATIC_PAD_TEMPLATE ("src", GST_PAD_SRC, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("audio/x-opus; audio/x-flac; audio/mpeg"));

#define spkl_decryptor_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (SparkleDecryptor, spkl_decryptor,
    GST_TYPE_BASE_TRANSFORM,
    GST_DEBUG_CATEGORY_INIT (spkl_decryptor_debug_category,
        "sprklwvdecryptor", 0, "Sparkle decryptor"););

static void
spklProcessChallenge (G_GNUC_UNUSED struct OpenCDMSession *session,
    void *userData, const char url[], const uint8_t challenge[],
    const uint16_t challengeLength)
{
  auto *self = SPKL_DECRYPTOR (userData);

  GST_DEBUG_OBJECT (self, "Challenge received from CDM");
  if (challenge[0] != '0') {
    GST_DEBUG_OBJECT (self, "Ignoring message different than license-request");
    return;
  }

  g_autoptr (GstBus) bus = gst_element_get_bus (GST_ELEMENT_CAST (self));
  g_autoptr (GBytes) challengeData =
      g_bytes_new (challenge + 7, challengeLength - 7);
  GST_MEMDUMP_OBJECT (self, "Challenge:", challenge + 7, challengeLength - 7);
  g_autoptr (GstBuffer) challengeBuffer =
      gst_buffer_new_wrapped_bytes (challengeData);
  gst_bus_post (bus, gst_message_new_element (GST_OBJECT_CAST (self),
          gst_structure_new ("spkl-challenge", "challenge", GST_TYPE_BUFFER,
              challengeBuffer, "url", G_TYPE_STRING, url, "session-id",
              G_TYPE_STRING, GST_OBJECT_NAME (self), nullptr)));
}

static void
spklKeyUpdate (struct OpenCDMSession *session, void *userData,
    const uint8_t keyId[], const uint8_t length)
{
  auto *self = SPKL_DECRYPTOR (userData);

  GST_MEMDUMP_OBJECT (self, "keyID:", keyId, length);
  auto status = opencdm_session_status (session, keyId, length);
  GST_DEBUG_OBJECT (self, "Got new key update to %d", status);

  if (status == Usable) {
    g_mutex_lock (&self->cdmAttachmentMutex);
    self->provisioned = TRUE;
    g_cond_signal (&self->cdmAttachmentCondition);
    g_mutex_unlock (&self->cdmAttachmentMutex);
  }

  if (status != Expired)
    return;

  g_autoptr (GstBus) bus = gst_element_get_bus (GST_ELEMENT_CAST (self));
  g_autoptr (GBytes) key = g_bytes_new (keyId, length);
  g_autoptr (GstBuffer) keyBuffer = gst_buffer_new_wrapped_bytes (key);
  const gchar *sessionId = opencdm_session_id (session);
  gst_bus_post (bus, gst_message_new_element (GST_OBJECT_CAST (self),
          gst_structure_new ("spkl-key-expired", "key", GST_TYPE_BUFFER,
              keyBuffer, "session-id", G_TYPE_STRING, sessionId, nullptr)));
}

static void
spklErrorMessage (G_GNUC_UNUSED struct OpenCDMSession *session, void *userData,
    const char message[])
{
  auto *self = SPKL_DECRYPTOR (userData);
  GST_ERROR_OBJECT (self, "Error! %s", message);
}

static void
spklKeysUpdated (G_GNUC_UNUSED const struct OpenCDMSession *session,
    void *userData)
{
  auto *self = SPKL_DECRYPTOR (userData);
  GST_DEBUG_OBJECT (self, "All keys updated, starting decryption");
  g_mutex_lock (&self->cdmAttachmentMutex);
  self->provisioned = TRUE;
  g_cond_signal (&self->cdmAttachmentCondition);
  g_mutex_unlock (&self->cdmAttachmentMutex);
}

static void
markupStartElement (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * element_name,
    G_GNUC_UNUSED const gchar ** attribute_names,
    G_GNUC_UNUSED const gchar ** attribute_values, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  auto *self = SPKL_DECRYPTOR (user_data);
  if (g_str_has_suffix (element_name, "pssh")) {
    self->parsingPssh = TRUE;
  }
}

static void
markupEndElement (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * element_name, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  auto *self = SPKL_DECRYPTOR (user_data);
  if (g_str_has_suffix (element_name, "pssh")) {
    self->parsingPssh = FALSE;
  }
}

static void
markupText (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * text, gsize text_len, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  auto *self = SPKL_DECRYPTOR (user_data);
  if (self->parsingPssh) {
    if (self->pssh)
      g_free (self->pssh);
    g_autofree gchar *encodedPssh = g_strndup (text, text_len);
    gsize len;
    guchar *pssh = g_base64_decode (encodedPssh, &len);
    GST_MEMDUMP_OBJECT (self, "pssh", (const guint8 *) pssh, len);
    self->pssh = g_bytes_new_take (pssh, len);
  }
}

static void
markupPassthrough (G_GNUC_UNUSED GMarkupParseContext * context,
    G_GNUC_UNUSED const gchar * passthrough_text,
    G_GNUC_UNUSED gsize text_len, G_GNUC_UNUSED gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
}

static void
markupError (G_GNUC_UNUSED GMarkupParseContext * context,
    G_GNUC_UNUSED GError * error, G_GNUC_UNUSED gpointer user_data)
{
}

static void
spkl_decryptor_init (SparkleDecryptor * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);
  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (base, FALSE);

  self->system = nullptr;
  self->session = nullptr;
  self->sessionCallbacks.process_challenge_callback = spklProcessChallenge;
  self->sessionCallbacks.key_update_callback = spklKeyUpdate;
  self->sessionCallbacks.error_message_callback = spklErrorMessage;
  self->sessionCallbacks.keys_updated_callback = spklKeysUpdated;
  self->provisioned = FALSE;

  self->markupParser.start_element = markupStartElement;
  self->markupParser.end_element = markupEndElement;
  self->markupParser.text = markupText;
  self->markupParser.passthrough = markupPassthrough;
  self->markupParser.error = markupError;
  self->markupParseContext =
      g_markup_parse_context_new (&self->markupParser, (GMarkupParseFlags) 0,
      gst_object_ref (GST_OBJECT_CAST (self)),
      (GDestroyNotify) gst_object_unref);
  self->parsingPssh = FALSE;

  self->currentSrcCaps = nullptr;
  g_cond_init (&self->cdmAttachmentCondition);
  g_mutex_init (&self->cdmAttachmentMutex);
}

static gboolean
proposeAllocation (GstBaseTransform *, GstQuery *, GstQuery *)
{
  return FALSE;
}

static GstCaps *
transformCaps (GstBaseTransform * base, GstPadDirection direction,
    GstCaps * caps, GstCaps * filter)
{
  if (direction == GST_PAD_UNKNOWN)
    return nullptr;

  GST_DEBUG_OBJECT (base,
      "direction: %s, caps: %" GST_PTR_FORMAT " filter: %" GST_PTR_FORMAT,
      (direction == GST_PAD_SRC) ? "src" : "sink", caps, filter);

  GstCaps *transformedCaps = gst_caps_new_empty ();
  auto *self = SPKL_DECRYPTOR (base);

  unsigned size = gst_caps_get_size (caps);
  for (unsigned i = 0; i < size; ++i) {
    GstStructure *incomingStructure = gst_caps_get_structure (caps, i);
    const char *encryptionScheme = gst_structure_get_name (incomingStructure);
    g_autoptr (GstStructure) outgoingStructure = nullptr;

    if (direction == GST_PAD_SINK) {
      if (!gst_structure_has_field (incomingStructure, "original-media-type"))
        continue;

      outgoingStructure = gst_structure_copy (incomingStructure);
      gst_structure_set_name (outgoingStructure,
          gst_structure_get_string (outgoingStructure, "original-media-type"));

      // Filter out the DRM related fields from the down-stream caps.
      gst_structure_remove_fields (outgoingStructure, "protection-system",
          "original-media-type", "encryption-algorithm",
          "encoding-scope", "cipher-mode", nullptr);
    } else {
      outgoingStructure = gst_structure_copy (incomingStructure);
      // Filter out the video related fields from the up-stream caps,
      // because they are not relevant to the input caps of this element and
      // can cause caps negotiation failures with adaptive bitrate streams.
      gst_structure_remove_fields (outgoingStructure, "base-profile",
          "codec_data", "height", "framerate", "level",
          "pixel-aspect-ratio", "profile", "rate", "width", nullptr);

      gst_structure_set (outgoingStructure, "protection-system", G_TYPE_STRING,
          WIDEVINE_UUID, "original-media-type", G_TYPE_STRING,
          gst_structure_get_name (incomingStructure), nullptr);

      gst_structure_set_name (outgoingStructure, encryptionScheme);
    }

    bool duplicate = false;
    unsigned size = gst_caps_get_size (transformedCaps);

    for (unsigned index = 0; !duplicate && index < size; ++index) {
      GstStructure *structure = gst_caps_get_structure (transformedCaps, index);
      if (gst_structure_is_equal (structure, outgoingStructure))
        duplicate = true;
    }

    /* *INDENT-OFF* */
    if (!duplicate)
      gst_caps_append_structure (transformedCaps,
          reinterpret_cast<GstStructure*>(g_steal_pointer (&outgoingStructure)));
    /* *INDENT-ON* */
  }

  if (filter) {
    GstCaps *intersection;

    GST_DEBUG_OBJECT (base, "Using filter caps %" GST_PTR_FORMAT, filter);
    intersection = gst_caps_intersect_full (transformedCaps, filter,
        GST_CAPS_INTERSECT_FIRST);
    gst_caps_unref (transformedCaps);
    transformedCaps = intersection;
  }

  GST_DEBUG_OBJECT (base, "current src caps: %" GST_PTR_FORMAT,
      self->currentSrcCaps);
  GST_DEBUG_OBJECT (base, "transformedCaps:  %" GST_PTR_FORMAT,
      transformedCaps);
  if (!self->currentSrcCaps) {
    self->currentSrcCaps = gst_caps_ref (transformedCaps);
    gst_base_transform_update_src_caps (base, transformedCaps);
  } else if (!gst_caps_is_equal (self->currentSrcCaps, transformedCaps)) {
    self->currentSrcCaps = gst_caps_ref (transformedCaps);
    gst_base_transform_update_src_caps (base, transformedCaps);
  }

  GST_DEBUG_OBJECT (base, "returning %" GST_PTR_FORMAT, transformedCaps);
  return transformedCaps;
}

static GstFlowReturn
transformInPlace (GstBaseTransform * base, GstBuffer * buffer)
{
  auto *self = SPKL_DECRYPTOR (base);
  /* *INDENT-OFF* */
  auto *protectionMeta = reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta (buffer));
  /* *INDENT-ON* */

  if (!protectionMeta) {
    GST_TRACE_OBJECT (self,
        "Buffer %p does not contain protection meta, not decrypting", buffer);
    return GST_FLOW_OK;
  }

  g_mutex_lock (&self->cdmAttachmentMutex);

  unsigned ivSize;
  if (!gst_structure_get_uint (protectionMeta->info, "iv_size", &ivSize)) {
    GST_ERROR_OBJECT (self, "Failed to get iv_size");
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_NOT_SUPPORTED;
  }

  gboolean encrypted;
  if (!gst_structure_get_boolean (protectionMeta->info, "encrypted",
          &encrypted)) {
    GST_ERROR_OBJECT (self, "Failed to get encrypted flag");
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_NOT_SUPPORTED;
  }

  if (!ivSize || !encrypted) {
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_OK;
  }

  unsigned subSampleCount;
  if (!gst_structure_get_uint (protectionMeta->info, "subsample_count",
          &subSampleCount)) {
    GST_ERROR_OBJECT (self, "Failed to get subsample_count");
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_NOT_SUPPORTED;
  }

  const GValue *value;
  GstBuffer *subSamplesBuffer = nullptr;
  if (subSampleCount) {
    value = gst_structure_get_value (protectionMeta->info, "subsamples");
    if (!value) {
      GST_ERROR_OBJECT (self, "Failed to get subsamples");
      g_mutex_unlock (&self->cdmAttachmentMutex);
      return GST_FLOW_NOT_SUPPORTED;
    }
    subSamplesBuffer = gst_value_get_buffer (value);
    if (!subSamplesBuffer) {
      GST_ERROR_OBJECT (self,
          "There is no subsamples buffer, but a positive subsample count");
      g_mutex_unlock (&self->cdmAttachmentMutex);
      return GST_FLOW_NOT_SUPPORTED;
    }
  }

  value = gst_structure_get_value (protectionMeta->info, "kid");
  if (!value) {
    GST_ERROR_OBJECT (self, "Failed to get key id for buffer");
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_NOT_SUPPORTED;
  }
  GstBuffer *keyIDBuffer = gst_value_get_buffer (value);

  value = gst_structure_get_value (protectionMeta->info, "iv");
  if (!value) {
    GST_ERROR_OBJECT (self, "Failed to get IV for sample");
    g_mutex_unlock (&self->cdmAttachmentMutex);
    return GST_FLOW_NOT_SUPPORTED;
  }

  GstBuffer *ivBuffer = gst_value_get_buffer (value);

  if (!self->provisioned) {
    auto endTime = g_get_monotonic_time () + 10 * G_TIME_SPAN_SECOND;
    while (!self->provisioned) {
      if (!g_cond_wait_until (&self->cdmAttachmentCondition,
              &self->cdmAttachmentMutex, endTime)) {
        GST_ERROR_OBJECT
            (self, "CDM still not configured after 10 seconds of waiting");
        g_mutex_unlock (&self->cdmAttachmentMutex);
        return GST_FLOW_NOT_SUPPORTED;
      }
    }
  }

  auto *sinkPad = GST_BASE_TRANSFORM_SINK_PAD (self);
  GstCaps *inputCaps = gst_pad_get_current_caps (sinkPad);
  auto *capsMeta = sprkl_gst_buffer_add_caps_meta (buffer, inputCaps);

  auto result = opencdm_gstreamer_session_decrypt (self->session, buffer,
      subSamplesBuffer, subSampleCount, ivBuffer, keyIDBuffer, 0);

  g_mutex_unlock (&self->cdmAttachmentMutex);

  if (result != ERROR_NONE) {
    auto *srcPad = GST_BASE_TRANSFORM_SRC_PAD (self);
    g_autoptr (GstCaps) outputCaps = gst_pad_get_current_caps (srcPad);
    auto *structure = gst_caps_get_structure (outputCaps, 0);
    const char *mediaType = gst_structure_get_name (structure);

    /* *INDENT-OFF* */
    gst_buffer_remove_meta (buffer, reinterpret_cast<GstMeta*>(capsMeta));
    /* *INDENT-ON* */

    GST_WARNING_OBJECT (self,
        "Decryption failed for %s (caps: %" GST_PTR_FORMAT ")",
        mediaType, inputCaps);
    GST_ERROR_OBJECT (self, "Decryption failed");
    return GST_FLOW_NOT_SUPPORTED;
  }

  /* *INDENT-OFF* */
  gst_buffer_remove_meta (buffer, reinterpret_cast<GstMeta*>(protectionMeta));
  gst_buffer_remove_meta (buffer, reinterpret_cast<GstMeta*>(capsMeta));
  /* *INDENT-ON* */

  return GST_FLOW_OK;
}

static gboolean
sinkEventHandler (GstBaseTransform * trans, GstEvent * event)
{
  auto *self = SPKL_DECRYPTOR (trans);
  gboolean result = FALSE;
  gboolean forward = TRUE;

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_PROTECTION:{
      const gchar *systemId;
      const gchar *origin;
      GstBuffer *protectionData;
      GST_DEBUG_OBJECT (self, "Got protection event %" GST_PTR_FORMAT, event);
      gst_event_parse_protection (event, &systemId, &protectionData, &origin);

      if (g_str_equal (origin, "dash/mpd")
          && g_str_equal (systemId, WIDEVINE_UUID)) {

        if (opencdm_is_type_supported ("com.widevine.alpha",
                nullptr) != ERROR_NONE) {
          GST_ERROR_OBJECT (self, "No Widevine support detected");
          break;
        }
        // Send the protection data to the app so it can parse potentially non-spec compliant markup.
        g_autoptr (GstBus) bus = gst_element_get_bus (GST_ELEMENT_CAST (self));
        gst_bus_post (bus, gst_message_new_element (GST_OBJECT_CAST (self),
                gst_structure_new ("spkl-protection", "payload",
                    GST_TYPE_BUFFER, protectionData, "origin", G_TYPE_STRING,
                    origin, nullptr)));

        GstMapInfo info GST_MAP_INFO_INIT;
        gst_buffer_map (protectionData, &info, GST_MAP_READ);
        GST_MEMDUMP_OBJECT (self, "data", info.data, info.size);

        g_autoptr (GError) error = NULL;
        if (!g_markup_parse_context_parse (self->markupParseContext,
                (const gchar *) info.data, info.size, &error)) {
          GST_WARNING_OBJECT (self, "XML parse error: %s", error->message);
          gst_buffer_unmap (protectionData, &info);
          break;
        }
        gst_buffer_unmap (protectionData, &info);

        self->system = opencdm_create_system ("com.widevine.alpha");
        gsize pssh_size;
        gconstpointer pssh_data = g_bytes_get_data (self->pssh, &pssh_size);
        opencdm_construct_session (self->system, Temporary, "cenc",
            (const uint8_t *) pssh_data, pssh_size, nullptr, 0,
            &self->sessionCallbacks, self, &self->session);
        GST_DEBUG_OBJECT (self, "Session: %p", self->session);
        if (self->session) {
          forward = FALSE;
          result = TRUE;
          gst_event_unref (event);
        }
      } else {
        GST_DEBUG_OBJECT (self, "Unhandled protection event %" GST_PTR_FORMAT,
            event);
      }
      break;
    }
    case GST_EVENT_CUSTOM_DOWNSTREAM_OOB:{
      if (gst_event_has_name (event, "spkl-session-update")) {
        GST_DEBUG_OBJECT (self, "Updating session");
        const auto *structure = gst_event_get_structure (event);
        GstBuffer *message;
        gst_structure_get (structure, "message", GST_TYPE_BUFFER, &message,
            nullptr);
        GstMapInfo info GST_MAP_INFO_INIT;
        gst_buffer_map (message, &info, GST_MAP_READ);
        auto success =
            opencdm_session_update (self->session, info.data, info.size);
        gst_buffer_unmap (message, &info);
        if (success == ERROR_NONE) {
          forward = FALSE;
          result = TRUE;
          gst_event_unref (event);
        }
        break;
      }
    }
    default:
      break;
  }

  if (forward)
    result = GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
  return result;
}

static GstStateChangeReturn
changeState (GstElement * element, GstStateChange transition)
{
  auto *self = SPKL_DECRYPTOR (element);

  switch (transition) {
    case GST_STATE_CHANGE_PAUSED_TO_READY:
      GST_DEBUG_OBJECT (self, "PAUSED->READY");
      g_cond_signal (&self->cdmAttachmentCondition);
      break;
    default:
      break;
  }

  return GST_ELEMENT_CLASS (parent_class)->change_state (element, transition);
}

static void
spkl_decryptor_dispose (GObject * object)
{
  auto *self = SPKL_DECRYPTOR (object);

  if (self->session) {
    opencdm_destruct_session (self->session);
    self->session = nullptr;
  }

  if (self->system) {
    opencdm_destruct_system (self->system);
    self->system = nullptr;
  }

  if (self->currentSrcCaps)
    gst_caps_unref (self->currentSrcCaps);

  if (self->pssh)
    g_bytes_unref (self->pssh);

  g_markup_parse_context_unref (self->markupParseContext);
  g_cond_clear (&self->cdmAttachmentCondition);
  g_mutex_clear (&self->cdmAttachmentMutex);
}

static void
spkl_decryptor_class_init (SparkleDecryptorClass * klass)
{
  GObjectClass *gobjectClass = G_OBJECT_CLASS (klass);
  gobjectClass->dispose = spkl_decryptor_dispose;

  GstBaseTransformClass *baseTransformClass = GST_BASE_TRANSFORM_CLASS (klass);
  baseTransformClass->transform_ip = GST_DEBUG_FUNCPTR (transformInPlace);
  baseTransformClass->transform_caps = GST_DEBUG_FUNCPTR (transformCaps);
  baseTransformClass->transform_ip_on_passthrough = FALSE;
  baseTransformClass->sink_event = GST_DEBUG_FUNCPTR (sinkEventHandler);
  baseTransformClass->propose_allocation =
      GST_DEBUG_FUNCPTR (proposeAllocation);

  GstElementClass *elementClass = GST_ELEMENT_CLASS (klass);
  gst_element_class_add_pad_template (elementClass,
      gst_static_pad_template_get (&sinkTemplate));
  gst_element_class_add_pad_template (elementClass,
      gst_static_pad_template_get (&srcTemplate));

  elementClass->change_state = GST_DEBUG_FUNCPTR (changeState);

  gst_element_class_set_static_metadata (elementClass,
      "Decrypt content using the Sparkle-CDM framework",
      GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
      "Decrypts media using Sparkle-CDM",
      "Sparkle-CDM Developers");
}
