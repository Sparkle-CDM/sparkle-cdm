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
#include <libsoup/soup.h>

static GMainLoop *loop;
static GstElement *pipeline;
static GstBus *bus1;

#define WIDEVINE_UUID "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
#define LICENSE_SERVER "https://drm-widevine-licensing.axtest.net/AcquireLicense"

// https://github.com/Axinom/public-test-vectors
#define URI "https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_AudioOnly.mpd"
#define TOKEN "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoxLCJjb21fa2V5X2lkIjoiYjMzNjRlYjUtNTFmNi00YWUzLThjOTgtMzNjZWQ1ZTMxYzc4IiwibWVzc2FnZSI6eyJ0eXBlIjoiZW50aXRsZW1lbnRfbWVzc2FnZSIsImtleXMiOlt7ImlkIjoiOWViNDA1MGQtZTQ0Yi00ODAyLTkzMmUtMjdkNzUwODNlMjY2IiwiZW5jcnlwdGVkX2tleSI6ImxLM09qSExZVzI0Y3Iya3RSNzRmbnc9PSJ9XX19.4lWwW46k-oWcah8oN18LPj5OLS5ZU-_AQv7fe0JhNjA"

static GstBuffer *
processChallenge (GstBuffer * challenge)
{
  GstMapInfo info = GST_MAP_INFO_INIT;
  g_autoptr (SoupSession) session =
      (SoupSession *) g_object_new (SOUP_TYPE_SESSION, NULL);
  if (g_getenv ("SOUP_DEBUG")) {
    g_autoptr (SoupLogger) logger = soup_logger_new (SOUP_LOGGER_LOG_BODY, -1);
    soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
  }

  g_autoptr (SoupMessage) soup_msg = soup_message_new ("POST", LICENSE_SERVER);
  gst_buffer_map (challenge, &info, GST_MAP_READ);
  soup_message_set_request (soup_msg, "application/octet-stream",
      SOUP_MEMORY_COPY, (const gchar *) info.data, info.size);
  gst_buffer_unmap (challenge, &info);
  soup_message_headers_append (soup_msg->request_headers,
      "X-AxDRM-Message", TOKEN);

  soup_session_send_message (session, soup_msg);
  if (SOUP_STATUS_IS_SUCCESSFUL (soup_msg->status_code)) {
    GBytes *result = g_bytes_new (soup_msg->response_body->data,
        soup_msg->response_body->length);
    return gst_buffer_new_wrapped_bytes (result);
  } else {
    GST_WARNING ("Error %d : %s", soup_msg->status_code,
        soup_msg->reason_phrase);
    return NULL;
  }
}

static void
_bus_watch (G_GNUC_UNUSED GstBus * bus, GstMessage * msg,
    G_GNUC_UNUSED gpointer userData)
{
  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_STATE_CHANGED:
      if (GST_ELEMENT (msg->src) == pipeline) {
        GstState old, new, pending;

        gst_message_parse_state_changed (msg, &old, &new, &pending);

        {
          gchar *dump_name = g_strconcat ("state_changed-",
              gst_element_state_get_name (old), "_",
              gst_element_state_get_name (new), NULL);
          GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (msg->src),
              GST_DEBUG_GRAPH_SHOW_ALL, dump_name);
          g_free (dump_name);
        }
      }
      break;
    case GST_MESSAGE_ERROR:{
      GError *err = NULL;
      gchar *dbg_info = NULL;

      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (pipeline),
          GST_DEBUG_GRAPH_SHOW_ALL, "error");

      gst_message_parse_error (msg, &err, &dbg_info);
      g_printerr ("ERROR from element %s: %s\n",
          GST_OBJECT_NAME (msg->src), err->message);
      g_printerr ("Debugging info: %s\n", (dbg_info) ? dbg_info : "none");
      g_error_free (err);
      g_free (dbg_info);
      g_main_loop_quit (loop);
      break;
    }
    case GST_MESSAGE_EOS:{
      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (pipeline),
          GST_DEBUG_GRAPH_SHOW_ALL, "eos");
      g_print ("EOS received\n");
      g_main_loop_quit (loop);
      break;
    }
    case GST_MESSAGE_ELEMENT:{
      const GstStructure *structure = gst_message_get_structure (msg);
      if (gst_structure_has_name (structure, "spkl-protection")) {
        GstMapInfo info = GST_MAP_INFO_INIT;
        GstBuffer *payload;
        const gchar *origin;
        const GstStructure *structure = gst_message_get_structure (msg);
        gchar* dumped;
        gst_structure_get (structure, "payload", GST_TYPE_BUFFER, &payload,
            "origin", G_TYPE_STRING, &origin, NULL);
        gst_printerrln ("Protection data received from origin %s", origin);
        gst_buffer_map (payload, &info, GST_MAP_READ);
        dumped = (gchar *) info.data;
        dumped[info.size] = 0;
        gst_printerrln ("payload: %s", dumped);
        gst_buffer_unmap (payload, &info);
        /* Optionally parse payload, extract custom data. */
      } else if (gst_structure_has_name (structure, "spkl-challenge")) {
        GstBuffer *challenge;
        gst_structure_get (structure, "challenge", GST_TYPE_BUFFER, &challenge,
            NULL);
        GstBuffer *resultMessage = processChallenge (challenge);
        if (resultMessage) {
          GstElement *decryptor = GST_ELEMENT_CAST (GST_MESSAGE_SRC (msg));
          g_autoptr (GstPad) pad =
              gst_element_get_static_pad (decryptor, "sink");
          g_autoptr (GstPad) peer = gst_pad_get_peer (pad);
          gst_pad_push_event (peer,
              gst_event_new_custom (GST_EVENT_CUSTOM_DOWNSTREAM_OOB,
                  gst_structure_new ("spkl-session-update", "message",
                      GST_TYPE_BUFFER, resultMessage, NULL)));
        }
      } else if (gst_structure_has_name (structure, "spkl-key-expired")) {
        gst_printerrln ("Key expired: %" GST_PTR_FORMAT, structure);
      }
      break;
    }
    default:
      break;
  }
}

static void
handleNeedContextMessage (G_GNUC_UNUSED GstBus * bus, GstMessage * msg,
    G_GNUC_UNUSED gpointer userData)
{
  const gchar *context_type;
  gst_message_parse_context_type (msg, &context_type);
  // TODO: handle gst.soup.session context (cookies).
  if (!g_strcmp0 (context_type, "drm-preferred-decryption-system-id")) {
    g_autoptr (GstContext) context = gst_context_new (context_type, FALSE);
    GstStructure *contextStructure = gst_context_writable_structure (context);
    gst_structure_set (contextStructure, "decryption-system-id", G_TYPE_STRING,
        WIDEVINE_UUID, NULL);
    gst_element_set_context (GST_ELEMENT (GST_MESSAGE_SRC (msg)), context);
  }
}

int
main (int argc, char *argv[])
{
  gst_init (&argc, &argv);

  loop = g_main_loop_new (NULL, FALSE);
  pipeline = gst_element_factory_make ("playbin", NULL);

  bus1 = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
  gst_bus_enable_sync_message_emission (bus1);
  gst_bus_add_signal_watch (bus1);
  g_signal_connect (bus1, "sync-message::need-context",
      G_CALLBACK (handleNeedContextMessage), NULL);
  g_signal_connect (bus1, "message", G_CALLBACK (_bus_watch), NULL);

  g_object_set (pipeline, "uri", URI, NULL);

  g_print ("Starting pipeline\n");
  gst_element_set_state (GST_ELEMENT (pipeline), GST_STATE_PLAYING);
  g_main_loop_run (loop);
  gst_element_set_state (GST_ELEMENT (pipeline), GST_STATE_NULL);
  g_print ("Pipeline stopped\n");

  gst_bus_disable_sync_message_emission (bus1);
  gst_bus_remove_watch (bus1);
  gst_object_unref (bus1);
  gst_object_unref (pipeline);
  gst_deinit ();
  return 0;
}
