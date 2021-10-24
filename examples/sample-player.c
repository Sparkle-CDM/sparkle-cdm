// SPDX-License-Identifier: MIT

#include <gst/gst.h>
#include <libsoup/soup.h>

// For Widevine support you need to set a `TOKEN` environment variable. If using
// the https://github.com/Axinom/public-test-vectors the token are listed as
// X-AxDRM-Message values.

GST_DEBUG_CATEGORY (player_debug);
#define GST_CAT_DEFAULT player_debug

typedef struct _AppData
{
  GMainLoop *loop;
  GstElement *pipeline;
  GstBus *bus;
  SoupSession *soupSession;
  gboolean parsingLaurl;
  gchar *licenseUrl;
  GMarkupParser markupParser;
  GMarkupParseContext *markupParseContext;
  const gchar *system_uuid;
} AppData;

static void
app_data_free (AppData * app_data)
{
  g_object_unref (app_data->soupSession);
  gst_object_unref (app_data->bus);
  gst_object_unref (app_data->pipeline);
  g_main_loop_unref (app_data->loop);
  g_markup_parse_context_unref (app_data->markupParseContext);
  g_free (app_data->licenseUrl);
  g_free (app_data);
}

static SoupCookie *
create_dummy_cookie ()
{
  SoupCookie *cookie =
      soup_cookie_new ("foo", "bar", "media.axprod.net", "", -1);
  soup_cookie_set_secure (cookie, TRUE);
#if SOUP_CHECK_VERSION(2, 70, 0)
  soup_cookie_set_same_site_policy (cookie, SOUP_SAME_SITE_POLICY_NONE);
#endif
  soup_cookie_set_http_only (cookie, TRUE);
  return cookie;
}

static GstBuffer *
processChallenge (GstBuffer * challenge, AppData * app_data)
{
  GstMapInfo info = GST_MAP_INFO_INIT;

  if (!app_data->licenseUrl) {
    GST_WARNING ("License URL not found. Not declared in DASH manifest?");
    return NULL;
  }
  g_autoptr (SoupMessage) soup_msg =
      soup_message_new ("POST", app_data->licenseUrl);
  gst_buffer_map (challenge, &info, GST_MAP_READ);
  gchar *request_type =
      (char) info.data[0] ==
      '{' ? "application/json" : "application/octet-stream";
  soup_message_set_request (soup_msg, request_type, SOUP_MEMORY_COPY,
      (const gchar *) info.data, info.size);
  gst_buffer_unmap (challenge, &info);

  const gchar *token = g_getenv ("TOKEN");
  if (token) {
    soup_message_headers_append (soup_msg->request_headers,
        "X-AxDRM-Message", token);
  }

  soup_session_send_message (app_data->soupSession, soup_msg);
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
extract_license_server_url (AppData * app_data, const guint8 * data, gsize size)
{
  g_autoptr (GError) error = NULL;
  if (!g_markup_parse_context_parse (app_data->markupParseContext,
          (const gchar *) data, size, &error)) {
    GST_WARNING ("XML parse error: %s", error->message);
  } else {
    gst_println ("License server URL: %s", app_data->licenseUrl);
  }
}

static void
_bus_watch (G_GNUC_UNUSED GstBus * bus, GstMessage * msg, gpointer user_data)
{
  AppData *app_data = (AppData *) user_data;
  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_STATE_CHANGED:
      if (GST_ELEMENT (msg->src) == app_data->pipeline) {
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

      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (app_data->pipeline),
          GST_DEBUG_GRAPH_SHOW_ALL, "error");

      gst_message_parse_error (msg, &err, &dbg_info);
      gst_printerrln ("ERROR from element %s: %s",
          GST_OBJECT_NAME (msg->src), err->message);
      gst_printerrln ("Debugging info: %s", (dbg_info) ? dbg_info : "none");
      g_error_free (err);
      g_free (dbg_info);
      g_main_loop_quit (app_data->loop);
      break;
    }
    case GST_MESSAGE_EOS:{
      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (app_data->pipeline),
          GST_DEBUG_GRAPH_SHOW_ALL, "eos");
      gst_println ("EOS received");
      g_main_loop_quit (app_data->loop);
      break;
    }
    case GST_MESSAGE_ELEMENT:{
      const GstStructure *structure = gst_message_get_structure (msg);
      if (gst_structure_has_name (structure, "spkl-protection")) {
        GstMapInfo info = GST_MAP_INFO_INIT;
        GstBuffer *payload;
        const gchar *origin;
        const GstStructure *structure = gst_message_get_structure (msg);
        gchar *dumped;
        gst_structure_get (structure, "payload", GST_TYPE_BUFFER, &payload,
            "origin", G_TYPE_STRING, &origin, NULL);
        gst_printerrln ("Protection data received from origin %s", origin);
        gst_buffer_map (payload, &info, GST_MAP_READ);
        dumped = (gchar *) info.data;
        dumped[info.size] = 0;
        gst_printerrln ("payload: %s", dumped);
        extract_license_server_url (app_data, info.data, info.size);
        gst_buffer_unmap (payload, &info);
      } else if (gst_structure_has_name (structure, "spkl-challenge")) {
        GstBuffer *challenge;
        gst_structure_get (structure, "challenge", GST_TYPE_BUFFER, &challenge,
            NULL);
        GstBuffer *resultMessage = processChallenge (challenge, app_data);
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
      }
      break;
    }
    default:
      break;
  }
}

static void
handleNeedContextMessage (G_GNUC_UNUSED GstBus * bus, GstMessage * msg,
    gpointer user_data)
{
  AppData *app_data = (AppData *) user_data;
  const gchar *context_type;
  gst_message_parse_context_type (msg, &context_type);

  if (!g_strcmp0 (context_type, "gst.soup.session")) {
    g_autoptr (GstContext) context = gst_context_new (context_type, FALSE);
    GstStructure *contextStructure = gst_context_writable_structure (context);
    gst_structure_set (contextStructure, "session", SOUP_TYPE_SESSION,
        app_data->soupSession, NULL);
    gst_element_set_context (GST_ELEMENT (GST_MESSAGE_SRC (msg)), context);
  }

  if (!g_strcmp0 (context_type, "drm-preferred-decryption-system-id")) {
    g_autoptr (GstContext) context = gst_context_new (context_type, FALSE);
    GstStructure *contextStructure = gst_context_writable_structure (context);
    gst_structure_set (contextStructure, "decryption-system-id", G_TYPE_STRING,
        app_data->system_uuid, NULL);
    gst_element_set_context (GST_ELEMENT (GST_MESSAGE_SRC (msg)), context);
  }
}

static void
markupStartElement (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * element_name,
    G_GNUC_UNUSED const gchar ** attribute_names,
    G_GNUC_UNUSED const gchar ** attribute_values, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  AppData *app_data = (AppData *) user_data;
  if (g_str_has_suffix (element_name, "Laurl")) {
    app_data->parsingLaurl = TRUE;
  }
}

static void
markupEndElement (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * element_name, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  AppData *app_data = (AppData *) user_data;
  if (g_str_has_suffix (element_name, "Laurl")) {
    app_data->parsingLaurl = FALSE;
  }
}

static void
markupText (G_GNUC_UNUSED GMarkupParseContext * context,
    const gchar * text, gsize text_len, gpointer user_data,
    G_GNUC_UNUSED GError ** error)
{
  AppData *app_data = (AppData *) user_data;
  if (app_data->parsingLaurl) {
    if (app_data->licenseUrl)
      g_free (app_data->licenseUrl);
    app_data->licenseUrl = g_strndup (text, text_len);
  }
}

int
main (int argc, char *argv[])
{
  if (argc != 3) {
    gst_printerrln ("Usage: %s <system-uuid> <dash manifest url>", argv[0]);
    gst_printerrln
        ("  Where system-uuid is edef8ba9-79d6-4ace-a3c8-27dcd51d21ed for Widevine, or e2719d58-a985-b3c9-781a-b030af78d30e for ClearKey");
    return 1;
  }

  AppData *app_data = g_new (AppData, 1);
  app_data->system_uuid = argv[1];
  app_data->soupSession =
      (SoupSession *) g_object_new (SOUP_TYPE_SESSION, NULL);
  if (g_getenv ("SAMPLE_PLAYER_SOUP_DEBUG")) {
    g_autoptr (SoupLogger) logger =
        soup_logger_new (SOUP_LOGGER_LOG_HEADERS, -1);
    soup_session_add_feature (app_data->soupSession,
        SOUP_SESSION_FEATURE (logger));
  }
  soup_session_add_feature_by_type (app_data->soupSession,
      SOUP_TYPE_COOKIE_JAR);
  SoupCookieJar *jar =
      SOUP_COOKIE_JAR (soup_session_get_feature (app_data->soupSession,
          SOUP_TYPE_COOKIE_JAR));
  soup_cookie_jar_add_cookie (jar, create_dummy_cookie ());

  app_data->markupParser.start_element = markupStartElement;
  app_data->markupParser.end_element = markupEndElement;
  app_data->markupParser.text = markupText;
  app_data->markupParseContext =
      g_markup_parse_context_new (&app_data->markupParser,
      (GMarkupParseFlags) 0, app_data, NULL);
  app_data->parsingLaurl = FALSE;
  app_data->licenseUrl = NULL;

  const gchar *licenseUrl = g_getenv ("LICENSE_URL");
  if (licenseUrl)
    app_data->licenseUrl = g_strdup (licenseUrl);

  GST_DEBUG_CATEGORY_INIT (player_debug, "sprklplayer", 0, "sample-player");
  gst_init (&argc, &argv);

  app_data->loop = g_main_loop_new (NULL, FALSE);
  app_data->pipeline = gst_element_factory_make ("playbin", NULL);

  app_data->bus = gst_pipeline_get_bus (GST_PIPELINE (app_data->pipeline));
  gst_bus_enable_sync_message_emission (app_data->bus);
  gst_bus_add_signal_watch (app_data->bus);
  g_signal_connect (app_data->bus, "sync-message::need-context",
      G_CALLBACK (handleNeedContextMessage), app_data);
  g_signal_connect (app_data->bus, "message", G_CALLBACK (_bus_watch),
      app_data);

  g_object_set (app_data->pipeline, "uri", argv[2], NULL);

  gst_println ("Starting pipeline");
  gst_element_set_state (GST_ELEMENT (app_data->pipeline), GST_STATE_PLAYING);
  g_main_loop_run (app_data->loop);
  gst_element_set_state (GST_ELEMENT (app_data->pipeline), GST_STATE_NULL);
  gst_println ("Pipeline stopped");

  gst_bus_disable_sync_message_emission (app_data->bus);
  gst_bus_remove_watch (app_data->bus);
  app_data_free (app_data);
  gst_deinit ();
  return 0;
}
