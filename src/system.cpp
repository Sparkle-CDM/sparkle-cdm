// SPDX-License-Identifier: MIT

#include <glib.h>
#include <gmodule.h>
#include <gst/gst.h>

#include "open_cdm_adapter.h"
#include "sparkle-cdm-config.h"

GST_DEBUG_CATEGORY(sparkle_cdm_debug_category);
#define GST_CAT_DEFAULT sparkle_cdm_debug_category

#define UNUSED_PARAM(x) (void)x

namespace {

static GList* s_plugins = nullptr;
static GHashTable* s_modules = nullptr;
static GHashTable* s_systems = nullptr;
static GHashTable* s_sessions = nullptr;

static void closePlugins()
{
    if (s_modules)
        g_hash_table_destroy(s_modules);
    s_modules = nullptr;
    if (s_systems)
        g_hash_table_destroy(s_systems);
    s_systems = nullptr;
    if (s_sessions)
        g_hash_table_destroy(s_sessions);
    s_sessions = nullptr;
    if (s_plugins)
        g_list_free_full(s_plugins, (GDestroyNotify)g_module_close);
    s_plugins = nullptr;
}

static void registerModule(const gchar* path)
{
    GModule* module = g_module_open(path, G_MODULE_BIND_LAZY);
    if (module) {
        GST_DEBUG("Plugin loaded: %s", path);
        s_plugins = g_list_append(s_plugins, module);
    } else
        GST_WARNING("Error loading %s: %s", path, g_module_error());
}

static const gchar* initCheck()
{
  if (!gst_is_initialized()) {
    g_autoptr(GError) error = nullptr;
    if (!gst_init_check(nullptr, nullptr, &error)) {
        return error ? error->message : "Initialization failed";
    }
  }
    GST_DEBUG_CATEGORY_INIT(sparkle_cdm_debug_category, "sprklcdm", 0,
        "Sparkle CDM");
    const char* path = g_getenv("WEBKIT_SPARKLE_CDM_MODULE_PATH");
    if (path)
        registerModule(path);

    GDir* plugins_dir = g_dir_open(EXTERNAL_MODULE_PATH, 0, NULL);
    if (plugins_dir) {
        GST_DEBUG("Loading plugins from %s", EXTERNAL_MODULE_PATH);
        const gchar* filename = g_dir_read_name(plugins_dir);
        while (filename != nullptr) {
            g_autofree gchar* path = g_build_filename(EXTERNAL_MODULE_PATH, filename, nullptr);
            if (!g_file_test(path, G_FILE_TEST_IS_DIR))
                registerModule(path);
            filename = g_dir_read_name(plugins_dir);
        }
        g_dir_close(plugins_dir);
    }
    return nullptr;
}

void cacheKeySystemCheck(GModule* module, const char* keySystem)
{
    if (!s_modules)
        s_modules = g_hash_table_new(g_str_hash, g_str_equal);
    GST_DEBUG("Caching module %s as supporting %s", g_module_name(module),
        keySystem);
    g_hash_table_insert(s_modules, (gpointer)keySystem, module);
}

GModule* moduleForKeySystem(const char* keySystem)
{
    auto* module = (GModule*)g_hash_table_lookup(s_modules, keySystem);
    GST_DEBUG("Module lookup result for %s: %s", keySystem,
        module ? g_module_name(module) : "");
    if (!module)
      GST_ERROR("Module not found for key system %s", keySystem);
    return module;
}

void cacheSystem(struct OpenCDMSystem* system, GModule* module)
{
    if (!s_systems)
        s_systems = g_hash_table_new(nullptr, nullptr);
    GST_DEBUG("Caching module %s as system %p holder", g_module_name(module),
        system);
    if (system)
        g_hash_table_insert(s_systems, (gpointer)system, module);
}

GModule* moduleForSystem(struct OpenCDMSystem* system)
{
    auto* module = (GModule*)g_hash_table_lookup(s_systems, system);
    GST_DEBUG("Module lookup result for system %p: %s", system,
        module ? g_module_name(module) : "");
    if (!module)
      GST_ERROR("Module not found");
    return module;
}

void unregisterSystem(struct OpenCDMSystem* system)
{
    GST_DEBUG("Unregistering system %p", system);
    g_hash_table_remove(s_systems, system);
}

void cacheSession(struct OpenCDMSession* session, GModule* module)
{
    if (!s_sessions)
        s_sessions = g_hash_table_new(nullptr, nullptr);
    GST_DEBUG("Caching module %s as session %p holder", g_module_name(module),
        session);
    if (session)
        g_hash_table_insert(s_sessions, (gpointer)session, module);
}

GModule* moduleForSession(const struct OpenCDMSession* session)
{
    auto* module = (GModule*)g_hash_table_lookup(s_sessions, session);
    GST_TRACE("Module lookup result for session %p: %s", session,
        module ? g_module_name(module) : "");
    if (!module)
      GST_ERROR("Module not found for session %p", session);
    return module;
}
void unregisterSession(struct OpenCDMSession* session)
{
    GST_DEBUG("Unregistering session %p", session);
    g_hash_table_remove(s_sessions, session);
}

} // namespace

extern "C" {
G_MODULE_EXPORT const gchar* g_module_check_init(GModule* self)
{
    UNUSED_PARAM(self);
    return initCheck();
}

G_MODULE_EXPORT void g_module_unload(GModule* self)
{
    UNUSED_PARAM(self);
    closePlugins();
}
}

typedef OpenCDMError (*IsTypeSupportedFunc)(const char* keySystem,
    const char* mimeType);
typedef struct OpenCDMSystem* (*CreateSystemFunc)(const char* keySystem);
typedef OpenCDMError (*DestructSystemFunc)(struct OpenCDMSystem* system);
typedef OpenCDMBool (*SupportsServerCertificateFunc)(
    struct OpenCDMSystem* system);
typedef struct OpenCDMSession* (*GetSystemSessionFunc)(
    struct OpenCDMSystem* system, const uint8_t* keyId, const uint8_t length,
    const uint32_t waitTime);
typedef OpenCDMError (*SetServerCertificateFunc)(
    struct OpenCDMSystem* system, const uint8_t serverCertificate[],
    const uint16_t serverCertificateLength);
typedef OpenCDMError (*ConstructSessionFunc)(
    struct OpenCDMSystem* system, const LicenseType licenseType,
    const char initDataType[], const uint8_t initData[],
    const uint16_t initDataLength, const uint8_t CDMData[],
    const uint16_t CDMDataLength, OpenCDMSessionCallbacks* callbacks,
    void* userData, struct OpenCDMSession** session);
typedef OpenCDMError (*DestructSessionFunc)(struct OpenCDMSession* session);
typedef const char* (*GetSessionIdFunc)(const struct OpenCDMSession* session);
typedef KeyStatus (*GetSessionStatusFunc)(const struct OpenCDMSession* session,
    const uint8_t* keyId,
    const uint8_t length);
typedef OpenCDMError (*LoadSessionFunc)(struct OpenCDMSession* session);
typedef OpenCDMError (*UpdateSessionFunc)(struct OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength);
typedef OpenCDMError (*RemoveSessionFunc)(struct OpenCDMSession* session);
typedef OpenCDMError (*CloseSessionFunc)(struct OpenCDMSession* session);
typedef OpenCDMError (*DecryptSessionFunc)(struct OpenCDMSession* session,
    GstBuffer* buffer,
    GstBuffer* subSamples,
    const uint32_t subSampleCount,
    OpenCDMEncryptionScheme encryptionScheme,
    GstBuffer* IV, GstBuffer* keyID,
    uint32_t initWithLast15);

OpenCDMError opencdm_is_type_supported(const char keySystem[],
    const char mimeType[])
{
    GST_DEBUG("is_type_supported: %s -- %s", keySystem, mimeType);
    OpenCDMError result = ERROR_FAIL;
    IsTypeSupportedFunc is_type_supported;
    for (GList* l = s_plugins; l != nullptr; l = l->next) {
        GModule* module = (GModule*)l->data;
        if (!g_module_symbol(module, "opencdm_is_type_supported",
                (gpointer*)&is_type_supported))
            continue;
        result = is_type_supported(keySystem, mimeType);

        if (result == ERROR_NONE) {
            // FIXME: No ranking for now, first come, first served.
            cacheKeySystemCheck(module, keySystem);
            return result;
        }
    }
    return ERROR_FAIL;
}

struct OpenCDMSystem* opencdm_create_system(const char keySystem[])
{
    GST_DEBUG("opencdm_create_system: %s", keySystem);
    auto* module = moduleForKeySystem(keySystem);
    CreateSystemFunc create_system;
    if (!g_module_symbol(module, "opencdm_create_system",
            (gpointer*)&create_system))
        return nullptr;

    auto* system = create_system(keySystem);
    cacheSystem(system, module);
    return system;
}

OpenCDMError opencdm_destruct_system(struct OpenCDMSystem* system)
{
    GST_DEBUG("opencdm_destruct_system: %p", system);
    auto* module = moduleForSystem(system);
    DestructSystemFunc destruct_system;
    if (!g_module_symbol(module, "opencdm_destruct_system",
            (gpointer*)&destruct_system))
        return ERROR_FAIL;

    unregisterSystem(system);
    return destruct_system(system);
}

OpenCDMBool opencdm_system_supports_server_certificate(
    struct OpenCDMSystem* system)
{
    GST_DEBUG("opencdm_system_supports_server_certificate: %p", system);
    auto* module = moduleForSystem(system);
    SupportsServerCertificateFunc supports_server_certificate;
    if (!g_module_symbol(module, "opencdm_system_supports_server_certificate",
            (gpointer*)&supports_server_certificate))
        return OPENCDM_BOOL_FALSE;

    return supports_server_certificate(system);
}

OpenCDMError opencdm_system_set_server_certificate(struct OpenCDMSystem* system, const uint8_t serverCertificate[],
    const uint16_t serverCertificateLength)
{
    GST_DEBUG("opencdm_system_set_server_certificate: %p", system);
    GST_MEMDUMP("server certificate", serverCertificate, serverCertificateLength);
    auto* module = moduleForSystem(system);
    SetServerCertificateFunc set_server_certificate;
    if (!g_module_symbol(module, "opencdm_system_set_server_certificate",
            (gpointer*)&set_server_certificate))
        return ERROR_FAIL;

    return set_server_certificate(system, serverCertificate,
        serverCertificateLength);
}

struct OpenCDMSession* opencdm_get_system_session(struct OpenCDMSystem* system,
    const uint8_t keyId[],
    const uint8_t length,
    const uint32_t waitTime)
{
    GST_DEBUG("opencdm_get_system_session: %p", system);
    auto* module = moduleForSystem(system);
    GetSystemSessionFunc get_system_session;
    if (!g_module_symbol(module, "opencdm_get_system_session",
            (gpointer*)&get_system_session))
        return nullptr;

    auto* session = get_system_session(system, keyId, length, waitTime);
    cacheSession(session, module);
    return session;
}

OpenCDMError opencdm_construct_session(
    struct OpenCDMSystem* system, const LicenseType licenseType,
    const char initDataType[], const uint8_t initData[],
    const uint16_t initDataLength, const uint8_t CDMData[],
    const uint16_t CDMDataLength, OpenCDMSessionCallbacks* callbacks,
    void* userData, struct OpenCDMSession** session)
{
    GST_DEBUG("opencdm_construct_session: %p", system);
    auto* module = moduleForSystem(system);
    ConstructSessionFunc construct_session;
    if (!g_module_symbol(module, "opencdm_construct_session",
            (gpointer*)&construct_session))
        return ERROR_FAIL;

    auto result = construct_session(system, licenseType, initDataType, initData,
        initDataLength, CDMData, CDMDataLength,
        callbacks, userData, session);
    if (result == ERROR_NONE)
        cacheSession(*session, module);
    return result;
}

OpenCDMError opencdm_destruct_session(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_destruct_session: %p", session);
    auto* module = moduleForSession(session);
    DestructSessionFunc destruct_session;
    if (!g_module_symbol(module, "opencdm_destruct_session",
            (gpointer*)&destruct_session))
        return ERROR_FAIL;

    unregisterSession(session);
    return destruct_session(session);
}

const char* opencdm_session_id(const struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_id: %p", session);
    auto* module = moduleForSession(session);
    GetSessionIdFunc get_session_id;
    if (!g_module_symbol(module, "opencdm_session_id",
            (gpointer*)&get_session_id))
        return nullptr;

    return get_session_id(session);
}

KeyStatus opencdm_session_status(const struct OpenCDMSession* session,
    const uint8_t keyId[], const uint8_t length)
{
    GST_DEBUG("opencdm_session_status: %p", session);
    auto* module = moduleForSession(session);
    GetSessionStatusFunc get_session_status;
    if (!g_module_symbol(module, "opencdm_session_status",
            (gpointer*)&get_session_status))
        return InternalError;

    return get_session_status(session, keyId, length);
}

OpenCDMError opencdm_session_load(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_load: %p", session);
    auto* module = moduleForSession(session);
    LoadSessionFunc load_session;
    if (!g_module_symbol(module, "opencdm_session_load",
            (gpointer*)&load_session))
        return ERROR_FAIL;

    return load_session(session);
}

OpenCDMError opencdm_session_update(struct OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength)
{
    GST_DEBUG("opencdm_session_update: %p", session);
    auto* module = moduleForSession(session);
    UpdateSessionFunc update_session;
    if (!g_module_symbol(module, "opencdm_session_update",
            (gpointer*)&update_session))
        return ERROR_FAIL;

    return update_session(session, keyMessage, keyLength);
}

OpenCDMError opencdm_session_remove(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_remove: %p", session);
    auto* module = moduleForSession(session);
    RemoveSessionFunc remove_session;
    if (!g_module_symbol(module, "opencdm_session_remove",
            (gpointer*)&remove_session))
        return ERROR_FAIL;

    return remove_session(session);
}

OpenCDMError opencdm_session_close(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_close: %p", session);
    auto* module = moduleForSession(session);
    CloseSessionFunc close_session;
    if (!g_module_symbol(module, "opencdm_session_close",
            (gpointer*)&close_session))
        return ERROR_FAIL;

    return close_session(session);
}

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session,
    GstBuffer* buffer,
    GstBuffer* subSamples,
    const uint32_t subSampleCount,
    OpenCDMEncryptionScheme encryptionScheme,
    GstBuffer* IV, GstBuffer* keyID,
    uint32_t initWithLast15)
{
    GST_TRACE("opencdm_gstreamer_session_decrypt: %p", session);
    auto* module = moduleForSession(session);
    DecryptSessionFunc decrypt_session;
    if (!g_module_symbol(module, "opencdm_gstreamer_session_decrypt",
            (gpointer*)&decrypt_session))
        return ERROR_FAIL;

    return decrypt_session(session, buffer, subSamples, subSampleCount,
        encryptionScheme, IV, keyID, initWithLast15);
}
