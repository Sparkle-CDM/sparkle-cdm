// SPDX-License-Identifier: MIT

#include "sprkl/sprkl-cdm.h"
#include <cstdint>
#include <glib.h>
#include <gmodule.h>
#include <gst/gst.h>
#include <unordered_map>

#include "open_cdm_adapter.h"
#include "sparkle-cdm-config.h"

GST_DEBUG_CATEGORY(sparkle_cdm_debug_category);
#define GST_CAT_DEFAULT sparkle_cdm_debug_category

#define UNUSED_PARAM(x) (void)x

struct OpenCDMSession {
    OpenCDMSession(OpenCDMSystem* system, SparkleCDMSession* sprklSession);
    ~OpenCDMSession();
    OpenCDMSession(const OpenCDMSession&) = default;
    OpenCDMSession(OpenCDMSession&&) = default;
    OpenCDMSession& operator=(OpenCDMSession&&) = default;
    OpenCDMSession& operator=(const OpenCDMSession&) = default;

    SparkleCDMSession* sprklSession() const { return m_sprklSession; }

private:
    OpenCDMSystem* m_system;
    SparkleCDMSession* m_sprklSession{ nullptr };
};

struct OpenCDMSystem {
    OpenCDMSystem(const char system[], SparkleCDMSystem* sprklSystem)
        : m_keySystem(system)
        , m_sprklSystem(sprklSystem)
    {
    }
    ~OpenCDMSystem() = default;
    OpenCDMSystem(const OpenCDMSystem&) = default;
    OpenCDMSystem(OpenCDMSystem&&) = default;
    OpenCDMSystem& operator=(OpenCDMSystem&&) = default;
    OpenCDMSystem& operator=(const OpenCDMSystem&) = default;

    SparkleCDMSystem* sprklSystem() const { return m_sprklSystem; }

    OpenCDMSession* getSystemSession(std::span<const uint8_t> keyId)
    {
        for (auto& it : m_sessions) {
            if (it.second->sprklSession()->hasKeyId(keyId))
                return it.second;
        }
        return nullptr;
    }

    void registerSession(OpenCDMSession* session)
    {
        m_sessions.insert({ session->sprklSession()->getId(), session });
    }

    void unregisterSession(const std::string& session_id)
    {
        auto result = m_sessions.find(session_id);
        if (result != m_sessions.end())
            m_sessions.erase(result);
    }

private:
    std::string m_keySystem;
    SparkleCDMSystem* m_sprklSystem{ nullptr };
    std::unordered_map<std::string, OpenCDMSession*> m_sessions;
};

OpenCDMSession::OpenCDMSession(OpenCDMSystem* system, SparkleCDMSession* sprklSession)
    : m_system(system)
    , m_sprklSession(sprklSession)
{
    m_system->registerSession(this);
    m_sprklSession->setParent(this);
}

OpenCDMSession::~OpenCDMSession()
{
    m_system->unregisterSession(m_sprklSession->getId());
}

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
        g_list_free_full(s_plugins, [](void* d) { g_module_close((GModule*)d); });
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

static void initCheck(GError** error)
{
    if (!gst_is_initialized()) {
        if (!gst_init_check(nullptr, nullptr, error)) {
            return;
        }
    }
    GST_DEBUG_CATEGORY_INIT(sparkle_cdm_debug_category, "sprklcdm", 0,
        "Sparkle CDM");
    auto module_paths = g_getenv("WEBKIT_SPARKLE_CDM_MODULE_PATH");
    if (module_paths) {
        auto paths = g_strsplit(module_paths, G_SEARCHPATH_SEPARATOR_S, 0);
        for (auto path = paths; *path; path++) {
            if (g_str_equal(*path, "")) {
                continue;
            }
            registerModule(*path);
        }
        g_strfreev(paths);
    }

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
    GError* error = nullptr;
    initCheck(&error);
    if (error) {
        g_printerr("Unable to initialize Sparkle-CDM. Error message: %s\n", error->message);
    }
    g_clear_error(&error);
    return g_module_error();
}

G_MODULE_EXPORT void g_module_unload(GModule* self)
{
    UNUSED_PARAM(self);
    closePlugins();
}
} // extern "C"

typedef OpenCDMError (*IsTypeSupportedFunc)(const char* keySystem,
    const char* mimeType);
typedef SparkleCDMSystem* (*CreateSystemFunc)(const char* keySystem);
typedef OpenCDMError (*DestructSystemFunc)(SparkleCDMSystem* system);
typedef OpenCDMError (*DestructSessionFunc)(SparkleCDMSession* session);

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
    if (!module)
        return nullptr;
    CreateSystemFunc create_system;
    if (!g_module_symbol(module, "sprkl_cdm_create_system",
            (gpointer*)&create_system)) {
        GST_ERROR("sprkl_cdm_create_system function not found in %s module: %s", keySystem, g_module_error());
        return nullptr;
    }

    auto system = new OpenCDMSystem(keySystem, create_system(keySystem));
    cacheSystem(system, module);
    return system;
}

OpenCDMError opencdm_destruct_system(struct OpenCDMSystem* system)
{
    GST_DEBUG("opencdm_destruct_system: %p", system);
    auto* module = moduleForSystem(system);
    if (!module) {
        unregisterSystem(system);
        return ERROR_NONE;
    }
    DestructSystemFunc destruct_system;
    if (!g_module_symbol(module, "sprkl_cdm_destruct_system",
            (gpointer*)&destruct_system)) {
        GST_ERROR("sprkl_cdm_destruct_system function not found, %s", g_module_error());
        return ERROR_FAIL;
    }
    auto result = destruct_system(system->sprklSystem());
    unregisterSystem(system);
    return result;
}

OpenCDMBool opencdm_system_supports_server_certificate(
    struct OpenCDMSystem* system)
{
    GST_DEBUG("opencdm_system_supports_server_certificate: %p", system);
    return system->sprklSystem()->supportsServerCertificate();
}

OpenCDMError opencdm_system_set_server_certificate(struct OpenCDMSystem* system, const uint8_t serverCertificate[],
    const uint16_t serverCertificateLength)
{
    GST_DEBUG("opencdm_system_set_server_certificate: %p", system);
    GST_MEMDUMP("server certificate", serverCertificate, serverCertificateLength);
    std::span<const uint8_t> certificate{ serverCertificate, serverCertificateLength };
    return system->sprklSystem()->setServerCertificate(certificate);
}

struct OpenCDMSession* opencdm_get_system_session(struct OpenCDMSystem* system,
    const uint8_t keyId[],
    const uint8_t length,
    const uint32_t)
{
    GST_DEBUG("opencdm_get_system_session: %p", system);
    auto* module = moduleForSystem(system);
    if (!module)
        return nullptr;
    std::span<const uint8_t> key{ keyId, length };
    return system->getSystemSession(key);
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
    if (!module)
        return ERROR_FAIL;

    std::span<const uint8_t> init{ initData, initDataLength };
    std::span<const uint8_t> cdmData{ CDMData, CDMDataLength };
    SparkleCDMSession* sprklSession = nullptr;
    auto result = system->sprklSystem()->constructSession(licenseType, initDataType, init, cdmData, callbacks, userData, &sprklSession);
    if (result == ERROR_NONE) {
        *session = new OpenCDMSession(system, sprklSession);
        cacheSession(*session, module);
    }
    return result;
}

OpenCDMError opencdm_destruct_session(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_destruct_session: %p", session);
    auto* module = moduleForSession(session);
    if (!module) {
        unregisterSession(session);
        delete session;
        return ERROR_NONE;
    }
    DestructSessionFunc destruct_session;
    if (!g_module_symbol(module, "sprkl_cdm_destruct_session",
            (gpointer*)&destruct_session)) {
        GST_ERROR("sprkl_cdm_destruct_session function not found in %p module: %s", module, g_module_error());
        return ERROR_FAIL;
    }
    unregisterSession(session);
    auto result = destruct_session(session->sprklSession());
    delete session;
    return result;
}

const char* opencdm_session_id(const struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_id: %p", session);
    const auto& id = session->sprklSession()->getId();
    return id.c_str();
}

KeyStatus opencdm_session_status(const struct OpenCDMSession* session,
    const uint8_t keyId[], const uint8_t length)
{
    GST_DEBUG("opencdm_session_status: %p", session);
    std::span<const uint8_t> id{ keyId, length };
    return session->sprklSession()->status(id);
}

uint32_t opencdm_session_has_key_id(struct OpenCDMSession* session,
    const uint8_t length, const uint8_t keyId[])
{
    GST_DEBUG("opencdm_session_has_key_id: %p", session);
    std::span<const uint8_t> id{ keyId, length };
    return session->sprklSession()->hasKeyId(id);
}

OpenCDMError opencdm_session_load(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_load: %p", session);
    return session->sprklSession()->load();
}

OpenCDMError opencdm_session_update(struct OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength)
{
    GST_DEBUG("opencdm_session_update: %p", session);
    std::span<const uint8_t> message{ keyMessage, keyLength };
    return session->sprklSession()->update(message);
}

OpenCDMError opencdm_session_remove(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_remove: %p", session);
    return session->sprklSession()->remove();
}

OpenCDMError opencdm_session_close(struct OpenCDMSession* session)
{
    GST_DEBUG("opencdm_session_close: %p", session);
    return session->sprklSession()->close();
}

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session,
    GstBuffer* buffer,
    GstBuffer* subSamples,
    const uint32_t subSampleCount,
    GstBuffer* IV, GstBuffer* keyID,
    uint32_t initWithLast15)
{
    GST_TRACE("opencdm_gstreamer_session_decrypt: %p", session);
    return session->sprklSession()->decrypt(buffer, subSamples, subSampleCount, IV, keyID, initWithLast15);
}

OpenCDMError opencdm_gstreamer_session_decrypt_buffer(struct OpenCDMSession* session, GstBuffer* buffer, GstCaps* caps)
{
    if (!session)
        return ERROR_INVALID_SESSION;

    GST_TRACE("opencdm_gstreamer_session_decrypt_buffer: %p", session);

    const GValue* value;
    unsigned subSampleCount = 0;
    GstBuffer* subSample = nullptr;
    GstBuffer* IV = nullptr;
    GstBuffer* keyID = nullptr;

    GstProtectionMeta* protectionMeta = reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(buffer));
    if (!protectionMeta) {
        GST_TRACE("opencdm_gstreamer_session_decrypt_buffer: Missing Protection Metadata.");
        return ERROR_INVALID_DECRYPT_BUFFER;
    }

    gst_structure_get_uint(protectionMeta->info, "subsample_count", &subSampleCount);
    if (subSampleCount) {
        value = gst_structure_get_value(protectionMeta->info, "subsamples");
        if (!value) {
            GST_TRACE("opencdm_gstreamer_session_decrypt_buffer: No subsample buffer.");
            return ERROR_INVALID_DECRYPT_BUFFER;
        }
        subSample = gst_value_get_buffer(value);
    }

    value = gst_structure_get_value(protectionMeta->info, "iv");
    if (!value) {
        GST_TRACE("opencdm_gstreamer_session_decrypt_buffer: Missing IV buffer.");
        return ERROR_INVALID_DECRYPT_BUFFER;
    }
    IV = gst_value_get_buffer(value);

    value = gst_structure_get_value(protectionMeta->info, "kid");
    if (!value) {
        GST_TRACE("opencdm_gstreamer_session_decrypt_buffer: Missing KeyId buffer.");
        return ERROR_INVALID_DECRYPT_BUFFER;
    }
    keyID = gst_value_get_buffer(value);

    return session->sprklSession()->decryptBuffer(buffer, caps, subSample, subSampleCount, IV, keyID);
}
