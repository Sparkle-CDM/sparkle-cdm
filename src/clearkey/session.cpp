// SPDX-License-Identifier: MIT

#include "session.h"
#include "open_cdm.h"
#include "open_cdm_adapter.h"
#include <gst/base/gstbytereader.h>
#include <json-glib/json-glib.h>
#include <glib.h>

#define GST_CAT_DEFAULT cdm_debug_category

class GMutexHolder {
public:
    GMutexHolder(GMutex& mutex)
        : m(mutex)
    {
        g_mutex_lock(&m);
    }
    ~GMutexHolder()
    {
        g_mutex_unlock(&m);
    }

private:
    GMutex& m;
};

OpenCDMSession::OpenCDMSession(OpenCDMSystem* system,
    const std::string& initDataType,
    const uint8_t* pbInitData, const uint16_t cbInitData,
    const uint8_t* pbCustomData,
    const uint16_t cbCustomData,
    const LicenseType licenseType,
    OpenCDMSessionCallbacks* callbacks,
    void* userData)
    : m_callbacks(callbacks)
    , m_userData(userData)
    , m_licenseType(licenseType)
    , m_initDataType(initDataType)
    , m_pbInitData(pbInitData)
    , m_cbInitData(cbInitData)
{
    UNUSED_PARAM(pbCustomData);
    UNUSED_PARAM(cbCustomData);
    UNUSED_PARAM(system);

    g_mutex_init(&m_mutex);

    static uint32_t gId = 0;
    m_id = g_strdup_printf("ck%u", gId++);

    processInitData();
}

OpenCDMSession::~OpenCDMSession()
{
    GST_DEBUG("Destroying session %p", this);
    g_mutex_clear(&m_mutex);
    g_free(m_id);
}

const char* opencdm_session_id(const struct OpenCDMSession* session)
{
    return session->id();
}

KeyStatus opencdm_session_status(const struct OpenCDMSession* session, const uint8_t keyId[], const uint8_t length)
{
    std::string key_id(keyId, keyId + length);
    return session->keyStatus(key_id);
}

OpenCDMError opencdm_session_load(struct OpenCDMSession* session)
{
    return session->load();
}

OpenCDMError opencdm_session_update(struct OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength)
{
    std::string response(keyMessage, keyMessage + keyLength);
    return session->update(response);
}

OpenCDMError opencdm_session_remove(struct OpenCDMSession* session)
{
    return session->remove();
}

OpenCDMError opencdm_session_close(struct OpenCDMSession* session)
{
    return session->close();
}

OpenCDMError opencdm_destruct_session(struct OpenCDMSession* session)
{
    return session->destruct();
}

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session, GstBuffer* buffer, GstBuffer* subSample, const uint32_t subSampleCount, OpenCDMEncryptionScheme encryptionScheme, GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15)
{
    return session->decrypt(buffer, subSample, subSampleCount, encryptionScheme, IV, keyID, initWithLast15);
}

gchar* OpenCDMSession::encode_kid(const guint8* d, gsize size)
{
    g_autofree gchar* encoded = g_base64_encode(d, size);
    encoded = g_strdelimit(encoded, "+", '-');
    encoded = g_strdelimit(encoded, "/", '_');
    return g_strndup(encoded, strlen(encoded) - 2);
}

void OpenCDMSession::processInitData()
{
    const char* sessionType = "";
    switch (m_licenseType) {
    case Temporary:
        sessionType = "temporary";
        break;
    case PersistentUsageRecord:
    case PersistentLicense:
        sessionType = "persistent-license";
        break;
    }

    GList* keys = nullptr;
    GST_DEBUG("Init data type: %s", m_initDataType.c_str());
    if (m_initDataType == "cenc") {
        GstByteReader br;
        const guint8* data;
        guint8 keyCount = 0;

        gst_byte_reader_init(&br, m_pbInitData, m_cbInitData);
        gst_byte_reader_skip(&br, 12);
        if (gst_byte_reader_get_data(&br, cencSystemIdSize, &data)) {
            if (memcmp(data, cencSystemId, cencSystemIdSize) == 0) {
                gst_byte_reader_skip(&br, 3);
                if (gst_byte_reader_get_uint8(&br, &keyCount)) {
                    GST_DEBUG("Found %u key IDs", keyCount);
                    for (guint8 i = 0; i < keyCount; ++i) {
                        const guint8* d;
                        if (!gst_byte_reader_get_data(&br, 16, &d))
                            break;

                        gchar* encoded_kid = encode_kid(d, 16);
                        keys = g_list_append(keys, encoded_kid);
                    }
                } else {
                    GST_WARNING("No key ID found");
                }
            } else {
                GST_WARNING("Unknown SystemID found in CENC payload");
            }
        } else {
            GST_WARNING("CENC payload too small");
        }
    } else if (m_initDataType == "keyids") {
        g_autoptr(GError) error = nullptr;
        g_autoptr(JsonParser) parser = json_parser_new_immutable();
        if (!json_parser_load_from_data(parser, reinterpret_cast<const gchar*>(m_pbInitData), m_cbInitData, &error)) {
            GST_ERROR("KeyIDs loading failed: %s", error->message);
            return;
        }
        JsonNode* root = json_parser_get_root(parser);
        JsonObject* root_obj = json_node_get_object(root);
        JsonNode* array_node = json_object_get_member(root_obj, "kids");
        JsonArray* array = json_node_get_array(array_node);
        guint length = json_array_get_length(array);
        for (guint i = 0; i < length; i++) {
            const gchar* value = json_array_get_string_element(array, i);
            keys = g_list_append(keys, g_strndup(value, strlen(value)));
        }
    } else if (m_initDataType == "webm") {
        gchar* encoded_kid = encode_kid(m_pbInitData, m_cbInitData);
        keys = g_list_append(keys, encoded_kid);
    }

    g_autoptr(JsonBuilder) builder = json_builder_new();

    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "kids");
    json_builder_begin_array(builder);
    for (GList* l = keys; l != nullptr; l = l->next) {
        json_builder_add_string_value(builder, reinterpret_cast<gchar*>(l->data));
    }
    json_builder_end_array(builder);

    json_builder_set_member_name(builder, "type");
    json_builder_add_string_value(builder, sessionType);

    json_builder_end_object(builder);

    g_autoptr(JsonNode) node = json_builder_get_root(builder);
    g_autoptr(JsonGenerator) generator = json_generator_new();
    json_generator_set_root(generator, node);
    gsize len;
    g_autofree gchar* jsonData = json_generator_to_data(generator, &len);
    GST_DEBUG("JSON payload: %s", jsonData);
    g_list_free_full(keys, g_free);

    // License request.
    unsigned webkitCDMMessageType = 0;
    g_autofree gchar* typ = g_strdup_printf("%u:Type:", webkitCDMMessageType);
    GString* payload = g_string_new_len(typ, 7);
    payload = g_string_append_len(payload, jsonData, len);
    g_autoptr(GBytes) payloadBytes = g_string_free_to_bytes(payload);
    m_callbacks->process_challenge_callback(this, m_userData, nullptr, reinterpret_cast<const uint8_t*>(g_bytes_get_data(payloadBytes, nullptr)), g_bytes_get_size(payloadBytes));
}

KeyStatus OpenCDMSession::keyStatus(const std::string& keyId) const
{
    KeyStatus status = Expired;
    bool found = false;
    auto lookupResult = m_keyStatusMap.find(keyId);
    if (lookupResult != m_keyStatusMap.end()) {
        found = true;
        status = lookupResult->second.first;
    }
    GST_DEBUG("Status for %s key : %d", found ? "found" : "not found", status);
    return status;
}

bool OpenCDMSession::hasKeyID(const std::string& key_id) const
{
    return m_keyStatusMap.find(key_id) != m_keyStatusMap.end();
}

OpenCDMError OpenCDMSession::load()
{
    GST_DEBUG("Loading session");
    return ERROR_NONE;
}

OpenCDMError OpenCDMSession::update(const std::string& response)
{
    GST_MEMDUMP("Updating session according to response", reinterpret_cast<const uint8_t*>(response.data()), response.size());

    if (response.find("kids") != std::string::npos && m_licenseType != Temporary) {
        m_keyStatusMap.clear();
        m_callbacks->keys_updated_callback(this, m_userData);
        return ERROR_NONE;
    }

    g_autoptr(GError) error = nullptr;
    g_autoptr(JsonParser) parser = json_parser_new_immutable();
    if (json_parser_load_from_data(parser, response.c_str(), response.size(), &error)) {
        JsonNode* root = json_parser_get_root(parser);
        JsonObject* root_obj = json_node_get_object(root);
        JsonNode* array_node = json_object_get_member(root_obj, "keys");
        JsonArray* array = json_node_get_array(array_node);
        json_array_foreach_element(
            array, [](JsonArray*, guint, JsonNode* item, gpointer userData) {
                JsonObject* node = json_node_get_object(item);
                const gchar* keyType = json_object_get_string_member(node, "kty");
                if (!keyType || !g_str_equal(keyType, "oct")) {
                    GST_WARNING("Invalid key type: %s", keyType);
                    return;
                }

                const gchar* keyID = json_object_get_string_member(node, "kid");
                if (!keyID) {
                    GST_WARNING("kid not found in node");
                    return;
                }

                GST_DEBUG("Processing keyID %s", keyID);

                const gchar* keyValue = nullptr;
                if (json_object_has_member(node, "k"))
                    keyValue = json_object_get_string_member(node, "k");

                if (!keyValue) {
                    GST_WARNING("Key value not found for keyID %s", keyID);
                    return;
                }

                // https://www.w3.org/TR/encrypted-media/#using-base64url
                g_autofree gchar* original_kid = g_strdup_printf("%s==", keyID);
                g_autofree gchar* original_key_val = g_strdup_printf("%s==", keyValue);
                gchar* key_val = g_strdelimit(original_key_val, "-", '+');
                key_val = g_strdelimit(original_key_val, "_", '/');

                gchar* kid = g_strdelimit(original_kid, "-", '+');
                kid = g_strdelimit(original_kid, "_", '/');

                auto* session = reinterpret_cast<OpenCDMSession*>(userData);
                session->cacheKey(kid, key_val);
            },
            this);
    } else {
        GST_ERROR("Session update failed: %s", error->message);
        if (error->code == JSON_PARSER_ERROR_INVALID_DATA)
            return ERROR_FAIL;
    }
    m_callbacks->keys_updated_callback(this, m_userData);
    return ERROR_NONE;
}

void OpenCDMSession::cacheKey(const gchar* keyID, const gchar* keyValue)
{
    gsize keyIDLen, keyValueLen;
    gchar* decodedKeyID = reinterpret_cast<gchar*>(g_base64_decode(keyID, &keyIDLen));
    gchar* decodedKeyValue = reinterpret_cast<gchar*>(g_base64_decode(keyValue, &keyValueLen));

    std::string kid{ decodedKeyID, decodedKeyID + keyIDLen };
    std::string val{ decodedKeyValue, decodedKeyValue + keyValueLen };
    GST_MEMDUMP("Caching key ID:", reinterpret_cast<const uint8_t*>(kid.c_str()), kid.size());
    GST_MEMDUMP("Caching key value:", reinterpret_cast<const uint8_t*>(val.c_str()), val.size());
    m_keyStatusMap.insert({ kid, { Usable, val } });
    m_callbacks->key_update_callback(this, m_userData, reinterpret_cast<const uint8_t*>(kid.c_str()), kid.size());
}

OpenCDMError OpenCDMSession::remove()
{
    GST_DEBUG("Removing session");
    return ERROR_NONE;
}

OpenCDMError OpenCDMSession::close()
{
    GST_DEBUG("Closing session");
    if (m_evpCtx) {
        EVP_CIPHER_CTX_free(m_evpCtx);
        m_evpCtx = nullptr;
    }
    return ERROR_NONE;
}

OpenCDMError OpenCDMSession::destruct()
{
    GST_DEBUG("Destructing session");
    return close();
}

OpenCDMError OpenCDMSession::decrypt(GstBuffer* buffer, GstBuffer* subSample, const uint32_t subSampleCount, OpenCDMEncryptionScheme, GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15)
{
    UNUSED_PARAM(initWithLast15);

    OpenCDMError ret = ERROR_FAIL;
    GstMapInfo bufferMap, ivMap, keyIdMap;
    GMutexHolder lock(m_mutex);

    gst_buffer_map(buffer, &bufferMap, GST_MAP_READWRITE);
    gst_buffer_map(IV, &ivMap, GST_MAP_READ);
    gst_buffer_map(keyID, &keyIdMap, GST_MAP_READ);

    // Add padding to IV, filling 16 bytes.
    memcpy(m_iv, ivMap.data, (ivMap.size > 16 ? 16 : ivMap.size));
    if (ivMap.size < 16) {
        memset(&(m_iv[ivMap.size]), 0, 16 - ivMap.size);
    }

    int outSize = 0;

    // TODO: Handle encryption scheme properly.
    auto* alg = EVP_aes_128_ctr();
    if (!m_evpCtx) {
        m_evpCtx = EVP_CIPHER_CTX_new();
        if (!m_evpCtx) {
            GST_ERROR("Ctx init");
            goto out;
        }
        EVP_CIPHER_CTX_set_padding(m_evpCtx, 0);
    }

    {
        std::string kid{ keyIdMap.data, keyIdMap.data + keyIdMap.size };
        auto statusAndValue = m_keyStatusMap.find(kid);
        if (statusAndValue == m_keyStatusMap.end()) {
            GST_MEMDUMP("Key ID not found:", reinterpret_cast<const uint8_t*>(kid.c_str()), kid.size());
            goto out;
        }
        const auto& keyValue = statusAndValue->second.second;
        if (!EVP_CipherInit_ex(m_evpCtx, alg, NULL, reinterpret_cast<const unsigned char*>(keyValue.c_str()), m_iv, 0)) {
            GST_ERROR("Init failure");
            goto out;
        }
    }

    GST_TRACE("Decrypting with session %s", m_id);
    if (!subSampleCount) {
        if (!EVP_CipherUpdate(m_evpCtx, bufferMap.data,
                &outSize, bufferMap.data, bufferMap.size)) {
            GST_ERROR("Unable to decrypt data");
            goto out;
        }
        ret = ERROR_NONE;
    } else {
        GstMapInfo subSampleInfo;
        gst_buffer_map(subSample, &subSampleInfo, GST_MAP_READ);

        GstByteReader reader;
        gst_byte_reader_init(&reader, subSampleInfo.data, subSampleInfo.size);

        unsigned position = 0;
        unsigned sampleIndex = 0;
        while (position < bufferMap.size) {
            guint16 nBytesClear = 0;
            guint32 nBytesEncrypted = 0;

            if (sampleIndex < subSampleCount) {
                if (!gst_byte_reader_get_uint16_be(&reader, &nBytesClear) || !gst_byte_reader_get_uint32_be(&reader, &nBytesEncrypted)) {
                    GST_ERROR("Invalid subsample data");
                    goto out2;
                }
            } else {
                nBytesClear = 0;
                nBytesEncrypted = bufferMap.size - position;
            }

            if (sampleIndex > subSampleCount - 1)
                break;
            GST_TRACE("Sample %u: %" G_GUINT16_FORMAT " clear bytes, %" G_GUINT32_FORMAT " encrypted bytes",
                sampleIndex, nBytesClear, nBytesEncrypted);

            position += nBytesClear;
            sampleIndex++;
            if (nBytesEncrypted) {
                if (!EVP_CipherUpdate(m_evpCtx, bufferMap.data + position,
                        &outSize, bufferMap.data + position, nBytesEncrypted)) {
                    GST_ERROR("Unable to decrypt subsample data");
                    goto out2;
                }
            }
            position += nBytesEncrypted;
        }
        ret = ERROR_NONE;

    out2:
        gst_buffer_unmap(subSample, &subSampleInfo);
    }

out:
    gst_buffer_unmap(buffer, &bufferMap);
    gst_buffer_unmap(IV, &ivMap);
    gst_buffer_unmap(keyID, &keyIdMap);
    return ret;
}
