// SPDX-License-Identifier: MIT

#include "common.h"
#include "open_cdm.h"
#include "system.h"
#include <mutex>

GST_DEBUG_CATEGORY(cdm_debug_category);
#define GST_CAT_DEFAULT cdm_debug_category

OpenCDMError opencdm_is_type_supported(const char keySystem[], const char mimeType[])
{
    // TODO: Also check mimeType
    UNUSED_PARAM(mimeType);
    if (g_strcmp0(keySystem, "org.w3.clearkey") != 0)
        return ERROR_FAIL;
    return ERROR_NONE;
}

struct OpenCDMSystem* opencdm_create_system(const char keySystem[])
{
    g_return_val_if_fail(g_str_equal(keySystem, "org.w3.clearkey"), nullptr);

    std::once_flag init_flag;
    std::call_once(init_flag, [&] {
        GST_DEBUG_CATEGORY_INIT(cdm_debug_category, "sprklclearkey", 0, "W3C ClearKey decryption module");
    });

    struct OpenCDMSystem* system = new OpenCDMSystem;
    GST_DEBUG("System %p created", system);
    return system;
}

OpenCDMError opencdm_destruct_system(struct OpenCDMSystem* system)
{
    delete system;
    return ERROR_NONE;
}

struct OpenCDMSession* opencdm_get_system_session(struct OpenCDMSystem* system, const uint8_t keyId[],
    const uint8_t length, const uint32_t waitTime)
{
    std::string key_id(keyId, keyId + length);
    return system->getSessionForKeyID(key_id, waitTime);
}
