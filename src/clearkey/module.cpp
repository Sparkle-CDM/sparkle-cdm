// SPDX-License-Identifier: MIT

#include "common.h"
#include "open_cdm.h"
#include "sprkl/sprkl-cdm.h"
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

SparkleCDMSystem* sprkl_cdm_create_system(const char keySystem[])
{
    g_return_val_if_fail(g_str_equal(keySystem, "org.w3.clearkey"), nullptr);

    std::once_flag init_flag;
    std::call_once(init_flag, [&] {
        GST_DEBUG_CATEGORY_INIT(cdm_debug_category, "sprklclearkey", 0, "W3C ClearKey decryption module");
    });

    auto system = new CKCDMSystem;
    GST_DEBUG("System %p created", system);
    return static_cast<SparkleCDMSystem*>(system);
}

OpenCDMError sprkl_cdm_destruct_system(SparkleCDMSystem* system)
{
    delete static_cast<CKCDMSystem*>(system);
    return ERROR_NONE;
}
