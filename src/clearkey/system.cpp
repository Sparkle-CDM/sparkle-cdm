// SPDX-License-Identifier: MIT

#include "system.h"
#include "open_cdm.h"
#include "session.h"
#include "sprkl/sprkl-cdm.h"

OpenCDMBool CKCDMSystem::supportsServerCertificate()
{
    return OPENCDM_BOOL_FALSE;
}

OpenCDMError CKCDMSystem::setServerCertificate(std::span<const uint8_t> certificate)
{
    UNUSED_PARAM(certificate);
    return ERROR_NONE;
}

OpenCDMError CKCDMSystem::constructSession(const LicenseType licenseType,
    const char initDataType[], std::span<const uint8_t> initData,
    std::span<const uint8_t> CDMData, OpenCDMSessionCallbacks* callbacks, void* userData,
    SparkleCDMSession** session)
{
    *session = new CKCDMSession(initDataType, initData, CDMData, licenseType, callbacks, userData);
    return ERROR_NONE;
}
