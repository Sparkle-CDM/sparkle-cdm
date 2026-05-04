// SPDX-License-Identifier: MIT

#include "system.h"
#include "open_cdm.h"
#include "session.h"
#include "sprkl/sprkl-cdm.h"
#include <sstream>

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
    std::stringstream stream;
    stream << m_sessionId;
    m_sessionId++;
    auto id = stream.str();

    *session = new CKCDMSession(id, initDataType, initData, CDMData, licenseType, callbacks, userData);
    return ERROR_NONE;
}
