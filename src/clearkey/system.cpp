// SPDX-License-Identifier: MIT

#include "system.h"
#include "open_cdm.h"

using namespace std;

#define GST_CAT_DEFAULT cdm_debug_category

OpenCDMSystem::OpenCDMSystem()
{
}

OpenCDMSystem::~OpenCDMSystem()
{
}

void OpenCDMSystem::registerSession(OpenCDMSession* session)
{
    m_sessions.insert({ session->id(), session });
}

void OpenCDMSystem::unregisterSession(const string& session_id)
{
    auto result = m_sessions.find(session_id);
    if (result != m_sessions.end())
        m_sessions.erase(result);
}

OpenCDMSession* OpenCDMSystem::getSessionForKeyID(const std::string& key_id, const uint32_t waitTime)
{
    UNUSED_PARAM(waitTime);
    for (auto& it : m_sessions) {
        if (it.second->hasKeyID(key_id))
            return it.second;
    }
    return nullptr;
}

OpenCDMBool opencdm_system_supports_server_certificate(struct OpenCDMSystem* system)
{
    UNUSED_PARAM(system);
    return OPENCDM_BOOL_FALSE;
}

OpenCDMError opencdm_system_set_server_certificate(struct OpenCDMSystem* system, const uint8_t serverCertificate[], const uint16_t serverCertificateLength)
{
    UNUSED_PARAM(system);
    UNUSED_PARAM(serverCertificate);
    UNUSED_PARAM(serverCertificateLength);
    return ERROR_NONE;
}

OpenCDMError opencdm_construct_session(struct OpenCDMSystem* system, const LicenseType licenseType,
    const char initDataType[], const uint8_t initData[], const uint16_t initDataLength,
    const uint8_t CDMData[], const uint16_t CDMDataLength, OpenCDMSessionCallbacks* callbacks, void* userData,
    struct OpenCDMSession** session)
{
    *session = new OpenCDMSession(system, initDataType, initData, initDataLength, CDMData, CDMDataLength, licenseType, callbacks, userData);
    return ERROR_NONE;
}
