// SPDX-License-Identifier: MIT

#include <gst/gst.h>
#include <stdio.h>
#include <string>

#include "open_cdm.h"
#include "sprkl-cdm.h"

#define UNUSED(v) (void)v
#define LOG(fmt, ...) \
    fprintf(stderr, "mock %s : " fmt "\n", __PRETTY_FUNCTION__, __VA_ARGS__)

OpenCDMError opencdm_is_type_supported(const char keySystem[],
    const char mimeType[])
{
    LOG("%s -- %s", keySystem, mimeType);
    return ERROR_NONE;
}

class MockCDMSystem final : public SparkleCDMSystem {
public:
    MockCDMSystem(const char keySystem[]) { UNUSED(keySystem); }
    OpenCDMBool supportsServerCertificate() final;
    OpenCDMError setServerCertificate(std::span<const uint8_t>) final;
    OpenCDMError constructSession(const LicenseType, const char initDataType[], std::span<const uint8_t> initData, std::span<const uint8_t> cdmData, OpenCDMSessionCallbacks*, void*, SparkleCDMSession**) final;
};

SparkleCDMSystem* sprkl_cdm_create_system(const char keySystem[])
{
    LOG("%s", keySystem);
    auto* system = new MockCDMSystem(keySystem);
    return static_cast<SparkleCDMSystem*>(system);
}

OpenCDMError sprkl_cdm_destruct_system(SparkleCDMSystem* system)
{
    LOG("%p", system);
    delete static_cast<MockCDMSystem*>(system);
    return ERROR_NONE;
}

OpenCDMBool MockCDMSystem::supportsServerCertificate()
{
    LOG("%p", this);
    return OPENCDM_BOOL_FALSE;
}

OpenCDMError MockCDMSystem::setServerCertificate(std::span<const uint8_t> certificate)
{
    LOG("%p", this);
    UNUSED(certificate);
    return ERROR_NONE;
}

OpenCDMError MockCDMSystem::constructSession(const LicenseType licenseType,
    const char initDataType[], std::span<const uint8_t> initData, std::span<const uint8_t> cdmData, OpenCDMSessionCallbacks* callbacks,
    void* userData, SparkleCDMSession** session)
{
    LOG("%p", this);
    UNUSED(licenseType);
    UNUSED(initDataType);
    UNUSED(initData);
    UNUSED(cdmData);
    UNUSED(callbacks);
    UNUSED(userData);
    *session = nullptr;
    return ERROR_NONE;
}

OpenCDMError spkrl_cdm_destruct_session(SparkleCDMSession* session)
{
    LOG("%p", session);
    return ERROR_NONE;
}

const char* opencdm_session_id(const struct OpenCDMSession* session)
{
    LOG("%p", session);
    return "mock";
}

KeyStatus opencdm_session_status(const struct OpenCDMSession* session,
    const uint8_t keyId[], const uint8_t length)
{
    LOG("%p", session);
    UNUSED(keyId);
    UNUSED(length);
    return Usable;
}

uint32_t opencdm_session_has_key_id(struct OpenCDMSession* session,
    const uint8_t length, const uint8_t keyId[])
{
    LOG("%p", session);
    UNUSED(length);
    UNUSED(keyId);
    return true;
}

OpenCDMError opencdm_session_load(struct OpenCDMSession* session)
{
    LOG("%p", session);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_update(struct OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength)
{
    LOG("%p", session);
    UNUSED(keyMessage);
    UNUSED(keyLength);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_remove(struct OpenCDMSession* session)
{
    LOG("%p", session);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_close(struct OpenCDMSession* session)
{
    LOG("%p", session);
    return ERROR_NONE;
}

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session,
    GstBuffer* buffer,
    GstBuffer* subSamples,
    const uint32_t subSampleCount,
    GstBuffer* IV, GstBuffer* keyID,
    uint32_t initWithLast15)
{
    LOG("%p", session);
    UNUSED(buffer);
    UNUSED(subSamples);
    UNUSED(subSampleCount);
    UNUSED(IV);
    UNUSED(keyID);
    UNUSED(initWithLast15);
    return ERROR_NONE;
}

OpenCDMError opencdm_gstreamer_session_decrypt_v2(struct OpenCDMSession* session,
    GstBuffer* buffer,
    GstCaps*,
    GstBuffer* subSample,
    const uint32_t subSampleCount,
    GstBuffer* IV, GstBuffer* keyID)
{
    LOG("%p", session);
    UNUSED(buffer);
    UNUSED(subSample);
    UNUSED(subSampleCount);
    UNUSED(IV);
    UNUSED(keyID);
    return ERROR_NONE;
}
