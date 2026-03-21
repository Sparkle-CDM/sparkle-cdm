
#pragma once

#include <gst/gst.h>
#include <open_cdm.h>
#include <string>
#include <span>

class SparkleCDMSession {
public:
    virtual const std::string& getId() const = 0;
    virtual KeyStatus status(std::span<const uint8_t> keyId) = 0;
    virtual uint32_t hasKeyId(std::span<const uint8_t> keyId) = 0;
    virtual OpenCDMError load() = 0;
    virtual OpenCDMError update(std::span<const uint8_t> message) = 0;
    virtual OpenCDMError remove() = 0;
    virtual OpenCDMError close() = 0;
    virtual OpenCDMError decrypt(GstBuffer* buffer, GstBuffer* subSamples, const uint32_t subSampleCount,
                                 GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15) = 0;
    virtual OpenCDMError decryptBuffer(GstBuffer *buffer, GstCaps *caps, GstBuffer *subSamples,
                                       const uint32_t subSampleCount, GstBuffer *IV, GstBuffer *keyID) = 0;

    void setParent(OpenCDMSession* parent) { m_parent = parent; }
    OpenCDMSession* parent() const { return m_parent; }

private:
    OpenCDMSession* m_parent;
};

class SparkleCDMSystem {
public:
    virtual OpenCDMBool supportsServerCertificate() = 0;
    virtual OpenCDMError setServerCertificate(std::span<const uint8_t> certificate) = 0;
    virtual OpenCDMError constructSession(const LicenseType, const char initDataType[], std::span<const uint8_t> initData, std::span<const uint8_t> cdmData, OpenCDMSessionCallbacks*, void*, SparkleCDMSession**) = 0;
};

#ifdef __cplusplus
extern "C" {
#endif

EXTERNAL SparkleCDMSystem* sprkl_cdm_create_system(const char keySystem[]);
EXTERNAL OpenCDMError sprkl_cdm_destruct_system(SparkleCDMSystem*);
EXTERNAL OpenCDMError sprkl_cdm_destruct_session(SparkleCDMSession*);

#ifdef __cplusplus
}
#endif
