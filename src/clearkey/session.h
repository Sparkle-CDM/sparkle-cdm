// SPDX-License-Identifier: MIT

#pragma once

#include "common.h"
#include "system.h"
#include <map>
#include <openssl/evp.h>
#include <vector>
#include "sprkl-cdm.h"

class CKCDMSession final : public SparkleCDMSession {
public:
    CKCDMSession(const char initDataType[],
                 std::span<const uint8_t> initData,
                 std::span<const uint8_t> customData,
        const LicenseType licenseType,
        OpenCDMSessionCallbacks* callbacks,
        void* userData);

    ~CKCDMSession();

    const std::string& getId() const final { return m_id; }
    KeyStatus status(std::span<const uint8_t> keyId) final;
    uint32_t hasKeyId(std::span<const uint8_t> keyId) final;
    OpenCDMError load() final;
    OpenCDMError update(std::span<const uint8_t> message) final;
    OpenCDMError remove() final;
    OpenCDMError close() final;
    OpenCDMError decrypt(GstBuffer* buffer, GstBuffer* subSamples, const uint32_t subSampleCount,
                         GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15) final;
    OpenCDMError decryptBuffer(GstBuffer* buffer, GstCaps* caps, GstBuffer* subSamples,
                               const uint32_t subSampleCount, GstBuffer* IV, GstBuffer* keyID) final;

    LicenseType licenseType() const { return m_licenseType; }

    OpenCDMError destruct();

    void cacheKey(const gchar* keyID, const gchar* keyValue);

private:
    void processInitData();
    gchar* encode_kid(const guint8* d, gsize size);

  std::string m_id;
    OpenCDMSessionCallbacks* m_callbacks;
    void* m_userData;
    LicenseType m_licenseType;
    std::string m_initDataType;
    std::span<const uint8_t> m_initData;

    std::map<std::string, std::pair<KeyStatus, std::string>> m_keyStatusMap;
    uint8_t m_iv[16];
    std::vector<uint8_t> m_buffer;
    EVP_CIPHER_CTX* m_evpCtx { nullptr };
    GMutex m_mutex; // For basic MT-safety in decrypt().
};
