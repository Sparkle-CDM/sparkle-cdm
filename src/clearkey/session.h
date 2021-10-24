// SPDX-License-Identifier: MIT

#pragma once

#include "common.h"
#include "system.h"
#include <gcrypt.h>
#include <map>
#include <vector>

struct OpenCDMSession {
public:
    OpenCDMSession(OpenCDMSystem* system,
        const std::string& initDataType,
        const uint8_t* pbInitData, const uint16_t cbInitData,
        const uint8_t* pbCustomData,
        const uint16_t cbCustomData,
        const LicenseType licenseType,
        OpenCDMSessionCallbacks* callbacks,
        void* userData);

    ~OpenCDMSession();

    const char* id() const { return m_id; }
    LicenseType licenseType() const { return m_licenseType; }

    KeyStatus keyStatus(const std::string& key_id) const;
    bool hasKeyID(const std::string& key_id) const;

    OpenCDMError load();
    OpenCDMError update(const std::string& response);
    OpenCDMError remove();
    OpenCDMError close();
    OpenCDMError destruct();
    OpenCDMError decrypt(GstBuffer* buffer, GstBuffer* subSample, const uint32_t subSampleCount, GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15);

    void cacheKey(const gchar* keyID, const gchar* keyValue);
    void processInitData();

private:
    gchar* encode_kid(const guint8* d, gsize size);

    gchar* m_id;
    OpenCDMSessionCallbacks* m_callbacks;
    void* m_userData;
    OpenCDMSystem* m_system;
    LicenseType m_licenseType;
    std::string m_initDataType;
    const uint8_t* m_pbInitData;
    const uint16_t m_cbInitData;

    std::map<std::string, std::pair<KeyStatus, std::string>> m_keyStatusMap;
    uint8_t m_iv[16];
    std::vector<uint8_t> m_buffer;
    gcry_cipher_hd_t m_handle;
    bool m_open{ false };
};
