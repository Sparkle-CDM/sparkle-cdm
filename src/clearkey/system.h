// SPDX-License-Identifier: MIT

#pragma once

#include "common.h"
#include "sprkl/sprkl-cdm.h"
#include <unordered_map>
#include <span>
#include <string>

class CKCDMSession;

class CKCDMSystem final : public SparkleCDMSystem {
public:
    OpenCDMBool supportsServerCertificate() final;
    OpenCDMError setServerCertificate(std::span<const uint8_t>) final;
    OpenCDMError constructSession(const LicenseType, const char initDataType[], std::span<const uint8_t> initData, std::span<const uint8_t> cdmData, OpenCDMSessionCallbacks*, void*, SparkleCDMSession**) final;

private:
    std::unordered_map<std::string, CKCDMSession*> m_sessions;
};
