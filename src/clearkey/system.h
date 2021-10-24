// SPDX-License-Identifier: MIT

#pragma once

#include "common.h"
#include "session.h"
#include <unordered_map>

struct OpenCDMSystem {
    OpenCDMSystem();
    OpenCDMSystem(const OpenCDMSystem&) = default;
    OpenCDMSystem(OpenCDMSystem&&) = default;
    OpenCDMSystem& operator=(OpenCDMSystem&&) = default;
    OpenCDMSystem& operator=(const OpenCDMSystem&) = default;
    ~OpenCDMSystem();

    void registerSession(OpenCDMSession*);
    void unregisterSession(const std::string& session_id);
    OpenCDMSession* getSessionForKeyID(const std::string& key_id, const uint32_t waitTime);

private:
    std::unordered_map<std::string, OpenCDMSession*> m_sessions;
};
