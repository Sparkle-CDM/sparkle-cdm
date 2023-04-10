// SPDX-License-Identifier: MIT

#include <gst/gst.h>
#include <stdio.h>

#include "open_cdm.h"

#define UNUSED(v) (void)v
#define LOG(fmt, ...) \
  fprintf(stderr, "mock %s : " fmt "\n", __PRETTY_FUNCTION__, __VA_ARGS__)

OpenCDMError opencdm_is_type_supported(const char keySystem[],
                                       const char mimeType[]) {
  LOG("%s -- %s", keySystem, mimeType);
  return ERROR_NONE;
}

struct OpenCDMSystem {
  OpenCDMSystem(const char keySystem[]) { UNUSED(keySystem); }
};

struct OpenCDMSystem* opencdm_create_system(const char keySystem[]) {
  LOG("%s", keySystem);
  auto* system = new OpenCDMSystem(keySystem);
  return system;
}

OpenCDMError opencdm_destruct_system(struct OpenCDMSystem* system) {
  LOG("%p", system);
  return ERROR_NONE;
}

OpenCDMBool opencdm_system_supports_server_certificate(
    struct OpenCDMSystem* system) {
  LOG("%p", system);
  return OPENCDM_BOOL_FALSE;
}

struct OpenCDMSession* opencdm_get_system_session(struct OpenCDMSystem* system,
                                                  const uint8_t keyId[],
                                                  const uint8_t length,
                                                  const uint32_t waitTime) {
  LOG("%p", system);
  UNUSED(keyId);
  UNUSED(length);
  UNUSED(waitTime);
  return nullptr;
}

OpenCDMError opencdm_system_set_server_certificate(
    struct OpenCDMSystem* system, const uint8_t serverCertificate[],
    const uint16_t serverCertificateLength) {
  LOG("%p", system);
  UNUSED(serverCertificate);
  UNUSED(serverCertificateLength);
  return ERROR_NONE;
}

OpenCDMError opencdm_construct_session(
    struct OpenCDMSystem* system, const LicenseType licenseType,
    const char initDataType[], const uint8_t initData[],
    const uint16_t initDataLength, const uint8_t CDMData[],
    const uint16_t CDMDataLength, OpenCDMSessionCallbacks* callbacks,
    void* userData, struct OpenCDMSession** session) {
  LOG("%p", system);
  UNUSED(licenseType);
  UNUSED(initDataType);
  UNUSED(initData);
  UNUSED(initDataLength);
  UNUSED(CDMData);
  UNUSED(CDMDataLength);
  UNUSED(callbacks);
  UNUSED(userData);
  *session = nullptr;
  return ERROR_NONE;
}

OpenCDMError opencdm_destruct_session(struct OpenCDMSession* session) {
  LOG("%p", session);
  return ERROR_NONE;
}

const char* opencdm_session_id(const struct OpenCDMSession* session) {
  LOG("%p", session);
  return "mock";
}

KeyStatus opencdm_session_status(const struct OpenCDMSession* session,
                                 const uint8_t keyId[], const uint8_t length) {
  LOG("%p", session);
  UNUSED(keyId);
  UNUSED(length);
  return Usable;
}

OpenCDMError opencdm_session_load(struct OpenCDMSession* session) {
  LOG("%p", session);
  return ERROR_NONE;
}

OpenCDMError opencdm_session_update(struct OpenCDMSession* session,
                                    const uint8_t keyMessage[],
                                    const uint16_t keyLength) {
  LOG("%p", session);
  UNUSED(keyMessage);
  UNUSED(keyLength);
  return ERROR_NONE;
}

OpenCDMError opencdm_session_remove(struct OpenCDMSession* session) {
  LOG("%p", session);
  return ERROR_NONE;
}

OpenCDMError opencdm_session_close(struct OpenCDMSession* session) {
  LOG("%p", session);
  return ERROR_NONE;
}

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session,
                                               GstBuffer* buffer,
                                               GstBuffer* subSamples,
                                               const uint32_t subSampleCount,
                                               OpenCDMEncryptionScheme encryptionScheme,
                                               GstBuffer* IV, GstBuffer* keyID,
                                               uint32_t initWithLast15) {
  LOG("%p", session);
  UNUSED(buffer);
  UNUSED(subSamples);
  UNUSED(subSampleCount);
  UNUSED(encryptionScheme);
  UNUSED(IV);
  UNUSED(keyID);
  UNUSED(initWithLast15);
  return ERROR_NONE;
}
