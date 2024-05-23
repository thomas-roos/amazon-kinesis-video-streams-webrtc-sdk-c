#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_CRYPTO_CRYPTO__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_CRYPTO_CRYPTO__
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../Include_i.h"

#ifdef KVS_USE_OPENSSL
#include "Crypto_openssl.h"
#elif KVS_USE_MBEDTLS
#include "Crypto_mbedtls.h"
#endif

// Define the CryptoCallbacks structure
typedef struct {
    STATUS (*createCertificateAndKey)(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey);
    void (*freeCertificate)(void* pCert);
    void (*freePrivateKey)(void* pKey);
} CryptoCallbacks;

// External declaration of the global CryptoCallbacks instance
extern CryptoCallbacks gCryptoCallbacks;

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_CRYPTO_CRYPTO__
