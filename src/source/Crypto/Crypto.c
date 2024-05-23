#define LOG_CLASS "Crypto"
#include "../Include_i.h"

#ifdef KVS_USE_OPENSSL
// Forward declarations of callback functions
STATUS createCertificateAndKeyOpenSSL(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey);
void freeCertificateOpenSSL(void* pCert);
void freePrivateKeyOpenSSL(void* pKey);

// Set callback functions based on the defined crypto library
CryptoCallbacks gCryptoCallbacks = {
    .createCertificateAndKey = createCertificateAndKeyOpenSSL,
    .freeCertificate = freeCertificateOpenSSL,
    .freePrivateKey = freePrivateKeyOpenSSL
};

#elif KVS_USE_MBEDTLS
// Forward declarations of callback functions
STATUS createCertificateAndKeyMbedTLS(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey);
void freeCertificateMbedTLS(void* pCert);
void freePrivateKeyMbedTLS(void* pKey);

// Set callback functions based on the defined crypto library
CryptoCallbacks gCryptoCallbacks = {
    .createCertificateAndKey = createCertificateAndKeyMbedTLS,
    .freeCertificate = freeCertificateMbedTLS,
    .freePrivateKey = freePrivateKeyMbedTLS
};
#else
#error "A Crypto implementation is required."
#endif
