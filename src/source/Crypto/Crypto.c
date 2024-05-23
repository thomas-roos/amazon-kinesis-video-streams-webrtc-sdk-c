#define LOG_CLASS "Crypto"
#include "../Include_i.h"

// OpenSSL-specific callback functions
#ifdef KVS_USE_OPENSSL
STATUS createCertificateAndKeyOpenSSL(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey) {
 return createCertificateAndKey(bits, isCa, (X509**) ppCert, (EVP_PKEY**) ppKey);
}
void freeCertificateOpenSSL(void* pCert) {
 X509_free((X509*) pCert);
}
void freePrivateKeyOpenSSL(void* pKey) {
 EVP_PKEY_free((EVP_PKEY*) pKey);
}
#endif

// MbedTLS-specific callback functions
#ifdef KVS_USE_MBEDTLS
STATUS createCertificateAndKeyMbedTLS(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey) {
    return createCertificateAndKey(bits, isCa, (mbedtls_x509_crt*) ppCert, (mbedtls_pk_context*) ppKey);
}

void freeCertificateMbedTLS(void* pCert) {
    mbedtls_x509_crt_free((mbedtls_x509_crt*) pCert);
    SAFE_MEMFREE(pCert);
}

void freePrivateKeyMbedTLS(void* pKey) {
    mbedtls_pk_free((mbedtls_pk_context*) pKey);
    SAFE_MEMFREE(pKey);
}
#endif

// Set callback functions
#ifdef KVS_USE_OPENSSL
CryptoCallbacks gCryptoCallbacks = {
    .createCertificateAndKey = createCertificateAndKeyOpenSSL,
    .freeCertificate = freeCertificateOpenSSL,
    .freePrivateKey = freePrivateKeyOpenSSL
};
#elif KVS_USE_MBEDTLS
CryptoCallbacks gCryptoCallbacks = {
    .createCertificateAndKey = createCertificateAndKeyMbedTLS,
    .freeCertificate = freeCertificateMbedTLS,
    .freePrivateKey = freePrivateKeyMbedTLS
};
#else
#error "A Crypto implementation is required."
#endif

// External declaration of the global CryptoCallbacks instance
extern CryptoCallbacks gCryptoCallbacks;

// Functions
STATUS createRtcCertificate(PRtcCertificate* ppRtcCertificate) {
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 startTimeInMacro = 0;
    PRtcCertificate pRtcCertificate = NULL;

    CHK(ppRtcCertificate != NULL, STATUS_NULL_ARG);

    CHK(NULL != (pRtcCertificate = (PRtcCertificate) MEMCALLOC(1, SIZEOF(RtcCertificate))), STATUS_NOT_ENOUGH_MEMORY);

#ifdef KVS_USE_OPENSSL
    PROFILE_CALL(CHK_STATUS(gCryptoCallbacks.createCertificateAndKey(GENERATED_CERTIFICATE_BITS, FALSE, (X509**) &pRtcCertificate->pCertificate,
                                                    (EVP_PKEY**) &pRtcCertificate->pPrivateKey)),
                 "Certificate creation time");
#elif KVS_USE_MBEDTLS
 // Need to allocate space for the cert and the key for mbedTLS
    CHK(NULL != (pRtcCertificate->pCertificate = (PBYTE) MEMCALLOC(1, SIZEOF(mbedtls_x509_crt))), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pRtcCertificate->pPrivateKey = (PBYTE) MEMCALLOC(1, SIZEOF(mbedtls_pk_context))), STATUS_NOT_ENOUGH_MEMORY);
    pRtcCertificate->certificateSize = SIZEOF(mbedtls_x509_crt);
    pRtcCertificate->privateKeySize = SIZEOF(mbedtls_pk_context);
    PROFILE_CALL(CHK_STATUS(gCryptoCallbacks.createCertificateAndKey(GENERATED_CERTIFICATE_BITS, FALSE, (mbedtls_x509_crt*) pRtcCertificate->pCertificate,
                                                    (mbedtls_pk_context*) pRtcCertificate->pPrivateKey)),
                 "Certificate creation time");
#else
#error "A Crypto implementation is required."
#endif

    *ppRtcCertificate = pRtcCertificate;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pRtcCertificate != NULL) {
        freeRtcCertificate(pRtcCertificate);
    }

    LEAVES();
    return retStatus;
}

STATUS freeRtcCertificate(PRtcCertificate pRtcCertificate)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    // The call is idempotent
    CHK(pRtcCertificate != NULL, retStatus);

    if (pRtcCertificate->pCertificate != NULL) {
        gCryptoCallbacks.freeCertificate(pRtcCertificate->pCertificate);
    }

    if (pRtcCertificate->pPrivateKey != NULL) {
        gCryptoCallbacks.freePrivateKey(pRtcCertificate->pPrivateKey);
    }

    MEMFREE(pRtcCertificate);

CleanUp:
    LEAVES();
    return retStatus;
}
