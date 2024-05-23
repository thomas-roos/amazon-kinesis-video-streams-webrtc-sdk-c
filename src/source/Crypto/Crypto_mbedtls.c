#include "Crypto.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

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

STATUS createRtcCertificate(PRtcCertificate* ppRtcCertificate) {
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 startTimeInMacro = 0;
    PRtcCertificate pRtcCertificate = NULL;

    CHK(ppRtcCertificate != NULL, STATUS_NULL_ARG);

    CHK(NULL != (pRtcCertificate = (PRtcCertificate) MEMCALLOC(1, SIZEOF(RtcCertificate))), STATUS_NOT_ENOUGH_MEMORY);

    // Allocate space for the cert and the key for mbedTLS
    CHK(NULL != (pRtcCertificate->pCertificate = (PBYTE) MEMCALLOC(1, SIZEOF(mbedtls_x509_crt))), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pRtcCertificate->pPrivateKey = (PBYTE) MEMCALLOC(1, SIZEOF(mbedtls_pk_context))), STATUS_NOT_ENOUGH_MEMORY);
    pRtcCertificate->certificateSize = SIZEOF(mbedtls_x509_crt);
    pRtcCertificate->privateKeySize = SIZEOF(mbedtls_pk_context);
    PROFILE_CALL(CHK_STATUS(gCryptoCallbacks.createCertificateAndKey(GENERATED_CERTIFICATE_BITS, FALSE, (mbedtls_x509_crt*) pRtcCertificate->pCertificate,
                                                    (mbedtls_pk_context*) pRtcCertificate->pPrivateKey)),
                 "Certificate creation time");
    *ppRtcCertificate = pRtcCertificate;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pRtcCertificate != NULL) {
        freeRtcCertificate(pRtcCertificate);
    }

    LEAVES();
    return retStatus;
}

STATUS freeRtcCertificate(PRtcCertificate pRtcCertificate) {
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
