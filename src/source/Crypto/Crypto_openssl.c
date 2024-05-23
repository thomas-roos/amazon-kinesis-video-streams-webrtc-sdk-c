#include "Crypto.h"

#include <openssl/x509.h>
#include <openssl/evp.h>

STATUS createCertificateAndKeyOpenSSL(UINT32 bits, BOOL isCa, void** ppCert, void** ppKey) {
    return createCertificateAndKey(bits, isCa, (X509**) ppCert, (EVP_PKEY**) ppKey);
}

void freeCertificateOpenSSL(void* pCert) {
    X509_free((X509*) pCert);
}

void freePrivateKeyOpenSSL(void* pKey) {
    EVP_PKEY_free((EVP_PKEY*) pKey);
}


STATUS createRtcCertificate(PRtcCertificate* ppRtcCertificate) {
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 startTimeInMacro = 0;
    PRtcCertificate pRtcCertificate = NULL;

    CHK(ppRtcCertificate != NULL, STATUS_NULL_ARG);

    CHK(NULL != (pRtcCertificate = (PRtcCertificate) MEMCALLOC(1, SIZEOF(RtcCertificate))), STATUS_NOT_ENOUGH_MEMORY);

    PROFILE_CALL(CHK_STATUS(gCryptoCallbacks.createCertificateAndKey(GENERATED_CERTIFICATE_BITS, FALSE, (X509**) &pRtcCertificate->pCertificate,
                                                    (EVP_PKEY**) &pRtcCertificate->pPrivateKey)),
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
