/**
 * \file mbedtls_config.h
 * Minimal configuration for AES-GCM 128-bit on Windows
 */

/* System support */
#define MBEDTLS_HAVE_ASM            /* Enable assembly optimizations (if available) */
#define MBEDTLS_HAVE_TIME           /* Enable time functions */
#define MBEDTLS_HAVE_TIME_DATE      /* Enable date/time functions */
#define MBEDTLS_PLATFORM_C          /* Enable platform functions (calloc, free, etc.) */
#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH /* Force 128-bit keys */

/* Enable only AES-GCM 128-bit */
#define MBEDTLS_AES_C              /* AES core */
#define MBEDTLS_GCM_C              /* GCM mode */
#define MBEDTLS_CIPHER_C           /* Cipher abstraction layer */
#define MBEDTLS_BIGNUM_C           /* Required for GCM */

/* Disable all other ciphers & hashes */
#undef MBEDTLS_AESNI_C            /* No AES-NI (unless you enable it for x86 acceleration) */
#undef MBEDTLS_AESCE_C            /* No ARM Crypto Extensions */
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_CCM_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_SHA1_C
#undef MBEDTLS_SHA224_C
#undef MBEDTLS_SHA256_C
#undef MBEDTLS_SHA384_C
#undef MBEDTLS_SHA512_C
#undef MBEDTLS_SHA3_C

/* Disable all cipher modes except GCM */
#undef MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_CIPHER_MODE_CFB
#undef MBEDTLS_CIPHER_MODE_CTR
#undef MBEDTLS_CIPHER_MODE_OFB
#undef MBEDTLS_CIPHER_MODE_XTS

/* Disable all unnecessary modules */
#undef MBEDTLS_ASN1_PARSE_C
#undef MBEDTLS_ASN1_WRITE_C
#undef MBEDTLS_BASE64_C
#undef MBEDTLS_CTR_DRBG_C
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_DHM_C
#undef MBEDTLS_ECDH_C
#undef MBEDTLS_ECDSA_C
#undef MBEDTLS_ECP_C
#undef MBEDTLS_ENTROPY_C
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_HMAC_DRBG_C
#undef MBEDTLS_MD_C
#undef MBEDTLS_NIST_KW_C
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_POLY1305_C
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_RSA_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_VERSION_C
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C

/* Optional optimizations */
//#define MBEDTLS_BLOCK_CIPHER_NO_DECRYPT /* If only encryption is needed */
//#define MBEDTLS_AES_ROM_TABLES          /* Store tables in ROM (not needed on Windows) */
//#define MBEDTLS_AES_FEWER_TABLES        /* Reduce table size (slower) */