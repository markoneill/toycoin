#ifndef UTIL_H
#define UTIL_H

/* util.h and util.c functionaliy is meant to provide
 * a thin wrapper around our chosen crypto library
 * (OpenSSL). */

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

#define MAX_DIGEST_LEN	EVP_MAX_MD_SIZE

typedef struct cryptokey {
	EVP_PKEY* ossl_key;
} cryptokey_t;

void util_init_crypto(void);
void util_deinit_crypto(void);
int util_digestlen(void);
cryptokey_t* util_generate_key(int bits);
int util_hash_pubkey(cryptokey_t* key, unsigned char* digest, size_t* digest_len);
void util_free_key(cryptokey_t* key);
int util_serialize_key(cryptokey_t* key, unsigned char** data, int* datalen);
cryptokey_t* util_deserialize_key(unsigned char* data, int datalen);

#endif
