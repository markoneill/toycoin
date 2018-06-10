#ifndef UTIL_H
#define UTIL_H

/* util.h and util.c functionaliy is meant to provide
 * a thin wrapper around our chosen crypto library
 * (OpenSSL). */

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define MAX_DIGEST_LEN	EVP_MAX_MD_SIZE
#define MAX_ID_LEN	ROUND_UP((MAX_DIGEST_LEN / 3) * 4, 4)

typedef struct cryptokey {
	EVP_PKEY* ossl_key;
} cryptokey_t;

/* Digest functions */
void util_init_crypto(void);
void util_deinit_crypto(void);
int util_digestlen(void);

/* Key functions */
cryptokey_t* util_generate_key(int bits);
void util_free_key(cryptokey_t* key);
int util_hash(unsigned char* data, size_t datalen, unsigned char* digest, 
		unsigned int* digestlen);
int util_hash_pubkey(cryptokey_t* key, unsigned char* digest,
		unsigned int* digestlen);
int util_serialize_key(cryptokey_t* key, unsigned char** data, int* datalen);
int util_serialize_pubkey(cryptokey_t* key, char** data, int* datalen);
cryptokey_t* util_deserialize_key(unsigned char* data, int datalen);

/* Signing functions */
int util_sign(cryptokey_t* key, unsigned char* digest, size_t digestlen,
		unsigned char** sig_out, size_t* siglen_out);

/* General functions */
int util_base64_encode(const unsigned char* input, size_t inlen, 
		char* output, size_t* outlen);
int util_bytes_to_str(unsigned char* buffer, size_t buffer_len, char** str);

#endif
