#ifndef UTIL_H
#define UTIL_H

/* util.h and util.c functionaliy is meant to provide
 * a thin wrapper around our chosen crypto library
 * (OpenSSL). */

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

typedef struct cryptokey {
	EVP_PKEY* ossl_key;
	int references;
} cryptokey_t;

/* Digest functions */
void util_init_crypto(void);
void util_deinit_crypto(void);
int util_digestlen(void);

/* Key functions */
cryptokey_t* util_generate_key(int bits);
void util_free_key(cryptokey_t* key);
cryptokey_t* util_copy_key(cryptokey_t* key);
int util_hash(unsigned char* data, size_t datalen, unsigned char** digest, 
		unsigned int* digestlen);
int util_hash_pubkey(cryptokey_t* key, unsigned char** digest,
		unsigned int* digestlen);
int util_serialize_key(cryptokey_t* key, unsigned char** data, int* datalen);
int util_serialize_pubkey(cryptokey_t* key, char** data, int* datalen);
cryptokey_t* util_deserialize_key(char* data, int datalen);
cryptokey_t* util_deserialize_pubkey(char* data, int datalen);

/* Signing functions */
int util_sign(cryptokey_t* key, unsigned char* digest, size_t digestlen,
		unsigned char** sig_out, size_t* siglen_out);
int util_verify(cryptokey_t* key, unsigned char* sig, size_t siglen,
		unsigned char* digest, size_t digestlen);

/* General functions */
int util_base64_encode(const unsigned char* input, size_t inlen, 
		char** output, size_t* outlen);
int util_bytes_to_str(unsigned char* buffer, size_t buffer_len, char** str);
int util_str_to_bytes(char* str, size_t len, unsigned char** bufout,
		size_t* outlen);
char* util_parse_str(char* serial, const char* token, size_t token_len);
char* util_parse_int(char* serial, const char* token, size_t token_len, int* out);
char* util_parse_timestamp(char* serial, const char* token, size_t token_len, 
		struct timespec* out);

#endif
