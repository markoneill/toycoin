#include <openssl/evp.h> /* for openssl message digest interface */
#include "log.h"
#include "util.h"

const EVP_MD* hash_alg;

void util_init_crypto(void) {
	OpenSSL_add_all_digests();
	hash_alg = EVP_sha256();
	return;
}

void util_deinit_crypto(void) {
	EVP_cleanup();
}

int util_digestlen(void) {
	return EVP_MD_size(hash_alg);
}

int util_hash(unsigned char* data, size_t* datalen, unsigned char* digest, 
		unsigned int* digestlen) {
	EVP_MD_CTX* md_ctx;
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	md_ctx = EVP_MD_CTX_new();
	#else
	md_ctx = EVP_MD_CTX_create();
	#endif

	if (EVP_DigestInit_ex(md_ctx, hash_alg, NULL) == 0) {
		log_printf(LOG_ERROR, "Failed to init digest\n");		
		return 0;
	}
	if (EVP_DigestUpdate(md_ctx, data, datalen) == 0) {
		log_printf(LOG_ERROR, "Failed to update digest\n");
		return 0;
	}
	if (EVP_DigestFinal_ex(md_ctx, digest, digestlen) == 0) {
		log_printf(LOG_ERROR, "Failed to finalize digest\n");
		return 0;
	}

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(md_ctx);
	#else
	EVP_MD_CTX_destroy(md_ctx);
	#endif
	return 1;
}
