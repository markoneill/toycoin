#include <openssl/evp.h> /* for pki operations */
#include <openssl/crypto.h> /* for RSA key generation */
#include <openssl/pem.h> /* for PEM format read and write */
#include <openssl/bio.h> /* for BIO operations */
#include <openssl/engine.h> /* for ENGINE_cleanup() */
#include <string.h> /* for memcpy */
#include <arpa/inet.h> /* for htonl */
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
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

int util_digestlen(void) {
	return EVP_MD_size(hash_alg);
}

int util_hash(unsigned char* data, size_t datalen, unsigned char** digest, 
		unsigned int* digestlen) {
	unsigned char* output;
	EVP_MD_CTX* md_ctx;
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	md_ctx = EVP_MD_CTX_new();
	#else
	md_ctx = EVP_MD_CTX_create();
	#endif

	output = (unsigned char*)malloc(util_digestlen());
	if (output == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate digest\n");
		return 0;
	}

	if (EVP_DigestInit_ex(md_ctx, hash_alg, NULL) == 0) {
		log_printf(LOG_ERROR, "Failed to init digest\n");
		free(output);
		return 0;
	}
	if (EVP_DigestUpdate(md_ctx, data, datalen) == 0) {
		log_printf(LOG_ERROR, "Failed to update digest\n");
		free(output);
		return 0;
	}
	if (EVP_DigestFinal_ex(md_ctx, output, digestlen) == 0) {
		log_printf(LOG_ERROR, "Failed to finalize digest\n");
		free(output);
		return 0;
	}

	*digest = output;

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(md_ctx);
	#else
	EVP_MD_CTX_destroy(md_ctx);
	#endif
	return 1;
}

int util_bytes_to_str(unsigned char* buffer, size_t buffer_len, char** str) {
	char* tmp;
	int i;
	tmp = (char*)malloc(buffer_len * 2 + 1);
	if (tmp == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate string space\n");
		return 0;
	}
	for (i = 0; i < buffer_len; i++) {
		sprintf(tmp + (i*2), "%02X", buffer[i]);
	}
	tmp[buffer_len * 2] =  '\0';
	*str = tmp;
	return 1;
}

int util_str_to_bytes(char* str, size_t len, unsigned char** bufout,
		size_t* outlen) {
	unsigned char* buffer;
	size_t buflen;
	unsigned int i;
	
	buflen = len / 2;
	buffer = (unsigned char*)malloc(buflen);
	if (buffer == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate buffer space\n");
		return 0;
	}

	for (i = 0; i < buflen; i++) {
		sscanf(str, "%02hhX", (char*)&buffer[i]);
		str += 2;
	}

	*bufout = buffer;
	if (outlen != NULL) {
		*outlen = buflen;
	}
	return 1;
}

cryptokey_t* util_generate_key(int bits) {
	unsigned long e;
	BIGNUM* bn_e;
	RSA* rsa;
	cryptokey_t* key;
	EVP_PKEY* keypair;

	e = RSA_F4;	

	bn_e = BN_new();
	if (bn_e == NULL) {
		log_printf(LOG_ERROR, "Failed to make bignum\n");
		return NULL;
	}
	if (BN_set_word(bn_e, e) != 1) {
		log_printf(LOG_ERROR, "Failed set bignum\n");
		BN_free(bn_e);
		return NULL;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new RSA\n");
		BN_free(bn_e);
		return NULL;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		log_printf(LOG_ERROR, "Failed to generate new RSA\n");
		BN_free(bn_e);
		RSA_free(rsa);
		return NULL;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new keypair\n");
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		log_printf(LOG_ERROR, "Failed to assign RSA to keypair\n");
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	key = calloc(1, sizeof(cryptokey_t));
	if (key == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new cryptokey\n");
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	key->ossl_key = keypair;
	key->references = 1;
	BN_free(bn_e);
	return key;
}

cryptokey_t* util_copy_key(cryptokey_t* key) {
	cryptokey_t* copy;
	/*copy = calloc(1, sizeof(cryptokey_t));
	if (copy == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate cryptokey copy\n");
		return NULL;
	}
	EVP_PKEY_dup(key->ossl_key);*/

	copy = key;
	copy->references++;
	copy->ossl_key = key->ossl_key;
	return copy;
}

int util_hash_pubkey(cryptokey_t* key, unsigned char** digest,
		unsigned int* digestlen) {
	EVP_PKEY* keypair;
	unsigned char* encoded_pubkey;
	unsigned char* encoded_pubkey_end;
	int encoded_len;

	keypair = key->ossl_key;

	encoded_len = i2d_PUBKEY(keypair, NULL);
	if (encoded_len < 0) {
		log_printf(LOG_ERROR, "Failed to get public key length\n");
		return 0;
	}
	encoded_pubkey = malloc(encoded_len);
	if (encoded_pubkey == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate encoded key\n");
		return 0;
	}
	encoded_pubkey_end = encoded_pubkey;
	encoded_len = i2d_PUBKEY(keypair, &encoded_pubkey_end);
	if (encoded_len < 0) {
		log_printf(LOG_ERROR, "Failed to encode public key\n");
		free(encoded_pubkey);
		return 0;
	}

	if (util_hash(encoded_pubkey, encoded_len, digest, digestlen) == 0) {
		log_printf(LOG_ERROR, "Unable to hash public key\n");
		free(encoded_pubkey);
		return 0;
	}

	free(encoded_pubkey);
	return 1;
}

void util_free_key(cryptokey_t* key) {
	if (key == NULL) {
		return;
	}
	key->references--;
	if (key->references == 0) {
		EVP_PKEY_free(key->ossl_key);
		free(key);
	}
	return;
}

int util_serialize_key(cryptokey_t* key, unsigned char** data, int* datalen) {
	BIO* bio;
	unsigned char* bio_data;
	unsigned char* buffer;
	long len;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		log_printf(LOG_ERROR, "Unable to create bio for key\n");
		return 0;
	}
	if (PEM_write_bio_PrivateKey(bio, key->ossl_key, 
			NULL, NULL, 0, NULL, NULL) == 0) {
		log_printf(LOG_ERROR, "Unable to write PEM string for key\n");
		BIO_free(bio);
		return 0;
	}
	len = BIO_get_mem_data(bio, &bio_data);
	buffer = malloc(len + 1);
	if (buffer == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate buffer for key\n");
		BIO_free(bio);
		return 0;
	}
	memcpy(buffer, bio_data, len);
	buffer[len] = '\0';

	if (datalen != NULL) {
		*datalen = (int)len + 1;
	}
	*data = buffer;
	BIO_free(bio);
	return 1;
}

cryptokey_t* util_deserialize_key(char* data, int datalen) {
	cryptokey_t* key;
	EVP_PKEY* ossl_key;
	BIO* bio;

	bio = BIO_new_mem_buf(data, datalen);
	if (bio == NULL) {
		log_printf(LOG_ERROR, "Unable to create bio for key\n");
		return NULL;
	}
	ossl_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (ossl_key == NULL) {
		log_printf(LOG_ERROR, "Unable to read key from bio\n");
		BIO_free(bio);
		return NULL;
	}
	BIO_free(bio);
	key = calloc(1, sizeof(cryptokey_t));
	if (key == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate cryptokey\n");
		return NULL;
	}

	key->ossl_key = ossl_key;
	key->references = 1;
	return key;
}

int util_serialize_pubkey(cryptokey_t* key, char** data, int* datalen) {
	BIO* bio;
	unsigned char* bio_data;
	long len;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		log_printf(LOG_ERROR, "Unable to create bio for key\n");
		return 0;
	}
	if (i2d_PUBKEY_bio(bio, key->ossl_key) == 0) {
		log_printf(LOG_ERROR, "Unable to write PEM string for key\n");
		BIO_free(bio);
		return 0;
	}
	len = BIO_get_mem_data(bio, &bio_data);

	if (util_bytes_to_str(bio_data, len, data) == 0) {
		log_printf(LOG_ERROR, "Unable to convert bytes to string\n");
		BIO_free(bio);
		return 0;
	}

	if (datalen != NULL) {
		*datalen = strlen(*data);
	}
	BIO_free(bio);
	return 1;
}

cryptokey_t* util_deserialize_pubkey(char* data, int datalen) {
	cryptokey_t* key;
	EVP_PKEY* ossl_key;
	unsigned char* buffer;
	unsigned char* p;
	size_t buflen;

	if (util_str_to_bytes(data, datalen, &buffer, &buflen) == 0) {
		log_printf(LOG_ERROR, "Unable to convert string to bytes\n");
		return NULL;
	}

	p = buffer;
	ossl_key = d2i_PUBKEY(NULL, (const unsigned char**)&p, buflen);
	if (ossl_key == NULL) {
		log_printf(LOG_ERROR, "Unable to deseralize pubkey\n");
		return NULL;
	}

	free(buffer);
	key = calloc(1, sizeof(cryptokey_t));
	if (key == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate cryptokey\n");
		return NULL;
	}

	key->ossl_key = ossl_key;
	key->references = 1;
	return key;
}

int util_base64_encode(const unsigned char* input, size_t inlen, 
		char** output, size_t* outlen) {
	BIO *bio;
	BIO *bio_b64;
	char* buffer_ptr;
	char* encoding;
	int written;

	bio_b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(bio_b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_set_close(bio, BIO_CLOSE);
	written = BIO_write(bio, input, inlen);
	if (written <= 0) {
		log_printf(LOG_ERROR, "Failed to write base64 input\n");
		BIO_free_all(bio);
		return 0;
	}
	BIO_flush(bio);

	written = BIO_get_mem_data(bio, &buffer_ptr);
	encoding = (char*)malloc(written + 1);
	if (encoding == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate encoding\n");
		BIO_free_all(bio);
	}
	memcpy(encoding, buffer_ptr, written);
	encoding[written] = '\0';
	*output = encoding;
	BIO_free_all(bio);
	if (outlen != NULL) {
		*outlen = written;
	}
	return 1;
}

int util_sign(cryptokey_t* key, unsigned char* digest, size_t digestlen,
		unsigned char** sig_out, size_t* siglen_out) {
	EVP_PKEY_CTX* ctx;
	unsigned char* sig;
	size_t siglen;
	ctx = EVP_PKEY_CTX_new(key->ossl_key, NULL);
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Unable to initialize pkey context\n");
		return 0;
	}

	if (EVP_PKEY_sign_init(ctx) <= 0) {
		log_printf(LOG_ERROR, "Unable to init signing\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		log_printf(LOG_ERROR, "Unable to set padding for signing\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}
	/*EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1);*/

	if (EVP_PKEY_CTX_set_signature_md(ctx, hash_alg) <= 0) {
		log_printf(LOG_ERROR, "Unable to set hash alg for signing\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	/* Get length of signature */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, digest, digestlen) <= 0) {
		log_printf(LOG_ERROR, "Unable to get signature length\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	sig = (unsigned char*)malloc(siglen);
	if (sig == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate signature\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_sign(ctx, sig, &siglen, digest, digestlen) <= 0) {
		log_printf(LOG_ERROR, "Unable to sign digest\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	*sig_out = sig;
	*siglen_out = siglen;

	EVP_PKEY_CTX_free(ctx);
	return 1;
}

int util_verify(cryptokey_t* key, unsigned char* sig, size_t siglen,
				unsigned char* digest, size_t digestlen) {
	EVP_PKEY_CTX* ctx;

	ctx = EVP_PKEY_CTX_new(key->ossl_key, NULL);
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Unable to initialize pubkey context\n");
		return 0;
	}

	if (EVP_PKEY_verify_init(ctx) <= 0) {
		log_printf(LOG_ERROR, "Unable to init verify\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		log_printf(LOG_ERROR, "Unable to set padding for verify\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, hash_alg) <= 0) {
		log_printf(LOG_ERROR, "Unable to set hash alg for verify\n");
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_verify(ctx, sig, siglen, digest, digestlen) != 1) {
		EVP_PKEY_CTX_free(ctx);
		log_printf(LOG_INFO, "Signature verify failed\n");
		return 0;
	}

	EVP_PKEY_CTX_free(ctx);
	return 1;
}

char* util_parse_int(char* serial, const char* token, size_t token_len,
		int* out) {
	int retval;
	if (strncmp(serial, token, token_len) != 0) {
		log_printf(LOG_ERROR, "Failed to parse token %s\n", token);
		return NULL;
	}
	serial += token_len;
	retval = strtol(serial, &serial, 10);
	serial++;
	*out = retval;
	return serial;
}

char* util_parse_timestamp(char* serial, const char* token, size_t token_len,
		time_t* out) {
	int retval;
	if (strncmp(serial, token, token_len) != 0) {
		log_printf(LOG_ERROR, "Failed to parse token %s\n", token);
		return NULL;
	}
	serial += token_len;
	retval = strtol(serial, &serial, 10);
	serial++;
	*out = retval;
	return serial;
}

char* util_parse_str(char* serial, const char* token, size_t token_len) {
	if (strncmp(serial, token, token_len) != 0) {
		log_printf(LOG_ERROR, "Failed to parse token %s\n", token);
		return NULL;
	}
	serial += token_len;
	return serial;
}

int util_digest_meets_target(unsigned char* digest, unsigned int digestlen,
		unsigned char* target, unsigned int targetlen) {
	BIGNUM* target_bn;
	BIGNUM* digest_bn;
	int result;
	
	digest_bn = BN_bin2bn(digest, digestlen, NULL);
	if (digest_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to parse digest\n");
		return 0;
	}
	target_bn = BN_bin2bn(target, targetlen, NULL);
	if (target_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to parse target\n");
		BN_free(digest_bn);
		return 0;
	}

	result = BN_cmp(digest_bn, target_bn);
	/*printf("Digest: %s\n", BN_bn2hex(digest_bn));
	printf("Target: %s\n", BN_bn2hex(target_bn));*/
	BN_free(digest_bn);
	BN_free(target_bn);

	/* BN_cmp(a,b) returns 1 if a > b */
	if (result == 1) {
		return 0;
	}
	return 1;
}

int util_get_new_target(int diff, int period, 
			unsigned char* cur_target, unsigned int cur_targetlen,
			unsigned char* base_target, unsigned int base_targetlen,
			unsigned char** new_target, unsigned int* new_targetlen) {
	int result;
	char* print_str;
	BN_CTX* bn_ctx;
	BIGNUM* diff_bn;
	BIGNUM* period_bn;
	BIGNUM* cur_target_bn;
	BIGNUM* base_target_bn;
	BIGNUM* new_target_bn;
	unsigned char* target;
	unsigned int targetlen;

	diff_bn = BN_new();
	if (diff_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to make diff bignum\n");
		return 0;
	}
	if (BN_set_word(diff_bn, diff) == 0) {
		log_printf(LOG_ERROR, "Failed to set diff bignum\n");
		BN_free(diff_bn);
		return 0;
	}
	period_bn = BN_new();
	if (period_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to make period bignum\n");
		BN_free(diff_bn);
		return 0;
	}
	if (BN_set_word(period_bn, period) == 0) {
		log_printf(LOG_ERROR, "Failed to set period bignum\n");
		BN_free(diff_bn);
		BN_free(period_bn);
		return 0;
	}
	cur_target_bn = BN_bin2bn(cur_target, cur_targetlen, NULL);
	if (cur_target_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to make cur target bignum\n");
		BN_free(diff_bn);
		BN_free(period_bn);
		return 0;
	}

	bn_ctx = BN_CTX_new();
	if (bn_ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to make bignum context\n");
		BN_free(diff_bn);
		BN_free(period_bn);
		BN_free(cur_target_bn);
		return 0;
	}

	if (BN_mul(cur_target_bn, cur_target_bn, diff_bn, bn_ctx) != 1) {
		log_printf(LOG_ERROR, "Failed multiply\n");
		BN_free(diff_bn);
		BN_free(period_bn);
		BN_free(cur_target_bn);
		BN_CTX_free(bn_ctx);
		return 0;
	}
	BN_free(diff_bn);

	if (BN_div(cur_target_bn, NULL, cur_target_bn, period_bn, bn_ctx) != 1) {
		log_printf(LOG_ERROR, "Failed multiply\n");
		BN_free(period_bn);
		BN_free(cur_target_bn);
		BN_CTX_free(bn_ctx);
		return 0;
	}
	BN_free(period_bn);
	BN_CTX_free(bn_ctx);

	base_target_bn = BN_bin2bn(base_target, base_targetlen, NULL);
	if (base_target_bn == NULL) {
		log_printf(LOG_ERROR, "Failed to make base target bignum\n");
		BN_free(cur_target_bn);
		return 0;
	}

	/* Don't let difficulty get too easy */
	result = BN_cmp(cur_target_bn, base_target_bn);
	if (result == 1) {
		targetlen = BN_num_bytes(base_target_bn);
		target = (unsigned char*)malloc(targetlen);
		new_target_bn = base_target_bn;
		BN_free(cur_target_bn);
	}
	else {
		targetlen = BN_num_bytes(cur_target_bn);
		target = (unsigned char*)malloc(targetlen);
		new_target_bn = cur_target_bn;
		BN_free(base_target_bn);
	}
	if (target == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new target\n");
		BN_free(new_target_bn);
		return 0;
	}

	if (BN_bn2bin(new_target_bn, target) != targetlen) {
		log_printf(LOG_ERROR, "Failed to set new target\n");
		BN_free(new_target_bn);
		return 0;
	}

	print_str = BN_bn2hex(new_target_bn);
	log_printf(LOG_INFO, "New Target: %s\n", print_str);
	OPENSSL_free(print_str);
	BN_free(new_target_bn);
	*new_target = target;
	*new_targetlen = targetlen;
	return 1;	
}

