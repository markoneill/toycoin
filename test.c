#include <openssl/evp.h>

#include "log.h"
#include "block.h"

const EVP_MD* hash_alg;

void test_block();
void print_digest(unsigned char* digest, size_t len); 
void print_serialization(block_t* block);

int main(int argc, char* argv[]) {
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	
	OpenSSL_add_all_digests();
	hash_alg = EVP_sha256();

	test_block();

	EVP_cleanup();
	log_close();
	return 0;
}


void test_block() {
	block_t* g_block;
	block_t* new_block;
	unsigned char* digest;
	size_t digest_len;

	unsigned char* orig_digest;
	orig_digest = calloc(1, EVP_MD_size(hash_alg));
	g_block = block_new(0, orig_digest, EVP_MD_size(hash_alg));
	free(orig_digest);

	block_hash(g_block, &digest, &digest_len);
	print_digest(digest, digest_len);
	free(digest);

	block_free(g_block);
	return;
}

void print_digest(unsigned char* digest, size_t len) {
	int i;
	printf("Digest: ");
	for (i = 0; i < len; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");
	return;
}
