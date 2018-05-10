#include <openssl/evp.h>

#include "log.h"
#include "block.h"
#include "blockchain.h"

const EVP_MD* hash_alg;

void test_chain();
void print_digest(unsigned char* digest, size_t len); 
void print_serialization(block_t* block);

int main(int argc, char* argv[]) {
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	
	OpenSSL_add_all_digests();
	hash_alg = EVP_sha256();

	test_chain();

	EVP_cleanup();
	log_close();
	return 0;
}


void test_chain() {
	block_t* new_block;
	blockchain_t* chain;
	size_t digest_len;
	unsigned char* digest;

	chain = blockchain_create();
	if (chain == NULL) {
		printf("Failed to create blockchain\n");		
		return;
	}

	if (block_hash(chain->tail, &digest, &digest_len) != 1) {
		printf("Failed to get hash of tail\n");
		return;
	}
	new_block = block_new(1, digest, digest_len);
	if (new_block == NULL) {
		printf("Failed to create new block\n");
		return;
	}
	blockchain_add_block(chain, new_block);
	free(digest);

	if (block_hash(chain->tail, &digest, &digest_len) != 1) {
		printf("Failed to get hash of tail\n");
		return;
	}
	new_block = block_new(2, digest, digest_len);
	if (new_block == NULL) {
		printf("Failed to create new block\n");
		return;
	}
	blockchain_add_block(chain, new_block);
	free(digest);

	blockchain_to_file(chain, stdout);
	blockchain_free(chain);
	return;
}

void print_digest(unsigned char* digest, size_t len) {
	size_t i;
	printf("Digest: ");
	for (i = 0; i < len; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");
	return;
}
