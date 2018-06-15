#include <stdlib.h>

#include "log.h"
#include "util.h"
#include "transaction.h"
#include "block.h"
#include "blockchain.h"
#include "wallet.h"

void test_chain();

int main(int argc, char* argv[]) {
	/* Global setup */
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	util_init_crypto();


	util_deinit_crypto();
	log_close();
	return 0;
}


void test_chain() {
	block_t* new_block;
	blockchain_t* chain;
	unsigned int digest_len;
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
	new_block = block_new(digest, digest_len);
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
	new_block = block_new(digest, digest_len);
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

