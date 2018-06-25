#include "node.h"
#include "blockchain.h"
#include "block.h"
#include "wallet.h"
#include "transaction.h"

void node_start(void) {
	int nonce;
	char* serialization;
	blockchain_t* chain;
	block_t* new_block;

	chain = blockchain_new();
	new_block = blockchain_new_block(chain);
	nonce = 0;
	printf("Start time %ld\n", time(NULL));
	while (block_is_valid(new_block) == 0) {
		nonce++;
		block_set_nonce(new_block, nonce);
	}
	printf("End time %ld\n", time(NULL));

	printf("Golden nonce found: %d\n", nonce);
	block_serialize(new_block, &serialization, NULL);
	printf("Block:\n%s\n", serialization);

	free(serialization);
	blockchain_free(chain);
	return;
}

