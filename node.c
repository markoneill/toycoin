#include "node.h"
#include "blockchain.h"
#include "block.h"
#include "wallet.h"
#include "transaction.h"

#define TRANSACTION_THRESHOLD	5

transaction_t* recv_txn(void);
void node_process_block(blockchain_t* chain);

void node_start(void) {
	/*blockchain_t* chain;
	wallet_t* wallet;*/
	
	return;
}

void node_process_block(blockchain_t* chain) {
	block_t* block;
	block_t* last_block;
	unsigned char* prev_digest;
	unsigned int prev_digestlen;
	transaction_t* txn;
	int nonce;

	last_block = blockchain_get_last_block(chain);
	block_hash(last_block, &prev_digest, &prev_digestlen);
	block = block_new(prev_digest, prev_digestlen);
	blockchain_add_block(chain, block);
	
	/* gather transactions here */
	txn = recv_txn();
	
	if (transaction_is_valid(txn, chain) == 0) {
		/* reject */
	}
	if (block_add_transaction(block, txn) == 0) {
		/* failed */
	}

	nonce = 0;
	while (block_is_valid(block) == 0) {
		block_set_nonce(block, nonce);
		nonce++;
	}

	/* broadcast block to peers */
	
	return;
}

transaction_t* recv_txn(void) {
	return NULL;
}
