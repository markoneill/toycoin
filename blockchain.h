#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "block.h"
#include "coin.h"
#include "transaction.h"

typedef struct blockchain {
	block_t* head;
	block_t* tail;
	int length;
} blockchain_t;

blockchain_t* blockchain_create();
void blockchain_free(blockchain_t* chain);
int blockchain_add_block(blockchain_t* chain, block_t* block);
int blockchain_get_length(blockchain_t* chain);
block_t* blockchain_get_last_block(blockchain_t* chain);

/* Returns a list of coins owned by the given address */
coin_t* blockchain_get_coins(blockchain_t* chain, char* address_id);

/* Returns a pointer to a transaction referenced by an input
 * from a new transaction. Used to verify signatures and addresses */
transaction_t* blockchain_get_transaction_by_digest(blockchain_t* chain,
		unsigned char* digest, unsigned int digestlen);

/* Returns 1 if the specified transaction digest and index are already
 * referenced in the chain. Used to detect double spending */
int blockchain_reference_exists(blockchain_t* chain,
		unsigned char* ref_txn_digest, unsigned int ref_digestlen,
		int index);

/* Saves the given blockchain in a serialized format in a file located
 * at the given path. Returns 1 on success */
int blockchain_save(blockchain_t* chain, char* filepath);

/* Returns a blockchain loaded from a file at the given path.
 * Returns null on error */
blockchain_t* blockchain_load(char* filepath);

#endif
