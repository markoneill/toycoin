#ifndef BLOCK_H
#define BLOCK_H

/* 
 * Basic block structure influenced by
 * https://en.bitcoin.it/wiki/Block
 */

#include <time.h> /* for timespec */
#include "util.h"
#include "transaction.h"

typedef struct block {
	/* Core members */
	int version; /* block format version */
	struct timespec timestamp; /* time created */
	unsigned char* prev_digest; /* hash of prev block */
	int prev_digest_len; /* length of prev digest */
	int nonce; /* nonce to increment for mining */
	int target_bits; /* number of leading zeroes for target difficulty */
	int num_transactions; /* number of transactions in block */
	int max_transactions; /* currently allocated number of transactions */
	transaction_t** transactions; /* transaction list */

	/* Members for operational use */
	struct block* next;
	struct block* prev;

} block_t;

block_t* block_new_genesis(void);
block_t* block_new(unsigned char* prev_digest, size_t digest_len);
void block_free(block_t* block);
int block_hash(block_t* block, unsigned char** digest, unsigned int* digest_len);
int block_serialize(block_t* block, char** data, size_t* len);
block_t* block_deserialize(char* serial, size_t len);
int block_add_transaction(block_t* block, transaction_t* txn);
int block_set_nonce(block_t* block, int nonce);

#endif
