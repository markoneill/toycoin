#ifndef BLOCK_H
#define BLOCK_H

/* 
 * Basic block structure influenced by
 * https://en.bitcoin.it/wiki/Block
 */

#include <time.h> /* for timespec */
#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

typedef struct block {
	/* Core members */
	int version; /* block format version */
	struct timespec timestamp; /* time created */
	unsigned char prev_digest[EVP_MAX_MD_SIZE]; /* hash of prev block */
	int nonce; /* nonce to increment for mining */
	int target_bits; /* number of leading zeroes for target difficulty */
	int num_transactions; /* number of transactions in block */

	/* Members for operational use */
	struct block* next;
	struct block* prev;

} block_t;

block_t* block_new(int index, unsigned char* prev_digest, size_t digest_len);
void block_free(block_t* block);
int block_hash(block_t* block, unsigned char** digest, size_t* digest_len);
int block_serialize(block_t* block, unsigned char** data, size_t* len);

#endif
