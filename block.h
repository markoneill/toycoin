#ifndef BLOCK_H
#define BLOCK_H

/* 
 * Basic block structure influenced by
 * https://en.bitcoin.it/wiki/Block
 */

#include <time.h> /* for timespec */
#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

typedef struct block {
	int index;
	struct timespec timestamp;
	/* digest of previous block */
	unsigned char prev_digest[EVP_MAX_MD_SIZE];
	size_t prev_digest_len;
	/* increase size of nonce if you want harder difficulties */
	int nonce;
	/* dictates the difficulty of the block */
	int num_zeroes;
	
	/* pointers for blockchain */
	struct block* next;
	struct block* prev;
} block_t;

block_t* block_new(int index, unsigned char* prev_digest, size_t digest_len);
void block_free(block_t* block);
int block_hash(block_t* block, unsigned char** digest, size_t* digest_len);
int block_serialize(block_t* block, unsigned char** data, size_t* len);

#endif
