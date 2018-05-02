#ifndef BLOCK_H
#define BLOCK_H

#include <time.h> /* for timespec */
#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

typedef struct block {
	int index;
	struct timespec timestamp;
	unsigned char prev_digest[EVP_MAX_MD_SIZE];
	size_t prev_digest_len;
} block_t;

block_t* block_new(int index, unsigned char* prev_digest, size_t digest_len);
void block_free(block_t* block);
int block_hash(block_t* block, unsigned char** digest, size_t* digest_len);
int block_serialize(block_t* block, unsigned char** data, size_t* len);

#endif
