#include <stdio.h> /* for sprintf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for calloc */

#include "block.h"
#include "util.h"
#include "log.h"

#define BLOCK_VERSION	1

const char serial_format[] = "version:%04X\n"
			     "timestamp:%lld.%.9ld\n"
			     "prev_digest:%s\n"
			     "nonce:%04X\n"
                             "target_bits:%04X\n"
			     "num_transactions:%04X\n";

static int digest_to_str(unsigned char* digest, size_t digest_len, char** str);

block_t* block_new(int index, unsigned char* prev_digest, size_t digest_len) {
	block_t* new_block;
	new_block = (block_t*)calloc(1, sizeof(block_t));
	if (new_block == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new block\n");
		return NULL;
	}
	new_block->version = BLOCK_VERSION;
	clock_gettime(CLOCK_REALTIME, &new_block->timestamp);
	memcpy(new_block->prev_digest, prev_digest, util_digestlen());
	return new_block;
}

block_t* block_new_genesis() {
	block_t* block;
	unsigned char* digest;
	size_t digest_len;

	/* Genesis block has zeroes for its hash */
	digest = (unsigned char*)calloc(1, util_digestlen());
	if (digest == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate genesis digest\n");
		return NULL;
	}
	block = block_new(0, digest, util_digestlen());
	if (block == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate genesis block\n");
		free(digest);
		return NULL;
	}
	free(digest);
	return block;
}

void block_free(block_t* block) {
	free(block);
	return;
}

int block_hash(block_t* block, unsigned char** digest, size_t* digest_len) {
	unsigned char* serialized_block;
	size_t serial_len;
	unsigned char* digest_data;
	unsigned int digest_datalen;
	if (block_serialize(block, &serialized_block, &serial_len) == 0) {
		log_printf(LOG_ERROR, "Unable to serialize block\n");
		return 0;
	}

	//log_printf(LOG_DEBUG, "Block serialization:\n%s\n", serialized_block);

	digest_data = (unsigned char*)malloc(util_digestlen());
	if (digest_data == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate digest\n");
		return 0;
	}

	if (util_hash(serialized_block, serial_len, digest_data, 
			&digest_datalen) == 0) {
		log_printf(LOG_ERROR, "Unable to hash block\n");
		return 0;
	}
	*digest = digest_data;
	*digest_len = digest_datalen;

	free(serialized_block);
	return 1;
}

int block_serialize(block_t* block, unsigned char** data, size_t* len) {
	unsigned char* block_data;
	char* digest_str;
	size_t block_data_len;
	if (digest_to_str(block->prev_digest, util_digestlen(),
			&digest_str) == 0) {
		log_printf(LOG_ERROR, "Failed to convert digest to string\n");
		return 0;
	}
	block_data_len = snprintf(NULL,
			0,
			serial_format,
			block->version,
			block->timestamp.tv_sec,
			block->timestamp.tv_nsec,
			digest_str,
			block->nonce,
			block->target_bits,
			block->num_transactions);
	if (block_data_len == -1) {
		log_printf(LOG_ERROR, "Cannot serialize block data\n");
		free(digest_str);
		return 0;
	}
	block_data = (unsigned char*)calloc(1, block_data_len + 1);
	if (block_data == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate memory for block\n");
		free(digest_str);
		return 0;
	}
	block_data_len = snprintf(block_data,
			block_data_len + 1,
			serial_format,
			block->version,
			block->timestamp.tv_sec,
			block->timestamp.tv_nsec,
			digest_str,
			block->nonce,
			block->target_bits,
			block->num_transactions);
	if (block_data_len == -1) {
		log_printf(LOG_ERROR, "Failed to serialize block data\n");
		free(digest_str);
		return 0;
	}
	free(digest_str);
	*data = block_data;
	*len = block_data_len;
	return 1;
}

int digest_to_str(unsigned char* digest, size_t digest_len, char** str) {
	char* tmp;
	int i;
	tmp = (char*)malloc(digest_len * 2 + 1);
	if (tmp == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate digest space\n");
		return 0;
	}
	for (i = 0; i < digest_len; i++) {
		sprintf(tmp + (i*2), "%02X", digest[i]);
	}
	*str = tmp;
	return 1;
}

