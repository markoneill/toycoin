#include <stdio.h> /* for sprintf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for calloc */

#include "block.h"
#include "util.h"
#include "log.h"

#define BLOCK_VERSION	1

static const char serial_format[] = "version:%0d\n"
			     "timestamp:%ld.%.9ld\n"
			     "prev_digest:%s\n"
			     "nonce:%04X\n"
                             "target_bits:%d\n"
			     "num_transactions:%d\n";

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

block_t* block_new_genesis(void) {
	block_t* block;
	unsigned char* digest;

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
	char* serialized_block;
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

	if (util_hash((unsigned char*)serialized_block, serial_len, 
			digest_data, &digest_datalen) == 0) {
		log_printf(LOG_ERROR, "Unable to hash block\n");
		return 0;
	}
	*digest = digest_data;
	*digest_len = digest_datalen;

	free(serialized_block);
	return 1;
}

int block_serialize(block_t* block, char** data, size_t* len) {
	char* block_data;
	char* digest_str;
	size_t block_data_len;
	if (util_bytes_to_str(block->prev_digest, util_digestlen(),
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
	block_data = (char*)calloc(1, block_data_len + 1);
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

	if (len != NULL) {
		*len = block_data_len;
	}
	return 1;
}

