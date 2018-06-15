#include <stdio.h> /* for sprintf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for calloc */

#include "block.h"
#include "transaction.h"
#include "util.h"
#include "log.h"

#define BLOCK_VERSION	1
#define BASE_TXN_COUNT	10

static const char header_serial_format[] = "version:%0d\n"
			     "timestamp:%ld.%.9ld\n"
			     "prev_digest:%s\n"
			     "nonce:%04X\n"
                             "target_bits:%d\n"
			     "num_transactions:%d\n";

static const char body_serial_format[] = "txn_len:%d\n"
					"txn:%s\n";

static void free_tmp_serials(char** serials, size_t num_serials);

block_t* block_new(unsigned char* prev_digest, size_t digest_len) {
	block_t* new_block;
	new_block = (block_t*)calloc(1, sizeof(block_t));
	if (new_block == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new block\n");
		return NULL;
	}
	new_block->version = BLOCK_VERSION;
	new_block->transactions = NULL;
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
	block = block_new(digest, util_digestlen());
	if (block == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate genesis block\n");
		free(digest);
		return NULL;
	}
	free(digest);
	return block;
}

void block_free(block_t* block) {
	int i;
	if (block->transactions != NULL) {
		for (i = 0; i < block->num_transactions; i++) {
			transaction_free(block->transactions[i]);
		}
		free(block->transactions);
	}
	free(block);
	return;
}

int block_hash(block_t* block, unsigned char** digest, unsigned int* digest_len) {
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
	if (digest_len != NULL) {
		*digest_len = digest_datalen;
	}

	free(serialized_block);
	return 1;
}

int block_serialize(block_t* block, char** data, size_t* len) {
	int i;
	char* serial;
	int pos;
	char* digest_str;
	char** serialized_txns;
	size_t* serialized_txn_lens;
	size_t serial_len;
	int written;

	serial_len = 0;
	if (util_bytes_to_str(block->prev_digest, util_digestlen(),
			&digest_str) == 0) {
		log_printf(LOG_ERROR, "Failed to convert digest to string\n");
		return 0;
	}
	written = snprintf(NULL,
			0,
			header_serial_format,
			block->version,
			block->timestamp.tv_sec,
			block->timestamp.tv_nsec,
			digest_str,
			block->nonce,
			block->target_bits,
			block->num_transactions);
	if (written == -1) {
		log_printf(LOG_ERROR, "Cannot serialize block header\n");
		free(digest_str);
		return 0;
	}
	serial_len += written;

	serialized_txn_lens = (size_t*)malloc(block->num_transactions * sizeof(size_t));
	if (serialized_txn_lens == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate txn serial lengths\n");
		free(digest_str);
		return 0;
	}
	serialized_txns = (char**)malloc(block->num_transactions * sizeof(char*));
	if (serialized_txns == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate txn serials\n");
		free(digest_str);
		free(serialized_txn_lens);
		return 0;
	}

	for (i = 0; i < block->num_transactions; i++) {
		if (transaction_serialize(block->transactions[i],
				  &serialized_txns[i],
				  &serialized_txn_lens[i],
				  1) == 0) {
			log_printf(LOG_ERROR, "Unable to serialize transaction\n");
			free_tmp_serials(serialized_txns, i);
			free(serialized_txn_lens);
			return 0;
		}
		written = snprintf(NULL,
				0,
				body_serial_format,
				(int)serialized_txn_lens[i],
				serialized_txns[i]);
		if (written == -1) {
			log_printf(LOG_ERROR, "Unable to serialize transaction header\n");
			free_tmp_serials(serialized_txns, i+1);
			free(serialized_txn_lens);
			return 0;
		}
		serial_len += written;
	}
	serial_len += 1;

	serial = (char*)calloc(1, serial_len);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate memory for block\n");
		free(digest_str);
		free_tmp_serials(serialized_txns, block->num_transactions);
		free(serialized_txn_lens);
		return 0;
	}
	written = snprintf(serial,
			serial_len,
			header_serial_format,
			block->version,
			block->timestamp.tv_sec,
			block->timestamp.tv_nsec,
			digest_str,
			block->nonce,
			block->target_bits,
			block->num_transactions);
	if (written == -1) {
		log_printf(LOG_ERROR, "Failed to write block header\n");
		free(digest_str);
		free_tmp_serials(serialized_txns, block->num_transactions);
		free(serialized_txn_lens);
		return 0;
	}
	free(digest_str);

	pos = written;
	for (i = 0; i < block->num_transactions; i++) {
		written = snprintf(serial+pos,
			serial_len-pos,
			body_serial_format,
			(int)serialized_txn_lens[i],
			serialized_txns[i]);
		if (written == -1) {
			log_printf(LOG_ERROR, "Unable to write transaction\n");
			free_tmp_serials(serialized_txns, block->num_transactions);
			free(serialized_txn_lens);
			return 0;
		}
		pos += written;
	}
	free_tmp_serials(serialized_txns, block->num_transactions);
	free(serialized_txn_lens);

	*data = serial;
	if (len != NULL) {
		*len = serial_len;
	}
	return 1;
}

void free_tmp_serials(char** serials, size_t num_serials) {
	int i;
	for (i = 0; i < num_serials; i++) {
		free(serials[i]);
	}
	free(serials);
	return;
}

int block_add_transaction(block_t* block, transaction_t* txn) {
	int num_txns;
	int max_txns;
	max_txns = block->max_transactions;
	num_txns = block->num_transactions;

	if (num_txns == max_txns) {
		if (max_txns == 0) {
			max_txns = BASE_TXN_COUNT;
		}
		else {
			max_txns = max_txns * 2;
		}
		block->transactions = (transaction_t**)realloc(
				block->transactions,
				sizeof(transaction_t*) * max_txns);
		if (block->transactions == NULL) {
			log_printf(LOG_ERROR, "Unable to allocate transaction\n");
			return 0;
		}
		block->max_transactions = max_txns;
	}

	block->transactions[num_txns] = txn;
	block->num_transactions++;
	return 1;
}
