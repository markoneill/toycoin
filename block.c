#include <stdio.h> /* for sprintf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for calloc */

#include "block.h"
#include "transaction.h"
#include "util.h"
#include "log.h"

#define BLOCK_VERSION	1
#define BASE_TXN_COUNT	10

static const char version_str[] = "version:";
static const char time_str[] = "timestamp:";
static const char digest_len_str[] = "prev_digest_len:";
static const char digest_str[] = "prev_digest:";
static const char nonce_str[] = "nonce:";
static const char target_str[] = "target_bits:";
static const char num_txns_str[] = "num_transactions:";
static const char header_serial_format[] = "version:%0d\n"
			     "timestamp:%ld.%.9ld\n"
			     "prev_digest_len:%d\n"
			     "prev_digest:%s\n"
			     "nonce:%d\n"
                             "target_bits:%d\n"
			     "num_transactions:%d\n";

static const char txn_len_str[] = "txn_len:";
static const char body_serial_format[] = "txn_len:%d\n"
					"%s";

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
	new_block->max_transactions = 0;
	clock_gettime(CLOCK_REALTIME, &new_block->timestamp);
	new_block->prev_digest_len = digest_len;
	new_block->prev_digest = prev_digest;
	return new_block;
}

block_t* block_new_genesis(void) {
	block_t* block;
	unsigned char* digest;
	int digest_len;

	digest_len = util_digestlen();

	/* Genesis block has zeroes for its hash */
	digest = (unsigned char*)calloc(1, digest_len);
	if (digest == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate genesis digest\n");
		return NULL;
	}
	block = block_new(digest, digest_len);

	/* Genesis block needs static date */
	block->timestamp.tv_sec = 1529210382;
	block->timestamp.tv_nsec = 0;
	if (block == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate genesis block\n");
		free(digest);
		return NULL;
	}
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
	free(block->prev_digest);
	free(block);
	return;
}

int block_is_valid(block_t* block) {
	int i;
	unsigned char* digest;
	unsigned int digestlen;

	if (block_hash(block, &digest, &digestlen) == 0) {
		log_printf(LOG_ERROR, "Unable to hash block to add\n");
		return 0;
	}

	for (i = 0; i < block->target_bits; i++) {
		/* XXX coming soon */
	}

	free(digest);
	return 1;
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

	if (util_hash((unsigned char*)serialized_block, serial_len, 
			&digest_data, &digest_datalen) == 0) {
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
	if (util_bytes_to_str(block->prev_digest, block->prev_digest_len,
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
			(int)strlen(digest_str),
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

	serial = (char*)calloc(1, serial_len + 1);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate memory for block\n");
		free(digest_str);
		free_tmp_serials(serialized_txns, block->num_transactions);
		free(serialized_txn_lens);
		return 0;
	}
	written = snprintf(serial,
			serial_len+1,
			header_serial_format,
			block->version,
			block->timestamp.tv_sec,
			block->timestamp.tv_nsec,
			(int)strlen(digest_str),
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
			serial_len+1-pos,
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

block_t* block_deserialize(char* serial, size_t len) {
	int i;
	int version;
	struct timespec timestamp;
	int digest_len;
	size_t bin_digest_len;
	unsigned char* digest;
	int nonce;
	int target;
	int num_txns;

	int txn_len;
	transaction_t* txn;
	block_t* block;

	serial = util_parse_int(serial, version_str, strlen(version_str), &version);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block version\n");
		return NULL;
	}
	serial = util_parse_timestamp(serial, time_str, strlen(time_str), &timestamp);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block timestamp\n");
		return NULL;
	}
	serial = util_parse_int(serial, digest_len_str, strlen(digest_len_str), &digest_len);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read digest len\n");
		return NULL;
	}
	serial = util_parse_str(serial, digest_str, strlen(digest_str));
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block digest token\n");
		return NULL;
	}
	if (util_str_to_bytes(serial, digest_len, &digest, &bin_digest_len) == 0) {
		log_printf(LOG_ERROR, "Failed to read prev digest\n");
		return NULL;
	}
	serial += digest_len + 1; /* +1 for newline */
	serial = util_parse_int(serial, nonce_str, strlen(nonce_str), &nonce);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block nonce\n");
		return NULL;
	}
	serial = util_parse_int(serial, target_str, strlen(target_str), &target);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block target\n");
		return NULL;
	}
	serial = util_parse_int(serial, num_txns_str, strlen(num_txns_str), &num_txns);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read block transaction count\n");
		return NULL;
	}
	
	block = block_new(digest, bin_digest_len);
	if (block == NULL) {
		log_printf(LOG_ERROR, "Failed to create block\n");
		return NULL;
	}

	block->version = version;
	block->timestamp = timestamp;
	block->nonce = nonce;
	block->target_bits = target;
	
	for (i = 0; i < num_txns; i++) {
		serial = util_parse_int(serial, txn_len_str, strlen(txn_len_str), &txn_len);	
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to parse transaction len token\n");
			block_free(block);
			return NULL;
		}
		txn = transaction_deserialize(serial, txn_len);
		if (txn == NULL) {
			log_printf(LOG_ERROR, "Failed to deserialize transaction\n");
			block_free(block);
			return NULL;
		}
		serial += txn_len;
		if (block_add_transaction(block, txn) == 0) {
			log_printf(LOG_ERROR, "Failed to add transaction\n");
			block_free(block);
			return NULL;
		}
	}

	return block;
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

transaction_t* block_get_transaction_by_digest(block_t* block,
		unsigned char* digest, unsigned int digestlen) {
	transaction_t* txn;
	unsigned char* src_digest;
	unsigned int src_digestlen;
	int i;
	for (i = 0; i < block->num_transactions; i++) {
		txn = block->transactions[i];
		if (transaction_hash(txn, &src_digest, &src_digestlen) != 1) {
			log_printf(LOG_ERROR, "Unable to hash transaction\n");
			return NULL;
		}

		if (memcmp(digest, src_digest, digestlen) == 0) {
			free(src_digest);
			return txn;
		}

		free(src_digest);
	}
	return NULL;
}

int block_reference_exists(block_t* block, unsigned char* ref_txn_digest,
		unsigned int ref_digestlen, int index) {
	transaction_t* txn;
	int i;
	for (i = 0; i < block->num_transactions; i++) {
		txn = block->transactions[i];
		if (transaction_references(txn, ref_txn_digest, 
			ref_digestlen, index) == 1) {
			return 1;
		}
	}
	return 0;
}

coin_t* block_get_coins(block_t* block, char* address_id) {
	int i;
	transaction_t* txn;
	coin_t* coins;
	coin_t* coin;
	int num_txns = block->num_transactions;

	for (i = 0; i < num_txns; i++) {
		txn = block->transactions[i];
		coin = transaction_get_coin(txn, address_id);
		coins = coin_add_coins(coins, coin);
	}
	return coins;
}

int block_set_nonce(block_t* block, int nonce) {
	block->nonce = nonce;
	return 1;
}

