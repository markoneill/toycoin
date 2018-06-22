#include <stdio.h> /* for FILE*  */
#include <stdlib.h> /* for calloc */
#include <string.h> /* for memcmp */

#include "blockchain.h"
#include "transaction.h"
#include "block.h"
#include "coin.h"
#include "log.h"
#include "util.h"

static const char begin_str[] = "-----BEGIN BLOCK-----\n";
static const char block_len_str[] = "block_len:";
static const char end_str[] = "------END BLOCK------\n";

blockchain_t* blockchain_create() {
	blockchain_t* chain;
	block_t* genesis_block;
	chain = (blockchain_t*)calloc(1, sizeof(blockchain_t));
	if (chain == NULL) {
		log_printf(LOG_ERROR, "Unable to create chain\n");
		return NULL;
	}

	
	genesis_block = block_new_genesis();
	if (genesis_block == NULL) {
		log_printf(LOG_ERROR, "Unable to create genesis block\n");
		free(chain);
		return NULL;
	}

	if (blockchain_add_block(chain, genesis_block) == 0) {
		log_printf(LOG_ERROR, "Unable to add genesis block to chain\n");
		block_free(genesis_block);
		free(chain);
		return NULL;
	}
	return chain;
}

void blockchain_free(blockchain_t* chain) {
	block_t* head;
	block_t* next;
	if (chain == NULL) {
		return;
	}
	head = chain->head;
	while (head != NULL) {
		next = head->next;
		block_free(head);
		head = next;
	}
	chain->length = 0;
	chain->head = NULL;
	chain->tail = NULL;
	free(chain);
	return;
}

int blockchain_get_length(blockchain_t* chain) {
	return chain->length;
}

block_t* blockchain_get_last_block(blockchain_t* chain) {
	return chain->tail;
}

int blockchain_add_block(blockchain_t* chain, block_t* block) {
	unsigned char* tail_digest;
	unsigned int tail_digest_len;
	
	/* No validation of genesis block should be performed */
	if (chain->head == NULL) {
		chain->head = block;
		chain->tail = block;
		block->prev = NULL;
		chain->length++;
		return 1;
	}

	/* Make sure block has valid prev_digest */
	if (block_hash(chain->tail, &tail_digest, &tail_digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash previous block\n");
		return 0;
	}
	if (memcmp(block->prev_digest, tail_digest, tail_digest_len) != 0) {
		log_printf(LOG_ERROR, 
			"New block's prev digest does not match latest block's digest\n");
		return 0;
	}

	chain->tail->next = block;
	block->prev = chain->tail;
	block->next = NULL;
	chain->tail = block;
	chain->length++;

	free(tail_digest);
	return 1;
}


coin_t* blockchain_get_coins(blockchain_t* chain, char* address_id) {
	block_t* cur_block;
	coin_t* coins_head;
	coin_t* coins;

	coins_head = NULL;
	cur_block = chain->head;
	while (cur_block != NULL) {
		coins = block_get_coins(cur_block, address_id);
		coins_head = coin_add_coins(coins_head, coins);
		cur_block = cur_block->next;
	}
	return coins_head;
}

transaction_t* blockchain_get_transaction_by_digest(blockchain_t* chain,
		unsigned char* digest, unsigned int digestlen) {
	block_t* cur_block;
	transaction_t* txn;

	cur_block = chain->head;
	while (cur_block != NULL) {
		txn = block_get_transaction_by_digest(cur_block, 
			digest, digestlen);
		if (txn != NULL) {
			return txn;
		}
		cur_block = cur_block->next;
	}
	return NULL;
}

int blockchain_reference_exists(blockchain_t* chain,
		unsigned char* ref_txn_digest, unsigned int ref_digestlen,
		int index) {
	block_t* cur_block;

	cur_block = chain->head;
	while (cur_block != NULL) {
		if (block_reference_exists(cur_block, ref_txn_digest,
			ref_digestlen, index) == 1) {
			return 1;
		}
		cur_block = cur_block->next;
	}
	return 0;
}

int blockchain_save(blockchain_t* chain, char* filepath) {
	FILE* chain_file;
	char* serial;
	size_t serial_len;
	block_t* cur_block;

	chain_file = fopen(filepath, "w");
	if (chain_file == NULL) {
		log_printf(LOG_ERROR, "Unable to open chain file\n");
		return 0;
	}
	cur_block = chain->head;

	/* We skip the first (genesis) block because it's hard-coded
	 * into the currency */
	cur_block = cur_block->next;	

	while (cur_block != NULL) {
		if (block_serialize(cur_block, &serial, &serial_len) == 0) {
			log_printf(LOG_ERROR, "Unable to serialize block\n");
			fclose(chain_file);
			return 0;
		}
		fprintf(chain_file, begin_str);
		fprintf(chain_file, "%s%d\n", block_len_str, (int)serial_len);
		fprintf(chain_file, "%s", serial);
		fprintf(chain_file, end_str);
		free(serial);
		cur_block = cur_block->next;
	}
	fclose(chain_file);
	return 1;
}

blockchain_t* blockchain_load(char* filepath) {
	FILE* chain_file;
	char* line;
	size_t len;
	char* serial;
	int serial_len;
	blockchain_t* chain;
	block_t* block;
	
	chain = blockchain_create();
	if (chain == NULL) {
		log_printf(LOG_ERROR, "Unable to init chain\n");
		return NULL;
	}

	chain_file = fopen(filepath, "r");
	if (chain_file == NULL) {
		log_printf(LOG_ERROR, "Unable to open chain file\n");
		return NULL;
	}

	line = NULL;
	len = 0;
	while (1) {
		if (getline(&line, &len, chain_file) == -1) {
			free(line);
			break;
		}
		if (strncmp(line, begin_str, len) != 0) {
			log_printf(LOG_ERROR, "block begin not found\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}

		if (getline(&line, &len, chain_file) == -1) {
			log_printf(LOG_ERROR, "block length not found\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
		util_parse_int(line, block_len_str, strlen(block_len_str),
			&serial_len);
		serial = (char*)malloc(serial_len + 1);
		serial[serial_len] = '\0';
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Unable to allocate serial\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
		if (fread(serial, serial_len, 1, chain_file) != 1) {
			log_printf(LOG_ERROR, "failed to read serial\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
		block = block_deserialize(serial, serial_len);
		if (block == NULL) {
			log_printf(LOG_ERROR, "failed to deserialize block\n");
			free(line);
			free(serial);
			blockchain_free(chain);
			return NULL;
		}
		free(serial);
		if (blockchain_add_block(chain, block) == 0) {
			log_printf(LOG_ERROR, "failed to add block\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
		if (getline(&line, &len, chain_file) == -1) {
			log_printf(LOG_ERROR, "end block not found\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
		if (strncmp(line, end_str, strlen(end_str)) != 0) {
			log_printf(LOG_ERROR, "end block malformed\n");
			free(line);
			blockchain_free(chain);
			return NULL;
		}
	}
	fclose(chain_file);
	return chain;
}

