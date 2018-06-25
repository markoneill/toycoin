#include <stdio.h> /* for FILE*  */
#include <stdlib.h> /* for calloc */
#include <string.h> /* for memcmp */

#include "blockchain.h"
#include "transaction.h"
#include "block.h"
#include "coin.h"
#include "log.h"
#include "util.h"

/* adjust target approximately daily */
#define ADJUSTMENT_TIME		(60 * 60 * 24)
/* target 1 block every 60 seconds */
#define BLOCK_TARGET_TIME	(60)
/* so recaluate target every 1440 blocks */
#define BLOCK_ADJUST_PERIOD	(ADJUSTMENT_TIME / BLOCK_TARGET_TIME)
/* don't allow new targets to be more than 4x larger/smaller than previous */
#define TARGET_CONSTRAIN_FACTOR	(4)

/* serialization strings */
static const char begin_str[] = "-----BEGIN BLOCK-----\n";
static const char block_len_str[] = "block_len:";
static const char end_str[] = "------END BLOCK------\n";
static block_t* blockchain_get_block(blockchain_t* chain, int index);

blockchain_t* blockchain_new(void) {
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

int blockchain_get_current_payout(blockchain_t* chain) {
	/* XXX calculate this based on chain length */
	return 1000;
}

int blockchain_get_current_target(blockchain_t* chain, 
			unsigned char** target, unsigned int* target_len) {
	block_t* old_block;
	int old_index;
	time_t old_time;
	time_t new_time;
	int time_diff;
	unsigned char* cur_target;
	unsigned int cur_target_len;
	if (chain->length % BLOCK_ADJUST_PERIOD != 0) {
		cur_target_len = chain->tail->target_len;
		cur_target = (unsigned char*)malloc(cur_target_len);
		if (cur_target == NULL) {
			log_printf(LOG_ERROR, "Unable to allocate target\n");
			return 0;
		}
		memcpy(cur_target, chain->tail->target, cur_target_len);
	}
	else {
		/* We need to adjust target */
		old_index = (chain->length - 1) - BLOCK_ADJUST_PERIOD;
		old_block = blockchain_get_block(chain, old_index);
		if (old_block == NULL) {
			log_printf(LOG_ERROR, "Failed to find old block\n");
			return 0;
		}
		old_time = old_block->timestamp;
		new_time = chain->tail->timestamp;
		time_diff = difftime(new_time, old_time);

		/* We cap the the difference to smooth difficulty */
		if (time_diff > TARGET_CONSTRAIN_FACTOR * ADJUSTMENT_TIME) {
			time_diff = TARGET_CONSTRAIN_FACTOR * ADJUSTMENT_TIME;
		}
		if (time_diff < ADJUSTMENT_TIME / TARGET_CONSTRAIN_FACTOR) {
			time_diff = ADJUSTMENT_TIME / TARGET_CONSTRAIN_FACTOR;
		}

		/*new_target = util_get_new_target(time_diff,
				ADJUSTMENT_TIME,
				chain->head->target,
				chain->head->target_len,
				chain->tail->target,
				chain->tail->target_len);*/

		/* don't allow the new target to be too easy */
	}

	*target = cur_target;
	if (target_len != NULL) {
		*target_len = cur_target_len;
	}

	return 1;
}


block_t* blockchain_new_block(blockchain_t* chain) {
	unsigned char* prev_digest;
	unsigned int prev_digestlen;
	unsigned char* target;
	unsigned int target_len;

	block_t* new_block;

	if (block_hash(chain->tail, &prev_digest, &prev_digestlen) == 0) {
		log_printf(LOG_ERROR, "Unable to hash previous block\n");
		return NULL;
	}
	new_block = block_new(prev_digest, prev_digestlen);
	if (new_block == NULL) {
		log_printf(LOG_ERROR, "Unable to make new block for chain\n");
		free(prev_digest);
		return NULL;
	}

	if (blockchain_get_current_target(chain, &target, &target_len) != 1) {
		log_printf(LOG_ERROR, "Unable to get target\n");
		block_free(new_block);
		return NULL;
	}
	if (block_set_target(new_block, target, target_len) != 1) {
		log_printf(LOG_ERROR, "Unable to set target\n");
		block_free(new_block);
		return NULL;
	}

	return new_block;
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

block_t* blockchain_get_block(blockchain_t* chain, int index) {
	int i;
	block_t* cur_block;
	cur_block = chain->head;
	if (index >= chain->length) {
		return NULL;
	}

	for (i = 0; i < index; i++) {
		cur_block = cur_block->next;
	}
	return cur_block;
}

coin_t* blockchain_get_coins(blockchain_t* chain, char* address_id) {
	block_t* cur_block;
	coin_t* coins_head;
	coin_t* coins;

	coins = NULL;
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
	
	chain = blockchain_new();
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

