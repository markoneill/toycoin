#include <stdio.h> /* for FILE*  */
#include <stdlib.h> /* for calloc */
#include <string.h> /* for memcmp */

#include "blockchain.h"
#include "block.h"
#include "log.h"

blockchain_t* blockchain_create() {
	blockchain_t* chain;
	block_t* genesis_block;
	chain = (blockchain_t*)calloc(1, sizeof(blockchain_t));
	if (chain == NULL) {
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

int blockchain_add_block(blockchain_t* chain, block_t* block) {
	unsigned char* tail_digest;
	size_t tail_digest_len;
	unsigned char* digest;
	size_t digest_len;
	int i;
	
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
		log_printf(LOG_ERROR, "Unable to hash genesis block\n");
		return 0;
	}
	if (memcmp(block->prev_digest, tail_digest, tail_digest_len) != 0) {
		log_printf(LOG_ERROR, 
			"New block's prev digest does not match latest block's digest\n");
		return 0;
	}

	/* Make sure the block is valid */
	if (block_hash(block, &digest, &digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash block to add\n");
		return 0;
	}
	/* XXX validate num_zeroes based on timestamp first */
	for (i = 0; i < block->target_bits; i++) {
		if (digest[i] != 0) {
			log_printf(LOG_ERROR,
				"Block does not have sufficient leading zeroes\n");
			return 0;
		}
	}

	chain->tail->next = block;
	block->prev = chain->tail;
	block->next = NULL;
	chain->tail = block;
	chain->length++;

	free(tail_digest);
	free(digest);
	return 1;
}

void blockchain_to_file(blockchain_t* chain, FILE* fd) {
	unsigned char* data;
	size_t len;
	block_t* cur_block;
	if (fd == NULL) {
		return;
	}
	cur_block = chain->head;
	while (cur_block != NULL) {
		if (block_serialize(cur_block, &data, &len) == 0) {
			log_printf(LOG_ERROR, "Unable to serialize block\n");
			return;
		}
		fprintf(fd, "-----BEGIN BLOCK-----\n");
		fprintf(fd, "%s", data);
		fprintf(fd, "\n------END BLOCK------\n");
		free(data);
		cur_block = cur_block->next;
	}
	return;
}
