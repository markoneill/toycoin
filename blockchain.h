#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdio.h>
#include "block.h"

typedef struct blockchain {
	block_t* head;
	block_t* tail;
	int length;
} blockchain_t;

blockchain_t* blockchain_create();
void blockchain_free(blockchain_t* chain);
int blockchain_add_block(blockchain_t* chain, block_t* block);

void blockchain_to_file(blockchain_t* chain, FILE* fd);
blockchain_t* blockchain_from_file(FILE* fd);

#endif
