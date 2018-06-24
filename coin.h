#ifndef COIN_H
#define COIN_H

#include "transaction.h"

typedef struct coin {
	transaction_t* transaction;
	int index;
	int amount;
	struct coin* next;
} coin_t;

coin_t* coin_new(transaction_t* transaction, int index, int amount);
void coin_free(coin_t* coin);
coin_t* coin_add_coins(coin_t* prev, coin_t* next);
void coin_free_coins(coin_t* head);
int coin_sum_coins(coin_t* coin);

#endif
