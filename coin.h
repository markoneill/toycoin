#ifndef COIN_H
#define COIN_H

#include "transaction.h"

typedef struct coin {
	transaction_t* transaction;
	int index;
} coin_t;

coin_t* coin_new(transaction_t* transaction, int index);
void coin_free(coin_t* coin);

#endif
