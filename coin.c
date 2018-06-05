#include "coin.h"
#include "log.h"

coin_t* coin_new(transaction_t* transaction, int index) {
	coin_t* coin;
	coin = (coin_t*)calloc(1, sizeof(coin_t));
	if (coin == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new coin\n");
		return NULL;
	}
	coin->transaction = transaction;
	coin->index = index;
	return coin;
}

void coin_free(coin_t* coin) {
	coin->transaction = NULL;
	free(coin);
	return;
}

