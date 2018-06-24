#include "coin.h"
#include "log.h"

coin_t* coin_new(transaction_t* transaction, int index, int amount) {
	coin_t* coin;
	coin = (coin_t*)calloc(1, sizeof(coin_t));
	if (coin == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new coin\n");
		return NULL;
	}
	coin->transaction = transaction;
	coin->index = index;
	coin->amount = amount;
	coin->next = NULL;
	return coin;
}

void coin_free(coin_t* coin) {
	coin->transaction = NULL;
	free(coin);
	return;
}

coin_t* coin_add_coins(coin_t* prev, coin_t* next) {
	coin_t* head;
	if (prev == NULL) {
		return next;
	}

	if (next == NULL) {
		return prev;
	}

	head = prev;
	while (prev->next != NULL) {
		prev = prev->next;
	}
	prev->next = next;
	return head;
}

void coin_free_coins(coin_t* head) {
	coin_t* tmp;
	while (head != NULL) {
		tmp = head->next;
		coin_free(head);
		head = tmp;
	}
	return;
}

int coin_sum_coins(coin_t* coin) {
	int value;

	value = 0;
	while (coin != NULL) {
		value += coin->amount;
		coin = coin->next;
	}
	return value;
}
