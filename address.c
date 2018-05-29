#include <string.h> /* for strerror */
#include <errno.h> /* for errno */
#include <stdlib.h> /* for calloc */

#include "address.h"
#include "transaction.h"
#include "log.h"

static coin_t* coin_new(transaction_t* transaction, int index);
static void coin_free(coin_t* coin);

address_t* address_new(void) {
	key_t* keypair;
	address_t* address;
	address = calloc(1, sizeof(address));
	if (address == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new address\n");
		return NULL;
	}
	keypair = util_generate_key(4096);
	if (keypair == NULL) {
		log_printf(LOG_ERROR, "Unable to generate key\n");
		free(address);
		return NULL;
	}
	
	if (util_hash_pubkey(keypair, &address->id, &address->id_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		util_free_key(keypair);
		free(address);
		return NULL;
	}
	address->coin = NULL;
	address->next = NULL;
	return address;
}

void address_free(address_t* address) {
	util_free_key(address->keypair);
	if (address->coin != NULL) {
		coin_free(address->coin);
	}
	address->keypair = NULL;
	address->coin = NULL;
	address->next = NULL;
	free(address);
	return;
}


coin_t* coin_new(transaction_t* transaction, int index) {
	coin_t* coin;
	coin = calloc(1, sizeof(coin_t));
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