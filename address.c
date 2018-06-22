#include <string.h> /* for strerror */
#include <errno.h> /* for errno */
#include <stdlib.h> /* for calloc */

#include "address.h"
#include "transaction.h"
#include "coin.h"
#include "log.h"
#include "util.h"

address_t* address_new(void) {
	cryptokey_t* keypair;
	address_t* address;
	address = (address_t*)calloc(1, sizeof(address_t));
	if (address == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new address\n");
		return NULL;
	}
	keypair = util_generate_key(2048);
	if (keypair == NULL) {
		log_printf(LOG_ERROR, "Unable to generate key\n");
		free(address);
		return NULL;
	}
	
	if (util_hash_pubkey(keypair, &address->digest, &address->digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		util_free_key(keypair);
		free(address);
		return NULL;
	}
	address->keypair = keypair;
	address->coins = NULL;
	address->next = NULL;
	return address;
}

void address_free(address_t* address) {
	coin_t* coin;
	coin_t* tmp;
	util_free_key(address->keypair);
	if (address->coins != NULL) {
		coin = address->coins;
		while (coin != NULL) {
			tmp = coin;
			coin = coin->next;
			coin_free(tmp);
		}
	}
	address->keypair = NULL;
	address->coins = NULL;
	address->next = NULL;
	free(address->digest);
	address->digest = NULL;
	free(address);
	return;
}

char* address_get_id(address_t* address) {
	char* id;
	int ret;
	ret = util_base64_encode(address->digest, address->digest_len, &id, NULL);
	if (ret == 0) {
		log_printf(LOG_ERROR, "Failed get address id\n");
		return NULL;
	}
	return id;
}

int address_serialize(address_t* addr, unsigned char** data, int* datalen) {
	if (util_serialize_key(addr->keypair, data, datalen) == 0) {
		return 0;
	}
	return 1;
}

address_t* address_deserialize(char* data, int datalen) {
	address_t* address;
	cryptokey_t* keypair;
	keypair = util_deserialize_key(data, datalen);
	if (keypair == NULL) {
		log_printf(LOG_ERROR, "Unable to load keypair\n");
		return NULL;
	}

	address = (address_t*)calloc(1, sizeof(address_t));
	if (address == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate address\n");
		util_free_key(keypair);
		return NULL;
	}

	/* Restore digest of key */
	if (util_hash_pubkey(keypair, &address->digest, &address->digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		util_free_key(keypair);
		free(address);
		return NULL;
	}

	address->keypair = keypair;
	address->coins = NULL;
	address->next = NULL;
	return address;
}

