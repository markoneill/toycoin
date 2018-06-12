#include <string.h> /* for strerror */
#include <errno.h> /* for errno */
#include <stdlib.h> /* for calloc */

#include "address.h"
#include "transaction.h"
#include "coin.h"
#include "log.h"

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
	
	if (util_hash_pubkey(keypair, address->digest, &address->digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		util_free_key(keypair);
		free(address);
		return NULL;
	}
	address->keypair = keypair;
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
	if (util_hash_pubkey(keypair, address->digest, &address->digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		util_free_key(keypair);
		free(address);
		return NULL;
	}

	address->keypair = keypair;
	address->coin = NULL;
	address->next = NULL;
	return address;
}

