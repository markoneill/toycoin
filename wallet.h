#ifndef WALLET_H
#define WALLET_H

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */
#include "transaction.h"
#include "address.h"

typedef struct wallet {
	address_t* addresses; /* head of linked list of addresses */
	int amount; /* total available funds */
} wallet_t;

wallet_t* wallet_new(void);
void wallet_free(wallet_t* wallet);
int wallet_save(char* filepath);
wallet_t* wallet_load(char* filepath);

#endif
