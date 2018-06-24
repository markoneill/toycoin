#ifndef WALLET_H
#define WALLET_H

#include "transaction.h"
#include "address.h"
#include "blockchain.h"

typedef struct wallet {
	address_t* addresses; /* head of linked list of addresses */
	int amount; /* total available funds */
} wallet_t;

wallet_t* wallet_new(void);
int wallet_add_address(wallet_t* wallet, address_t* addr);
int wallet_del_address(wallet_t* wallet, address_t* addr);
void wallet_free(wallet_t* wallet);
int wallet_save(wallet_t* wallet, char* filepath);
wallet_t* wallet_load(char* filepath);

int wallet_sync(wallet_t* wallet, blockchain_t* chain);
/*int wallet_transfer_to_address(int amount);*/

#endif
