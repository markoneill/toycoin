#include <stdlib.h> /* for calloc */
#include <stdio.h> /* for fopen and other file ops */
#include <string.h> /* for strerror */
#include <errno.h> /* for errno */

#include "wallet.h"
#include "log.h"

wallet_t* wallet_new(void) {
	wallet_t* wallet;
	wallet = calloc(1, sizeof(wallet_t));

	if (wallet == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new wallet\n");
		return NULL;
	}

	return wallet;
}

void wallet_free(wallet_t* wallet) {
	address_t* cur_addr;
	address_t* tmp_addr;
	cur_addr = wallet->addresses;
	while (cur_addr != NULL) {
		tmp_addr = cur_addr->next;
		address_free(cur_addr);
		cur_addr = tmp_addr;
	}
	wallet->addresses = NULL;
	wallet->amount = 0;
	free(wallet);
	return;
}

wallet_t* wallet_load(char* filepath) {
	FILE* wallet_file;
	wallet_t* wallet;
	wallet_file = fopen(filepath, "r");
	if (wallet_file == NULL) {
		log_printf(LOG_ERROR, "Unable to open wallet file: %s\n",
			 strerror(errno));
		return NULL;
	}

	

	fclose(wallet_file);
	return wallet;
}

int wallet_save(char* filepath) {
}
