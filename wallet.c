#include <stdlib.h> /* for calloc */
#include <stdio.h> /* for fopen and other file ops */
#include <string.h> /* for strerror */
#include <errno.h> /* for errno */

#include "wallet.h"
#include "blockchain.h"
#include "log.h"
#include "coin.h"

#define MAX_SERIAL_HEADER_LEN	32

/*static int wallet_get_address_count(wallet_t* wallet);*/
static coin_t* remove_spent_coins(blockchain_t* chain, coin_t* head);

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

int wallet_add_address(wallet_t* wallet, address_t* new_addr) {
	address_t* last_addr;

	if (wallet->addresses == NULL) {
		wallet->addresses = new_addr;
		return 1;
	}

	last_addr = wallet->addresses;
	while (last_addr->next != NULL) {
		last_addr = last_addr->next;
	}

	last_addr->next = new_addr;

	return 1;
}

wallet_t* wallet_load(char* filepath) {
	FILE* wallet_file;
	wallet_t* wallet;
	char size_str[MAX_SERIAL_HEADER_LEN];
	char* data;
	address_t* head_addr;
	address_t* cur_addr;
	address_t* prev_addr;
	int datalen;
	wallet_file = fopen(filepath, "r");
	if (wallet_file == NULL) {
		log_printf(LOG_ERROR, "Unable to open wallet file: %s\n",
			 strerror(errno));
		return NULL;
	}

	head_addr = NULL;
	while (fgets(size_str, MAX_SERIAL_HEADER_LEN, wallet_file) != NULL) {
		datalen = strtol(size_str, NULL, 10);
		data = (char*)malloc(datalen);
		if (data == NULL) {
			log_printf(LOG_ERROR, 
				"Unable to allocate address data\n");
			return NULL;
		}
		if (fread(data, datalen, 1, wallet_file) != 1) {
			log_printf(LOG_ERROR, "failed to read address\n");
			free(data);
			return NULL;
		}
		cur_addr = address_deserialize(data, datalen);
		if (cur_addr == NULL) {
			log_printf(LOG_ERROR, "failed to load address\n");
			free(data);
			return NULL;
		}
		free(data);
		if (head_addr == NULL) {
			head_addr = cur_addr;
		}
		else {
			prev_addr->next = cur_addr;
		}
		prev_addr = cur_addr;
	}

	wallet = wallet_new();
	if (wallet == NULL) {
		log_printf(LOG_ERROR, "failed to allocate wallet\n");
		free(data);
	}
	wallet->addresses = head_addr;

	fclose(wallet_file);
	return wallet;
}

int wallet_save(wallet_t* wallet, char* filepath) {
	FILE* wallet_file;
	address_t* cur_addr;
	unsigned char* serialized_addr;
	char size_str[MAX_SERIAL_HEADER_LEN];
	int len;
	int written;

	wallet_file = fopen(filepath, "w");
	if (wallet_file == NULL) {
		log_printf(LOG_ERROR, "Unable to open wallet file: %s\n",
			 strerror(errno));
		return 0;
	}

	cur_addr = wallet->addresses;
	while (cur_addr != NULL) {
		if (address_serialize(cur_addr, &serialized_addr, &len) == 0) {
			log_printf(LOG_ERROR, "Unable to serialize address\n");
			return 0;
		}
		written = snprintf(size_str, MAX_SERIAL_HEADER_LEN-1, "%d\n",
			 len);
		if (written < 0 || written == MAX_SERIAL_HEADER_LEN-1) {
			log_printf(LOG_ERROR,"Failed to stringify size: %s\n",
				strerror(errno));
			free(serialized_addr);
		}
		if (fwrite(size_str, written, 1, wallet_file) != 1) {
			log_printf(LOG_ERROR,"Failed to write size: %s\n",
				strerror(errno));
			free(serialized_addr);
			return 0;
		}
		if (fwrite(serialized_addr, len, 1, wallet_file) != 1) {
			log_printf(LOG_ERROR,"Failed to write address: %s\n",
				strerror(errno));
			free(serialized_addr);
			return 0;
		}
		
		free(serialized_addr);
		cur_addr = cur_addr->next;
	}
	
	fclose(wallet_file);
	return 1;
}


/*int wallet_get_address_count(wallet_t* wallet) {
	address_t* cur_addr;
	int count;

	cur_addr = wallet->addresses;
	count = 0;
	while (cur_addr != NULL) {
		count++;
		cur_addr = cur_addr->next;
	}
	return count;
}*/

coin_t* remove_spent_coins(blockchain_t* chain, coin_t* head) {
	coin_t* cur_coin;
	coin_t* tmp_coin;
	unsigned char* digest;
	unsigned int digest_len;

	cur_coin = head;
	while (cur_coin != NULL) {
		tmp_coin = cur_coin->next;
		if (transaction_hash(cur_coin->transaction,
					&digest, &digest_len) != 1) {
			log_printf(LOG_ERROR, "Failed to hash transaction\n");
			return NULL;
		}
		if (blockchain_reference_exists(chain, digest, digest_len,
				cur_coin->index) == 1) {
			coin_free(cur_coin);
			if (cur_coin == head) {
				head = tmp_coin;
			}
		}
		cur_coin = tmp_coin;
		free(digest);
	}
	return head;
}

int wallet_sync(wallet_t* wallet, blockchain_t* chain) {
	address_t* cur_addr;
	char* address_id;
	coin_t* coins = NULL;
	int total = 0;

	cur_addr = wallet->addresses;
	while (cur_addr != NULL) {
		address_id = address_get_id(cur_addr);

		/* remove all coins first */	
		coin_free_coins(cur_addr->coins);

		/* find current coins */
		coins = blockchain_get_coins(chain, address_id);
		coins = remove_spent_coins(chain, coins);

		/* add coins to address */
		cur_addr->coins = coins;
		total += coin_sum_coins(coins);

		cur_addr = cur_addr->next;
		free(address_id);
	}
	return total;
}

int wallet_del_address(wallet_t* wallet, address_t* addr) {
	address_t* cur_addr;

	cur_addr = wallet->addresses;

	if (cur_addr == addr) {
		wallet->addresses = addr->next;
		address_free(addr);
		return 1;
	}

	while (cur_addr->next != NULL) {
		if (cur_addr->next == addr) {
			cur_addr->next = addr->next;
			address_free(addr);
			return 1;
		}
		cur_addr = cur_addr->next;
	}

	return 0;
}

