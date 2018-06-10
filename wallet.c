#include <stdlib.h> /* for calloc */
#include <stdio.h> /* for fopen and other file ops */
#include <string.h> /* for strerror */
#include <errno.h> /* for errno */

#include "wallet.h"
#include "log.h"

#define MAX_SERIAL_HEADER_LEN	32

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

int wallet_add_address(wallet_t* wallet) {
	address_t* last_addr;
	address_t* new_addr;

	new_addr = address_new();
	if (new_addr == NULL) {
		log_printf(LOG_ERROR, "Address creation failed\n");
		return 0;
	}

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
	unsigned char* data;
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
		data = (unsigned char*)malloc(datalen);
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

