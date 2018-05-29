#ifndef ADDRESS_H
#define ADDRESS_H

#include "transaction.h"
#include "util.h"

typedef struct coin {
	transaction_t* transaction;
	int index;
} coin_t;

typedef struct address {
	unsigned char id[MAX_DIGEST_LEN]; /* digest of pubkey */
	int id_len;
	key_t* keypair;
	coin_t* coin; /* coin associated with address, if any */
	struct address* next; /* pointer to next address in wallet */
} address_t;

address_t* address_new(void);
void address_free(address_t* address);

#endif