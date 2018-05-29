#ifndef ADDRESS_H
#define ADDRESS_H

#include "transaction.h"

typedef struct coin {
	transaction_t* transaction;
	int index;
} coin_t;

typedef struct address {
	unsigned char id[EVP_MAX_MD_SIZE]; /* digest of pubkey */
	int id_len;
	EVP_PKEY* keypair;
	coin_t* coin; /* coin associated with address, if any */
	struct address* next; /* pointer to next address in wallet */
} address_t;

address_t* address_new(void);
void address_free(address_t* address);

#endif
