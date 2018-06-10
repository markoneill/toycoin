#ifndef ADDRESS_H
#define ADDRESS_H

#include "transaction.h"
#include "coin.h"
#include "util.h"

typedef struct address {
	unsigned char digest[MAX_DIGEST_LEN]; /* digest of pubkey */
	unsigned int digest_len;
	cryptokey_t* keypair;
	coin_t* coin; /* coin associated with address, if any */
	struct address* next; /* pointer to next address in wallet */
} address_t;

address_t* address_new(void);
void address_free(address_t* address);
int address_serialize(address_t* addr, unsigned char** data, int* datalen);
address_t* address_deserialize(unsigned char* data, int datalen);

#endif
