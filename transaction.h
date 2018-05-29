#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "util.h"

/* 
 * Basic transaction structure influenced by
 * https://en.bitcoin.it/wiki/Transaction
 *
 * This could be made more generic to support
 * contracts and basic or advanced scripting*/

typedef struct input {
	unsigned char ref_txn_digest[MAX_DIGEST_LEN]; /* hash of ref transaction */
	int index; /* index into referenced transaction */
	cryptokey_t* owner_pubkey; /* pubkey of owner of ref transaction[index] */
	unsigned char signature[MAX_DIGEST_LEN]; /* auth signature from owner */
} input_t;

typedef struct output {
	int amount; /* amount of coin to send, expressed in base unit */
	unsigned char recv_addr[MAX_DIGEST_LEN]; /* hash of recvr pub key */
} output_t;

typedef struct transaction {
	int version; /* transaction format version */
	int num_inputs;
	int num_outputs;
} transaction_t;

transaction_t* transaction_new(int amount, unsigned char* recv_addr);
tranaction_free(transaction_t* transaction);

#endif
