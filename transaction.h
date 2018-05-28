#ifndef TRANSACTION_H
#define TRANSACTION_H

/* 
 * Basic transaction structure influenced by
 * https://en.bitcoin.it/wiki/Transaction
 *
 * This could be made more generic to support
 * contracts and basic or advanced scripting*/

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

typedef struct input {
	unsigned char ref_txn_digest[EVP_MAX_MD_SIZE]; /* hash of ref transaction */
	int index; /* index into referenced transaction */
	EVP_PKEY* owner_pubkey; /* pubkey of owner of ref transaction[index] */
	unsigned char signature[EVP_MAX_MD_SIZE]; /* auth signature from owner */
} input_t;

typedef struct output {
	int amount; /* amount of coin to send, expressed in base unit */
	unsigned char recv_addr[EVP_MAX_MD_SIZE]; /* hash of recvr pub key */
} output_t;

typedef struct transaction {
	int version; /* transaction format version */
	int num_inputs;
	int num_outputs;
	EVP_PKEY* sender;
	EVP_PKEY* recver;
	
} transaction_t;

transaction_t* transaction_new(int amount, unsigned char* recv_addr);
tranaction_free(transaction_t* transaction);

#endif
