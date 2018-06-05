#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "util.h"

/* 
 * Basic transaction structure influenced by
 * https://en.bitcoin.it/wiki/Transaction
 *
 * This could be made more generic to support
 * contracts and basic or advanced scripting*/

typedef struct txinput {
	unsigned char ref_txn_digest[MAX_DIGEST_LEN]; /* hash of ref txn */
	int ref_digest_len; /* length of ref txn digest */
	int ref_index; /* index into referenced transaction */
	cryptokey_t* owner_key; /* pubkey of owner of ref txn[index] */
} txinput_t;

typedef struct txoutput {
	int amount; /* amount of coin to send, expressed in base unit */
	char addr_id[MAX_ID_LEN]; /* base64(sha256(recv pubkey)) */
} txoutput_t;

typedef struct transaction {
	int version; /* transaction format version */
	int num_inputs;
	int num_outputs;
	txinput_t* inputs;
	txoutput_t* outputs;
	unsigned char signature[MAX_DIGEST_LEN]; /* auth sig from owner */
} transaction_t;

transaction_t* transaction_new(int input_count, int output_count);
void transaction_free(transaction_t* transaction);
int transaction_set_input(transaction_t* txn, int index, transaction_t* src,
		int ref_index, cryptokey_t* key);
int transaction_set_output(transaction_t* txn, int index, int amount,
		unsigned char* addr_id);
int transaction_finalize(transaction_t* txn);
int transaction_hash(transaction_t* transaction, unsigned char* digest,
		size_t digest_len);
int transaction_serialize(transaction_t* txn, unsigned char** data,
	 size_t* len);



#endif
