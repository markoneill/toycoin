#include <stdlib.h> /* for calloc */
#include <string.h> /* for strerror */
#include "transaction.h"
#include "coin.h"
#include "log.h"

#define TRANSACTION_VERSION	1

transaction_t* transaction_new(int input_count, int output_count) {
	transaction_t* transaction;
	txinput_t* inputs;
	txoutput_t* outputs;

	inputs = calloc(input_count, sizeof(txinput_t));
	if (inputs == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate inputs\n");
		return NULL;
	}

	outputs = calloc(output_count, sizeof(txoutput_t));
	if (outputs == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate outputs\n");
		free(inputs);
		return NULL;
	}

	transaction = calloc(1, sizeof(transaction_t));
	if (transaction == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate transaction\n");
		free(inputs);
		free(outputs);
		return NULL;
	}

	transaction->version = TRANSACTION_VERSION;
	transaction->num_inputs = input_count;
	transaction->num_outputs = output_count;
	transaction->inputs = inputs;
	transaction->outputs = outputs;

	return transaction;
}

void transaction_free(transaction_t* transaction) {
	int i;
	if (transaction->inputs != NULL) {
		free(transaction->inputs);
	}
	if (transaction->outputs != NULL) {
		free(transaction->outputs);
	}
	transaction->inputs = NULL;
	transaction->outputs = NULL;
	free(transaction);
	return;
}

int transaction_set_input(transaction_t* txn, int index, transaction_t* src,
		int ref_index, cryptokey_t* key) {

	unsigned char* ref_digest;

	if (index < 0 || index >= txn->num_inputs) {
		log_printf(LOG_ERROR, "Invalid input index\n");
		return 0;
	}

	ref_digest = &txn->inputs[index].ref_txn_digest;
	if (transaction_hash(src, ref_digest, util_digestlen()) != 1) {
		log_printf(LOG_ERROR, "Failed to hash ref transaction\n");
		return 0;
	}
	txn->inputs[index].ref_index = ref_index;
	txn->inputs[index].owner_key = key;
	return 1;
}

int transaction_set_output(transaction_t* txn, int index, int amount,
		unsigned char* addr_id) {
	
	if (index < 0 || index >= txn->num_outputs) {
		log_printf(LOG_ERROR, "Invalid output index\n");
		return 0;
	}
	txn->outputs[index].amount = amount;
	strncpy(&txn->outputs[index].addr_id, addr_id, MAX_ID_LEN);

	return 1;
}

int transaction_finalize(transaction_t* txn) {
	/*
	 * 1) Serialize transaction 
	 * 2) Sign transaction
	 */
	return 1;
}

int transaction_serialize(transaction_t* txn, unsigned char** data,
		 size_t* len) {
	return 1;
}

int transaction_hash(transaction_t* transaction, unsigned char* digest,
		size_t digest_len) {
	return 1;
}


