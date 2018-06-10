#include <stdlib.h> /* for calloc */
#include <string.h> /* for strerror */
#include "transaction.h"
#include "coin.h"
#include "log.h"

#define TRANSACTION_VERSION	1

static const char header_serial_format[] = "version:%d\n"
			     "num_inputs:%d\n"
			     "num_outputs:%d\n";

static const char input_serial_format[] = "ref_txn_digest:%s\n"
				"ref_index:%d\n"
				"pubkey:%s\n";

static const char output_serial_format[] = "amount:%d\n"
				"addr_id:%s\n";

static const char signature_serial_format[] = "sig:%s\n";

static size_t serial_write(transaction_t* txn, char* data, size_t len,
	 int include_sigs);

transaction_t* transaction_new(int input_count, int output_count) {
	transaction_t* transaction;
	txinput_t* inputs;
	txoutput_t* outputs;

	if (input_count < 0 || output_count <= 0) {
		log_printf(LOG_ERROR, "Invalid input/output count\n");
		return NULL;
	}

	if (input_count > 0) {
		inputs = calloc(input_count, sizeof(txinput_t));
		if (inputs == NULL) {
			log_printf(LOG_ERROR, "Unable to allocate inputs\n");
			return NULL;
		}
	}
	else {
		inputs = NULL;
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
	transaction->is_finalized = 0;

	return transaction;
}

void transaction_free(transaction_t* transaction) {
	int i;
	if (transaction->inputs != NULL) {
		for (i = 0; i < transaction->num_inputs; i++) {
			free(transaction->inputs[i].ref_txn_digest);
		}
		free(transaction->inputs);
	}
	if (transaction->outputs != NULL) {
		free(transaction->outputs);
	}

	if (transaction->is_finalized == 1) {
		for (i = 0; i < transaction->num_inputs; i++) {
			free(transaction->signatures[i].signature);
		}
		free(transaction->signatures);
	}

	transaction->inputs = NULL;
	transaction->outputs = NULL;
	transaction->signatures = NULL;
	free(transaction);
	return;
}

int transaction_set_input(transaction_t* txn, int index, transaction_t* src,
		int ref_index, cryptokey_t* key) {

	if (index < 0 || index >= txn->num_inputs) {
		log_printf(LOG_ERROR, "Invalid input index\n");
		return 0;
	}

	if (transaction_hash(src, &txn->inputs[index].ref_txn_digest,
				&txn->inputs[index].ref_digest_len) == 0) {
		log_printf(LOG_ERROR, "Failed to hash ref transaction\n");
		return 0;
	}
	txn->inputs[index].ref_index = ref_index;
	txn->inputs[index].owner_key = key;
	return 1;
}

int transaction_set_output(transaction_t* txn, int index, int amount,
		char* addr_id) {
	
	if (index < 0 || index >= txn->num_outputs) {
		log_printf(LOG_ERROR, "Invalid output index\n");
		return 0;
	}
	txn->outputs[index].amount = amount;
	strncpy(txn->outputs[index].addr_id, addr_id, MAX_ID_LEN);

	return 1;
}

int transaction_finalize(transaction_t* txn) {
	txsig_t* signatures;
	unsigned char* digest;
	unsigned int digest_len;
	int i;

	/* coinbase transactions have no need to be finalized */
	if (txn->num_inputs == 0) {
		return 1;
	}

	if (transaction_hash(txn, &digest, &digest_len) == 0) {
		log_printf(LOG_ERROR, "Failed to hash transaction\n");
		return 0;
	}

	signatures = (txsig_t*)calloc(txn->num_inputs, sizeof(txsig_t));
	if (signatures == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate signatures\n");
		return 0;
	}

	for (i = 0; i < txn->num_inputs; i++) {
		if (util_sign(txn->inputs[i].owner_key, digest, digest_len,
				&signatures[i].signature,
				&signatures[i].len) == 0) {
			log_printf(LOG_ERROR, "Failed to sign digest\n");
			return 0;
		}
	}
	txn->signatures = signatures;
	txn->is_finalized = 1;
	free(digest);
	return 1;
}

int transaction_serialize(transaction_t* txn, char** data, size_t* len,
		 int include_sigs) {
	char* txn_serial;
	size_t txn_serial_len;

	/* Test write and get length */
	txn_serial_len = serial_write(txn, NULL, 0, include_sigs);
	if (txn_serial_len == 0) {
		log_printf(LOG_ERROR, "Test serialize transaction failed\n");
		return 0;
	}

	/* Allocate storage for serialization */
	txn_serial = (char*)calloc(1, txn_serial_len + 1);
	if (txn_serial == NULL) {
		log_printf(LOG_ERROR, 
			"Cannot allocate serialized transaction\n");
		return 0;
	}

	/* Actual write */
	if (serial_write(txn, txn_serial, txn_serial_len, include_sigs)
			 != txn_serial_len) {
		log_printf(LOG_ERROR, "Failed to serialize transaction\n");
		free(txn_serial);
		return 0;
	}
	*data = txn_serial;
	if (len != NULL) {
		*len = txn_serial_len;
	}
	return 1;
}

size_t serial_write(transaction_t* txn, char* data, size_t len, 
		int include_sigs) {
	int i;
	int written;
	char* digest_str;
	char* key_str;
	char* sig_str;
	size_t txn_serial_len = 0;
	written = snprintf(data,
			len != 0 ? len + 1 : 0,
			header_serial_format,
			txn->version,
			txn->num_inputs,
			txn->num_outputs);
	if (written == -1) {
		log_printf(LOG_ERROR, "Cannot serialize transaction header\n");
		return 0;
	}
	txn_serial_len += written;
	for (i = 0; i < txn->num_inputs; i++) {
		if (util_bytes_to_str(txn->inputs[i].ref_txn_digest, 
					txn->inputs[i].ref_digest_len, 
					&digest_str) == 0) {
			log_printf(LOG_ERROR, 
				"Failed to convert digest to string\n");
			return 0;
		}
		if (util_serialize_pubkey(txn->inputs[i].owner_key, 
				&key_str, NULL) == 0) {
			log_printf(LOG_ERROR, 
				"Failed to serialize pubkey\n");
			free(digest_str);
			return 0;
		}
		written = snprintf(data != NULL ? data+txn_serial_len : NULL,
				len != 0 ? len-txn_serial_len + 1: 0,
				input_serial_format,
				digest_str,
				txn->inputs[i].ref_index,
				key_str);
		if (written == -1) {
			log_printf(LOG_ERROR, "Cannot serialize input\n");
			free(digest_str);
			free(key_str);
			return 0;
		}
		free(digest_str);
		free(key_str);
		txn_serial_len += written;
	}

	for (i = 0; i < txn->num_outputs; i++) {
		written = snprintf(data != NULL ? data+txn_serial_len : NULL,
			len != 0 ? len-txn_serial_len + 1: 0,
			output_serial_format,
			txn->outputs[i].amount,
			txn->outputs[i].addr_id);
		if (written == -1) {
			log_printf(LOG_ERROR, "Cannot serialize output\n");
			return 0;
		}
		txn_serial_len += written;
	}

	/* Stop here if the transaction hasn't been signed yet
	 * or if caller doesn't want signatures included in serial */
	if (txn->is_finalized == 0 || include_sigs == 0) {
		return txn_serial_len;
	}

	for (i = 0; i < txn->num_inputs; i++) {
		if (util_bytes_to_str(txn->signatures[i].signature,
				txn->signatures[i].len, &sig_str) == 0) {
			log_printf(LOG_ERROR, 
				"Unable to serialize signature\n");
			return 0;
		}
		written = snprintf(data != NULL ? data+txn_serial_len : NULL,
				len != 0 ? len-txn_serial_len + 1: 0,
				signature_serial_format,
				sig_str);
		if (written == -1) {
			log_printf(LOG_ERROR, "Cannot serialize signature\n");
			free(sig_str);
			return 0;
		}
		free(sig_str);
		txn_serial_len += written;
	}

	return txn_serial_len;
}

int transaction_hash(transaction_t* txn, unsigned char** digest_out,
		unsigned int* digest_len_out) {
	char* serialized_txn;
	size_t serial_len;
	unsigned char* digest;
	unsigned int digest_len;
	if (transaction_serialize(txn, &serialized_txn, &serial_len, 0) == 0) {
		log_printf(LOG_ERROR, "Unable to serialize transaction\n");
		return 0;
	}

	//log_printf(LOG_DEBUG, "Transaction serial:\n%s\n", serialized_txn);

	digest = (unsigned char*)malloc(util_digestlen());
	if (digest == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate digest\n");
		return 0;
	}

	if (util_hash((unsigned char*)serialized_txn, serial_len, digest, 
			&digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash transaction\n");
		return 0;
	}
	*digest_out = digest;

	if (digest_len_out != NULL) {
		*digest_len_out = digest_len;
	}

	free(serialized_txn);
	return 1;
}


