#include <stdlib.h> /* for calloc */
#include <string.h> /* for strerror */
#include "transaction.h"
#include "coin.h"
#include "log.h"

#define TRANSACTION_VERSION	1

static const char version_str[] = "version:";
static const char inputs_str[] = "num_inputs:";
static const char outputs_str[] = "num_outputs:";
static const char header_serial_format[] = "version:%d\n"
			     "num_inputs:%d\n"
			     "num_outputs:%d\n";

static const char ref_txn_len_str[] = "ref_txn_len:";
static const char ref_txn_str[] = "ref_txn_digest:";
static const char ref_index_str[] = "ref_index:";
static const char pubkey_len_str[] = "pubkey_len:";
static const char pubkey_str[] = "pubkey:";
static const char input_serial_format[] = "ref_txn_len:%d\n"
				"ref_txn_digest:%s\n"
				"ref_index:%d\n"
				"pubkey_len:%d\n"
				"pubkey:%s\n";

static const char amount_str[] = "amount:";
static const char addr_len_str[] = "addr_id_len:";
static const char addr_str[] = "addr_id:";
static const char output_serial_format[] = "amount:%d\n"
				"addr_id_len:%d\n"
				"addr_id:%s\n";

static const char signature_serial_format[] = "sig:%s\n";

static char* parse_str(char* serial, const char* token, size_t token_len);
static char* parse_int(char* serial, const char* token, size_t token_len, int* out);
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
			util_free_key(transaction->inputs[i].owner_key);
		}
		free(transaction->inputs);
	}
	if (transaction->outputs != NULL) {
		for (i = 0; i < transaction->num_outputs; i++) {
			free(transaction->outputs[i].addr_id);
		}
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

int transaction_set_input(transaction_t* txn, int index, 
		unsigned char* ref_txn_digest, unsigned int ref_digest_len,
		int ref_index, cryptokey_t* key) {
	unsigned char* digest_copy;
	cryptokey_t* key_copy;
	if (index < 0 || index >= txn->num_inputs) {
		log_printf(LOG_ERROR, "Invalid input index\n");
		return 0;
	}

	digest_copy = (unsigned char*)malloc(ref_digest_len);
	if (digest_copy == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate digest\n");
		return 0;
	}
	memcpy(digest_copy, ref_txn_digest, ref_digest_len);

	txn->inputs[index].ref_txn_digest = digest_copy;
	txn->inputs[index].ref_digest_len = ref_digest_len;
	txn->inputs[index].ref_index = ref_index;

	key_copy = util_copy_key(key);
	if (key_copy == NULL) {
		log_printf(LOG_ERROR, "Failed to copy key\n");
		free(digest_copy);
		return 0;
	}
	txn->inputs[index].owner_key = key_copy;
	return 1;
}

int transaction_set_output(transaction_t* txn, int index, int amount, char* addr_id, int addr_len) {
	char* addr_copy;
	if (index < 0 || index >= txn->num_outputs) {
		log_printf(LOG_ERROR, "Invalid output index\n");
		return 0;
	}

	addr_copy = (char*)malloc(addr_len + 1);
	if (addr_copy == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate addr\n");
		return 0;
	}
	memcpy(addr_copy, addr_id, addr_len);
	addr_copy[addr_len] = '\0';

	txn->outputs[index].addr_id = addr_copy;
	txn->outputs[index].amount = amount;

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
	//log_printf(LOG_DEBUG, "Transaction digest %u bytes\n", digest_len);

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

int transaction_serialize(transaction_t* txn, char** data, size_t* len, int include_sigs) {
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
		log_printf(LOG_ERROR, "Cannot allocate serialized transaction\n");
		return 0;
	}

	/* Actual write */
	if (serial_write(txn, txn_serial, txn_serial_len, include_sigs) != txn_serial_len) {
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
	int keylen;
	char* sig_str;
	int txn_serial_len = 0;
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
				&key_str, &keylen) == 0) {
			log_printf(LOG_ERROR, 
				"Failed to serialize pubkey\n");
			free(digest_str);
			return 0;
		}
		written = snprintf(data != NULL ? data+txn_serial_len : NULL,
				len != 0 ? len-txn_serial_len + 1: 0,
				input_serial_format,
				(int)strlen(digest_str),
				digest_str,
				txn->inputs[i].ref_index,
				keylen,
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
			(int)strlen(txn->outputs[i].addr_id),
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

char* parse_int(char* serial, const char* token, size_t token_len, int* out) {
	int retval;
	if (strncmp(serial, token, token_len) != 0) {
		log_printf(LOG_ERROR, "Failed to parse token %s\n", token);
		return NULL;
	}
	serial += token_len;
	retval = strtol(serial, &serial, 10);
	serial++;
	*out = retval;
	return serial;
}

char* parse_str(char* serial, const char* token, size_t token_len) {
	if (strncmp(serial, token, token_len) != 0) {
		log_printf(LOG_ERROR, "Failed to parse token %s\n", token);
		return NULL;
	}
	serial += token_len;
	return serial;
}

transaction_t* transaction_deserialize(char* serial, size_t len) {
	int i;
	int version;
	int num_inputs;
	int num_outputs;

	int ref_txn_len;
	unsigned char* ref_txn;
	size_t bin_ref_txn_len;
	int ref_index;
	int pubkey_len;
	cryptokey_t* pubkey;

	int amount;
	int addr_len;

	transaction_t* txn;

	serial = parse_int(serial, version_str, strlen(version_str), &version);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read transaction version\n");
		return NULL;
	}
	serial = parse_int(serial, inputs_str, strlen(inputs_str), &num_inputs);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read transaction input number\n");
		return NULL;
	}
	serial = parse_int(serial, outputs_str, strlen(outputs_str), &num_outputs);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read transaction output number\n");
		return NULL;
	}

	txn = transaction_new(num_inputs, num_outputs);
	if (txn == NULL) {
		log_printf(LOG_ERROR, "Failed to create transaction\n");
		return NULL;
	}


	for (i = 0; i < num_inputs; i++) {
		serial = parse_int(serial, ref_txn_len_str, strlen(ref_txn_len_str), &ref_txn_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read ref transaction len\n");
			transaction_free(txn);
			return NULL;
		}
		serial = parse_str(serial, ref_txn_str, strlen(ref_txn_str));
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read ref transaction token\n");
			transaction_free(txn);
			return NULL;
		}
		if (util_str_to_bytes(serial, ref_txn_len, &ref_txn, &bin_ref_txn_len) == 0) {
			log_printf(LOG_ERROR, "Failed to read reference transaction\n");
			transaction_free(txn);
			return NULL;
		}
		serial += ref_txn_len + 1; /* +1 for newline */
		serial = parse_int(serial, ref_index_str, strlen(ref_index_str), &ref_index);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read ref index\n");
			transaction_free(txn);
			return NULL;
		}
		serial = parse_int(serial, pubkey_len_str, strlen(pubkey_len_str), &pubkey_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read pubkey length\n");
			transaction_free(txn);
			return NULL;
		}
		serial = parse_str(serial, pubkey_str, strlen(pubkey_str));
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read pubkey token\n");
			transaction_free(txn);
			return NULL;
		}
		pubkey = util_deserialize_pubkey(serial, pubkey_len);
		if (pubkey == NULL) {
			log_printf(LOG_ERROR, "Failed to read pubkey\n");
			transaction_free(txn);
			return NULL;
		}
		serial += pubkey_len;
		if (transaction_set_input(txn, i, ref_txn, bin_ref_txn_len, ref_index, pubkey) == 0) {
			log_printf(LOG_ERROR, "Failed to set input\n");
			transaction_free(txn);
			return NULL;
		}
		util_free_key(pubkey);
		free(ref_txn);
	}

	for (i = 0; i < num_outputs; i++) {
		serial = parse_int(serial, amount_str, strlen(amount_str), &amount);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read amount\n");
			transaction_free(txn);
			return NULL;
		}
		printf("before %.20s\n", serial);
		serial = parse_int(serial, addr_len_str, strlen(addr_len_str), &addr_len);
		printf("after %.20s %d\n", serial, addr_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read address length\n");
			transaction_free(txn);
			return NULL;
		}
		serial = parse_str(serial, addr_str, strlen(addr_str));
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read address token\n");
			transaction_free(txn);
			return NULL;
		}
		if (transaction_set_output(txn, i, amount, serial, addr_len) == 0) {
			log_printf(LOG_ERROR, "Failed to set output\n");
			transaction_free(txn);
			return NULL;
		}
		serial += addr_len;
	}

	return txn;
}

int transaction_hash(transaction_t* txn, unsigned char** digest_out, unsigned int* digest_len_out) {
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

	if (util_hash((unsigned char*)serialized_txn, serial_len, digest, &digest_len) == 0) {
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


