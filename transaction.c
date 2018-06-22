#include <stdlib.h> /* for calloc */
#include <string.h> /* for strerror */
#include "transaction.h"
#include "blockchain.h"
#include "coin.h"
#include "log.h"

#define TRANSACTION_VERSION	1

static const char version_str[] = "\tversion:";
static const char inputs_str[] = "\tnum_inputs:";
static const char outputs_str[] = "\tnum_outputs:";
static const char header_serial_format[] = "\tversion:%d\n"
			     "\tnum_inputs:%d\n"
			     "\tnum_outputs:%d\n";

static const char ref_txn_len_str[] = "\tref_txn_len:";
static const char ref_txn_str[] = "\tref_txn_digest:";
static const char ref_index_str[] = "\tref_index:";
static const char pubkey_len_str[] = "\tpubkey_len:";
static const char pubkey_str[] = "\tpubkey:";
static const char input_serial_format[] = "\tref_txn_len:%d\n"
				"\tref_txn_digest:%s\n"
				"\tref_index:%d\n"
				"\tpubkey_len:%d\n"
				"\tpubkey:%s\n";

static const char amount_str[] = "\tamount:";
static const char addr_len_str[] = "\taddr_id_len:";
static const char addr_str[] = "\taddr_id:";
static const char output_serial_format[] = "\tamount:%d\n"
				"\taddr_id_len:%d\n"
				"\taddr_id:%s\n";

static const char sig_len_str[] = "\tsig_len:";
static const char sig_str[] = "\tsig:";
static const char signature_serial_format[] = "\tsig_len:%d\n"
					"\tsig:%s\n";

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
				(int)strlen(sig_str),
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

	txsig_t* signatures;	
	int sig_len;
	size_t bin_sig_len;
	unsigned char* sig;

	transaction_t* txn;

	serial = util_parse_int(serial, version_str, strlen(version_str), &version);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read transaction version\n");
		return NULL;
	}
	serial = util_parse_int(serial, inputs_str, strlen(inputs_str), &num_inputs);
	if (serial == NULL) {
		log_printf(LOG_ERROR, "Failed to read transaction input number\n");
		return NULL;
	}
	serial = util_parse_int(serial, outputs_str, strlen(outputs_str), &num_outputs);
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
		serial = util_parse_int(serial, ref_txn_len_str, strlen(ref_txn_len_str), &ref_txn_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read ref transaction len\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_str(serial, ref_txn_str, strlen(ref_txn_str));
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
		serial = util_parse_int(serial, ref_index_str, strlen(ref_index_str), &ref_index);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read ref index\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_int(serial, pubkey_len_str, strlen(pubkey_len_str), &pubkey_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read pubkey length\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_str(serial, pubkey_str, strlen(pubkey_str));
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
		serial += pubkey_len + 1; /* +1 for newline */
		if (transaction_set_input(txn, i, ref_txn, bin_ref_txn_len, ref_index, pubkey) == 0) {
			log_printf(LOG_ERROR, "Failed to set input\n");
			transaction_free(txn);
			return NULL;
		}
		util_free_key(pubkey);
		free(ref_txn);
	}
	
	for (i = 0; i < num_outputs; i++) {
		serial = util_parse_int(serial, amount_str, strlen(amount_str), &amount);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read amount\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_int(serial, addr_len_str, strlen(addr_len_str), &addr_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read address length\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_str(serial, addr_str, strlen(addr_str));
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
		serial += addr_len + 1; /* +1 for newline */

	}

	signatures = (txsig_t*)calloc(txn->num_inputs, sizeof(txsig_t));
	if (signatures == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate signatures\n");
		return 0;
	}
	txn->signatures = signatures;
	
	for (i = 0; i < num_inputs; i++) {
		serial = util_parse_int(serial, sig_len_str, strlen(sig_len_str), &sig_len);
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read signature length\n");
			transaction_free(txn);
			return NULL;
		}
		serial = util_parse_str(serial, sig_str, strlen(sig_str));
		if (serial == NULL) {
			log_printf(LOG_ERROR, "Failed to read signature token\n");
			transaction_free(txn);
			return NULL;
		}
		if (util_str_to_bytes(serial, sig_len, &sig, &bin_sig_len) == 0) {
			log_printf(LOG_ERROR, "Failed to read signature\n");
			transaction_free(txn);
			return NULL;
		}
		serial += sig_len + 1; /* +1 for newline */
		
		signatures[i].signature = sig;
		signatures[i].len = bin_sig_len;
	}

	txn->is_finalized = 1;

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

	if (util_hash((unsigned char*)serialized_txn, serial_len, &digest, &digest_len) == 0) {
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

coin_t* transaction_get_coin(transaction_t* txn, char* address_id) {
	int i;
	coin_t* coin;
	for (i = 0; i < txn->num_outputs; i++) {
		if (strcmp(txn->outputs[i].addr_id, address_id) == 0) {
			coin = coin_new(txn, i, txn->outputs[i].amount);
			if (coin == NULL) {
				log_printf(LOG_ERROR, "Unable make coin\n");
				return NULL;
			}
			return coin;
		}
	}
	return NULL;
}

int transaction_references(transaction_t* txn, unsigned char* ref_txn_digest,
		unsigned int ref_digestlen, int index) {
	int i;
	for (i = 0; i < txn->num_inputs; i++) {
		if (memcmp(txn->inputs[i].ref_txn_digest,
				ref_txn_digest, ref_digestlen) == 0) {
			return 1;
		}
	}
	return 0;
}

int transaction_is_valid(transaction_t* txn, blockchain_t* chain) {
	int i;
	int is_valid;
	int input_amount;
	int output_amount;
	transaction_t* ref_txn;
	int ref_idx;
	txoutput_t* ref_output;

	unsigned char* digest;
	unsigned int digestlen;
	char* b64_encoding;

	unsigned char* txn_digest;
	unsigned int txn_digestlen;

	is_valid = 0;
	input_amount = 0;
	output_amount = 0;

	/* hash the transaction for verification later */
	if (transaction_hash(txn, &txn_digest, &txn_digestlen) != 1) {
		return 0;
	}

	/* calculate money spent */
	for (i = 0; i < txn->num_outputs; i++) {
		output_amount += txn->outputs[i].amount;
	}

	/* verify the money is owned */
	for (i = 0; i < txn->num_inputs; i++) {
		ref_txn = blockchain_get_transaction_by_digest(chain,
			txn->inputs[i].ref_txn_digest, 
			txn->inputs[i].ref_digest_len);
		if (ref_txn == NULL) {
			/* referenced transaction doesn't exist */
			free(txn_digest);
			return 0;
		}

		ref_idx = txn->inputs[i].ref_index;
		if (ref_idx < 0 || ref_idx > ref_txn->num_outputs-1) {
			/* referenced output doesn't exist */
			free(txn_digest);
			return 0;
		}

		ref_output = &ref_txn->outputs[ref_idx];
		if (util_hash_pubkey(txn->inputs[i].owner_key,
			 &digest, &digestlen) != 1) {
			/* unable to hash key */
			free(txn_digest);
			return 0;
		}

		if (util_base64_encode(digest, digestlen, 
				&b64_encoding, NULL) != 1) {
			/* unable to base64 encode the key digest */
			free(txn_digest);
			free(digest);
			return 0;
		}
		
		if (strcmp(b64_encoding, ref_output->addr_id) == 0) {
			/* the specified address does not own the
			 * referenced money */
			free(b64_encoding);
			free(txn_digest);
			free(digest);
			return 0;
		}

		/* verify they own the key they claim to */
		if (util_verify(txn->inputs[i].owner_key,
				txn->signatures[i].signature,
				txn->signatures[i].len,
				txn_digest,
				txn_digestlen) != 1) {
			free(b64_encoding);
			free(txn_digest);
			free(digest);
			/* they don't */
			return 0;
			
		}
		free(b64_encoding);
		free(digest);

		if (blockchain_reference_exists(chain,
					txn->inputs[i].ref_txn_digest,
					txn->inputs[i].ref_digest_len,
					txn->inputs[i].ref_index) == 1) {
			/* attempted double spend */
			return 0;
		}

		input_amount += ref_output->amount;
	}
	free(txn_digest);

	/* no spending more than you have! */
	if (output_amount > input_amount) {
		return 0;
	}

	return is_valid;
}

