#include <check.h>
#include "block.h"
#include "transaction.h"
#include "address.h"

unsigned char* dummy_mem(int size) {
	return calloc(1, size);
}

START_TEST(block_create_01) {
	block_t* block;
	block_t* new_block;
	transaction_t* prev_txn;
	transaction_t* txn;
	address_t* prev_addr;
	address_t* addr;
	char* prev_addr_id;
	char* addr_id;
	unsigned char* digest;
	unsigned int digest_len;
	int ret;

	/* create dummy address */
	prev_addr = address_new();
	prev_addr_id = address_get_id(prev_addr);
	fail_unless(prev_addr_id != NULL, "prev addr get id failed");

	/* create dummy transaction */
	prev_txn = transaction_new(0, 1);
	fail_unless(prev_txn != NULL, "prev transaction create failed");
	ret = transaction_set_output(prev_txn, 0, 25, prev_addr_id);
	fail_unless(ret == 1, "prev transaction set output failed");
	ret = transaction_finalize(prev_txn);
	fail_unless(ret == 1, "prev transaction finalize failed");

	/* create new transaction */
	addr = address_new();
	txn = transaction_new(1, 1);
	fail_unless(txn != NULL, "new transaction create failed");
	ret = transaction_hash(prev_txn, &digest, &digest_len);
	fail_unless(ret == 1, "hashing previous transaction failed");
	ret = transaction_set_input(txn, 0, digest, digest_len, 0, prev_addr->keypair);
	fail_unless(ret == 1, "new transaction set input failed");
	addr_id = address_get_id(addr);
	fail_unless(addr_id != NULL, "addr get id failed");
	ret = transaction_set_output(txn, 0, 25, addr_id);
	fail_unless(ret == 1, "new transaction set output failed");
	ret = transaction_finalize(txn);
	fail_unless(ret == 1, "new transaction finalize failed");
	free(digest);

	/* create block */
	block = block_new_genesis();
	fail_unless(block != NULL, "create genesis block failed");
	block_hash(block, &digest, (unsigned int*)&digest_len);
	new_block = block_new(digest, digest_len);
	block_set_target(new_block, dummy_mem(32), 32);
	fail_unless(new_block != NULL, "create new block failed");
	ret = block_add_transaction(new_block, prev_txn);
	fail_unless(ret == 1, "add transaction 1 failed");
	ret = block_add_transaction(new_block, txn);
	fail_unless(ret == 1, "add transaction 2 failed");

	block_free(block);
	block_free(new_block);
	address_free(addr);
	address_free(prev_addr);
	free(prev_addr_id);
	free(addr_id);
}
END_TEST

START_TEST(block_serialize_01) {
	block_t* block;
	block_t* new_block;
	block_t* block_copy;
	transaction_t* prev_txn;
	transaction_t* txn;
	address_t* prev_addr;
	address_t* addr;
	char* prev_addr_id;
	char* addr_id;
	unsigned char* digest;
	unsigned int digest_len;
	int ret;

	char* serialized_block;
	size_t serial_len;
	char* serialized_block_copy;
	size_t serial_len_copy;

	/* create dummy address */
	prev_addr = address_new();
	prev_addr_id = address_get_id(prev_addr);
	fail_unless(prev_addr_id != NULL, "prev addr get id failed");

	/* create dummy transaction */
	prev_txn = transaction_new(0, 1);
	fail_unless(prev_txn != NULL, "prev transaction create failed");
	ret = transaction_set_output(prev_txn, 0, 25, prev_addr_id);
	fail_unless(ret == 1, "prev transaction set output failed");
	ret = transaction_finalize(prev_txn);
	fail_unless(ret == 1, "prev transaction finalize failed");

	/* create new transaction */
	addr = address_new();
	txn = transaction_new(1, 1);
	fail_unless(txn != NULL, "new transaction create failed");
	ret = transaction_hash(prev_txn, &digest, &digest_len);
	fail_unless(ret == 1, "hashing previous transaction failed");
	ret = transaction_set_input(txn, 0, digest, digest_len, 0, prev_addr->keypair);
	fail_unless(ret == 1, "new transaction set input failed");
	addr_id = address_get_id(addr);
	fail_unless(addr_id != NULL, "addr get id failed");
	ret = transaction_set_output(txn, 0, 25, addr_id);
	fail_unless(ret == 1, "new transaction set output failed");
	ret = transaction_finalize(txn);
	fail_unless(ret == 1, "new transaction finalize failed");
	free(digest);

	/* create block */
	block = block_new_genesis();
	fail_unless(block != NULL, "create genesis block failed");
	block_hash(block, &digest, (unsigned int*)&digest_len);
	new_block = block_new(digest, digest_len);
	block_set_target(new_block, dummy_mem(32), 32);
	fail_unless(new_block != NULL, "create new block failed");
	ret = block_add_transaction(new_block, prev_txn);
	fail_unless(ret == 1, "add transaction 1 failed");
	ret = block_add_transaction(new_block, txn);
	fail_unless(ret == 1, "add transaction 2 failed");

	/* serialize block */
	ret = block_serialize(new_block, &serialized_block, &serial_len);
	fail_unless(ret == 1, "block serialize failed");

	/* deserialize block */
	block_copy = block_deserialize(serialized_block, serial_len);
	fail_unless(block_copy != NULL, "block deserialize failed");

	/* compare */
	ret = block_serialize(block_copy, &serialized_block_copy, &serial_len_copy);
	fail_unless(ret == 1, "copy serialization failed");
	fail_unless(serial_len == serial_len_copy, "serial lengths are not equal");
	ret = strncmp(serialized_block, serialized_block_copy, serial_len);
	fail_unless(ret == 0, "blocks do not match");

	block_free(block);
	block_free(new_block);
	block_free(block_copy);
	free(serialized_block);
	free(serialized_block_copy);
	address_free(addr);
	address_free(prev_addr);
	free(prev_addr_id);
	free(addr_id);
}
END_TEST

Suite* block_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("block");
	tc = tcase_create("block_create");
	tcase_add_test(tc, block_create_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("block_serialize");
	tcase_add_test(tc, block_serialize_01);
	suite_add_tcase(s, tc);
	return s;
}
