#include <check.h>
#include "transaction.h"
#include "blockchain.h"
#include "address.h"
#include "util.h"

static void buildup(void);
static void teardown(void);

static blockchain_t* test_chain;
static address_t* addra;
static address_t* addrb;
static address_t* addrc;
static char* ida;
static char* idb;
static char* idc;
static unsigned char* digest;
static unsigned int digestlen;
static unsigned char* src_txn_digest;
static unsigned int src_txn_digestlen;


START_TEST(transaction_create_01) {
	transaction_t* txn;
	txn = transaction_new(1, 1);
	fail_unless(txn != NULL, "transaction null");
	transaction_free(txn);
}
END_TEST

START_TEST(transaction_serialize_01) {
	transaction_t* prev_txn;
	transaction_t* txn;
	transaction_t* txn_copy;
	address_t* prev_addr;
	address_t* addr;
	char* addr_id;
	char* prev_addr_id;
	unsigned char* digest;
	unsigned int digest_len;
	char* str;
	size_t str_len;
	char* str_copy;
	size_t str_copy_len;
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

	/* serialize new transaction */
	ret = transaction_serialize(txn, &str, &str_len, 1);
	fail_unless(ret == 1, "new transaction serialze failed");

	/* deserialize the transaction */
	txn_copy = transaction_deserialize(str, str_len);
	fail_unless(txn_copy != NULL, "deserialization failed");
	ret = transaction_serialize(txn_copy, &str_copy, &str_copy_len, 1);
	fail_unless(ret == 1, "serialization of copy failed");

	/* compare outputs */
	/*printf("%s\n", str);
	printf("%s\n", str_copy);
	prntf("%lu vs %lu\n", str_len, str_copy_len);*/
	fail_unless(str_copy_len == str_len, "serialization lengths do not match");
	ret = strncmp(str, str_copy, str_copy_len);
	/*printf("%s\n---------------------------\n%s", str, str_copy);*/
	fail_unless(ret == 0, "serializations do not match");

	transaction_free(prev_txn);
	transaction_free(txn);
	transaction_free(txn_copy);
	address_free(addr);
	address_free(prev_addr);
	free(digest);
	free(str);
	free(str_copy);
	free(addr_id);
	free(prev_addr_id);
}
END_TEST

void buildup(void) {
	int ret;
	unsigned char* prev_digest;
	unsigned int prev_digestlen;
	block_t* new_block;
	block_t* last_block;
	transaction_t* txn;

	addra = address_new();
	ida = address_get_id(addra);
	addrb = address_new();
	idb = address_get_id(addrb);
	addrc = address_new();
	idc = address_get_id(addrc);
	
	/* add a new block */
	test_chain = blockchain_new();
	last_block = blockchain_get_last_block(test_chain);
	block_hash(last_block, &prev_digest, &prev_digestlen);
	new_block = block_new(prev_digest, prev_digestlen);
	blockchain_add_block(test_chain, new_block);

	/* send money to A*/
	txn = transaction_new(0, 1);
	transaction_set_output(txn, 0, 1000, ida);
	transaction_finalize(txn);
	block_add_transaction(new_block, txn);
	transaction_hash(txn, &digest, &digestlen);
	transaction_hash(txn, &src_txn_digest, &src_txn_digestlen);
	
	/* add a new block */
	last_block = blockchain_get_last_block(test_chain);
	block_hash(last_block, &prev_digest, &prev_digestlen);
	new_block = block_new(prev_digest, prev_digestlen);
	blockchain_add_block(test_chain, new_block);

	/* use money from previous txn, split it, and send to
	 * B and C */
	txn = transaction_new(1, 2);
	transaction_set_input(txn, 0, digest, digestlen, 0, addra->keypair);
	transaction_set_output(txn, 0, 500, idb);
	transaction_set_output(txn, 1, 500, idc);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	fail_unless(ret == 1, "transaction should be valid");
	block_add_transaction(new_block, txn);
	free(digest);
	/* leave reference to old transaction in digest for tests */
	transaction_hash(txn, &digest, &digestlen);
}

void teardown(void) {
	blockchain_free(test_chain);
	address_free(addra);
	address_free(addrb);
	address_free(addrc);
	free(ida);
	free(idb);
	free(idc);
	free(src_txn_digest);
	free(digest);
}

START_TEST(transaction_validate_01) {
	int ret;
	transaction_t* txn;
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, src_txn_digest, src_txn_digestlen, 0, addra->keypair);
	transaction_set_output(txn, 0, 1000, idb);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	transaction_free(txn);
	fail_unless(ret != 1, "allowed double spending");
}
END_TEST

START_TEST(transaction_validate_02) {
	int ret;
	transaction_t* txn;
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, digest, digestlen, 1, addrc->keypair);
	transaction_set_output(txn, 0, 500, ida);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	transaction_free(txn);
	fail_unless(ret == 1, "transaction should be valid");
}
END_TEST

START_TEST(transaction_validate_03) {
	int ret;
	transaction_t* txn;
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, digest, digestlen, 1, addra->keypair);
	transaction_set_output(txn, 0, 500, ida);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	transaction_free(txn);
	fail_unless(ret != 1, "spent coins we don't own");
}
END_TEST

START_TEST(transaction_validate_04) {
	int ret;
	transaction_t* txn;
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, digest, digestlen, 1, addrc->keypair);
	transaction_set_output(txn, 0, 501, ida);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	transaction_free(txn);
	fail_unless(ret != 1, "spent more than owned");
}
END_TEST

START_TEST(transaction_validate_05) {
	int ret;
	transaction_t* txn;
	unsigned char fakedigest[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
					0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
					0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, fakedigest, sizeof(fakedigest), 1, addrc->keypair);
	transaction_set_output(txn, 0, 500, ida);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	transaction_free(txn);
	fail_unless(ret != 1, "allowed unknown coins to be spent");
}
END_TEST

START_TEST(transaction_validate_06) {
	int ret;
	transaction_t* txn;
	address_t* fakeaddress = address_new();
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, digest, digestlen, 1, addrc->keypair);
	transaction_set_output(txn, 0, 500, ida);
	txn->inputs[0].owner_key = fakeaddress->keypair;
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	txn->inputs[0].owner_key = addrc->keypair;
	transaction_free(txn);
	address_free(fakeaddress);
	fail_unless(ret != 1, "accepted fake signature");
}
END_TEST

Suite* transaction_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("transaction");
	tc = tcase_create("transaction_create");
	tcase_add_test(tc, transaction_create_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("transaction_serialize");
	tcase_add_test(tc, transaction_serialize_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("transaction_validate");
	tcase_add_checked_fixture(tc, buildup, teardown);
	tcase_add_test(tc, transaction_validate_01);
	tcase_add_test(tc, transaction_validate_02);
	tcase_add_test(tc, transaction_validate_03);
	tcase_add_test(tc, transaction_validate_04);
	tcase_add_test(tc, transaction_validate_05);
	tcase_add_test(tc, transaction_validate_06);
	suite_add_tcase(s, tc);
	return s;
}
