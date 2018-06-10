#include <check.h>
#include "transaction.h"
#include "address.h"
#include "util.h"

START_TEST(transaction_create_01) {
	transaction_t* txn;
	txn = transaction_new(1, 1);
	fail_unless(txn != NULL, "transaction null");
	transaction_free(txn);
}
END_TEST

START_TEST(transaction_serialize_01) {
	transaction_t* prev_txn;
	address_t* prev_addr;
	transaction_t* txn;
	address_t* addr;
	char addr_str[MAX_ID_LEN];
	char* str;
	unsigned char* digest;

	prev_addr = address_new();
	fail_unless(prev_addr != NULL, "prev address null");
	util_base64_encode(prev_addr->digest, prev_addr->digest_len,
		 addr_str, NULL);


	prev_txn = transaction_new(0, 1);
	fail_unless(prev_txn != NULL, " prev transaction null");
	fail_unless(transaction_set_output(prev_txn, 0, 25, addr_str),
		"set output failure on prev");
	fail_unless(transaction_finalize(prev_txn), "prev finalize failure");
	fail_unless(transaction_hash(prev_txn, &digest, NULL), "ugh");
	free(digest);


	addr = address_new();
	fail_unless(addr != NULL, "prev address null");
	txn = transaction_new(1, 1);
	fail_unless(txn != NULL, "transaction null");
	fail_unless(transaction_set_input(txn, 0, prev_txn, 0,
		prev_addr->keypair), "set input failure");
	util_base64_encode(addr->digest, addr->digest_len, 
		addr_str, NULL);
	fail_unless(transaction_set_output(txn, 0, 25, addr_str),
		"set output failure");
	fail_unless(transaction_finalize(txn), "finalize failure");
	transaction_serialize(txn, &str, NULL, 1);

	transaction_free(txn);
	transaction_free(prev_txn);
	address_free(addr);
	address_free(prev_addr);
	free(str);
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
	return s;
}