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
	transaction_t* txn;
	transaction_t* txn_copy;
	address_t* prev_addr;
	address_t* addr;
	char addr_str[MAX_ID_LEN];
	unsigned char* digest;
	unsigned int digest_len;
	char* str;
	size_t str_len;
	char* str_copy;
	size_t str_copy_len;
	int ret;

	/* create dummy address */
	prev_addr = address_new();
	util_base64_encode(prev_addr->digest, prev_addr->digest_len, addr_str, NULL);

	/* create dummy transaction */
	prev_txn = transaction_new(0, 1);
	fail_unless(prev_txn != NULL, "prev transaction create failed");
	ret = transaction_set_output(prev_txn, 0, 25, addr_str, strlen(addr_str));
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
	util_base64_encode(addr->digest, addr->digest_len, addr_str, NULL);
	ret = transaction_set_output(txn, 0, 25, addr_str, strlen(addr_str));
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
	fail_unless(str_copy_len == str_len, "serialization lengths do not match");
	ret = strncmp(str, str_copy, str_copy_len);
	printf("%s\n---------------------------\n%s", str, str_copy);
	fail_unless(ret == 0, "serializations do not match");

	transaction_free(prev_txn);
	transaction_free(txn);
	transaction_free(txn_copy);
	address_free(addr);
	address_free(prev_addr);
	free(digest);
	free(str);
	free(str_copy);
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
