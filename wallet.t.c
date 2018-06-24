#include <check.h>
#include <unistd.h>
#include "wallet.h"
#include "blockchain.h"
#include "transaction.h"
#include "address.h"

START_TEST(wallet_create_01) {
	wallet_t* wallet;
	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	wallet_free(wallet);	
}
END_TEST

START_TEST(wallet_create_02) {
	int ret;
	wallet_t* wallet;
	address_t* addra;
	address_t* addrb;
	address_t* addrc;

	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	addra = address_new();
	addrb = address_new();
	addrc = address_new();

	ret = wallet_add_address(wallet, addra);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrb);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrc);
	fail_unless(ret == 1, "failed to add address");
	wallet_free(wallet);
}
END_TEST

START_TEST(wallet_io_01) {
	int ret;
	wallet_t* wallet;
	address_t* addra;
	address_t* addrb;
	address_t* addrc;

	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	addra = address_new();
	addrb = address_new();
	addrc = address_new();

	ret = wallet_add_address(wallet, addra);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrb);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrc);
	fail_unless(ret == 1, "failed to add address");

	ret = wallet_save(wallet, "test.wallet");
	fail_unless(ret == 1, "failed wallet save");
	wallet_free(wallet);
}
END_TEST

START_TEST(wallet_io_02) {
	int ret;
	wallet_t* wallet;
	wallet_t* ref_wallet;
	address_t* addra;
	address_t* addrb;
	address_t* addrc;

	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	addra = address_new();
	addrb = address_new();
	addrc = address_new();

	ret = wallet_add_address(wallet, addra);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrb);
	fail_unless(ret == 1, "failed to add address");
	ret = wallet_add_address(wallet, addrc);
	fail_unless(ret == 1, "failed to add address");

	ret = wallet_save(wallet, "test.wallet");
	fail_unless(ret == 1, "failed wallet save");

	ref_wallet = wallet_load("test.wallet");
	fail_unless(ref_wallet != NULL, "failed load wallet");
	ret = wallet_save(wallet, "test2.wallet");
	fail_unless(ret == 1, "failed wallet save");
	
	wallet_free(wallet);
	wallet_free(ref_wallet);
}
END_TEST

START_TEST(wallet_sync_01) {
	blockchain_t* test_chain;
	wallet_t* wallet;
	address_t* addra;
	address_t* addrb;
	address_t* addrc;
	char* ida;
	char* idb;
	char* idc;
	unsigned char* digest;
	unsigned int digestlen;
	int ret;
	unsigned char* prev_digest;
	unsigned int prev_digestlen;
	block_t* new_block;
	block_t* last_block;
	transaction_t* txn;

	addra = address_new();
	addrb = address_new();
	addrc = address_new();
	ida = address_get_id(addra);
	idb = address_get_id(addrb);
	idc = address_get_id(addrc);

	wallet = wallet_new();

	wallet_add_address(wallet, addrc);
	wallet_add_address(wallet, addrb);
	
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
	
	/* add a new block */
	last_block = blockchain_get_last_block(test_chain);
	block_hash(last_block, &prev_digest, &prev_digestlen);
	new_block = block_new(prev_digest, prev_digestlen);
	blockchain_add_block(test_chain, new_block);

	ret = wallet_sync(wallet, test_chain);
	fail_unless(ret == 0, "unexpected funds in wallet");

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
	transaction_hash(txn, &digest, &digestlen);

	/* check money */
	ret = wallet_sync(wallet, test_chain);
	fail_unless(ret == 1000, "lost money from wallet");

	last_block = blockchain_get_last_block(test_chain);
	block_hash(last_block, &prev_digest, &prev_digestlen);
	new_block = block_new(prev_digest, prev_digestlen);
	blockchain_add_block(test_chain, new_block);

	/* spend some of it */
	txn = transaction_new(1, 1);
	transaction_set_input(txn, 0, digest, digestlen, 0, addrb->keypair);
	transaction_set_output(txn, 0, 500, ida);
	transaction_finalize(txn);
	ret = transaction_is_valid(txn, test_chain);
	fail_unless(ret == 1, "transaction should be valid");
	block_add_transaction(new_block, txn);

	/* check balance again */		
	ret = wallet_sync(wallet, test_chain);
	fail_unless(ret == 500, "kept money from wallet");

	free(digest);
	address_free(addra);
	free(ida);
	free(idb);
	free(idc);
	wallet_free(wallet);
	blockchain_free(test_chain);
}
END_TEST

void teardown(void) {
	unlink("test.wallet");
	unlink("test2.wallet");
}

Suite* wallet_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("wallet");
	tc = tcase_create("wallet_create");
	tcase_add_test(tc, wallet_create_01);
	tcase_add_test(tc, wallet_create_02);
	suite_add_tcase(s, tc);

	tc = tcase_create("wallet_io");
	tcase_add_checked_fixture(tc, NULL, teardown);
	tcase_add_test(tc, wallet_io_01);
	tcase_add_test(tc, wallet_io_02);
	suite_add_tcase(s, tc);

	tc = tcase_create("wallet_sync");
	tcase_add_test(tc, wallet_sync_01);
	suite_add_tcase(s, tc);
	return s;
}
