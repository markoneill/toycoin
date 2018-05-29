#include <check.h>
#include "wallet.h"

START_TEST(wallet_create_01) {
	wallet_t* wallet;
	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	wallet_free(wallet);	
}
END_TEST

START_TEST(wallet_create_02) {
	wallet_t* wallet;
	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	fail_unless(wallet_add_address(wallet) == 1, "wallet add addr");
	wallet_free(wallet);
}
END_TEST

START_TEST(wallet_create_03) {
	wallet_t* wallet;
	wallet = wallet_new();
	fail_unless(wallet != NULL, "null wallet");
	fail_unless(wallet_add_address(wallet) == 1, "wallet add addr");
	fail_unless(wallet_save(wallet, "test.wallet") == 1, "wallet save");
	wallet_free(wallet);
}
END_TEST

Suite* wallet_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("wallet");
	tc = tcase_create("wallet_create");
	tcase_add_test(tc, wallet_create_01);
	tcase_add_test(tc, wallet_create_02);
	tcase_add_test(tc, wallet_create_03);
	suite_add_tcase(s, tc);
	return s;
}
