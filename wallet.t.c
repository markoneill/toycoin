#include <check.h>
#include "wallet.h"

START_TEST(address_create_01) {
	fail_unless(1 == 1, "test test");
}
END_TEST

Suite* wallet_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("wallet");
	tc = tcase_create("address_create");
	tcase_add_test(tc, address_create_01);
	suite_add_tcase(s, tc);
	return s;
}
