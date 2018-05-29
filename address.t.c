#include <check.h>
#include "address.h"

START_TEST(address_create_01) {
	address_t* address;
	address = address_new();
	fail_unless(address != NULL, "null address");
	address_free(address);	
}
END_TEST

Suite* address_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("address");
	tc = tcase_create("address_create");
	tcase_add_test(tc, address_create_01);
	suite_add_tcase(s, tc);
	return s;
}
