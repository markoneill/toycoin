#include <check.h>
#include "util.h"

START_TEST(util_base64_01) {
	unsigned char to_encode[] = "base64test";
	unsigned char encoded[] = "YmFzZTY0dGVzdA==";
	char encoded_test[MAX_ID_LEN];
	size_t len;
	util_base64_encode(to_encode, strlen(to_encode), &encoded_test, &len);
	fail_unless(strncmp(encoded, encoded_test, len) == 0, "base64 error");
}
END_TEST

Suite* util_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("util");
	tc = tcase_create("util_base64");
	tcase_add_test(tc, util_base64_01);
	suite_add_tcase(s, tc);

	return s;
}
