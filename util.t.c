#include <check.h>
#include "util.h"

START_TEST(util_base64_01) {
	const char to_encode[] = "base64test";
	char encoded[] = "YmFzZTY0dGVzdA==";
	char* encoded_test;
	size_t len;
	util_base64_encode((unsigned char*)to_encode, strlen(to_encode),
		 &encoded_test, &len);
	fail_unless(strncmp(encoded, encoded_test, len) == 0, "base64 error");
	free(encoded_test);
}
END_TEST

START_TEST(util_pubkey_01) {
	cryptokey_t* key;
	char* str;
	key = util_generate_key(2048);
	fail_unless(key, "null key");
	fail_unless(util_serialize_pubkey(key, &str, NULL), 
		"pubkey serial fail");
	free(str);
	util_free_key(key);
}
END_TEST

Suite* util_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("util");
	tc = tcase_create("util_base64");
	tcase_add_test(tc, util_base64_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("util_pubkey");
	tcase_add_test(tc, util_pubkey_01);
	suite_add_tcase(s, tc);
	return s;
}
