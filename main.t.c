#include <stdlib.h>
#include <check.h>

#include "log.h"
#include "util.h"
#include "transaction.h"
#include "block.h"
#include "blockchain.h"

Suite* empty_suite(void);
Suite* wallet_suite(void);
Suite* address_suite(void);
Suite* util_suite(void);
Suite* transaction_suite(void);

Suite* empty_suite(void) {
	Suite* s;
	s = suite_create("");
	return s;
}

int main(int argc, char* argv[]) {
	int num_fails;
	SRunner* sr;

	/* Global setup */
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	util_init_crypto();

	/* Tests */
	sr = srunner_create(empty_suite());
	srunner_add_suite(sr, util_suite());
	srunner_add_suite(sr, address_suite());
	srunner_add_suite(sr, transaction_suite());
	srunner_add_suite(sr, wallet_suite());
	srunner_run_all(sr, CK_NORMAL);
	num_fails = srunner_ntests_failed(sr);
	srunner_free(sr);

	util_deinit_crypto();
	log_close();
	if (num_fails != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

