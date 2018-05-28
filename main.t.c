#include <openssl/evp.h>
#include <stdlib.h>
#include <check.h>

#include "log.h"
#include "transaction.h"
#include "block.h"
#include "blockchain.h"

const EVP_MD* hash_alg;

Suite* empty_suite(void);
Suite* wallet_suite(void);
Suite* transaction_suite(void);
Suite* chain_suite(void);

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
	OpenSSL_add_all_digests();
	hash_alg = EVP_sha256();

	/* Tests */
	sr = srunner_create(empty_suite());
	srunner_add_suite(sr, wallet_suite());
	srunner_run_all(sr, CK_NORMAL);
	num_fails = srunner_ntests_failed(sr);

	EVP_cleanup();
	log_close();
	if (num_fails != 0) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

