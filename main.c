#include <stdlib.h>

#include "log.h"
#include "util.h"
#include "transaction.h"
#include "block.h"
#include "blockchain.h"
#include "wallet.h"

int main(int argc, char* argv[]) {
	/* Global setup */
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	util_init_crypto();


	util_deinit_crypto();
	log_close();
	return 0;
}

