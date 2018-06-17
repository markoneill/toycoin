#include <stdlib.h> /* exit macros */

#include "log.h"
#include "node.h"
#include "util.h"

int main(int argc, char* argv[]) {
	/* Global setup */
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	util_init_crypto();

	node_start();

	util_deinit_crypto();
	log_close();
	return 0;
}

