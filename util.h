#ifndef UTIL_H
#define UTIL_H

#include <openssl/evp.h> /* for EVP_MAX_MD_SIZE */

#define MAX_DIGEST_LEN	EVP_MAX_MD_SIZE

void util_init_crypto(void);
void util_deinit_crypto(void);
int util_digestlen(void);

#endif
