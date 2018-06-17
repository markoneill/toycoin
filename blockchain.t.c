#include <check.h>
#include <unistd.h>
#include "block.h"
#include "blockchain.h"

int files_equal(char* path_a, char* path_b);

START_TEST(blockchain_serialize_01) {
	block_t* new_block;
	blockchain_t* chain;
	blockchain_t* chain_copy;
	unsigned int digest_len;
	unsigned char* digest;
	int ret;

	/* create sample chain */
	chain = blockchain_create();
	fail_unless(chain != NULL, "chain create failed");
	ret = block_hash(chain->tail, &digest, &digest_len);
	fail_unless(ret == 1, "block hash failed");
	new_block = block_new(digest, digest_len);
	fail_unless(new_block != NULL, "new block create failed");
	ret = blockchain_add_block(chain, new_block);
	fail_unless(ret == 1, "block add failed");
	ret = block_hash(new_block, &digest, &digest_len);
	fail_unless(ret == 1, "block hash failed");
	new_block = block_new(digest, digest_len);
	fail_unless(new_block != NULL, "new block create failed");
	ret = blockchain_add_block(chain, new_block);
	fail_unless(ret == 1, "block add failed");

	/* save chain */
	ret = blockchain_save(chain, "test.chain");
	fail_unless(ret == 1, "chain save failed");

	/* load chain */
	chain_copy = blockchain_load("test.chain");
	fail_unless(chain_copy != NULL, "chain load failed");

	/* compare chains */
	ret = blockchain_save(chain_copy, "test2.chain");
	fail_unless(ret == 1, "chain save failed");
	ret = files_equal("test.chain", "test2.chain");
	fail_unless(ret == 1, "chains unequal");

	unlink("test.chain");
	unlink("test2.chain");
	blockchain_free(chain);
	blockchain_free(chain_copy);
	return;
}
END_TEST

Suite* blockchain_suite(void) {
	Suite* s;
	TCase* tc;

	s = suite_create("blockchain");
	tc = tcase_create("blockchain_serialize");
	tcase_add_test(tc, blockchain_serialize_01);
	suite_add_tcase(s, tc);
	return s;
}

int files_equal(char* path_a, char* path_b) {
	int equal;
	FILE* a;
	FILE* b;
	long size_a;
	long size_b;
	char* data_a;
	char* data_b;

	equal = 1;

	a = fopen(path_a, "r");
	b = fopen(path_b, "r");

	fseek(a, 0, SEEK_END);
	size_a = ftell(a);
	fseek(a, 0, SEEK_SET);
	fseek(b, 0, SEEK_END);
	size_b = ftell(b);
	fseek(b, 0, SEEK_SET);


	data_a = (char*)malloc(size_a);
	data_b = (char*)malloc(size_b);

	fread(data_a, size_a, 1, a);
	fread(data_b, size_b, 1, b);

	if (size_a != size_b || strncmp(data_a, data_b, size_a) != 0) {
		equal = 0;
	}

	free(data_a);
	free(data_b);

	fclose(a);
	fclose(b);
	return equal;
}

