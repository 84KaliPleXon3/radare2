
#include <r_anal.h>

#include "minunit.h"

bool test_meta_set() {
	RAnal *anal = r_anal_new ();

	r_meta_set (anal, R_META_TYPE_DATA, 0x100, 4, NULL);
	r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x100, "summer of love");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	bool found[3] = { 0 };
	size_t count = 0;
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&anal->meta, it, item) {
		count++;
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		switch (item->type) {
		case R_META_TYPE_DATA:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x103, "node end (inclusive)");
			mu_assert_null (item->str, "no string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case R_META_TYPE_COMMENT:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x100, "node end (inclusive)");
			mu_assert_streq (item->str, "summer of love", "comment string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case R_META_TYPE_STRING:
			mu_assert_eq (node->start, 0x200, "node start");
			mu_assert_eq (node->end, 0x22f, "node end (inclusive)");
			mu_assert_streq (item->str, "true confessions", "string string");
			mu_assert_eq (item->subtype, R_STRING_ENC_UTF8, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq (count, 3, "set count");
	mu_assert ("meta 0", found[0]);
	mu_assert ("meta 1", found[1]);
	mu_assert ("meta 2", found[2]);

	// Override an item, changing only its size
	r_meta_set (anal, R_META_TYPE_DATA, 0x100, 8, NULL);

	count = 0;
	r_interval_tree_foreach (&anal->meta, it, item) {
		count++;
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		switch (item->type) {
		case R_META_TYPE_DATA:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x107, "node end (inclusive)");
			mu_assert_null (item->str, "no string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case R_META_TYPE_COMMENT:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x100, "node end (inclusive)");
			mu_assert_streq (item->str, "summer of love", "comment string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case R_META_TYPE_STRING:
			mu_assert_eq (node->start, 0x200, "node start");
			mu_assert_eq (node->end, 0x22f, "node end (inclusive)");
			mu_assert_streq (item->str, "true confessions", "string string");
			mu_assert_eq (item->subtype, R_STRING_ENC_UTF8, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq (count, 3, "set count");
	mu_assert ("meta 0", found[0]);
	mu_assert ("meta 1", found[1]);
	mu_assert ("meta 2", found[2]);

	// Override items, changing their contents
	r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x100, "this ain't the summer of love");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF16LE, 0x200, 0x40, "e.t.i. (extra terrestrial intelligence)");

	count = 0;
	r_interval_tree_foreach (&anal->meta, it, item) {
		count++;
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		switch (item->type) {
		case R_META_TYPE_DATA:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x107, "node end (inclusive)");
			mu_assert_null (item->str, "no string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[0] = true;
			break;
		case R_META_TYPE_COMMENT:
			mu_assert_eq (node->start, 0x100, "node start");
			mu_assert_eq (node->end, 0x100, "node end (inclusive)");
			mu_assert_streq (item->str, "this ain't the summer of love", "comment string");
			mu_assert_eq (item->subtype, 0, "no subtype");
			found[1] = true;
			break;
		case R_META_TYPE_STRING:
			mu_assert_eq (node->start, 0x200, "node start");
			mu_assert_eq (node->end, 0x23f, "node end (inclusive)");
			mu_assert_streq (item->str, "e.t.i. (extra terrestrial intelligence)", "string string");
			mu_assert_eq (item->subtype, R_STRING_ENC_UTF16LE, "subtype");
			found[2] = true;
			break;
		default:
			break;
		}
	}
	mu_assert_eq (count, 3, "set count");
	mu_assert ("meta 0", found[0]);
	mu_assert ("meta 1", found[1]);
	mu_assert ("meta 2", found[2]);

	r_anal_free (anal);
	mu_end;
}

bool test_meta_get() {
	RAnal *anal = r_anal_new ();

	r_meta_set (anal, R_META_TYPE_DATA, 0x100, 4, NULL);
	r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x100, "vera gemini");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF8, 0x200, 0x30, "true confessions");

	// TODO: finish this stuff

	r_anal_free (anal);
	mu_end;
}

bool test_meta_rebase() {
	RAnal *anal = r_anal_new ();

	r_meta_rebase (anal, -0x100);
	mu_assert ("TODO: add some tests here", false);

	r_anal_free (anal);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_meta_set);
	mu_run_test(test_meta_get);
	mu_run_test(test_meta_rebase);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
