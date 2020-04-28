
#include <r_anal.h>

#include "minunit.h"

bool test_meta_rebase() {
	RAnal *anal = r_anal_new ();

	r_meta_rebase (anal, 0x100);
	mu_assert ("TODO: add some tests here", false);

	r_anal_free (anal);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_meta_rebase);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
