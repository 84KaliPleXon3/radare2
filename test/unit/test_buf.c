#include <r_util.h>
#include <r_io.h>
#include <stdlib.h>
#include "minunit.h"

bool test_buf(RBuffer *b) {
	ut8 buffer[1024] = { 0 };

	ut64 buf_sz;

	const char *s = "This is a new content";
	const size_t sl = strlen (s);
	bool res = r_buf_set_bytes (b, (ut8 *)s, sl);
	mu_assert ("New content should be written", res);

	res = r_buf_resize (b, 10);
	mu_assert ("file should be resized", res);
	buf_sz = r_buf_size (b);
	mu_assert_eq (buf_sz, 10, "file size should be 10");

	const int rl = r_buf_read_at (b, 1, buffer, sizeof (buffer));
	mu_assert_eq (rl, 9, "only 9 bytes can be read from offset 1");
	mu_assert_memeq (buffer, (ut8 *)"his is a ", 9, "read right bytes from offset 1");

	return MU_PASSED;
}

bool test_r_buf_io(void) {
	RBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	RIO *io = r_io_new ();
	RIODesc *desc = r_io_open_at (io, "file:///tmp/r-buf-io.test", R_PERM_RW | R_PERM_CREAT, 0644, 0);
	mu_assert_notnull (desc, "file should be opened for writing");

	bool res = r_io_write_at (io, 0, (ut8 *)content, length);
	mu_assert ("initial content should be written", res);

	RIOBind bnd;
	r_io_bind (io, &bnd);

	b = r_buf_new_with_io(&bnd, desc->fd);
	mu_assert_notnull (b, "r_buf_new_file failed");

	if (test_buf (b) != MU_PASSED) {
		mu_fail ("test failed");
	}

	// Cleanup
	r_buf_free (b);
	r_io_close (io);
	r_io_free (io);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_buf_io);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
