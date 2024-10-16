#include <solution.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fs_malloc.h>
#include <errno.h>

int copy(int in, int out)
{
	struct stat st_in, st_out;
	int r;

	if ((r = fstat(in, &st_in)) ||
	    (r = fstat(out, &st_out)))
	{
		return -errno;
	}

	size_t len = st_in.st_size;
	void *buf = fs_xmalloc(len);
	r = pread(in, buf, len, 0);
	if (r < 0) {
		r = -errno;
		goto out;
	}
	if ((size_t)r != len) {
		r = -EAGAIN;
		goto out;
	}

	r = write(out, buf, len);
	if (r < 0) {
		r = -errno;
		goto out;
	}
	if ((size_t)r != len) {
		r = -EAGAIN;
		goto out;
	}

	r = 0;
out:
	fs_xfree(buf);
	return r;
}
