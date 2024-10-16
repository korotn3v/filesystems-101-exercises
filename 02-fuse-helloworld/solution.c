#include <solution.h>

#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>

static void* hellofs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void) conn;
	(void) cfg;
	return NULL;
}

static int hellofs_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	fill(buf, ".", NULL, 0, 0);
	fill(buf, "..", NULL, 0, 0);
	fill(buf, "hello", NULL, 0, 0);
	return 0;
}

static int hellofs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	(void) fi;
	memset(stbuf, 0, sizeof(*stbuf));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH;
		stbuf->st_nlink = 2;
		return 0;
	}
	if (strcmp(path, "/hello") == 0) {
		stbuf->st_mode = S_IFREG | S_IRUSR;
		stbuf->st_nlink = 1;
		stbuf->st_size = 4096;
		return 0;
	}

	return -ENOENT;
}

static int hellofs_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/hello") != 0)
		return -ENOENT;
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EROFS;

	return 0;
}

static int hellofs_read(const char *path, char *out_buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	(void) fi;

	if (strcmp(path, "/hello") != 0)
		return -ENOENT;

	char buf[64];
	off_t len = snprintf(buf, sizeof(buf), "hello, %d\n", fuse_get_context()->pid);

	if (offset >= len)
		return 0;
	if (size > (size_t)(len - offset))
		size = len - offset;

	memcpy(out_buf, buf + offset, size);
	return size;
}

static const struct fuse_operations hellofs_ops = {
	.init = &hellofs_init,
	.readdir = &hellofs_readdir,
	.getattr = &hellofs_getattr,
	.open = &hellofs_open,
	.read = &hellofs_read,
};

int helloworld(const char *mntp)
{
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}
