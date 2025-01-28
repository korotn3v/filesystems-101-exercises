#include "solution.h"

#include <stdio.h>
#include <string.h>

void report_path(const char *path)
{
	printf("%s\n", path);
}

void report_error(const char *parent, const char *child, int errno_code)
{
	printf("error at %s, child %s: %i (%s)\n",
	       parent, child,
	       errno_code, strerror(errno_code));
}
