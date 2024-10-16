#include <solution.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <err.h>

static void* test_thread_fn(void *arg);

static char mntp[128];

int main(int argc, char **argv)
{
	if (argc != 3 || strcmp(argv[1], "test") != 0)
		errx(1, "invalid invocation");

	long long int rnd = 0;
	getrandom(&rnd, sizeof(rnd), GRND_NONBLOCK);
	snprintf(mntp, sizeof(mntp), "/tmp/fs101ex-%016llx", rnd);

	if (mkdir(mntp, 0777) != 0)
		errx(1, "mkdir() failed");

	pthread_t test_thread;
	pthread_create(&test_thread, NULL, test_thread_fn, argv[2]);

	(void) helloworld(mntp);
	pthread_join(test_thread, NULL);
	return 0;
}

static void* test_thread_fn(void *arg)
{
	const char *test_name = arg;

	// give FUSE some time to mount
	struct timespec delay = {.tv_sec = 0, .tv_nsec = 20*1000*1000};
	nanosleep(&delay, NULL);

	if (strcmp(test_name, "00-ls") == 0) {
		DIR *d = opendir(mntp);
		if (d == NULL)
			errx(2, "opendir() failed");

		struct dirent *e;

		e = readdir(d);
		if (e == NULL || strcmp(e->d_name, ".") != 0)
			errx(2, "'.' not listed");

		e = readdir(d);
		if (e == NULL || strcmp(e->d_name, "..") != 0)
			errx(2, "'..' not listed");

		e = readdir(d);
		if (e == NULL || strcmp(e->d_name, "hello") != 0)
			errx(2, "'hello' not listed");

		e = readdir(d);
		if (e != NULL)
			errx(2, "too many entries listed");

		closedir(d);
	} else if (strcmp(test_name, "01-read") == 0) {
		char path[256];
		snprintf(path, sizeof(path), "%s/hello", mntp);

		int fd = open(path, O_RDONLY);
		if (fd < 0)
			errx(2, "open(hello) failed");

		char buf[4096];
		int n = read(fd, buf, sizeof(buf));
		if (n < 0)
			errx(2, "read(hello) failed");

		close(fd);
	} else if (strcmp(test_name, "02-read-pid") == 0) {
		pid_t child_pid = fork();
		if (child_pid < 0) {
			errx(1, "fork() failed");
		} else if (child_pid == 0) {
			char path[256];
			snprintf(path, sizeof(path), "%s/hello", mntp);

			int fd = open(path, O_RDONLY);
			if (fd < 0)
				errx(2, "open(hello) failed");

			char buf[4096];
			int n = read(fd, buf, sizeof(buf));
			if (n < 0)
				errx(2, "read(hello) failed");

			close(fd);

			char expected[128];
			int m = snprintf(expected, sizeof(expected), "hello, %ld\n", (long int)getpid());

			if (n != m || memcmp(buf, expected, m) != 0)
				errx(2, "'hello' does not include the pid of the accessor");

			_exit(0);
		} else {
			int wstatus;
			pid_t r = waitpid(child_pid, &wstatus, 0);
			if (r != child_pid)
				errx(1, "waitpid() failed");
			if (!WIFEXITED(wstatus))
				errx(1, "child read() failed");
			exit(WEXITSTATUS(wstatus));
		}
	} else if (strcmp(test_name, "03-erofs") == 0) {
		char path[256];
		snprintf(path, sizeof(path), "%s/hello", mntp);

		int fd = open(path, O_WRONLY);
		if (fd >= 0 || errno != EROFS)
			errx(2, "erofs was not reported");
	} else {
		errx(1, "invalid invocation");
	}

	kill(getpid(), SIGINT);
	return NULL;
}
