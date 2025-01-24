#include "solution.h"
#include <stdio.h>
#include <string.h>

void report_process(pid_t pid, const char *exe, char **argv, char **envp) {
	printf("Process PID: %d\n", pid);
	printf("Executable: %s\n", exe);

	printf("Arguments:\n");
	for (char **arg = argv; *arg != NULL; ++arg) {
		printf("  %s\n", *arg);
	}

	printf("Environment Variables:\n");
	for (char **env = envp; *env != NULL; ++env) {
		printf("  %s\n", *env);
	}
	printf("\n");
}

void report_error(const char *path, int errno_code) {
	fprintf(stderr, "Error accessing: %s, errno: %d (%s)\n", path, errno_code, strerror(errno_code));
}

int main() {
	printf("Listing all running processes:\n\n");
	ps();
	return 0;
}
