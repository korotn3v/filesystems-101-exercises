#include "solution.h"
#include <stdio.h>
#include <string.h>

void report_file(const char *path) {
	printf("File: %s\n", path); // Выводим путь к файлу
}

void report_error(const char *path, int errno_code) {
	fprintf(stderr, "Error accessing %s: %s\n", path, strerror(errno_code)); // Выводим сообщение об ошибке
}

int main(int argc, char **argv) {
	(void) argc;
	(void) argv;

	lsof(); // Вызываем функцию lsof
	return 0;
}
