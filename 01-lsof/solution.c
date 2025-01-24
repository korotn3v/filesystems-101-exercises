#include "solution.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

static const char* PROC_PATH = "/proc/";
static const char* FD_PATH = "/fd/";

#define MAX_FILEPATH_LENGTH 4096 // In linux, the maximum path length is 255 bytes

void lsof(void) {
    DIR* proc_directory = opendir(PROC_PATH); // open proc_directory
    if (proc_directory == NULL) {
        report_error(PROC_PATH, errno);
        return;
    }

    char file_path[MAX_FILEPATH_LENGTH];
    char lsof_path[MAX_FILEPATH_LENGTH];

    struct dirent* proc_dirent;

    while ((proc_dirent = readdir(proc_directory)) != NULL) {

        char* p_end;
        strtol(proc_dirent->d_name, &p_end, 10); // Преобразуем имя директории в число pid = PID

        if (*p_end) {
            continue;
        }

        snprintf(file_path, MAX_FILEPATH_LENGTH, "%s%s%s", PROC_PATH, proc_dirent->d_name, FD_PATH); // file_path = /proc/PID/fd/

        DIR* files_directory = opendir(file_path); // open /proc/pid/fd/ directory
        if (files_directory == NULL) {
            report_error(file_path, errno);
            continue;
        }

        // берем указатель на начало file_path и сдвигаем на его длину
        char* ptr_on_end_file_path = file_path + (strlen(PROC_PATH) + strlen(proc_dirent->d_name) + strlen(FD_PATH)) * sizeof(char);
        struct dirent* files_dirent;

        while ((files_dirent = readdir(files_directory)) != NULL) {

            if (strcmp(files_dirent->d_name, ".") == 0 || strcmp(files_dirent->d_name, "..") == 0) // check that name is digit
            {
                continue;
            }

            // на место куда указывает ptr_on_end_file_path копируем имя files_dirent (то есть к file_path добавим имя files_dirent)
            strncpy(ptr_on_end_file_path, files_dirent->d_name, MAX_FILEPATH_LENGTH - (strlen(PROC_PATH) + strlen(proc_dirent->d_name) + strlen(FD_PATH)));
            int len_lsof;

            if ((len_lsof = readlink(file_path, lsof_path, MAX_FILEPATH_LENGTH)) == -1) // читаем ссылку по пути file_path в lsof_path
            {
                report_error(file_path, errno);
                continue;
            }

            lsof_path[len_lsof] = '\0';
            report_file(lsof_path);
        }
        closedir(files_directory);
    }
    closedir(proc_directory);
}