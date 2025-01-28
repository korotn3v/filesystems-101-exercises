#include "solution.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILEPATH_LENGTH 4096

void abspath(const char *path) {
    char realPath[MAX_FILEPATH_LENGTH] = "/";
    char remainingPath[MAX_FILEPATH_LENGTH];
    char componentPath[MAX_FILEPATH_LENGTH];

    // Обработка начального пути
    if (path[0] == '/') {
        strncpy(remainingPath, path + 1, MAX_FILEPATH_LENGTH - 1);
    } else {
        strncpy(remainingPath, path, MAX_FILEPATH_LENGTH - 1);
    }
    remainingPath[MAX_FILEPATH_LENGTH - 1] = '\0';

    char *start = remainingPath;
    char *end;

    // Если путь пустой или "/"
    if (strlen(remainingPath) == 0) {
        report_path("/");
        return;
    }

    while ((end = strchr(start, '/')) != NULL || *start) {
        size_t len;
        if (end) {
            len = end - start;
            strncpy(componentPath, start, len);
            componentPath[len] = '\0';
            start = end + 1;
        } else {
            len = strlen(start);
            strncpy(componentPath, start, len);
            componentPath[len] = '\0';
            start += len;
        }

        if (len == 0 || strcmp(componentPath, ".") == 0) {
            continue;
        }

        if (strcmp(componentPath, "..") == 0) {
            char *lastSlash = strrchr(realPath, '/');
            if (lastSlash != realPath) {
                *lastSlash = '\0';
                lastSlash = strrchr(realPath, '/');
                if (lastSlash) *(lastSlash + 1) = '\0';
            }
            continue;
        }

        char testPath[MAX_FILEPATH_LENGTH];
        size_t realPathLen = strlen(realPath);
        size_t componentPathLen = strlen(componentPath);

        if (realPathLen + componentPathLen + 1 >= MAX_FILEPATH_LENGTH) {
            report_error("/", componentPath, ENAMETOOLONG);
            return;
        }

        strcpy(testPath, realPath);
        strcat(testPath, componentPath);

        struct stat sb;
        if (lstat(testPath, &sb) == -1) {
            report_error("/", componentPath, ENOENT);
            return;
        }

        if (S_ISLNK(sb.st_mode)) {
            char linkPath[MAX_FILEPATH_LENGTH];
            ssize_t linkLen = readlink(testPath, linkPath, MAX_FILEPATH_LENGTH - 1);
            if (linkLen == -1) {
                report_error(realPath, componentPath, errno);
                return;
            }
            linkPath[linkLen] = '\0';

            if (linkPath[0] == '/') {
                if (strlen(linkPath) >= MAX_FILEPATH_LENGTH) {
                    report_error("/", componentPath, ENAMETOOLONG);
                    return;
                }
                strcpy(realPath, linkPath);
            } else {
                if (realPathLen + strlen(linkPath) + 1 >= MAX_FILEPATH_LENGTH) {
                    report_error("/", componentPath, ENAMETOOLONG);
                    return;
                }
                strcat(realPath, linkPath);
            }
        } else {
            if (realPathLen + componentPathLen + 2 >= MAX_FILEPATH_LENGTH) {
                report_error("/", componentPath, ENAMETOOLONG);
                return;
            }
            strcat(realPath, componentPath);
            if (*start) strcat(realPath, "/");
        }
    }

    // Проверка на директорию
    struct stat final_stat;
    if (stat(realPath, &final_stat) == 0 && S_ISDIR(final_stat.st_mode)) {
        if (realPath[strlen(realPath) - 1] != '/') {
            if (strlen(realPath) + 1 >= MAX_FILEPATH_LENGTH) {
                report_error("/", realPath, ENAMETOOLONG);
                return;
            }
            strcat(realPath, "/");
        }
    }

    report_path(realPath);
}