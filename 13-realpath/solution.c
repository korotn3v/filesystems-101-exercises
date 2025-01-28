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
    size_t pathLen = strlen(path);
    if (pathLen >= MAX_FILEPATH_LENGTH) {
        report_error("/", path, ENAMETOOLONG);
        return;
    }

    if (path[0] == '/') {
        memcpy(remainingPath, path + 1, pathLen);
    } else {
        memcpy(remainingPath, path, pathLen + 1);
    }

    char *start = remainingPath;
    char *end;

    // Если путь пустой или "/"
    if (!*start) {
        report_path("/");
        return;
    }

    while ((end = strchr(start, '/')) != NULL || *start) {
        size_t len;
        if (end) {
            len = end - start;
            if (len >= MAX_FILEPATH_LENGTH) {
                report_error("/", start, ENAMETOOLONG);
                return;
            }
            memcpy(componentPath, start, len);
            componentPath[len] = '\0';
            start = end + 1;
        } else {
            len = strlen(start);
            if (len >= MAX_FILEPATH_LENGTH) {
                report_error("/", start, ENAMETOOLONG);
                return;
            }
            memcpy(componentPath, start, len + 1);
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
        size_t realLen = strlen(realPath);
        size_t compLen = strlen(componentPath);

        if (realLen + compLen >= MAX_FILEPATH_LENGTH) {
            report_error("/", componentPath, ENAMETOOLONG);
            return;
        }

        memcpy(testPath, realPath, realLen);
        memcpy(testPath + realLen, componentPath, compLen + 1);

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
                if (linkLen >= MAX_FILEPATH_LENGTH) {
                    report_error("/", linkPath, ENAMETOOLONG);
                    return;
                }
                memcpy(realPath, linkPath, linkLen + 1);
            } else {
                if (realLen + linkLen >= MAX_FILEPATH_LENGTH) {
                    report_error("/", linkPath, ENAMETOOLONG);
                    return;
                }
                memcpy(realPath + realLen, linkPath, linkLen + 1);
            }
        } else {
            size_t addLen = *start ? 1 : 0;  // для слэша
            if (realLen + compLen + addLen >= MAX_FILEPATH_LENGTH) {
                report_error("/", componentPath, ENAMETOOLONG);
                return;
            }
            memcpy(realPath + realLen, componentPath, compLen);
            realPath[realLen + compLen] = '\0';
            if (*start) {
                realPath[realLen + compLen] = '/';
                realPath[realLen + compLen + 1] = '\0';
            }
        }
    }

    // Проверка на директорию
    struct stat final_stat;
    if (stat(realPath, &final_stat) == 0 && S_ISDIR(final_stat.st_mode)) {
        size_t len = strlen(realPath);
        if (realPath[len - 1] != '/') {
            if (len + 1 >= MAX_FILEPATH_LENGTH) {
                report_error("/", realPath, ENAMETOOLONG);
                return;
            }
            realPath[len] = '/';
            realPath[len + 1] = '\0';
        }
    }

    report_path(realPath);
}