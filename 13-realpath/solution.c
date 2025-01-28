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
    char *curr_component;
    char *next_slash;

    // Копируем исходный путь
    if (path[0] == '/') {
        memcpy(remainingPath, path + 1, strlen(path));
    } else {
        memcpy(remainingPath, path, strlen(path) + 1);
    }

    curr_component = remainingPath;
    if (!*curr_component) {
        report_path("/");
        return;
    }

    while (curr_component && *curr_component) {
        // Находим следующий слэш
        next_slash = strchr(curr_component, '/');
        if (next_slash) {
            *next_slash = '\0';
        }

        // Пропускаем "." и пустые компоненты
        if (!strcmp(curr_component, ".") || !*curr_component) {
            if (next_slash) {
                curr_component = next_slash + 1;
            } else {
                curr_component = NULL;
            }
            continue;
        }

        // Обработка ".."
        if (!strcmp(curr_component, "..")) {
            char *last_slash = strrchr(realPath, '/');
            if (last_slash != realPath) {
                *last_slash = '\0';
            }
            if (next_slash) {
                curr_component = next_slash + 1;
            } else {
                curr_component = NULL;
            }
            continue;
        }

        // Проверяем текущий компонент
        char testPath[MAX_FILEPATH_LENGTH];
        memcpy(testPath, realPath, strlen(realPath));
        memcpy(testPath + strlen(realPath), curr_component, strlen(curr_component) + 1);

        struct stat sb;
        if (lstat(testPath, &sb) == -1) {
            report_error("/", curr_component, ENOENT);
            return;
        }

        // Если это символическая ссылка
        if (S_ISLNK(sb.st_mode)) {
            char linkPath[MAX_FILEPATH_LENGTH];
            ssize_t len = readlink(testPath, linkPath, sizeof(linkPath) - 1);
            if (len == -1) {
                report_error("/", curr_component, errno);
                return;
            }
            linkPath[len] = '\0';

            if (linkPath[0] == '/') {
                memcpy(realPath, linkPath, len + 1);
            } else {
                size_t realLen = strlen(realPath);
                memcpy(realPath + realLen, linkPath, len + 1);
            }
        } else {
            // Добавляем компонент к пути
            strcat(realPath, curr_component);
            if (next_slash) {
                strcat(realPath, "/");
            }
        }

        if (next_slash) {
            curr_component = next_slash + 1;
        } else {
            curr_component = NULL;
        }
    }

    // Проверяем, является ли путь директорией
    struct stat final_stat;
    if (stat(realPath, &final_stat) == 0 && S_ISDIR(final_stat.st_mode)) {
        if (realPath[strlen(realPath) - 1] != '/') {
            strcat(realPath, "/");
        }
    }

    // Убеждаемся, что путь начинается с "/"
    if (realPath[0] != '/') {
        memmove(realPath + 1, realPath, strlen(realPath) + 1);
        realPath[0] = '/';
    }

    report_path(realPath);
}