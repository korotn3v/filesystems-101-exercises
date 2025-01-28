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
    char currentPath[MAX_FILEPATH_LENGTH] = "";
    char tempPath[MAX_FILEPATH_LENGTH];

    // Если путь начинается с '/', копируем его без изменений
    if (path[0] == '/') {
        snprintf(remainingPath, MAX_FILEPATH_LENGTH, "%s", path + 1);
    } else {
        // Для относительного пути добавляем текущую директорию '/'
        snprintf(remainingPath, MAX_FILEPATH_LENGTH, "%s", path);
    }

    // Пока есть путь для обработки
    while (*remainingPath) {
        char *slash = strchr(remainingPath, '/');
        if (slash) {
            *slash = '\0';  // Разделяем на части
        }

        snprintf(currentPath, MAX_FILEPATH_LENGTH, "%s", remainingPath);
        snprintf(tempPath, MAX_FILEPATH_LENGTH, "%s%s%s", realPath, *realPath != '/' ? "/" : "", currentPath);

        struct stat path_stat;
        if (lstat(tempPath, &path_stat) != 0) {
            // Ошибка при обработке пути
            report_error(realPath, currentPath, errno);
            return;
        }

        if (S_ISLNK(path_stat.st_mode)) {
            // Обрабатываем символическую ссылку
            char linkTarget[MAX_FILEPATH_LENGTH];
            ssize_t len = readlink(tempPath, linkTarget, MAX_FILEPATH_LENGTH - 1);
            if (len == -1) {
                report_error(realPath, currentPath, errno);
                return;
            }
            linkTarget[len] = '\0';

            if (linkTarget[0] == '/') {
                // Абсолютный путь в ссылке
                snprintf(realPath, MAX_FILEPATH_LENGTH, "%s", linkTarget);
            } else {
                // Относительный путь в ссылке
                snprintf(realPath, MAX_FILEPATH_LENGTH, "%s%s%s", realPath, *realPath != '/' ? "/" : "", linkTarget);
            }
        } else {
            // Добавляем текущий компонент к реальному пути
            snprintf(realPath, MAX_FILEPATH_LENGTH, "%s%s%s", realPath, *realPath != '/' ? "/" : "", currentPath);
        }

        // Добавляем оставшуюся часть пути
        if (slash) {
            *slash = '/';
            snprintf(remainingPath, MAX_FILEPATH_LENGTH, "%s", slash + 1);
        } else {
            remainingPath[0] = '\0';
        }
    }

    // Проверяем, указывает ли путь на каталог
    struct stat final_stat;
    if (stat(realPath, &final_stat) == 0 && S_ISDIR(final_stat.st_mode)) {
        size_t len = strlen(realPath);
        if (realPath[len - 1] != '/') {
            strcat(realPath, "/");
        }
    }

    // Отчёт о результате
    report_path(realPath);
}
