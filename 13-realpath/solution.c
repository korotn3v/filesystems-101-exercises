#include "solution.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_FILEPATH_LENGTH 4096 // В Linux максимальная длина пути 4096 байт

char* giveFirstPtr(const char* str, char symbol) {
    while (*str != '\0') {
        if (*str == symbol) {
            return (char*)str;  // Возвращаем указатель на найденный символ
        }
        ++str;
    }
    return NULL;  // Возвращаем NULL, если символ не найден
}

char* giveLastPtr(const char* str, char symbol) {
    const char* last = NULL;
    while (*str != '\0') {
        if (*str == symbol) {
            last = str;  // Запоминаем указатель на найденный символ
        }
        ++str;
    }
    return (char*)last;  // Иначе возвращаем указатель на последнее вхождение символа
}

void undoPath(char* realPath) {
    if (strlen(realPath) > 1) {
        char* last = giveLastPtr(realPath, '/');
        if (last) {
            *last = '\0';
        }
    }
}

void abspath(const char* path) {
    char currentPath[MAX_FILEPATH_LENGTH] = "";

    // Если путь абсолютный, убираем начальный '/'
    if (path[0] == '/') {
        snprintf(currentPath, MAX_FILEPATH_LENGTH, "%s", path + 1);
    } else {
        snprintf(currentPath, MAX_FILEPATH_LENGTH, "%s", path);
    }

    int len = strlen(currentPath);
    char realPath[MAX_FILEPATH_LENGTH] = "";
    char piecePath[MAX_FILEPATH_LENGTH] = "";

    while (len > 0) {
        char* ptrPiecePath = giveFirstPtr(currentPath, '/');

        if (ptrPiecePath) {
            *ptrPiecePath = '\0';
            snprintf(piecePath, MAX_FILEPATH_LENGTH, "%s", currentPath);
            snprintf(currentPath, MAX_FILEPATH_LENGTH, "%s", ptrPiecePath + 1);
        } else {
            snprintf(piecePath, MAX_FILEPATH_LENGTH, "%s", currentPath);
            currentPath[0] = '\0';
        }
        len = strlen(currentPath);

        if (piecePath[0] == '\0' || strcmp(piecePath, ".") == 0) {
            continue;
        }

        if (strcmp(piecePath, "..") == 0) {
            undoPath(realPath);
            continue;
        }

        // Добавляем текущий кусок пути в реальный путь
        if (strlen(realPath) + strlen(piecePath) + 2 >= MAX_FILEPATH_LENGTH) {
            fprintf(stderr, "Path is too long\n");
            exit(EXIT_FAILURE);
        }
        strncat(realPath, "/", MAX_FILEPATH_LENGTH - strlen(realPath) - 1);
        strncat(realPath, piecePath, MAX_FILEPATH_LENGTH - strlen(realPath) - 1);

        char temporaryPath[MAX_FILEPATH_LENGTH] = "";
        snprintf(temporaryPath, MAX_FILEPATH_LENGTH, "%s", realPath);

        struct stat path_stat;
        if (lstat(temporaryPath, &path_stat) != 0) {
            undoPath(realPath);
            report_error(realPath, piecePath, errno);
            return;
        }

        char link[MAX_FILEPATH_LENGTH];
        if (S_ISLNK(path_stat.st_mode)) {
            int lenLink = readlink(temporaryPath, link, MAX_FILEPATH_LENGTH - 1);
            if (lenLink == -1) {
                report_error(realPath, piecePath, errno);
                return;
            }
            link[lenLink] = '\0';

            if (link[0] == '/') {
                realPath[0] = '\0';
            } else {
                undoPath(realPath);
            }

            if (strlen(link) + strlen(currentPath) + 2 >= MAX_FILEPATH_LENGTH) {
                fprintf(stderr, "Path is too long\n");
                exit(EXIT_FAILURE);
            }
            if (strlen(currentPath) > 0) {
                if (link[lenLink - 1] != '/') {
                    strncat(link, "/", MAX_FILEPATH_LENGTH - strlen(link) - 1);
                }
                strncat(link, currentPath, MAX_FILEPATH_LENGTH - strlen(link) - 1);
            }
            snprintf(currentPath, MAX_FILEPATH_LENGTH, "%s", link);
        }
        len = strlen(currentPath);
    }

    struct stat path_stat;
    stat(realPath, &path_stat);

    if (strlen(realPath) == 0 || S_ISDIR(path_stat.st_mode)) {
        size_t len = strlen(realPath);
        if (realPath[len - 1] != '/') {
            strncat(realPath, "/", MAX_FILEPATH_LENGTH - strlen(realPath) - 1);
        }
    }
    report_path(realPath);
}
