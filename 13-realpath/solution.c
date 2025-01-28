#include <solution.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_FILEPATH_LENGTH 4096 // In linux, the maximum path length is 255 bytes

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
        *last = '\0';
    }
}

void abspath(const char* path) {

    char currentPath[MAX_FILEPATH_LENGTH] = "";

    if (path[0] == '/') {
        strncpy(currentPath, path + 1, MAX_FILEPATH_LENGTH); // убираем / вначале, если он есть
    } else {
        strncpy(currentPath, path, MAX_FILEPATH_LENGTH);
    }

    int len = strlen(currentPath);
    char realPath[MAX_FILEPATH_LENGTH] = "";
    char piecePath[MAX_FILEPATH_LENGTH] = "";

    while (len > 0) {

        char* ptrPiecePath = giveFirstPtr(currentPath, '/');

        if (ptrPiecePath) {
            *ptrPiecePath = '\0';
            strncpy(piecePath, currentPath, MAX_FILEPATH_LENGTH);
            memcpy(currentPath, ptrPiecePath + 1, strlen(ptrPiecePath + 1) + 1);
        } else {
            strncpy(piecePath, currentPath, MAX_FILEPATH_LENGTH);
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

        strcat(realPath, "/");

        char temporaryPath[MAX_FILEPATH_LENGTH * 2] = "";

        snprintf(temporaryPath, MAX_FILEPATH_LENGTH * 2, "%s%s", realPath, piecePath);

        struct stat path_stat;
        if (lstat(temporaryPath, &path_stat) != 0) {
            undoPath(realPath);
            report_error(realPath, piecePath, errno);
            return;
        }

        char copyRealPath[MAX_FILEPATH_LENGTH] = "";
        strncpy(copyRealPath, realPath, MAX_FILEPATH_LENGTH);
        strncpy(realPath, temporaryPath, MAX_FILEPATH_LENGTH);

        char link[MAX_FILEPATH_LENGTH];
        if (S_ISLNK(path_stat.st_mode)) {
            int lenLink;
            if ((lenLink = readlink(realPath, link, MAX_FILEPATH_LENGTH - 1)) == -1) {
                report_error(copyRealPath, piecePath, errno);
                return;
            }
            link[lenLink] = '\0';
            if (link[0] == '/') {
                realPath[0] = '\0';
            } else {
                undoPath(realPath);
            }
            if (strlen(currentPath) > 0) {
                if (link[lenLink - 1] != '/') {
                    strcat(link, "/");
                }
                strcat(link, currentPath);
            }
            strncpy(currentPath, link, MAX_FILEPATH_LENGTH);
        }
        len = strlen(currentPath);
    }

    struct stat path_stat;
    stat(realPath, &path_stat);

    if (strlen(realPath) == 0 || S_ISDIR(path_stat.st_mode)) {
        size_t len = strlen(realPath);
        if (realPath[len - 1] != '/') {
            strcat(realPath, "/");
        }
    }
    report_path(realPath);
}