#include "solution.h"
#include <dirent.h>    // (DIR, struct dirent)
#include <errno.h>     // codes of errno
#include <stdio.h>     // (fopen, fclose, sprintf)
#include <stdlib.h>    // (malloc, calloc, free)
#include <string.h>    // (strtol, strlen)
#include <unistd.h>    // (readlink, close)
#include <fcntl.h>     // (open, O_RDONLY)
#include <sys/types.h> // pid_t

// Константы для предельных значений аргументов и длины строк
#define MAX_ARG 4096             // max number of elements in argv and envp
#define MAX_ARG_LENGTH 4096      // max length of elements in argv and envp
#define MAX_FILEPATH_LENGTH 4096 // max length of path to file in Linux
#define EXE_MAX_LENGTH 4096      // max length of path to exe(after readlink)

// Пути к системным файлам в каталоге /proc
static const char* PROC_PATH = "/proc/";       //path for proc
static const char* EXE_PATH = "/exe";          //path for exe
static const char* CMDLINE_PATH = "/cmdline";  //path for argv
static const char* ENVIRON_PATH = "/environ";  //path for envp

void ps(void) {
    DIR* proc_directory = opendir(PROC_PATH); // Открываем каталог /proc
    if (proc_directory == NULL)
    {
        report_error(PROC_PATH, errno);
        return;
    }

    // Выделяем память для хранения пути к исполняемому файлу(exe) и массивов аргументов(argv) и переменных окружения(envp)
    char* exe = (char*) calloc(EXE_MAX_LENGTH, sizeof(char)); // absolute path to the executable file of the process
    char** argv = (char**) malloc(MAX_ARG * sizeof(char*)); // array of command line arguments to the process
    char** envp = (char**) malloc(MAX_ARG * sizeof(char*)); // array of environment variables of the process

    // Инициализируем память для каждого элемента argv и envp
    for (int i = 0; i < MAX_ARG; ++i)
    {
        argv[i] = (char*) malloc(MAX_ARG_LENGTH);
        envp[i] = (char*) malloc(MAX_ARG_LENGTH);
    }

    struct dirent* proc_dirent; // Структура файла/директории
    char* current_path = (char*) malloc(MAX_FILEPATH_LENGTH); // Буфер для хранения пути к файлам в /proc

    // Перебираем все записи в каталоге /proc
    while ((proc_dirent = readdir(proc_directory)) != NULL) {
        char* p_end;
        pid_t pid = (pid_t) strtol(proc_dirent->d_name, &p_end, 10); // Преобразуем имя директории в число pid = PID
        if (*p_end)
        {
            continue;
        }

        sprintf(current_path, "%s%s%s", PROC_PATH, proc_dirent->d_name, EXE_PATH); //current_path = /proc/PID/exe
        if (readlink(current_path, exe, EXE_MAX_LENGTH) == -1) //читаем в exe ссылку по пути current_path
        {
            report_error(current_path, errno);
            continue;
        }

        sprintf(current_path, "%s%s%s", PROC_PATH, proc_dirent->d_name, CMDLINE_PATH); //current_path = /proc/PID/cmdline
        FILE* ptr_file1; //файл по пути current_path
        if ((ptr_file1 = fopen(current_path, "r")) == NULL)
        {
            report_error(current_path, errno);
            continue;
        }

        // Читаем аргументы из файла и сохраняем их в argv_report_process
        char** argv_report_process = (char**) malloc(MAX_ARG * sizeof(char*));
        for (int i = 0; i < MAX_ARG; i++)
        {
            size_t max_arg_length = MAX_ARG_LENGTH;
            if (getdelim(&argv[i], &max_arg_length, '\0', ptr_file1) != -1 && argv[i][0] != '\0') { //читаем в argv[i] элемент из ptr_file1 разделенный '\0'
                argv_report_process[i] = argv[i];
            } else {
                argv_report_process[i] = NULL;
                break;
            }
        }
        fclose(ptr_file1);

        sprintf(current_path, "%s%s%s", PROC_PATH, proc_dirent->d_name, ENVIRON_PATH); //current_path = /proc/pid/environ
        FILE* ptr_file2; //файл по пути current_path
        if ((ptr_file2 = fopen(current_path, "r")) == NULL)
        {
            free(argv_report_process);
            report_error(current_path, errno);
            continue;
        }

        // Читаем переменные окружения из файла и сохраняем их в envp_report_process
        char** envp_report_process = (char**) malloc(MAX_ARG * sizeof(char*));
        for (int i = 0; i < MAX_ARG; i++)
        {
            size_t max_arg_length = MAX_ARG_LENGTH;
            if (getdelim(&envp[i], &max_arg_length, '\0', ptr_file2) != -1 && envp[i][0] != '\0') //читаем в argv[i] элемент из ptr_file2 разделенный '\0'
            {
                envp_report_process[i] = envp[i];
            } else {
                envp_report_process[i] = NULL;
                break;
            }
        }
        fclose(ptr_file2);

        report_process(pid, exe, argv_report_process, envp_report_process);

        //освобождаем память и закрываем файлы
        free(argv_report_process);
        free(envp_report_process);
    }

    free(current_path);
    closedir(proc_directory);

    for (int i = 0; i < MAX_ARG; i++)
    {
        free(argv[i]);
        free(envp[i]);
    }
    free(exe);
    free(argv);
    free(envp);
}
