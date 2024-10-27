#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#define PATH_MAX_LEN 4096

int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit(*str))
            return 0;
        str++;
    }
    return 1;
}

char *read_symlink(const char *path) {
    char *buf = malloc(PATH_MAX_LEN);
    if (!buf) {
        return NULL;
    }
    ssize_t len = readlink(path, buf, PATH_MAX_LEN - 1);
    if (len == -1) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

char **read_file_split(const char *path, const char delimiter) {
    FILE *file = fopen(path, "r");
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    char *content = malloc(size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }

    fread(content, 1, size, file);
    content[size] = '\0';
    fclose(file);

    int count = 1;
    for (long i = 0; i < size; i++) {
        if (content[i] == delimiter) count++;
    }

    char **result = malloc((count + 1) * sizeof(char *));
    if (!result) {
        free(content);
        return NULL;
    }

    int idx = 0;
    char *token = strtok(content, (delimiter == '\0') ? "\0" : &delimiter);
    while (token) {
        result[idx++] = strdup(token);
        token = strtok(NULL, (delimiter == '\0') ? "\0" : &delimiter);
    }
    result[idx] = NULL;

    free(content);
    return result;
}

void ps(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        report_error("/proc", errno);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR)
            continue;

        if (!is_numeric(entry->d_name))
            continue;

        pid_t pid = (pid_t)atoi(entry->d_name);

        char exe_path[PATH_MAX_LEN];
        char cmdline_path[PATH_MAX_LEN];
        char environ_path[PATH_MAX_LEN];

        snprintf(exe_path, PATH_MAX_LEN, "/proc/%d/exe", pid);
        snprintf(cmdline_path, PATH_MAX_LEN, "/proc/%d/cmdline", pid);
        snprintf(environ_path, PATH_MAX_LEN, "/proc/%d/environ", pid);

        char *exe = read_symlink(exe_path);
        if (!exe) {
            report_error(exe_path, errno);
            continue;
        }

        char **argv = read_file_split(cmdline_path, '\0');
        if (!argv) {
            report_error(cmdline_path, errno);
            free(exe);
            continue;
        }

        char **envp = read_file_split(environ_path, '\0');
        if (!envp) {
            report_error(environ_path, errno);
            for (int i = 0; argv[i] != NULL; i++) {
                free(argv[i]);
            }
            free(argv);
            free(exe);
            continue;
        }

        report_process(pid, exe, argv, envp);

        free(exe);
        for (int i = 0; argv[i] != NULL; i++) {
            free(argv[i]);
        }
        free(argv);
        for (int i = 0; envp[i] != NULL; i++) {
            free(envp[i]);
        }
        free(envp);
    }

    closedir(proc);
}

