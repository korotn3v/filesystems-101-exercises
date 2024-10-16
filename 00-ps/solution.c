#include "solution.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

struct linux_dirent {
    long           d_ino;    
    off_t          d_off;    
    unsigned short d_reclen; 
    char           d_name[]; 
};

#define BUF_SIZE 1024

int is_numeric(const char *str) {
    if (str == NULL || *str == '\0') {
        return 0;
    }
    while (*str) {
        if (!isdigit((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

ssize_t read_file(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    ssize_t bytes_read = read(fd, buffer, size - 1);
    if (bytes_read >= 0) {
        buffer[bytes_read] = '\0';
    }
    close(fd);
    return bytes_read;
}

char **split_null_separated(const char *str) {
    if (str == NULL) {
        return NULL;
    }

    size_t count = 0;
    for (const char *s = str; *s; s++) {
        if (*s == '\0') {
            count++;
        }
    }

    char **argv = malloc((count + 1) * sizeof(char *));
    if (argv == NULL) {
        return NULL;
    }

    size_t index = 0;
    const char *start = str;
    for (const char *s = str; ; s++) {
        if (*s == '\0') {
            if (s != start) { 
                argv[index++] = strdup(start);
                if (argv[index - 1] == NULL) {
                    for (size_t i = 0; i < index - 1; i++) {
                        free(argv[i]);
                    }
                    free(argv);
                    return NULL;
                }
            }
            start = s + 1;
            if (*s == '\0') {
                break;
            }
        }
    }
    argv[index] = NULL;
    return argv;
}

int get_exe_path(pid_t pid, char *exe_path, size_t size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, exe_path, size - 1);
    if (len == -1) {
        return -1;
    }
    exe_path[len] = '\0';
    return 0;
}

void ps(void) {
    int fd;
    long nread;
    char buf[BUF_SIZE];
    struct linux_dirent *d;
    int bpos;

    fd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        report_error("/proc", errno);
        return;
    }

    while ((nread = syscall(SYS_getdents, fd, buf, sizeof(buf))) > 0) {
        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *)(buf + bpos);
            char *d_name = d->d_name;

            if (is_numeric(d_name)) {
                pid_t pid = (pid_t)atoi(d_name);
                char exe_path[PATH_MAX];
                char cmdline_buffer[4096];
                char environ_buffer[4096];
                char **argv = NULL;
                char **envp = NULL;

                if (get_exe_path(pid, exe_path, sizeof(exe_path)) == -1) {
                    char exe_link_path[PATH_MAX];
                    snprintf(exe_link_path, sizeof(exe_link_path), "/proc/%d/exe", pid);
                    report_error(exe_link_path, errno);
                    bpos += d->d_reclen;
                    continue;
                }

                char cmdline_path[PATH_MAX];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
                ssize_t cmdlen = read_file(cmdline_path, cmdline_buffer, sizeof(cmdline_buffer));
                if (cmdlen == -1) {
                    report_error(cmdline_path, errno);
                    bpos += d->d_reclen;
                    continue;
                }
                argv = split_null_separated(cmdline_buffer);
                if (argv == NULL) {
                    report_error(cmdline_path, errno);
                    bpos += d->d_reclen;
                    continue;
                }

                char environ_path[PATH_MAX];
                snprintf(environ_path, sizeof(environ_path), "/proc/%d/environ", pid);
                ssize_t envlen = read_file(environ_path, environ_buffer, sizeof(environ_buffer));
                if (envlen == -1) {
                    report_error(environ_path, errno);
                    for (size_t i = 0; argv[i] != NULL; i++) {
                        free(argv[i]);
                    }
                    free(argv);
                    bpos += d->d_reclen;
                    continue;
                }
                envp = split_null_separated(environ_buffer);
                if (envp == NULL) {
                    report_error(environ_path, errno);
                    for (size_t i = 0; argv[i] != NULL; i++) {
                        free(argv[i]);
                    }
                    free(argv);
                    bpos += d->d_reclen;
                    continue;
                }

                report_process(pid, exe_path, argv, envp);

                for (size_t i = 0; argv[i] != NULL; i++) {
                    free(argv[i]);
                }
                free(argv);
                for (size_t i = 0; envp[i] != NULL; i++) {
                    free(envp[i]);
                }
                free(envp);
            }

            bpos += d->d_reclen;
        }
    }

    if (nread == -1) {
        report_error("/proc", errno);
    }

    close(fd);
}

