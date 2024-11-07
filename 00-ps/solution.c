#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#define BUFFER_SIZE 1024 * 1024

void ps(void){

	DIR *proc_dir = opendir("/proc");
	if (!proc_dir){
		report_error("/proc", ENOENT);
		return;
	}

	struct dirent *cur_dir;
	while ((cur_dir = readdir(proc_dir))){

        if (!isdigit(cur_dir->d_name[0])){
            continue;
        }

        char buf_exe[PATH_MAX];
        char cur_path[PATH_MAX];
        char *read_argv = malloc(BUFFER_SIZE + 1);
        char *read_envp = malloc(BUFFER_SIZE + 1);
        char **buf_argv = NULL;
        char **buf_envp = NULL;

        if (!read_argv || !read_envp){
            report_error("/proc", ENOMEM);
            exit(EXIT_FAILURE);
        }

        //read into buf_exe
        pid_t pid = atoi(cur_dir->d_name);
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/exe", pid);
        ssize_t exe_len = readlink(cur_path, buf_exe, PATH_MAX);

        if (exe_len == -1){
            report_error(cur_path, errno);
            free(read_argv);
            free(read_envp);
            continue;
        }
        buf_exe[exe_len] = '\0';

        //read into arg_read
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/cmdline", pid);
        FILE *file_cmdline = fopen(cur_path, "r");

        if (!file_cmdline){
            if (errno != EACCES)
                report_error(cur_path, errno);
            free(read_argv);
            free(read_envp);
            continue;
        }

        ssize_t bytes_read_cmdline = fread(read_argv, 1, BUFFER_SIZE - 1, file_cmdline);
        fclose(file_cmdline);

        if (bytes_read_cmdline == -1)
        {
            report_error(cur_path, errno);
            free(read_argv);
            free(read_envp);
            continue;
        }
        read_argv[bytes_read_cmdline] = '\0';

        //count nuber of strings
        size_t count = 0;
        for (size_t i = 0; i < (size_t)bytes_read_cmdline; i++){
            if (read_argv[i] == '\0')
                count++;
        }

        buf_argv = malloc((count + 1) * sizeof(char *));
        if(!buf_argv){
            report_error(cur_path, ENOMEM);
            free(read_argv);
            free(read_envp);
            exit(EXIT_FAILURE);
        }

        //parse arv_read into arv_buf
        count = 0;
        char *ptr_argv = read_argv;
        while (*ptr_argv && count < BUFFER_SIZE / sizeof(char *) - 1){
            buf_argv[count++] = ptr_argv;
            ptr_argv += strlen(ptr_argv) + 1;
        }
        buf_argv[count] = NULL;

        //read into env_read
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/environ", pid);
        FILE *file_env = fopen(cur_path, "r");

        if (!file_env){
            if (errno != EACCES)
                report_error(cur_path, errno);
            free(read_argv);
            free(read_envp);
            free(buf_argv);
            continue;
        }

        ssize_t bytes_read_envp = fread(read_envp, 1, BUFFER_SIZE - 1, file_env);
        fclose(file_env);

        if (bytes_read_envp == -1)
        {
            report_error(cur_path, errno);
            free(read_argv);
            free(read_envp);
            free(buf_argv);
            continue;
        }
        read_argv[bytes_read_envp] = '\0';

        //count nuber of strings
        count = 0;
        for (size_t i = 0; i < (size_t)(bytes_read_envp); i++){
            if (read_envp[i] == '\0')
                count++;
        }

        buf_envp = malloc((count + 1) * sizeof(char *));
        if(!buf_envp){
            report_error(cur_path, ENOMEM);
            free(read_argv);
            free(read_envp);
            free(buf_argv);
            exit(EXIT_FAILURE);
        }

        //parse read_envp into buf_envp
        count = 0;
        char *ptr_envp = read_envp;
        while (*ptr_envp && count < BUFFER_SIZE / sizeof(char *) - 1){
            buf_envp[count++] = ptr_envp;
            ptr_envp += strlen(ptr_envp) + 1;
        }
        buf_envp[count] = NULL;

        //report process
        report_process(pid, buf_exe, buf_argv, buf_envp);
        free(buf_argv);
        free(buf_envp);
        free(read_argv);
        free(read_envp);
	}
	closedir(proc_dir);
}