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

#define BUFFER_SIZE 65536

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

        char exe_buf[PATH_MAX];
        char cur_path[PATH_MAX];
        char *argv_read = malloc(BUFFER_SIZE + 1);
        char *envp_read = malloc(BUFFER_SIZE + 1);
        char **argv_buf = NULL;
        char **envp_buf = NULL;

        if (!argv_read || !envp_read){
            report_error("/proc", ENOMEM);
            exit(EXIT_FAILURE);
        }

        //read into exe_buf
        pid_t pid = atoi(cur_dir->d_name);
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/exe", pid);
        ssize_t exe_len = readlink(cur_path, exe_buf, PATH_MAX);

        if (exe_len == -1){
            report_error(cur_path, errno);
            free(argv_read);
            free(envp_read);
            continue;
        }
        exe_buf[exe_len] = '\0';

        //read into arg_read
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/cmdline", pid);
        FILE *file_cmdline = fopen(cur_path, "r");

        if (!file_cmdline){
            if (errno != EACCES)
                report_error(cur_path, errno);
            free(argv_read);
            free(envp_read);
            continue;
        }

        ssize_t bytes_read_cmdline = fread(argv_read, 1, BUFFER_SIZE - 1, file_cmdline);
        fclose(file_cmdline);

        if (bytes_read_cmdline == -1)
        {
            report_error(cur_path, errno);
            free(argv_read);
            free(envp_read);
            continue;
        }
        argv_read[bytes_read_cmdline] = '\0';

        //count nuber of strings
        size_t count = 0;
        for (size_t i = 0; i < (size_t)bytes_read_cmdline; i++){
            if (argv_read[i] == '\0')
                count++;
        }

        argv_buf = malloc((count + 1) * sizeof(char *));
        if(!argv_buf){
            report_error(cur_path, ENOMEM);
            free(argv_read);
            free(envp_read);
            exit(EXIT_FAILURE);
        }

        //parse arv_read into arv_buf
        count = 0;
        char *ptr_argv = argv_read;
        while (*ptr_argv && count < BUFFER_SIZE / sizeof(char *) - 1){
            argv_buf[count++] = ptr_argv;
            ptr_argv += strlen(ptr_argv) + 1;
        }
        argv_buf[count] = NULL;

        //read into env_read
        snprintf(cur_path, sizeof(cur_path), "/proc/%d/environ", pid);
        FILE *file_env = fopen(cur_path, "r");

        if (!file_env){
            if (errno != EACCES)
                report_error(cur_path, errno);
            free(argv_read);
            free(envp_read);
            free(argv_buf);
            continue;
        }

        ssize_t bytes_read_envp = fread(envp_read, 1, BUFFER_SIZE - 1, file_env);
        fclose(file_env);

        if (bytes_read_envp == -1)
        {
            report_error(cur_path, errno);
            free(argv_read);
            free(envp_read);
            free(argv_buf);
            continue;
        }
        argv_read[bytes_read_envp] = '\0';

        //count nuber of strings
        count = 0;
        for (size_t i = 0; i < (size_t)(bytes_read_envp); i++){
            if (envp_read[i] == '\0')
                count++;
        }

        envp_buf = malloc((count + 1) * sizeof(char *));
        if(!envp_buf){
            report_error(cur_path, ENOMEM);
            free(argv_read);
            free(envp_read);
            free(argv_buf);
            exit(EXIT_FAILURE);
        }

        //parse envp_read into envp_buf
        count = 0;
        char *ptr_envp = envp_read;
        while (*ptr_envp && count < BUFFER_SIZE / sizeof(char *) - 1){
            envp_buf[count++] = ptr_envp;
            ptr_envp += strlen(ptr_envp) + 1;
        }
        envp_buf[count] = NULL;

        //report process
        report_process(pid, exe_buf, argv_buf, envp_buf);
        free(argv_buf);
        free(envp_buf);
        free(argv_read);
        free(envp_read);
	}
	closedir(proc_dir);
}