#pragma once

#include <unistd.h>

/**
   Implement this function to to mount a "helloworld" FUSE filesystem to @mntp.
   The root of a filesystem must contain the following entries:

   $ ls -lha /helloworld
   drwxrwxr-x. 2 artem artem 19 Oct  6 05:39 .
   drwxr-xr-x. 4 artem artem 99 Oct  6 05:39 ..
   -r--------. 1 artem artem  0 Oct  6 05:39 hello

   The owner UID and GID of "hello" must be reported as the effective UID
   and GID of a process that lists the directory. For example,

   $ sudo ls -lha /helloworld
   drwxrwxr-x. 2 root root 19 Oct  6 05:39 .
   drwxr-xr-x. 4 root root 99 Oct  6 05:39 ..
   -r--------. 1 root root  0 Oct  6 05:39 hello

   The content of "hello" must be (without quotes) "hello, ${PID}" where
   PID is the id of a process that reads "hello". It is OK to report the
   size of "hello" that does not match the content of it.
*/
int helloworld(const char *mntp);
