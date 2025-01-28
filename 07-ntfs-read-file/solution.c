#include "solution.h"
#include <errno.h>
#include <stdarg.h>
#define _STRUCT_TIMESPEC 1
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <ntfs-3g/volume.h>
#include <string.h>

#define PATH_SEP '/'

ntfs_inode *ntfs_pathName_to_Inode(ntfs_volume *volume, ntfs_inode *parent_inode,
                                   const char *pathName);

int dump_file(int img, const char *path, int out)
{
    char path_to_FS[PATH_MAX];
    snprintf(path_to_FS, PATH_MAX, "/proc/self/fd/%d", img);

    char *filename = calloc(1, NAME_MAX);
    if (!filename) {
        return -ENOMEM;
    }

    int status = readlink(path_to_FS, filename, NAME_MAX);
    if (status < 0)
    {
        free(filename);
        return -errno;
    }

    ntfs_volume *volume = ntfs_mount(path_to_FS, NTFS_MNT_RDONLY);
    if (volume == NULL)
    {
        free(filename);
        return -errno;
    }

    ntfs_inode *inode = ntfs_pathName_to_Inode(volume, NULL, path);
    if (inode == NULL)
    {
        int return_value = -errno;
        ntfs_umount(volume, TRUE);
        free(filename);
        return return_value;
    }

    ntfs_attr *attribute = ntfs_attr_open(inode, AT_DATA, NULL, 0);
    if (!attribute)
    {
        int return_value = -errno;
        ntfs_inode_close(inode);
        ntfs_umount(volume, TRUE);
        free(filename);
        return return_value;
    }

    int64_t position = 0;
    char *buffer = calloc(1, BUFSIZ);
    if (!buffer) {
        ntfs_attr_close(attribute);
        ntfs_inode_close(inode);
        ntfs_umount(volume, TRUE);
        free(filename);
        return -ENOMEM;
    }

    while (1)
    {
        int64_t status = ntfs_attr_pread(attribute, position, BUFSIZ, buffer);
        if (status < 0)
        {
            free(buffer);
            ntfs_attr_close(attribute);
            ntfs_inode_close(inode);
            ntfs_umount(volume, TRUE);
            free(filename);
            return -errno;
        }

        if (status == 0)
        {
            break;
        }

        int write_status = pwrite(out, buffer, status, position);
        if (write_status < 0)
        {
            free(buffer);
            ntfs_attr_close(attribute);
            ntfs_inode_close(inode);
            ntfs_umount(volume, TRUE);
            free(filename);
            return -errno;
        }

        position += status;
    }

    free(buffer);
    ntfs_attr_close(attribute);
    ntfs_inode_close(inode);
    ntfs_umount(volume, TRUE);
    free(filename);

    return 0;
}

#include <ntfs-3g/dir.h>
ntfs_inode *ntfs_pathName_to_Inode(ntfs_volume *volume, ntfs_inode *parent_inode,
                                   const char *pathName)
{
    uint64_t inumber;
    int length, status = 0;
    char *pp, *qq;
    ntfs_inode *n_i;
    ntfs_inode *result_path = NULL;
    ntfschar *uni_code = NULL;
    char *ascii_code = NULL;

    if (!volume || !pathName)
    {
        errno = EINVAL;
        return NULL;
    }

    ntfs_log_trace("path: '%s'\n", pathName);

    ascii_code = strdup(pathName);
    if (!ascii_code)
    {
        ntfs_log_error("Out of memory.\n");
        status = ENOMEM;
        free(ascii_code);
        free(uni_code);
        if (status)
            errno = status;
        return result_path;
    }

    pp = ascii_code;

    while (pp && *pp && *pp == PATH_SEP)
        pp++;

    if (parent_inode)
    {
        n_i = parent_inode;
    }
    else
    {
        n_i = ntfs_inode_open(volume, FILE_root);
        if (!n_i)
        {
            status = EIO;
            result_path = NULL;
            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }
    }

    while (pp && *pp)
    {
        qq = strchr(pp, PATH_SEP);
        if (qq != NULL)
        {
            *qq = '\0';
        }

        length = ntfs_mbstoucs(pp, &uni_code);
        if (length < 0)
        {
            status = errno;
            if (n_i && (n_i != parent_inode))
                if (ntfs_inode_close(n_i) && !status)
                    status = errno;

            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }
        else if (length > NTFS_MAX_NAME_LEN)
        {
            status = ENAMETOOLONG;
            if (n_i && (n_i != parent_inode))
                if (ntfs_inode_close(n_i) && !status)
                    status = errno;

            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }

        inumber = ntfs_inode_lookup_by_name(n_i, uni_code, length);

        if (inumber == (uint64_t)-1)
        {
            status = ENOENT;
            if (n_i && (n_i != parent_inode))
                if (ntfs_inode_close(n_i) && !status)
                    status = errno;

            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }

        if (n_i != parent_inode)
            if (ntfs_inode_close(n_i))
            {
                status = errno;
                free(ascii_code);
                free(uni_code);
                if (status)
                    errno = status;
                return result_path;
            }

        inumber = MREF(inumber);
        n_i = ntfs_inode_open(volume, inumber);
        if (!n_i)
        {
            status = EIO;
            if (n_i && (n_i != parent_inode))
                if (ntfs_inode_close(n_i) && !status)
                    status = errno;

            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }

        if (!(n_i->mrec->flags & MFT_RECORD_IS_DIRECTORY) && qq)
        {
            status = ENOTDIR;
            if (n_i && (n_i != parent_inode))
                if (ntfs_inode_close(n_i) && !status)
                    status = errno;

            free(ascii_code);
            free(uni_code);
            if (status)
                errno = status;
            return result_path;
        }

        free(uni_code);
        uni_code = NULL;

        if (qq)
            *qq++ = PATH_SEP;
        pp = qq;
        while (pp && *pp && *pp == PATH_SEP)
            pp++;
    }

    result_path = n_i;
    n_i = NULL;

    if (n_i && (n_i != parent_inode))
        if (ntfs_inode_close(n_i) && !status)
            status = errno;

    free(ascii_code);
    free(uni_code);
    if (status)
        errno = status;

    return result_path;
}
