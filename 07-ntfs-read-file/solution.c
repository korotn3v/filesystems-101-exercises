#include <solution.h>
#include <errno.h>
#include <unistd.h>
#include "fs_malloc.h"
#include "fs_string.h"
#include <ntfs-3g/device.h> 
#include <ntfs-3g/inode.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/runlist.h>


int dump_file(int img, const char *path, int out) {
    ntfs_volume *vol;
    ntfs_inode *inode;
    ntfs_attr *attr;
    char *buf;
    s64 offset = 0;
    const int buf_size = 4096;  // Размер буфера для чтения
    int bytes_read;
    int result = 0;

    vol = ntfs_device_mount(img, 0);
    if (!vol) {
        return -errno;
    }

    inode = ntfs_pathname_to_inode(vol, NULL, path);
    if (!inode) {
        ntfs_umount(vol, FALSE);
        return -errno;
    }

    if (!NF_IS_REG(inode)) {
        ntfs_inode_close(inode);
        ntfs_umount(vol, FALSE);
        return -EINVAL;
    }

    attr = ntfs_attr_open(inode, AT_DATA, NULL, 0);
    if (!attr) {
        ntfs_inode_close(inode);
        ntfs_umount(vol, FALSE);
        return -errno;
    }

    buf = fs_xmalloc(buf_size);

    while ((bytes_read = ntfs_attr_pread(attr, offset, buf_size, buf)) > 0) {
        ssize_t bytes_written = write(out, buf, bytes_read);
        if (bytes_written != bytes_read) {
            result = -errno;
            break;
        }
        offset += bytes_read;
    }

    if (bytes_read < 0) {
        result = -errno;
    }

    fs_xfree(buf);
    ntfs_attr_close(attr);
    ntfs_inode_close(inode);
    ntfs_umount(vol, FALSE);

    return result;
}

