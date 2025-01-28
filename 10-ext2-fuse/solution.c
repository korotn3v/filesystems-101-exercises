#include "solution.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <ext2fs/ext2fs.h>
#include <fuse.h>

#define EXT2_SB_OFFSET 1024

int inode_Directory(int img, struct ext2_super_block* SB, size_t blk, const char* path);
int block_Size(struct ext2_super_block* SB) {
    return 1024 << SB->s_log_block_size;
}
ssize_t SB_Read(int img, struct ext2_super_block* SB) {
    size_t size = sizeof(struct ext2_super_block);
	int status = pread(img, SB, size, EXT2_SB_OFFSET);
    if (status < 0) {
        return -errno;
    };
    return 0;
}
int inode_Read(int img, struct ext2_inode* inode, int inode_number, struct ext2_super_block* SB) {

    size_t inode_index = (inode_number - 1) % SB->s_inodes_per_group;
    size_t desc_index = (inode_number - 1) / SB->s_inodes_per_group;

    struct ext2_group_desc group_desc;

    int blk_size = EXT2_BLOCK_SIZE(SB);

    size_t offset = (SB->s_first_data_block + 1) * blk_size + sizeof(struct ext2_group_desc) * desc_index;

	int status = pread(img, &group_desc, sizeof(struct ext2_group_desc), offset);

	if (status < 0) {
        return -errno;
    }

    int pos = group_desc.bg_inode_table * blk_size + inode_index * SB->s_inode_size;

    int inode_size = sizeof(struct ext2_inode);
    status = pread(img, inode, inode_size, pos);

    if (status) {
        return -errno;
    }
    return 0;
}
int ind_get(int img, struct ext2_super_block* SB, size_t blk, const char* path) {

    int blk_size = EXT2_BLOCK_SIZE(SB);
    int status;
    uint32_t* buffer = malloc(blk_size);

    if (blk == 0) {
        free(buffer);
        return -ENOENT;
    }
    else
	{
		status = pread(img, buffer, blk_size, blk_size * blk);
		if (status < 0) {
        free(buffer);
        return -errno;
    }
	}
    for (uint i = 0; i < blk_size / sizeof(int); ++i) {
        status = inode_Directory(img, SB, buffer[i], path);
        if (status) {
            free(buffer);
            return status;
        }
    }

    free(buffer);
    return 0;
}
int dind_get(int img, struct ext2_super_block* SB, size_t blk, const char* path) {

	int status;
    int blk_size = EXT2_BLOCK_SIZE(SB);
    unsigned int* doubled_ind = malloc(blk_size);

    if (blk == 0) {
        free(doubled_ind);
        return -ENOENT;
    }
	status = pread(img, doubled_ind, blk_size, blk_size * blk);
    if ( status< 0) {
        free(doubled_ind);
        return -errno;
    }

    for (size_t i = 0; i < blk_size / sizeof(int); ++i) {
        status = ind_get(img, SB, doubled_ind[i], path);
        if (status != 0) {
            free(doubled_ind);
            return status;
        }
    }

    free(doubled_ind);
    return 0;
}
int inode_Get(int img, struct ext2_super_block* SB, int inode_number, const char* path) {

    struct ext2_inode inode;
    int status;
    if (inode_number == 0) {
        return -ENOENT;
    }
    if (path[0] != '/') {
        return inode_number;
    }

    ++path;
    status = inode_Read(img, &inode, inode_number, SB);

    if (status < 0) {
        return -errno;
    }



    for (size_t i = 0; i < EXT2_NDIR_BLOCKS; ++i) {
		status = inode_Directory(img, SB, inode.i_block[i], path);

        if (status)
            return status;

    }
    status = ind_get(img, SB, inode.i_block[EXT2_IND_BLOCK], path);
    if (status)
        return status;

    status = dind_get(img, SB, inode.i_block[EXT2_DIND_BLOCK], path);

    if (status)
        return status;


    return -ENOENT;
}
int inode_Directory(int img, struct ext2_super_block* SB, size_t blk, const char* path) {

    if (blk == 0) {
        return -ENOENT;
    }
    int status;
    int blk_size = EXT2_BLOCK_SIZE(SB);

    char* buffer = malloc(blk_size);
    status = pread(img, buffer, blk_size, blk * blk_size);
    if (status < 0) {
        free(buffer);
        return -errno;
    }

    char* pc = buffer;

    while (pc - buffer < blk_size) {

        struct ext2_dir_entry_2* dir_entry = (struct ext2_dir_entry_2*) pc;

        int inode = dir_entry->inode;

        if (inode == 0) {
            free(buffer);
            return -ENOENT;
        }
        const char* next_c = path;

        while (*next_c && *next_c != '/') {
            ++next_c;
        }
        int equivavlent = strncmp(path, dir_entry->name, dir_entry->name_len);

        if (next_c - path == dir_entry->name_len && equivavlent == 0) {

            int inode_number = dir_entry->inode;

            if (next_c[0] != '/') {
                free(buffer);
                return inode_number;
            }
            if (dir_entry->file_type == EXT2_FT_DIR) {
                free(buffer);
                return inode_Get(img, SB, inode_number, next_c);
            }
            free(buffer);
            return -ENOTDIR;
        }
        pc += dir_entry->rec_len;
    }
    free(buffer);
    return 0;
}

//new functions

int Read;
int ext2_Img;
struct ext2_super_block ext2_SB;

void *init_(struct fuse_conn_info *conn_info, struct fuse_config *config) {
    (void)conn_info;
	(void)config;
    return NULL;
}
static int _create(const char *path, mode_t mode, struct fuse_file_info *info) {
    (void)path;
    (void)mode;
    (void)info;
    return -EROFS;
}
static int _open(const char *path, struct fuse_file_info *info) {
    int status;

    if ((info->flags & O_ACCMODE) != O_RDONLY) {
        return -EROFS;
    }
    status = inode_Get(ext2_Img, &ext2_SB, EXT2_ROOT_INO, path);
    if (status < 0) {
        return -ENOENT;
    }
    return 0;
}
static int _write(const char *req, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info) {
    (void)req;
    (void)buffer;
    (void)size;
    (void)offset;
    (void)info;
    return -EROFS;
}
static int _write_buf(const char *path, struct fuse_bufvec *buffer, off_t offset, struct fuse_file_info *info) {
    (void)path;
    (void)buffer;
    (void)offset;
    (void)info;
    return -EROFS;
}
static int _mkdir(const char *path, mode_t mode) {
    (void)path;
    (void)mode;
    return -EROFS;
}
static int _mknod(const char *path, mode_t mode, dev_t dev) {
    (void)path;
    (void)mode;
    (void)dev;
    return -EROFS;
}
static int _getattr(const char *path, struct stat *stat, struct fuse_file_info *info) {
	(void)info;
	int status;
    size_t stat_size = sizeof(struct stat);
    memset(stat, 0, stat_size);

    int inode_number;

    if ((inode_number = inode_Get(ext2_Img, &ext2_SB, EXT2_ROOT_INO, path)) < 0) {
        return -ENOENT;
    }

    struct ext2_inode inode;
    status = inode_Read(ext2_Img, &inode, inode_number, &ext2_SB);
    if (status < 0) {
        return -errno;
    }

    stat->st_blksize = block_Size(&ext2_SB);
    stat->st_ino = inode_number;
    stat->st_mode = inode.i_mode;
    stat->st_nlink = inode.i_links_count;
    stat->st_uid = inode.i_uid;
    stat->st_gid = inode.i_gid;
    stat->st_size = inode.i_size;
    stat->st_blocks = inode.i_blocks;
    stat->st_atime = inode.i_atime;
    stat->st_mtime = inode.i_mtime;
    stat->st_ctime = inode.i_ctime;

    return 0;
}
static const struct fuse_operations ext2_ops = {
	.init = init_,
	.create = _create,
    .write = _write,
    .write_buf = _write_buf,
	.open = _open,
    .mkdir = _mkdir,
    .mknod = _mknod,
    .getattr = _getattr,
};

int ext2fuse(int img, const char *mntp)
{
	(void) img;

	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &ext2_ops, NULL);
}