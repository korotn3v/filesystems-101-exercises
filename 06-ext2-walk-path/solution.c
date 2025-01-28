#include "solution.h"
#include <ext2fs/ext2fs.h>
#include <unistd.h>
#include <sys/stat.h>

#define EXT2_SB_OFFSET 1024
int inode_Directory(int img, struct ext2_super_block* SB, size_t blk, const char* path);
int block_Size(struct ext2_super_block* SB) {
    return 1024 << SB->s_log_block_size;
}

int block_Read(int img, int out, size_t blk, size_t blk_size, size_t _part) {

    char buffer[_part];

    int status = pread(img, buffer, _part, blk * blk_size);

    if (status < 0) {
        return -errno;
    }
    status = write(out, buffer, _part);

    if ( status < 0) {
        return -errno;
    }

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

int copy_file(int img, int out, struct ext2_super_block* SB, int inode_number, struct ext2_inode *inode) {

    size_t blk_size = EXT2_BLOCK_SIZE(SB);
    int status = inode_Read(img, inode, inode_number, SB);

    if (status < 0) {
        return -errno;
    }

    size_t read = inode->i_size;

    size_t _part = 0;

    for (size_t i = 0; i < EXT2_NDIR_BLOCKS; ++i) {

        if (read > blk_size) {
            _part = blk_size;
        }
        else {
            _part = read;
        }
        status = block_Read(img, out, inode->i_block[i], blk_size, _part);
        if (status < 0) {
          return -errno;
        }

        if (!(read -= _part)) {
            return 0;
        }
    }


    _part = 0;
    uint32_t* blk = malloc(blk_size);
    status = pread(img, blk, blk_size, blk_size * inode->i_block[EXT2_IND_BLOCK]);
    if (status < 0) {
        free(blk);
        return -errno;
    }

    for (uint i = 0; i < blk_size / sizeof(int); ++i) {
        _part = read > blk_size ? blk_size : read;

        if (block_Read(img, out, blk[i], blk_size, _part) < 0) {
          free(blk);
          return -errno;
        }

        if (!(read -= _part)) {
            free(blk);
            return 0;
        }

      }

      free(blk);



    _part = 0;
    size_t num = blk_size / sizeof(int);
    uint32_t* double_blk = malloc(2 * blk_size);
    uint32_t* blk_index = double_blk + num;
    if (pread(img, double_blk, blk_size, inode->i_block[EXT2_DIND_BLOCK] * blk_size) < 0) {
        free(double_blk);
        return -errno;
    }

    for (size_t i = 0; i < num; ++i) {
        if (pread(img, blk_index, blk_size, double_blk[i] * blk_size) < 0) {
          free(double_blk);
          return -errno;
        }
        for (size_t j = 0; j < num; ++j) {

            if (read > blk_size) {
                _part = blk_size;
            }
            else {
                _part = read;
            }

            if (block_Read(img, out, blk_index[j], blk_size, _part) < 0) {
                free(double_blk);
                return -errno;
            }

            if (!(read -= _part)) {
                free(double_blk);
                return 0;
            }
        }
    }

    free(double_blk);

    return 0;
}

int dump_file(int img, const char *path, int out)
{
	struct ext2_super_block SB;
    struct ext2_inode inode;
    int status;
    size_t SB_size = sizeof(struct ext2_super_block);
    status = pread(img, &SB, SB_size, EXT2_SB_OFFSET);
    if (status < 0) {
        return -errno;
    }
    int inode_number = inode_Get(img, &SB, 2, path);

    if (inode_number < 0) {
        return inode_number;
    }
    status = inode_Read(img, &inode, inode_number, &SB);
    if (status < 0) {
        return -errno;
    }
    status = copy_file(img, out, &SB, inode_number, &inode);
    if (status < 0) {
        return -errno;
    }

    return 0;
}