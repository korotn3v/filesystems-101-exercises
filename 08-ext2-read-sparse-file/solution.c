#include <solution.h>

#include <solution.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <ext2fs/ext2fs.h>

int dir_copy(int img, void* buf, const int block_size, const int block, int* left, int out) {

    int write_size;

    if (block_size < *left) {
        write_size = block_size;
    } else {
        write_size = *left;
    }

    if (pread(img, buf, write_size, block_size * block) < write_size) {
        return -errno;
    }

    if (write(out, buf, write_size) < write_size) {
        return -errno;
    } else {
        *left -= write_size;
    }

    return 0;
}

int in_dir_copy(int img, int* buf, const int block_size, const int block, int* left, int out, int flag) {

    if (pread(img, buf, block_size, block_size * block) < block_size) {
        return -errno;
    }

    void* another_buf = malloc(block_size);

    int k = 0;
    int result = 0;
    while (result >= 0 && k < (block_size / (int)sizeof(int)) && *left > 0) {
        if (flag == 0) {
            result = dir_copy(img, another_buf, block_size, buf[k], left, out);
        } else {
            result = in_dir_copy(img, (int*)another_buf, block_size, buf[k], left, out, 0);
        }
        ++k;
    }
    free(another_buf);
    return result;
}

int dump_file(int img, int inode_nr, int out) {

    struct ext2_super_block super_block;
    int result = pread(img, &super_block, SUPERBLOCK_SIZE, SUPERBLOCK_OFFSET);

//    if (result <  SUPERBLOCK_SIZE) {
//        return -errno;
//    }

    if (result < 0) {
        return -errno;
    }

    int block_size = EXT2_BLOCK_SIZE(&super_block);

    struct ext2_group_desc group_block;
    int id_group = (inode_nr - 1) / super_block.s_inodes_per_group;

    result = pread(img, &group_block, sizeof(group_block), block_size * (super_block.s_first_data_block + 1) + sizeof(group_block) * id_group);

//    if (result < sizeof(group_block)) {
//        return -errno;
//    }

    if (result < 0) {
        return -errno;
    }

    int id_inode = (inode_nr - 1) % super_block.s_inodes_per_group;

    struct ext2_inode inode;
    result = pread(img, &inode, sizeof(inode), block_size * group_block.bg_inode_table + super_block.s_inode_size * id_inode);

//    if (result < sizeof(inode)) {
//        return -errno;
//    }

    if (result < 0) {
        return -errno;
    }

    int copy_left = inode.i_size;
    void* buf = malloc(block_size);
    int k = 0;
    while (copy_left > 0 && k < EXT2_N_BLOCKS) {
        int result = -1;
        if (k < EXT2_NDIR_BLOCKS) {
            result = dir_copy(img, buf, block_size, inode.i_block[k], &copy_left, out);
        } else if (k == EXT2_DIND_BLOCK) {
            result = in_dir_copy(img, (int*)buf, block_size, inode.i_block[k], &copy_left, out, 1);
        } else if (k == EXT2_IND_BLOCK) {
            result = in_dir_copy(img, (int*)buf, block_size, inode.i_block[k], &copy_left, out, 0);
        }
        if (result < 0) {
            free(buf);
            return result;
        }
        ++k;
    }
    free(buf);
    return 0;
}