#include <solution.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fs_malloc.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_fs.h>
#include <errno.h>
#include <unistd.h>

int dump_file(int img, int inode_nr, int out)
{
	struct ext2_super_block super_block;
    int read_sb = pread(img, &super_block, SUPERBLOCK_SIZE, SUPERBLOCK_OFFSET);
    if (read_sb < 0) {
        return -errno;
    }

    int group_id = (inode_nr - 1) / super_block.s_inodes_per_group;
    int inode_id = (inode_nr - 1) % super_block.s_inodes_per_group;
    int block_size = EXT2_BLOCK_SIZE(&super_block);

    struct ext2_group_desc group_desc;
    int read_group_desc = pread(img, &group_desc, sizeof(group_desc), block_size * (super_block.s_first_data_block + 1) + sizeof(group_desc) * group_id);
    if (read_group_desc < 0) {
        return -errno;
    }

    struct ext2_inode inode;
    int read_inode = pread(img, &inode, sizeof(inode), block_size * group_desc.bg_inode_table + super_block.s_inode_size * inode_id);
    if (read_inode < 0) {
        return -errno;
    }

    int left_to_copy = inode.i_size;
    int* direct_block = fs_xmalloc(block_size);
    int* indirect_block = NULL;
    int* double_indirect_block = NULL;
    int i = 0;

    while (i < EXT2_N_BLOCKS && left_to_copy > 0 && inode.i_block[i] != 0) {

        if(i < EXT2_NDIR_BLOCKS){
            if (pread(img, direct_block, block_size, block_size * inode.i_block[i]) < block_size) {
                return -errno;
            }

            int size_to_write = (block_size < left_to_copy) ? block_size : left_to_copy;

            if (write(out, direct_block, size_to_write) < size_to_write) {
                return -errno;
            } else {
                left_to_copy -= size_to_write;
            }
        }

        if(i < EXT2_DIND_BLOCK){
            if (pread(img, direct_block, block_size, block_size * inode.i_block[i]) < block_size) {
                return -errno;
            }
            if(!indirect_block){
                indirect_block = fs_xmalloc(block_size);
            }

            int k = 0;
            while (k < (block_size / (int)sizeof(int)) && left_to_copy > 0 && direct_block[k] != 0){
                if (pread(img, indirect_block, block_size, block_size * direct_block[k]) < block_size) {
                    return -errno;
                }

                int size_to_write = (block_size < left_to_copy) ? block_size : left_to_copy;

                if (write(out, indirect_block, size_to_write) < size_to_write) {
                    return -errno;
                } else {
                    left_to_copy -= size_to_write;
                }

                k++;
            }
        }

        if(i < EXT2_TIND_BLOCK){
            if (pread(img, direct_block, block_size, block_size * inode.i_block[i]) < block_size) {
                return -errno;
            }
            if(!indirect_block){
                indirect_block = fs_xmalloc(block_size);
            }

            int k = 0;
            while (k < (block_size / (int)sizeof(int)) && left_to_copy > 0 && direct_block[k] != 0){
                if (pread(img, indirect_block, block_size, block_size * direct_block[k]) < block_size) {
                    return -errno;
                }

                if(!double_indirect_block){
                    double_indirect_block = fs_xmalloc(block_size);
                }

                int n = 0;
                while (n < (block_size / (int)sizeof(int)) && left_to_copy > 0 && indirect_block[n] != 0){
                    if (pread(img, double_indirect_block, block_size, block_size * indirect_block[n]) < block_size) {
                        return -errno;
                    }

                    int size_to_write = (block_size < left_to_copy) ? block_size : left_to_copy;

                    if (write(out, double_indirect_block, size_to_write) < size_to_write) {
                        return -errno;
                    } else {
                        left_to_copy -= size_to_write;
                    }

                    n++;
                }

                k++;
            }
        }

        i++;
    }
    free(direct_block);
    if(indirect_block){
        free(indirect_block);
    }
    if(double_indirect_block){
        free(double_indirect_block);
    }
	return 0;
}
