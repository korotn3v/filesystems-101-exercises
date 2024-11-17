#include <solution.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fs_malloc.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_fs.h>
#include <errno.h>
#include <unistd.h>

void report_file(int inode_nr, char type, const char *name){
    printf("Inode: %d, Type: %c, Name: %s\n", inode_nr, type, name);
}

int read_block(int img, int* buffer, int* left_to_copy, int block_size, int block) {
    if (pread(img, buffer, block_size, block_size * block) < block_size) {
        fprintf(stderr, "cant read from img (block %d)\n", block);
        return -errno;
    }

    int size_to_process = (*left_to_copy < block_size) ? *left_to_copy : block_size;
    *left_to_copy -= size_to_process;
    int shift = 0;

    while (shift < size_to_process) {
        struct ext2_dir_entry_2* entry = (struct ext2_dir_entry_2*)((char*)buffer + shift);

        if (entry->inode == 0) {
            break;
        }

        if (entry->rec_len == 0 || shift + entry->rec_len > block_size) {
            fprintf(stderr, "bad catalog: invalid rec_len in entry (inode: %d, rec_len: %d)\n", entry->inode, entry->rec_len);
            return -EINVAL;
        }

        char name[EXT2_NAME_LEN + 1] = {0};
        memcpy(name, entry->name, entry->name_len);
        name[entry->name_len] = '\0';

        char type = '?';
        if (entry->file_type == EXT2_FT_DIR) {
            type = 'd';
        } else if (entry->file_type == EXT2_FT_REG_FILE) {
            type = 'f';
        } else {
            fprintf(stderr, "Unknown file type: %d\n", entry->file_type);
            return -EINVAL;
        }

        report_file(entry->inode, type, name);

        shift += entry->rec_len;
    }

    return 0;
}


int dump_dir(int img, int inode_nr)
{
    struct ext2_super_block super_block;
    int read_sb = pread(img, &super_block, SUPERBLOCK_SIZE, SUPERBLOCK_OFFSET);
    if (read_sb < 0) {
        fprintf(stderr, "cant read superblock from img\n");
        return -errno;
    }

    int group_id = (inode_nr - 1) / super_block.s_inodes_per_group;
    int inode_id = (inode_nr - 1) % super_block.s_inodes_per_group;
    int block_size = EXT2_BLOCK_SIZE(&super_block);

    struct ext2_group_desc group_desc;
    int read_group_desc = pread(img, &group_desc, sizeof(group_desc), block_size * (super_block.s_first_data_block + 1) + sizeof(group_desc) * group_id);
    if (read_group_desc < 0) {
        fprintf(stderr, "cant read group_desc from img\n");
        return -errno;
    }

    struct ext2_inode inode;
    int read_inode = pread(img, &inode, sizeof(inode), block_size * group_desc.bg_inode_table + super_block.s_inode_size * inode_id);
    if (read_inode < 0) {
        fprintf(stderr, "cant read inode from img\n");
        return -errno;
    }

    int left_to_copy = inode.i_size;
    int* direct_block = fs_xmalloc(block_size);
    int* indirect_block = NULL;
    int* double_indirect_block = NULL;
    int i = 0;
    int read_block_result = 0;

    while(i < EXT2_N_BLOCKS && left_to_copy > 0 && inode.i_block[i] != 0){

        if(i < EXT2_NDIR_BLOCKS){
            read_block_result = read_block(img, direct_block, &left_to_copy, block_size, inode.i_block[i]);
            if(read_block_result < 0){
                free(direct_block);
                return read_block_result;
            }
        }

        if(i == EXT2_IND_BLOCK){
            if (pread(img, direct_block, block_size, block_size * inode.i_block[i]) < block_size) {
                free(direct_block);
                return -errno;
            }
            if(!indirect_block){
                indirect_block = fs_xmalloc(block_size);
            }

            int k = 0;
            while (k < (block_size / (int)sizeof(int)) && direct_block[k] != 0 && left_to_copy > 0){
                read_block_result = read_block(img, indirect_block, &left_to_copy, block_size, direct_block[k]);
                if(read_block_result < 0){
                    free(direct_block);
                    free(indirect_block);
                    return read_block_result;
                }
                k++;
            }
        }

        if(i == EXT2_DIND_BLOCK){
            if (pread(img, direct_block, block_size, block_size * inode.i_block[i]) < block_size) {
                free(direct_block);
                free(indirect_block);
                return -errno;
            }
            if(!indirect_block){
                indirect_block = fs_xmalloc(block_size);
            }
            int k = 0;
            while (k < (block_size / (int)sizeof(int)) && left_to_copy > 0 && direct_block[k] != 0){
                if (pread(img, indirect_block, block_size, block_size * direct_block[k]) < block_size) {
                    free(direct_block);
                    free(indirect_block);
                    free(double_indirect_block);
                    return -errno;
                }

                if(!double_indirect_block){
                    double_indirect_block = fs_xmalloc(block_size);
                }

                int n = 0;
                while (n < (block_size / (int)sizeof(int)) && left_to_copy > 0 && indirect_block[n] != 0){
                    read_block_result = read_block(img, double_indirect_block, &left_to_copy, block_size, indirect_block[n]);
                    if(read_block_result < 0){
                        free(direct_block);
                        free(indirect_block);
                        free(double_indirect_block);
                        return read_block_result;
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
