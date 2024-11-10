#include <solution.h>
#include <fs_malloc.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_fs.h>
#include <errno.h>
#include <unistd.h>

#include <errno.h>

struct ext2_fs
{
	int fd;
	int block_size;
	struct ext2_super_block sb;
};

struct ext2_blkiter
{
	struct ext2_fs *fs;
	int inode_table;

	struct ext2_inode inode;
	int current;

	int *indirect_block;
	int *double_indirect_block;
};

int ext2_fs_init(struct ext2_fs **fs, int fd)
{
    struct ext2_fs *fs_temp = fs_xmalloc(sizeof(struct ext2_fs));
    fs_temp->fd = fd;

    ssize_t read_sb = pread(fs_temp->fd, &fs_temp->sb, SUPERBLOCK_SIZE, SUPERBLOCK_OFFSET);
    if(read_sb == -1){
        fs_xfree(fs_temp);
        return -errno;
    }

    fs_temp->block_size = EXT2_BLOCK_SIZE(&fs_temp->sb);
    *fs = fs_temp;

    return 0;
}

void ext2_fs_free(struct ext2_fs *fs)
{
	fs_xfree(fs);
}

int ext2_blkiter_init(struct ext2_blkiter **i, struct ext2_fs *fs, int ino)
{
    size_t desc_per_block = fs->block_size / sizeof(struct ext2_group_desc);
    size_t ino_group = (ino - 1) / fs->sb.s_inodes_per_group;
    size_t ino_id = (ino - 1) % fs->sb.s_inodes_per_group;
    size_t offset = fs->block_size * (fs->sb.s_first_data_block + 1 + (ino_group / desc_per_block));
    size_t block_offset = (ino_group % desc_per_block) * sizeof(struct ext2_group_desc);

    struct ext2_group_desc group_desc;
    ssize_t read_group_desc = pread(fs->fd, &group_desc, sizeof(group_desc), offset + block_offset);
    if(read_group_desc == -1){
        return -errno;
    }

    struct ext2_blkiter *i_temp = fs_xmalloc(sizeof(struct ext2_blkiter));
    i_temp->inode_table = group_desc.bg_inode_table;

    ssize_t read_inode = pread(fs->fd, &i_temp->inode, sizeof(struct ext2_inode), fs->block_size * i_temp->inode_table + ino_id * fs->sb.s_inode_size);
    if (read_inode == -1){
        return -errno;
    }

    *i = i_temp;
    i_temp->current = 0;

    i_temp->fs = fs;

    i_temp->indirect_block = NULL;
    i_temp->double_indirect_block = NULL;

    return 0;
}

int ext2_blkiter_next(struct ext2_blkiter *i, int *blkno)
{
	int ptrs_per_block = i->fs->block_size / sizeof(int);

    int direct_end = EXT2_NDIR_BLOCKS;
    int indirect_start = direct_end;
    int indirect_end = direct_end + ptrs_per_block;
    int double_indirect_start = indirect_end;
    int double_indirect_end = indirect_end + ptrs_per_block * ptrs_per_block;

    if (i->current < direct_end){
        int ptr = i->inode.i_block[i->current];
        if (ptr == 0){
            return 0;
        }

        *blkno = ptr;
        i->current++;
        return 1;
    }

    if(i->current < indirect_end){
        if (!i->indirect_block) {
            i->indirect_block = fs_xmalloc(i->fs->block_size);
            if (pread(i->fs->fd, i->indirect_block, i->fs->block_size, i->inode.i_block[EXT2_IND_BLOCK] * i->fs->block_size) == -1) {
                return -errno;
            }
//            *blkno = i->inode.i_block[EXT2_IND_BLOCK];
//            return 1;
        }

        if (i->indirect_block[i->current - indirect_start] == 0) {
            return 0;
        }

        *blkno = i->indirect_block[i->current - indirect_start];
        i->current++;
        return 1;
    }

    if (i->current < double_indirect_end){
        if (!i->double_indirect_block){
            i->double_indirect_block = fs_xmalloc(i->fs->block_size);
            if (pread(i->fs->fd, i->double_indirect_block, i->fs->block_size, i->inode.i_block[EXT2_DIND_BLOCK] * i->fs->block_size) == -1){
                return -errno;
            }
            *blkno = i->inode.i_block[EXT2_DIND_BLOCK];
            return 1;
        }

        int indirect_pos = (i->current - double_indirect_start) / ptrs_per_block;
        int double_indirect_pos = (i->current - double_indirect_start) % ptrs_per_block;
        int block_offset = i->double_indirect_block[indirect_pos] * i->fs->block_size;

        if (i->indirect_block != (int *)block_offset){
            if (pread(i->fs->fd, i->indirect_block, i->fs->block_size, block_offset) == -1){
                return -errno;
            }
            *blkno = i->double_indirect_block[double_indirect_pos];
            return 1;
        }

        if (i->indirect_block[double_indirect_pos] == 0){
            return 0;
        }

        *blkno = i->indirect_block[double_indirect_pos];
        i->current++;
        return 1;
    }
    return 0;
}

void ext2_blkiter_free(struct ext2_blkiter *i)
{
	if (i != NULL){
        fs_xfree(i->indirect_block);
        fs_xfree(i->double_indirect_block);
        fs_xfree(i);
    }
}
