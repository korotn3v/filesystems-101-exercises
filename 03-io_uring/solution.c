#include "solution.h"

#include <liburing.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define QUEUE_CAPACITY 4
#define BLOCKSIZE 256 * 1024

struct req_data {
    int is_read;
    off_t offset;
    size_t buf_size;
    char* buffer;
};

int read_q(struct io_uring* ring, size_t buf_size, off_t offset, int fd) {

    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        return 1;
    }

    struct req_data* req_data = (struct req_data*) malloc(buf_size + sizeof(*req_data));
    if (!req_data) {
        return 1;
    }

    req_data->is_read  = 1;
    req_data->offset  = offset;
    req_data->buf_size = buf_size;
    req_data->buffer = (char*)req_data + sizeof(*req_data);

    io_uring_prep_read(sqe, fd, req_data->buffer, buf_size, offset);
    io_uring_sqe_set_data(sqe, req_data);

    return 0;
}

int write_q(struct io_uring* ring, struct req_data* req_data, int fd) {

    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        return 1;
    }

    req_data->is_read = 0;

    io_uring_prep_write(sqe, fd, req_data->buffer, req_data->buf_size, req_data->offset);
    io_uring_sqe_set_data(sqe, req_data);

    return 0;
}

int copy(int in, int out) {

    struct io_uring ring;
    if (io_uring_queue_init(QUEUE_CAPACITY, &ring, 0) < 0) {
        return -errno;
    }

    struct stat st;
    if (fstat(in, &st) < 0) {
        return -errno;
    }
    off_t read_left = st.st_size;
    off_t write_left = read_left;
    off_t offset = 0;

    int reads_q = 0;
    int writes_q = 0;

    struct io_uring_cqe* cqe;

    while (read_left || write_left || writes_q) {

        int read_flag = 0;
        while (read_left) {

            if (reads_q + writes_q == QUEUE_CAPACITY) {
                break;
            }

            size_t buf_size;
            if (read_left > BLOCKSIZE) {
                buf_size = BLOCKSIZE;
            } else {
                buf_size = read_left;
            }

            if (read_q(&ring, buf_size, offset, in)) {
                break;
            }

            read_left -= buf_size;
            offset += buf_size;
            reads_q++;
            read_flag = 1;
        }

        if (read_flag) {
            if (io_uring_submit(&ring) < 0) {
                return -errno;
            }
        }

        int get_cqe_flag = 0;

        while (write_left || writes_q) {

            if (!get_cqe_flag) {
                if (io_uring_wait_cqe(&ring, &cqe) < 0) {
                    return -errno;
                }
                get_cqe_flag = 1;
            } else {
                if (io_uring_peek_cqe(&ring, &cqe) == -EAGAIN) {
                    break;
                }
            }

            struct req_data* req_data = io_uring_cqe_get_data(cqe);

            if (req_data->is_read) {

                if (write_q(&ring, req_data, out)) {
                    break;
                }

                io_uring_submit(&ring);
                reads_q--;
                writes_q++;
                write_left -= req_data->buf_size;
            } else {
                free(req_data);
                writes_q--;
            }
            io_uring_cqe_seen(&ring, cqe);
        }
    }
    io_uring_queue_exit(&ring);
    return 0;
}