/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

#define LOG_TAG "Binder"
#include <cutils/log.h>

void bio_init_from_txn(struct binder_io *io, struct binder_txn *txn);

#if TRACE
void hexdump(void *_data, unsigned len)
{
    unsigned char *data = _data;
    unsigned count;

    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            fprintf(stderr,"%04x:", count);
        fprintf(stderr," %02x %c", *data,
                (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            fprintf(stderr,"\n");
    }
    if ((count & 15) != 0)
        fprintf(stderr,"\n");
}

void binder_dump_txn(struct binder_txn *txn)
{
    struct binder_object *obj;
    unsigned *offs = txn->offs;
    unsigned count = txn->offs_size / 4;

    fprintf(stderr,"  target %p  cookie %p  code %08x  flags %08x\n",
            txn->target, txn->cookie, txn->code, txn->flags);
    fprintf(stderr,"  pid %8d  uid %8d  data %8d  offs %8d\n",
            txn->sender_pid, txn->sender_euid, txn->data_size, txn->offs_size);
    hexdump(txn->data, txn->data_size);
    while (count--) {
        obj = (void*) (((char*) txn->data) + *offs++);
        fprintf(stderr,"  - type %08x  flags %08x  ptr %p  cookie %p\n",
                obj->type, obj->flags, obj->pointer, obj->cookie);
    }
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

/**
 * 宏 BIO_F_SHARED 表示结构体binder_io内部的数据缓冲区是一块在内核空间分配的内核缓冲区，
 * 并且可以通过用户空间地址来共享访问。当进程使用完成这个数据缓冲区之后，
 * 它就必须使用BC_FREE_BUFFER命令协议来通知Binder驱动程序释放相应的内核缓冲区。
 */
#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
/**
 * BIO_F_OVERFLOW 表示数据溢出，即上次要求从结构体binder_io读出的数据的大小超出了其内部的数据缓冲区的大小；
 */
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
/**
 * BIO_F_IOERROR 表示上次从结构体binder_io读数据时发生了IO错误。
 */
#define BIO_F_IOERROR   0x04
/**
 * 宏 BIO_F_MALLOCED 表示结构体binder_io内部的数据缓冲区是通过函数malloc来分配的，
 * 即它指向的是一块在用户空间分配的缓冲区。当进程使用完成这个数据缓冲区之后，直接调用函数free释放它即可。
 */
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

/**
 * Service Manager 打开了设备文件 /dev/binder 之后，就会将得到的文件描述符
 * 保存在一个 binder_state 结构体的成员变量 fd 中，以便后面可以通过它来和 Binder 驱动程序交互。
 * Service Manager 将设备文件 /dev/binder 映射到自己的进程地址空间，并且将映射后得到的地址空间大小
 * 和起始地址保存在一个 binder_state 结构体的成员变量 mapsize 和 mapped 中;
 */ 
struct binder_state
{
    int fd; // 打开设备文件 /dev/binder 之后的文件描述符;
    void *mapped;   // 设备文件 /dev/binder 映射到自己进程空间后的起始地址;
    unsigned mapsize;   // 设备文件 /dev/binder 映射到自己进程空间后的地址空间大小;
};

/**
 * binder_open 用来打开设备文件 /dev/binder，并且将它映射到进程的地址空间;
 * binder_open 打开设备文件 /dev/binder 之后，就会将得到的文件描述符保存在一个 binder_state 结构体的成员变量 fd 中;
 * 以便后面可以通过它来和 Binder 驱动程序交互;
 * 同时将 设备文件 /dev/binder 映射到自己的进程地址空间，并且将映射后得到的地址空间大小和起始地址
 * 保存在一个 binder_state 结构体的成员变量 mapsize 和 mapped 中。
 * 
 * @mapsize : 参数mapsize的大小为 128*1024，即128K。
 */
struct binder_state *binder_open(unsigned mapsize)
{
    struct binder_state *bs;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return 0;
    }

    // 调用 open 打开设备文件 /dev/binder;
    // Binder 驱动程序中的函数 binder_open 就会调用，它会为当前进程创建一个 binder_proc 结构体，
    // 用来描述当前进程的Binder进程间通信状态;
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }

    bs->mapsize = mapsize;
    // 函数 mmap 将设备文件 /dev/binder 映射到进程的地址空间，它请求映射的地址空间大小为 mapsize，
    // 即请求 Binder 驱动程序为进程分配 128K 大小的内核缓冲区。映射后得到的地址空间的起始地址和大小分别保存
    // 在一个 binder_state 结构体 bs 的成员变量 mapped 和 mapsize 中。
    // 最后，将 binder_state 结构体 bs 返回给调用者。
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }

        /* TODO: check version */

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return 0;
}

void binder_close(struct binder_state *bs)
{
    munmap(bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

// 注册Binder进程间通信机制的上下文管理者;
int binder_become_context_manager(struct binder_state *bs)
{
    // Binder驱动程序是在它的函数 binder_ioctl 中处理IO控制命令 BINDER_SET_CONTEXT_MGR 的;
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}

/**
 * binder_write: 通过IO控制命令BINDER_WRITE_READ来将BC_FREE_BUFFER和BC_REPLY命令协议发送给Binder驱动程序;
 */
int binder_write(struct binder_state *bs, void *data, unsigned len)
{
    // 定义一个 binder_write_read 结构体 bwr;
    struct binder_write_read bwr;
    int res;
    bwr.write_size = len;
    bwr.write_consumed = 0;
    // 将 data 所指向的一块缓冲区作为它的输入缓冲区;
    // 将binder_write_read结构体bwr的输入缓冲区write_buffer设置为由参数data所描述的一块用户空间缓冲区;
    // eg:参数data所描述的一块用户空间缓冲区包含了一个BC_FREE_BUFFER和一个BC_REPLY命令协议;
    bwr.write_buffer = (unsigned) data;
    // 将输出缓冲区设置为空，这样，当前线程将自己注册到 Binder 驱动程序中之后，就会马上返回到用户空间，
    // 而不会在 Binder 驱动程序中等待 Client 进程的通信请求。
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    // 调用 ioct 将当前线程注册到 Binder 驱动程序中;
    // IO 控制命令 BINDER_WRITE_READ 是由 Binder 驱动程序中的函数 binder_ioctl 负责处理的;
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}

/**
 * binder_send_reply: 将Service组件注册结果返回给Binder驱动程序，Binder驱动程序再将该结果返回给请求注册Service组件的进程。
 * @reply: 指向一个binder_io结构体，它内部包含了进程间通信结果数据；
 * @buffer_to_free: 是一个用户空间地址，它指向了一块用来传输进程间通信数据的内核缓冲区；
 * @status: 用来描述Service Manager是否成功地处理了一个进程间通信请求，即是否成功地注册了一个Service组件。
 */
void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       void *buffer_to_free,
                       int status)
{
    // 定义了一个匿名结构体data，用来描述一个BC_FREE_BUFFER和一个BC_REPLY命令协议，
    // 分别用成员变量 cmd_free 和 cmd_reply 来表示。
    struct {
        uint32_t cmd_free;
        void *buffer;
        uint32_t cmd_reply;
        struct binder_txn txn;
    } __attribute__((packed)) data;

    // 设置匿名结构体data中的 BC_FREE_BUFFER 命令协议内容；
    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    // 设置匿名结构体data中的 BC_REPLY 命令协议内容
    data.cmd_reply = BC_REPLY;
    data.txn.target = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {
        // 如果参数status的值不等于0，就说明Service Manager在处理一个进程间通信请求时，发生了错误，
        // 错误代码就为status。在这种情况下，Service Manager需要将该错误代码通过 BC_REPLY 命令协议返回给Binder驱动程序，
        // 以便Binder驱动程序可以继续将它返回给发出该进程间通信请求的Client进程;
        data.txn.flags = TF_STATUS_CODE;
        data.txn.data_size = sizeof(int);
        data.txn.offs_size = 0;
        data.txn.data = &status;
        data.txn.offs = 0;
    } else {
        // 如果参数status的值等于0，就说明Service Manager成功地处理了一个进程间通信请求。
        // 在这种情况下，进程间通信结果就保存在binder_io结构体reply中，
        // 因此，就将binder_io结构体reply的数据缓冲区和偏移数组设置到匿名结构体data中，
        // 以便可以通过BC_REPLY命令协议返回给Binder驱动程序，Binder驱动程序再将它们返回给发出该进程间通信请求的Client进程。
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;
        data.txn.offs_size = ((char*) reply->offs) - ((char*) reply->offs0);
        data.txn.data = reply->data0;
        data.txn.offs = reply->offs0;
    }
    // 调用函数binder_write将匿名结构体data中的BC_FREE_BUFFER和BC_REPLY命令协议发送给Binder驱动程序。
    binder_write(bs, &data, sizeof(data));
}

/**
 * binder_parse: 处理从 Binder 驱动程序接收到的返回协议;
 */
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uint32_t *ptr, uint32_t size, binder_handler func)
{
    int r = 1;
    uint32_t *end = ptr + (size / 4);

    while (ptr < end) {
        // 从缓冲区ptr读出BR_TRANSACTION返回协议代码;
        uint32_t cmd = *ptr++;
#if TRACE
        fprintf(stderr,"%s:\n", cmd_name(cmd));
#endif
        switch(cmd) {
        case BR_NOOP:
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
#if TRACE
            fprintf(stderr,"  %08x %08x\n", ptr[0], ptr[1]);
#endif
            ptr += 2;
            break;
        case BR_TRANSACTION: {
            // 将BR_TRANSACTION返回协议内容读取到一个binder_txn结构体txn中。
            struct binder_txn *txn = (void *) ptr;
            if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) {
                LOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {
                unsigned rdata[256/4];
                // 定义了两个binder_io结构体msg和reply，
                // 其中，msg用来解析从Binder驱动程序读取回来的进程间通信数据；
                // 而reply用来将进程间通信结果数据保存到缓冲区rdata中，以便后面可以将它返回给Binder驱动程序。
                // 它们分别使用函数 bio_init 和 bio_init_from_txn 来初始化;
                struct binder_io msg;
                struct binder_io reply;
                int res;

                bio_init(&reply, rdata, sizeof(rdata), 4);
                bio_init_from_txn(&msg, txn);

                // 调用函数func来处理保存在binder_io结构体msg中的BR_TRANSACTION返回协议，
                // 并且将处理结果保存在binder_io结构体reply中。
                res = func(bs, txn, &msg, &reply);
                // 调用函数binder_send_reply将进程间通信结果，即binder_io结构体reply返回给Binder驱动程序。
                binder_send_reply(bs, &reply, txn->data, res);
            }
            ptr += sizeof(*txn) / sizeof(uint32_t);
            break;
        }
        case BR_REPLY: {
            struct binder_txn *txn = (void*) ptr;
            if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) {
                LOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                    /* todo FREE BUFFER */
            }
            ptr += (sizeof(*txn) / sizeof(uint32_t));
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (void*) *ptr++;
            death->func(bs, death->ptr);
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            LOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}

void binder_acquire(struct binder_state *bs, void *ptr)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = (uint32_t) ptr;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, void *ptr)
{
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = (uint32_t) ptr;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, void *ptr, struct binder_death *death)
{
    uint32_t cmd[3];
    cmd[0] = BC_REQUEST_DEATH_NOTIFICATION;
    cmd[1] = (uint32_t) ptr;
    cmd[2] = (uint32_t) death;
    binder_write(bs, cmd, sizeof(cmd));
}


int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                void *target, uint32_t code)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_txn txn;
    } writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        fprintf(stderr,"binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offs_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data = msg->data0;
    writebuf.txn.offs = msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned) &writebuf;
    
    hexdump(msg->data0, msg->data - msg->data0);
    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (unsigned) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            fprintf(stderr,"binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, readbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}

/* 函数 binder_loop 通过构造一个无限循环来等待和处理 Service 组件和 Client 组件的进程间通信请求;
 * @bs : 指向之前在 binder_open 中创建的一个 binder_state 结构体，保存有 /dev/binder 的文件句柄和映射的用户空间地址和大小;
 * @func : 指向 Service Manager 中的函数 svcmgr_handle，用来处理 Service 组件和 Client 组件的进程间通信请求;
 */
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    unsigned readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;
    
    // 使用 BC_ENTER_LOOPER 协议将自己注册到 Binder 驱动程序中;
    readbuf[0] = BC_ENTER_LOOPER;
    // 调用 binder_write 将它发送到 Binder 驱动程序中;
    binder_write(bs, readbuf, sizeof(unsigned));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (unsigned) readbuf;

        // 循环使用 IO 控制命令 BINDER_WRITE_READ 来检查 Binder 驱动程序是否有新的进程间通信请求需要它来处理;
        //      BINDER_WRITE_READ => binder_ioct->binder_thread_read 检查 Service Manager 进程是否有新的进程间通信请求需要处理;
        // 如果有，就将它们交给函数 binder_parse 来处理;
        // 否则，当前线程就会在 Binder 驱动程序中睡眠等待，直到有新的进程间通信请求到来为止;
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            LOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        // 如果有请求，就交给函数 binder_parse 来处理;
        res = binder_parse(bs, 0, readbuf, bwr.read_consumed, func);
        if (res == 0) {
            LOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            LOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}

/**
 * bio_init_from_txn
 * @bio: 指向要初始化的 binder_io 结构体;
 * @txn: 指向一个 binder_txn 结构体 txn, 它里面包含了binder_io结构体bio要解析的数据缓冲区和偏移数组。
 */
void bio_init_from_txn(struct binder_io *bio, struct binder_txn *txn)
{
    // 设置binder_io结构体bio的数据缓冲区和偏移数组，它们分别指向binder_txn结构体txn中的数据缓冲区和偏移数组。
    bio->data = bio->data0 = txn->data;
    bio->offs = bio->offs0 = txn->offs;
    // 设置binder_io结构体bio的数据缓冲区和偏移数组的可用大小。
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offs_size / 4;
    // 将binder_io结构体bio的成员变量flags的值设置为BIO_F_SHARED，表示它内部的数据缓冲区和偏移数组是在内核空间分配的。
    bio->flags = BIO_F_SHARED;
}

/**
 * bio_init
 * @bio: 指向要初始化的 binder_io 结构体;
 * @data: 指向 binder_io 结构体 bio 内部所使用的缓冲区;
 * @maxdata: 用来描述缓冲区data的大小;
 * @maxoffs: 描述 binder_io 结构体 bio 内部的偏移数组的大小;
 */
void bio_init(struct binder_io *bio, void *data,
              uint32_t maxdata, uint32_t maxoffs)
{
    uint32_t n = maxoffs * sizeof(uint32_t);

    // 判断binder_io结构体bio所需要的偏移数组的大小是否大于缓冲区data的大小。
    // 如果是，那么就说明缓冲区data的大小不足，因此，就直接返回了。
    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    // 将缓冲区data划分成两部分，其中一部分用于binder_io结构体bio的数据缓冲区，
    // 另一部分用于binder_io结构体bio的偏移数组。
    bio->data = bio->data0 = data + n;
    bio->offs = bio->offs0 = data;
    // 设置binder_io结构体bio的数据缓冲区和偏移数组的可用大小。
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

static void *bio_alloc(struct binder_io *bio, uint32_t size)
{
    size = (size + 3) & (~3);
    if (size > bio->data_avail) {
        bio->flags |= BIO_F_OVERFLOW;
        return 0;
    } else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

void binder_done(struct binder_state *bs,
                 struct binder_io *msg,
                 struct binder_io *reply)
{
    if (reply->flags & BIO_F_SHARED) {
        uint32_t cmd[2];
        cmd[0] = BC_FREE_BUFFER;
        cmd[1] = (uint32_t) reply->data0;
        binder_write(bs, cmd, sizeof(cmd));
        reply->flags = 0;
    }
}

static struct binder_object *bio_alloc_obj(struct binder_io *bio)
{
    struct binder_object *obj;

    obj = bio_alloc(bio, sizeof(*obj));
    
    if (obj && bio->offs_avail) {
        bio->offs_avail--;
        *bio->offs++ = ((char*) obj) - ((char*) bio->data0);
        return obj;
    }

    bio->flags |= BIO_F_OVERFLOW;
    return 0;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
    uint32_t *ptr = bio_alloc(bio, sizeof(n));
    if (ptr)
        *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
    struct binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_BINDER;
    obj->pointer = ptr;
    obj->cookie = 0;
}

void bio_put_ref(struct binder_io *bio, void *ptr)
{
    struct binder_object *obj;

    if (ptr)
        obj = bio_alloc_obj(bio);
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_HANDLE;
    obj->pointer = ptr;
    obj->cookie = 0;
}

void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
    uint32_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = 0;
    while (str[len]) len++;

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    bio_put_uint32(bio, len);
    len = (len + 1) * sizeof(uint16_t);
    ptr = bio_alloc(bio, len);
    if (ptr)
        memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
    unsigned char *str = (unsigned char*) _str;
    uint32_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = strlen(_str);

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    bio_put_uint32(bio, len);
    ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
    if (!ptr)
        return;

    while (*str)
        *ptr++ = *str++;
    *ptr++ = 0;
}

/**
 * bio_get
 * @size: 表示要从binder_io结构体bio的数据缓冲区的当前位置读取的数据对象的大小;
 */
static void *bio_get(struct binder_io *bio, uint32_t size)
{
    // 将它对齐到4个字节边界。
    size = (size + 3) & (~3);

    // if语句检查 binder_io 结构体 bio 的数据缓冲区的剩余未解析字节数 data_avail 是否
    // 小于要求读取的字节数size。如果是，就说明出错了;
    if (bio->data_avail < size){
        bio->data_avail = 0;
        // 将binder_io结构体bio的成员变量flags的BIO_F_OVERFLOW位设置为1，接着返回一个地址值0给调用者。
        bio->flags |= BIO_F_OVERFLOW;
        return 0;
    }  else {
        // 如果binder_io结构体bio的数据缓冲区的剩余未解析字节数data_avail大于或者等于要求读取的字节数size;
        // 就将binder_io结构体bio的数据缓冲区data的当前位置保存在变量ptr中。
        void *ptr = bio->data;
        // 再将它往前推进size个字节;
        bio->data += size;
        // 将binder_io结构体bio的数据缓冲区的剩余未读取字节数减少size个字节;
        bio->data_avail -= size;
        // 将变量ptr的值返回给调用者;
        return ptr;
    }
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
    uint32_t *ptr = bio_get(bio, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, unsigned *sz)
{
    unsigned len;
    len = bio_get_uint32(bio);
    if (sz)
        *sz = len;
    return bio_get(bio, (len + 1) * sizeof(uint16_t));
}

/**
 * 函数_bio_get_obj: 从binder_io结构体bio的数据缓冲区的当前位置读取一个binder_object结构体;
 */
static struct binder_object *_bio_get_obj(struct binder_io *bio)
{
    unsigned n;
    unsigned off = bio->data - bio->data0;

        /* TODO: be smarter about this? */
    // for循环检查binder_io结构体bio的数据缓冲区的当前位置保存的是否是一个binder_object结构体，
    // 方法是检查binder_io结构体bio的偏移数组中是否有一个元素的值刚好等于binder_io结构体bio的数据缓冲区的当前位置。
    // 合法性检查通过之后，就继续调用函数 bio_get 将该binder_object结构体读取出来。
    for (n = 0; n < bio->offs_avail; n++) {
        if (bio->offs[n] == off)
            return bio_get(bio, sizeof(struct binder_object));
    }

    bio->data_avail = 0;
    bio->flags |= BIO_F_OVERFLOW;
    return 0;
}

/**
 * 函数bio_get_ref: 通过调用函数_bio_get_obj从binder_io结构体bio中取出一个binder_object结构体obj。
 * 如果取出来的binder_object结构体obj的类型为BINDER_TYPE_HANDLE，那么就将它的成员变量pointer返回给调用者。
 * 类型为BINDER_TYPE_HANDLE的binder_object结构体的成员变量pointer保存的是一个由Binder驱动程序创建的Binder引用对象的句柄值，
 * 这个Binder引用对象引用了即将要注册的Service组件。
 */
void *bio_get_ref(struct binder_io *bio)
{
    struct binder_object *obj;

    obj = _bio_get_obj(bio);
    if (!obj)
        return 0;

    if (obj->type == BINDER_TYPE_HANDLE)
        return obj->pointer;

    return 0;
}
