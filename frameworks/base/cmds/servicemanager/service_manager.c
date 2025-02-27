/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <private/android_filesystem_config.h>

#include "binder.h"

#if 0
#define LOGI(x...) fprintf(stderr, "svcmgr: " x)
#define LOGE(x...) fprintf(stderr, "svcmgr: " x)
#else
#define LOG_TAG "ServiceManager"
#include <cutils/log.h>
#endif

/* TODO:
 * These should come from a config file or perhaps be
 * based on some namespace rules of some sort (media
 * uid can register media.*, etc)
 */
static struct {
    // uid用来描述一个用户ID;
    unsigned uid;
    // name用来描述一个服务名称;
    const char *name;
} allowed[] = {
#ifdef LVMX
    { AID_MEDIA, "com.lifevibes.mx.ipc" },
#endif
    // 只有用户ID为uid的进程才可以注册名称为name的Service组件。
    // 例如，匿名结构体{AID_MEDIA，"media.audio_flinger"}
    // 表示只有用户ID为 AID_MEDIA 的进程才可以注册名称为 "media.audio_flinger" 的Service组件。
    { AID_MEDIA, "media.audio_flinger" },
    { AID_MEDIA, "media.player" },
    { AID_MEDIA, "media.camera" },
    { AID_MEDIA, "media.audio_policy" },
    { AID_NFC,   "nfc" },
    { AID_RADIO, "radio.phone" },
    { AID_RADIO, "radio.sms" },
    { AID_RADIO, "radio.phonesubinfo" },
    { AID_RADIO, "radio.simphonebook" },
/* TODO: remove after phone services are updated: */
    { AID_RADIO, "phone" },
    { AID_RADIO, "sip" },
    { AID_RADIO, "isms" },
    { AID_RADIO, "iphonesubinfo" },
    { AID_RADIO, "simphonebook" },
};

void *svcmgr_handle;

const char *str8(uint16_t *x)
{
    static char buf[128];
    unsigned max = 127;
    char *p = buf;

    if (x) {
        while (*x && max--) {
            *p++ = *x++;
        }
    }
    *p++ = 0;
    return buf;
}

int str16eq(uint16_t *a, const char *b)
{
    while (*a && *b)
        if (*a++ != *b++) return 0;
    if (*a || *b)
        return 0;
    return 1;
}

/**
 * 将Service组件注册到Service Manager是一种特权，即不是所有的进程都可以将Service组件注册Service Manager中。
 * Service Manager定义了一个全局数组 allowed，它定义了哪些进程可以注册什么名称的Service组件;
 */
int svc_can_register(unsigned uid, uint16_t *name)
{
    unsigned n;
    
    // 系统进程，直接返回有权限（注册服务）;
    if ((uid == 0) || (uid == AID_SYSTEM))
        return 1;

    // for循环检查参数uid和name是否对应于数组allowed中的某一个元素。
    // 如果是，就说明用户ID为uid的进程有权限将名称为name的Service组件注册到Service Manager中;
    for (n = 0; n < sizeof(allowed) / sizeof(allowed[0]); n++)
        if ((uid == allowed[n].uid) && str16eq(name, allowed[n].name))
            // 返回1给调用者，表示可以注册一个名称为name的Service组件。
            return 1;

    return 0;
}

/**
 * 每一个被注册了的Service组件都使用一个svcinfo结构体来描述;
 */
struct svcinfo 
{
    // next用来指向下一个svcinfo结构体;
    struct svcinfo *next;
    // ptr是一个句柄值，用来描述一个注册了的Service组件;
    void *ptr;
    // death指向一个binder_death结构体，用来描述一个死亡接收通知;
    struct binder_death death;
    // name和len分别用来描述已经注册了的Service组件的名称及其长度;
    unsigned len;
    uint16_t name[0];
};

struct svcinfo *svclist = 0;

/**
 * find_svc: 检查服务名称 s16 是否被已经注册了的 Service 组件使用了;
 * 在Service Manager中，每一个被注册了的Service组件都使用一个svcinfo结构体来描述，并且保存在一个全局队列svclist中。
 */
struct svcinfo *find_svc(uint16_t *s16, unsigned len)
{
    struct svcinfo *si;

    // for循环依次检查全局队列svclist中的已注册Service组件列表。
    // 如果发现参数s16所描述的Service组件名称已经被使用了，
    // 那么就会将与参数s16所对应的一个svcinfo结构体返回给调用者。
    for (si = svclist; si; si = si->next) {
        if ((len == si->len) &&
            !memcmp(s16, si->name, len * sizeof(uint16_t))) {
            return si;
        }
    }
    return 0;
}

void svcinfo_death(struct binder_state *bs, void *ptr)
{
    struct svcinfo *si = ptr;
    LOGI("service '%s' died\n", str8(si->name));
    if (si->ptr) {
        binder_release(bs, si->ptr);
        si->ptr = 0;
    }   
}

uint16_t svcmgr_id[] = { 
    'a','n','d','r','o','i','d','.','o','s','.',
    'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' 
};
  

void *do_find_service(struct binder_state *bs, uint16_t *s, unsigned len)
{
    struct svcinfo *si;
    si = find_svc(s, len);

//    LOGI("check_service('%s') ptr = %p\n", str8(s), si ? si->ptr : 0);
    if (si && si->ptr) {
        return si->ptr;
    } else {
        return 0;
    }
}

/**
 * do_add_service: 将 Service 组件注册到 Service Manager 中;
 * @s: 表示要注册的Service组件的名称;
 * @uid: 表示请求Service Manager注册Service组件的进程的用户ID;
 */
int do_add_service(struct binder_state *bs,
                   uint16_t *s, unsigned len,
                   void *ptr, unsigned uid)
{
    struct svcinfo *si;
//    LOGI("add_service('%s',%p) uid=%d\n", str8(s), ptr, uid);

    if (!ptr || (len == 0) || (len > 127))
        return -1;

    // 调用函数svc_can_register来检查用户ID为uid的进程是否有权限请求Service Manager注册一个名称为s的Serivce组件。
    // 如果没有，就直接返回错误码 -1 给调用者。
    if (!svc_can_register(uid, s)) {
        LOGE("add_service('%s',%p) uid=%d - PERMISSION DENIED\n",
             str8(s), ptr, uid);
        return -1;
    }

    // 通过了注册Service组件的权限检查之后，
    // 接着继续调用函数 find_svc 来检查服务名称 s 是否被已经注册了的 Service 组件使用了。
    si = find_svc(s, len);
    if (si) {
        // 如果指定要注册的Service组件的名称s已经被使用了,
        // 就继续检查与名称s关联的svcinfo结构体si的成员变量ptr的值是否等于NULL。
        // 如果不等于，那么就说明该名称s已经被使用了，因此，直接返回一个错误码-1给调用者；
        // 否则，就将svcinfo结构体si的成员变量ptr的值修改为参数ptr的值，
        // 即将它修改为一个引用了要注册的Service组件的Binder引用对象的句柄值。
        if (si->ptr) {
            LOGE("add_service('%s',%p) uid=%d - ALREADY REGISTERED\n",
                 str8(s), ptr, uid);
            return -1;
        }
        si->ptr = ptr;
    } else {
        // 如果指定要注册的Service组件的名称s没有被使用，
        // 就会创建一个 svcinfo 结构体来描述要注册的Service组件，并且将它添加到全局队列svclist中。
        si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t));
        if (!si) {
            LOGE("add_service('%s',%p) uid=%d - OUT OF MEMORY\n",
                 str8(s), ptr, uid);
            return -1;
        }
        si->ptr = ptr;
        si->len = len;
        memcpy(si->name, s, (len + 1) * sizeof(uint16_t));
        si->name[len] = '\0';
        si->death.func = svcinfo_death;
        si->death.ptr = si;
        si->next = svclist;
        svclist = si;
    }

    // 调用函数binder_acquire来增加相应的Binder引用对象的引用计数值，避免它过早地被销毁。
    // 函数 binder_acquire 实际上是使用 BC_ACQUIRE 命令协议来通知Binder驱动程序增加
    // 相应的Binder引用对象的引用计数的。
    binder_acquire(bs, ptr);
    // 由于新注册的Service组件可能会意外地死亡，因此，
    // 需要调用函数binder_link_to_death向Binder驱动程序注册一个Binder本地对象死亡接收通知，
    // 以便Service Manager可以在该Service组件死亡时采取相应的处理措施。
    binder_link_to_death(bs, ptr, &si->death);
    return 0;
}

/**
 * svcmgr_handler 用来处理 Client 进程的通信请求;
 * 支持如下代码请求:
 *  SVC_MGR_GET_SERVICE
 *  SVC_MGR_CHECK_SERVICE
 *  SVC_MGR_ADD_SERVICE
 *  SVC_MGR_LIST_SERVICES
 */
int svcmgr_handler(struct binder_state *bs,
                   struct binder_txn *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;
    uint16_t *s;
    unsigned len;
    void *ptr;
    uint32_t strict_policy;

//    LOGI("target=%p code=%d pid=%d uid=%d\n",
//         txn->target, txn->code, txn->sender_pid, txn->sender_euid);

    // 检查从Binder驱动程序传进来的目标Binder本地对象 txn-＞target 是否指向在Service Manager中定义的虚拟Binder本地对象svcmgr_handle。
    // 如果不是，就说明Service Manager正在处理一个非法的进程间通信请求，因此，就直接返回一个错误码-1给调用者。
    if (txn->target != svcmgr_handle)
        return -1;

    // Equivalent to Parcel::enforceInterface(), reading the RPC
    // header with the strict mode policy mask and the interface name.
    // Note that we ignore the strict_policy and don't propagate it
    // further (since we do no outbound RPCs anyway).
    // 检查Binder进程间通信请求头是否合法。一个合法的Binder进程间通信请求头由一个Strict Mode Policy和一个服务接口描述符组成。
    strict_policy = bio_get_uint32(msg);
    s = bio_get_string16(msg, &len);
    // svcmgr_id 是一个uint16_t类型的字符数组，因此在计算svcmgr_id的字符串长度时，需要将数组的长度除以2。
    // Service Manager忽略了Binder进程间通信请求头的Strict Mode Policy值，但是它需要验证传递过来的服务接口描述符是否等于svcmgr_id。
    // 如果不相等，就说明这是一个非法的进程间通信请求，因此，就直接返回一个错误码 -1 给调用者。
    if ((len != (sizeof(svcmgr_id) / 2)) ||
        memcmp(svcmgr_id, s, sizeof(svcmgr_id))) {
        fprintf(stderr,"invalid id %s\n", str8(s));
        return -1;
    }

    switch(txn->code) {
    case SVC_MGR_GET_SERVICE:
    case SVC_MGR_CHECK_SERVICE:
        s = bio_get_string16(msg, &len);
        ptr = do_find_service(bs, s, len);
        if (!ptr)
            break;
        bio_put_ref(reply, ptr);
        return 0;

    case SVC_MGR_ADD_SERVICE:
        // 从binder_io结构体msg的数据缓冲区中取出要注册的Service组件的名称;
        s = bio_get_string16(msg, &len);
        // 调用函数bio_get_ref从binder_io结构体msg的数据缓冲区中获得一个Binder引用对象的句柄值，
        // 这个Binder引用对象是在Binder驱动程序中创建的，它引用了即将要注册的Serivce组件。
        ptr = bio_get_ref(msg);
        // 获得了用来描述即将要注册的Service组件的一个句柄值ptr之后，
        // 接着就调用函数 do_add_service 将这个Service组件注册到Service Manager中。
        if (do_add_service(bs, s, len, ptr, txn->sender_euid))
            return -1;
        break;

    case SVC_MGR_LIST_SERVICES: {
        unsigned n = bio_get_uint32(msg);

        si = svclist;
        while ((n-- > 0) && si)
            si = si->next;
        if (si) {
            bio_put_string16(reply, si->name);
            return 0;
        }
        return -1;
    }
    default:
        LOGE("unknown code %d\n", txn->code);
        return -1;
    }

    // 调用函数bio_put_uint32将注册成功代码0写入到binder_io结构体reply中，
    // 以便后面可以将它返回给请求注册Service组件的进程。
    bio_put_uint32(reply, 0);
    return 0;
}

// Service Manager启动入口;
int main(int argc, char **argv)
{
    struct binder_state *bs;
    // Service Manager 是一个特殊的 Service 组件，它的特殊之处就在于与它对应的Binder本地对象是一个虚拟的对象。
    // 这个虚拟的 Binder 本地对象的地址值等于0，并且在 Binder 驱动程序中引用了它的 Binder 引用对象的句柄值也等于0;
    // 将变量 svcmgr 的值设置为 BINDER_SERVICE_MANAGER;
    void *svcmgr = BINDER_SERVICE_MANAGER;

    // 第一步: 调用 binder_open 打开设备文件 /dev/binder，以及将它映射到本进程的地址空间;
    bs = binder_open(128*1024);

    // 第二步: 调用 binder_become_context_manager 将自己注册为 Binder 进程间通信机制的上下文管理者;
    if (binder_become_context_manager(bs)) {
        LOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }

    // svcmgr_handle 用来描述一个与 Service Manager 对应的 Binder 本地对象;
    svcmgr_handle = svcmgr;
    // 第三步: 调用 binder_loop 来循环等待和处理 Client 进程的通信请求;
    binder_loop(bs, svcmgr_handler);
    return 0;
}
