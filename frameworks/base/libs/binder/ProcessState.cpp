/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "ProcessState"

#include <cutils/process_name.h>

#include <binder/ProcessState.h>

#include <utils/Atomic.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include <binder/IServiceManager.h>
#include <utils/String8.h>
#include <utils/threads.h>

#include <private/binder/binder_module.h>
#include <private/binder/Static.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define BINDER_VM_SIZE ((1*1024*1024) - (4096 *2))

static bool gSingleProcess = false;


// ---------------------------------------------------------------------------

namespace android {
 
// Global variables
int                 mArgC;
const char* const*  mArgV;
int                 mArgLen;

class PoolThread : public Thread
{
public:
    PoolThread(bool isMain)
        : mIsMain(isMain)
    {
    }
    
protected:
    virtual bool threadLoop()
    {
        // 调用当前线程中的IPCThreadState对象的成员函数joinThreadPool，
        // 将当前线程注册到Binder驱动程序中去成为一个Binder线程，以便Binder驱动程序可以分发进程间通信请求给它处理。
        IPCThreadState::self()->joinThreadPool(mIsMain);
        return false;
    }
    
    const bool mIsMain;
};

// 获得进程内的一个 ProcessState 对象;
sp<ProcessState> ProcessState::self()
{
    // 如果 gProcess 不为 NULL，说明Binder库已经为进程创建过一个 ProcessState 了.
    if (gProcess != NULL) return gProcess;
    
    AutoMutex _l(gProcessMutex);
    // 创建一个 ProcessState 对象;
    if (gProcess == NULL) gProcess = new ProcessState;
    return gProcess;
}

void ProcessState::setSingleProcess(bool singleProcess)
{
    gSingleProcess = singleProcess;
}


void ProcessState::setContextObject(const sp<IBinder>& object)
{
    setContextObject(object, String16("default"));
}

/**
 * getContextObject 用来创建一个 Binder 代理对象;
 */
sp<IBinder> ProcessState::getContextObject(const sp<IBinder>& caller)
{
    // supportsProcess 来检查系统是否支持 Binder 进程间通信机制,即检查进程是否成功地打开了设备文件 /dev/binder;
    if (supportsProcesses()) {
        // 调用 getStrongProxyForHandle 来创建一个 Binder 代理对象;
        return getStrongProxyForHandle(0);
    } else {
        return getContextObject(String16("default"), caller);
    }
}

void ProcessState::setContextObject(const sp<IBinder>& object, const String16& name)
{
    AutoMutex _l(mLock);
    mContexts.add(name, object);
}

sp<IBinder> ProcessState::getContextObject(const String16& name, const sp<IBinder>& caller)
{
    mLock.lock();
    sp<IBinder> object(
        mContexts.indexOfKey(name) >= 0 ? mContexts.valueFor(name) : NULL);
    mLock.unlock();
    
    //printf("Getting context object %s for %p\n", String8(name).string(), caller.get());
    
    if (object != NULL) return object;

    // Don't attempt to retrieve contexts if we manage them
    if (mManagesContexts) {
        LOGE("getContextObject(%s) failed, but we manage the contexts!\n",
            String8(name).string());
        return NULL;
    }
    
    IPCThreadState* ipc = IPCThreadState::self();
    {
        Parcel data, reply;
        // no interface token on this magic transaction
        data.writeString16(name);
        data.writeStrongBinder(caller);
        status_t result = ipc->transact(0 /*magic*/, 0, data, &reply, 0);
        if (result == NO_ERROR) {
            object = reply.readStrongBinder();
        }
    }
    
    ipc->flushCommands();
    
    if (object != NULL) setContextObject(object, name);
    return object;
}

bool ProcessState::supportsProcesses() const
{
    return mDriverFD >= 0;
}

void ProcessState::startThreadPool()
{
    AutoMutex _l(mLock);
    // 当前进程的ProcessState对象的成员变量mThreadPoolStarted被初始化为false，
    // 当它将一个Binder线程池启动起来之后，就会将内部的成员变量mThreadPoolStarted的值设置为true，
    // 防止它的成员函数 spawnPooledThread 被重复调用来启动Binder线程池。
    if (!mThreadPoolStarted) {
        mThreadPoolStarted = true;
        spawnPooledThread(true);
    }
}

bool ProcessState::isContextManager(void) const
{
    return mManagesContexts;
}

bool ProcessState::becomeContextManager(context_check_func checkFunc, void* userData)
{
    if (!mManagesContexts) {
        AutoMutex _l(mLock);
        mBinderContextCheckFunc = checkFunc;
        mBinderContextUserData = userData;
        if (mDriverFD >= 0) {
            int dummy = 0;
#if defined(HAVE_ANDROID_OS)
            status_t result = ioctl(mDriverFD, BINDER_SET_CONTEXT_MGR, &dummy);
#else
            status_t result = INVALID_OPERATION;
#endif
            if (result == 0) {
                mManagesContexts = true;
            } else if (result == -1) {
                mBinderContextCheckFunc = NULL;
                mBinderContextUserData = NULL;
                LOGE("Binder ioctl to become context manager failed: %s\n", strerror(errno));
            }
        } else {
            // If there is no driver, our only world is the local
            // process so we can always become the context manager there.
            mManagesContexts = true;
        }
    }
    return mManagesContexts;
}

ProcessState::handle_entry* ProcessState::lookupHandleLocked(int32_t handle)
{
    // 一个 Binder 代理对象的句柄值同时也是它在列表 mHandleToObject 中的索引值;
    const size_t N=mHandleToObject.size();
    // 句柄值 handle 如果大于或者等于 mHandleToObject 的大小，说明不存在该句柄值对应的 handle_entry 结构体;
    if (N <= (size_t)handle) {
        handle_entry e;
        e.binder = NULL;
        e.refs = NULL;
        status_t err = mHandleToObject.insertAt(e, N, handle+1-N);
        if (err < NO_ERROR) return NULL;
    }
    return &mHandleToObject.editItemAt(handle);
}

/**
 * getStrongProxyForHandle : 创建一个 Binder 代理对象;
 */
sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
    sp<IBinder> result;

    AutoMutex _l(mLock);

    // 调用 lookupHandleLocked 来检查成员变量 mHandleToObject 中是否已经存在一个与句柄值 handle 对应的 handle_entry 结构体;
    handle_entry* e = lookupHandleLocked(handle);

    if (e != NULL) {
        // We need to create a new BpBinder if there isn't currently one, OR we
        // are unable to acquire a weak reference on this current one.  See comment
        // in getWeakProxyForHandle() for more info about this.
        IBinder* b = e->binder;
        // handle_entry 结构体 e 的成员变量 binder 的值如果为 NULL，说明尚未为句柄值 handle 创建过 Binder 代理对象;
        // 如果已经存在 Binder 代理对象，则尝试调用 attemptIncWeak 增加弱引用计数;
        // 由于 Binder 代理对象(即 BpBinder 对象)的生命周期是受弱引用计数控制的，如果不能成功增加它的弱引用计数，那么就说明它已经被销毁了。
        if (b == NULL || !e->refs->attemptIncWeak(this)) {
            b = new BpBinder(handle); 
            e->binder = b;
            if (b) e->refs = b->getWeakRefs();
            result = b;
        } else {
            // This little bit of nastyness is to allow us to add a primary
            // reference to the remote proxy when this team doesn't have one
            // but another team is sending the handle to us.
            result.force_set(b);
            // 这里要调用 decWeak 减少它的弱引用计数，因为之前的 if 语句，调用了 attemptIncWeak 增加了它的弱引用计数;
            e->refs->decWeak(this);
        }
    }

    return result;
}

wp<IBinder> ProcessState::getWeakProxyForHandle(int32_t handle)
{
    wp<IBinder> result;

    AutoMutex _l(mLock);

    handle_entry* e = lookupHandleLocked(handle);

    if (e != NULL) {        
        // We need to create a new BpBinder if there isn't currently one, OR we
        // are unable to acquire a weak reference on this current one.  The
        // attemptIncWeak() is safe because we know the BpBinder destructor will always
        // call expungeHandle(), which acquires the same lock we are holding now.
        // We need to do this because there is a race condition between someone
        // releasing a reference on this BpBinder, and a new reference on its handle
        // arriving from the driver.
        IBinder* b = e->binder;
        if (b == NULL || !e->refs->attemptIncWeak(this)) {
            b = new BpBinder(handle);
            result = b;
            e->binder = b;
            if (b) e->refs = b->getWeakRefs();
        } else {
            result = b;
            e->refs->decWeak(this);
        }
    }

    return result;
}

void ProcessState::expungeHandle(int32_t handle, IBinder* binder)
{
    AutoMutex _l(mLock);
    
    handle_entry* e = lookupHandleLocked(handle);

    // This handle may have already been replaced with a new BpBinder
    // (if someone failed the AttemptIncWeak() above); we don't want
    // to overwrite it.
    if (e && e->binder == binder) e->binder = NULL;
}

void ProcessState::setArgs(int argc, const char* const argv[])
{
    mArgC = argc;
    mArgV = (const char **)argv;

    mArgLen = 0;
    for (int i=0; i<argc; i++) {
        mArgLen += strlen(argv[i]) + 1;
    }
    mArgLen--;
}

int ProcessState::getArgC() const
{
    return mArgC;
}

const char* const* ProcessState::getArgV() const
{
    return mArgV;
}

void ProcessState::setArgV0(const char* txt)
{
    if (mArgV != NULL) {
        strncpy((char*)mArgV[0], txt, mArgLen);
        set_process_name(txt);
    }
}

/**
 * spawnPooledThread:
 * @isMain: true，表示线程 t 是进程主动创建来加入到它的Binder线程池的，
 *          以区别于Binder驱动程序请求进程创建新的线程来加入到它的Binder线程池的情况。
 */
void ProcessState::spawnPooledThread(bool isMain)
{
    if (mThreadPoolStarted) {
        int32_t s = android_atomic_add(1, &mThreadPoolSeq);
        char buf[32];
        sprintf(buf, "Binder Thread #%d", s);
        LOGV("Spawning new pooled thread, name=%s\n", buf);
        // 创建了一个PoolThread对象t，接着调用它的成员函数run来启动一个新的线程。
        // PoolThread类继承了线程类Thread，并且重写了它的线程入口成员函数threadLoop，
        // 因此，当一个PoolThread对象t所对应的线程启动起来之后，它的成员函数threadLoop就会被调用。
        sp<Thread> t = new PoolThread(isMain);
        t->run(buf);
    }
}

static int open_driver()
{
    if (gSingleProcess) {
        return -1;
    }

    // 调用函数 open 打开设备文件 /dev/binder;
    int fd = open("/dev/binder", O_RDWR);
    if (fd >= 0) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        int vers;
#if defined(HAVE_ANDROID_OS)
        // 使用 IO 控制命令 BINDER_VERSION 来获得 Binder 驱动程序的版本号;
        status_t result = ioctl(fd, BINDER_VERSION, &vers);
#else
        status_t result = -1;
        errno = EPERM;
#endif
        if (result == -1) {
            LOGE("Binder ioctl to obtain version failed: %s", strerror(errno));
            close(fd);
            fd = -1;
        }
        if (result != 0 || vers != BINDER_CURRENT_PROTOCOL_VERSION) {
            LOGE("Binder driver protocol does not match user space protocol!");
            close(fd);
            fd = -1;
        }
#if defined(HAVE_ANDROID_OS)
        size_t maxThreads = 15;
        // 使用 IO 控制命令 BINDER_SET_MAX_THREADS 来通知 Binder 驱动程序，
        // 它最多可以请求进程创建 15 个 Binder 线程来处理进程间通信请求;
        result = ioctl(fd, BINDER_SET_MAX_THREADS, &maxThreads);
        if (result == -1) {
            LOGE("Binder ioctl to set max threads failed: %s", strerror(errno));
        }
#endif
        
    } else {
        LOGW("Opening '/dev/binder' failed: %s\n", strerror(errno));
    }
    return fd;
}

// 进程中的 ProcessState 对象的创建过程;
ProcessState::ProcessState()
    : mDriverFD(open_driver()) // 调用 open_driver 打开设备文件 /dev/binder,并将得到的文件描述符保存在 mDriverFD 中;
    , mVMStart(MAP_FAILED)
    , mManagesContexts(false)
    , mBinderContextCheckFunc(NULL)
    , mBinderContextUserData(NULL)
    , mThreadPoolStarted(false)
    , mThreadPoolSeq(1)
{
    if (mDriverFD >= 0) {
        // XXX Ideally, there should be a specific define for whether we
        // have mmap (or whether we could possibly have the kernel module
        // availabla).
#if !defined(HAVE_WIN32_IPC)
        // mmap the binder, providing a chunk of virtual address space to receive transactions.
        // 调用 mmap 把设备文件 /dev/binder 映射到进程的地址空间，映射的地址空间大小为 BINDER_VM_SIZE;
        // #define BINDER_VM_SIZE ((1*1024*1024) - (4096 *2))
        // 将设备文件 /dev/binder 映射到进程的地址空间实际上是请求 Binder 驱动程序为进程分配内核缓冲区,
        // 这个内核缓冲区的大小被 Binder 库默认设置为 1016KB.
        mVMStart = mmap(0, BINDER_VM_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, mDriverFD, 0);
        if (mVMStart == MAP_FAILED) {
            // *sigh*
            LOGE("Using /dev/binder failed: unable to mmap transaction memory.\n");
            close(mDriverFD);
            mDriverFD = -1;
        }
#else
        mDriverFD = -1;
#endif
    }
    if (mDriverFD < 0) {
        // Need to run without the driver, starting our own thread pool.
    }
}

ProcessState::~ProcessState()
{
}
        
}; // namespace android
