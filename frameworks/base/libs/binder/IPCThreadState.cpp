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

#define LOG_TAG "IPCThreadState"

#include <binder/IPCThreadState.h>

#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <cutils/sched_policy.h>
#include <utils/Debug.h>
#include <utils/Log.h>
#include <utils/TextOutput.h>
#include <utils/threads.h>

#include <private/binder/binder_module.h>
#include <private/binder/Static.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#ifdef HAVE_PTHREADS
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#endif
#ifdef HAVE_WIN32_THREADS
#include <windows.h>
#endif


#if LOG_NDEBUG

#define IF_LOG_TRANSACTIONS() if (false)
#define IF_LOG_COMMANDS() if (false)
#define LOG_REMOTEREFS(...) 
#define IF_LOG_REMOTEREFS() if (false)
#define LOG_THREADPOOL(...) 
#define LOG_ONEWAY(...) 

#else

#define IF_LOG_TRANSACTIONS() IF_LOG(LOG_VERBOSE, "transact")
#define IF_LOG_COMMANDS() IF_LOG(LOG_VERBOSE, "ipc")
#define LOG_REMOTEREFS(...) LOG(LOG_DEBUG, "remoterefs", __VA_ARGS__)
#define IF_LOG_REMOTEREFS() IF_LOG(LOG_DEBUG, "remoterefs")
#define LOG_THREADPOOL(...) LOG(LOG_DEBUG, "threadpool", __VA_ARGS__)
#define LOG_ONEWAY(...) LOG(LOG_DEBUG, "ipc", __VA_ARGS__)

#endif

// ---------------------------------------------------------------------------

namespace android {

static const char* getReturnString(size_t idx);
static const char* getCommandString(size_t idx);
static const void* printReturnCommand(TextOutput& out, const void* _cmd);
static const void* printCommand(TextOutput& out, const void* _cmd);

// This will result in a missing symbol failure if the IF_LOG_COMMANDS()
// conditionals don't get stripped...  but that is probably what we want.
#if !LOG_NDEBUG
static const char *kReturnStrings[] = {
#if 1 /* TODO: error update strings */
    "unknown",
#else
    "BR_OK",
    "BR_TIMEOUT",
    "BR_WAKEUP",
    "BR_TRANSACTION",
    "BR_REPLY",
    "BR_ACQUIRE_RESULT",
    "BR_DEAD_REPLY",
    "BR_TRANSACTION_COMPLETE",
    "BR_INCREFS",
    "BR_ACQUIRE",
    "BR_RELEASE",
    "BR_DECREFS",
    "BR_ATTEMPT_ACQUIRE",
    "BR_EVENT_OCCURRED",
    "BR_NOOP",
    "BR_SPAWN_LOOPER",
    "BR_FINISHED",
    "BR_DEAD_BINDER",
    "BR_CLEAR_DEATH_NOTIFICATION_DONE"
#endif
};

static const char *kCommandStrings[] = {
#if 1 /* TODO: error update strings */
    "unknown",
#else
    "BC_NOOP",
    "BC_TRANSACTION",
    "BC_REPLY",
    "BC_ACQUIRE_RESULT",
    "BC_FREE_BUFFER",
    "BC_TRANSACTION_COMPLETE",
    "BC_INCREFS",
    "BC_ACQUIRE",
    "BC_RELEASE",
    "BC_DECREFS",
    "BC_INCREFS_DONE",
    "BC_ACQUIRE_DONE",
    "BC_ATTEMPT_ACQUIRE",
    "BC_RETRIEVE_ROOT_OBJECT",
    "BC_SET_THREAD_ENTRY",
    "BC_REGISTER_LOOPER",
    "BC_ENTER_LOOPER",
    "BC_EXIT_LOOPER",
    "BC_SYNC",
    "BC_STOP_PROCESS",
    "BC_STOP_SELF",
    "BC_REQUEST_DEATH_NOTIFICATION",
    "BC_CLEAR_DEATH_NOTIFICATION",
    "BC_DEAD_BINDER_DONE"
#endif
};

static const char* getReturnString(size_t idx)
{
    if (idx < sizeof(kReturnStrings) / sizeof(kReturnStrings[0]))
        return kReturnStrings[idx];
    else
        return "unknown";
}

static const char* getCommandString(size_t idx)
{
    if (idx < sizeof(kCommandStrings) / sizeof(kCommandStrings[0]))
        return kCommandStrings[idx];
    else
        return "unknown";
}

static const void* printBinderTransactionData(TextOutput& out, const void* data)
{
    const binder_transaction_data* btd =
        (const binder_transaction_data*)data;
    out << "target=" << btd->target.ptr << " (cookie " << btd->cookie << ")" << endl
        << "code=" << TypeCode(btd->code) << ", flags=" << (void*)btd->flags << endl
        << "data=" << btd->data.ptr.buffer << " (" << (void*)btd->data_size
        << " bytes)" << endl
        << "offsets=" << btd->data.ptr.offsets << " (" << (void*)btd->offsets_size
        << " bytes)" << endl;
    return btd+1;
}

static const void* printReturnCommand(TextOutput& out, const void* _cmd)
{
    static const int32_t N = sizeof(kReturnStrings)/sizeof(kReturnStrings[0]);
    
    const int32_t* cmd = (const int32_t*)_cmd;
    int32_t code = *cmd++;
    if (code == BR_ERROR) {
        out << "BR_ERROR: " << (void*)(*cmd++) << endl;
        return cmd;
    } else if (code < 0 || code >= N) {
        out << "Unknown reply: " << code << endl;
        return cmd;
    }
    
    out << kReturnStrings[code];
    switch (code) {
        case BR_TRANSACTION:
        case BR_REPLY: {
            out << ": " << indent;
            cmd = (const int32_t *)printBinderTransactionData(out, cmd);
            out << dedent;
        } break;
        
        case BR_ACQUIRE_RESULT: {
            const int32_t res = *cmd++;
            out << ": " << res << (res ? " (SUCCESS)" : " (FAILURE)");
        } break;
        
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS: {
            const int32_t b = *cmd++;
            const int32_t c = *cmd++;
            out << ": target=" << (void*)b << " (cookie " << (void*)c << ")";
        } break;
    
        case BR_ATTEMPT_ACQUIRE: {
            const int32_t p = *cmd++;
            const int32_t b = *cmd++;
            const int32_t c = *cmd++;
            out << ": target=" << (void*)b << " (cookie " << (void*)c
                << "), pri=" << p;
        } break;

        case BR_DEAD_BINDER:
        case BR_CLEAR_DEATH_NOTIFICATION_DONE: {
            const int32_t c = *cmd++;
            out << ": death cookie " << (void*)c;
        } break;
    }
    
    out << endl;
    return cmd;
}

static const void* printCommand(TextOutput& out, const void* _cmd)
{
    static const int32_t N = sizeof(kCommandStrings)/sizeof(kCommandStrings[0]);
    
    const int32_t* cmd = (const int32_t*)_cmd;
    int32_t code = *cmd++;
    if (code < 0 || code >= N) {
        out << "Unknown command: " << code << endl;
        return cmd;
    }
    
    out << kCommandStrings[code];
    switch (code) {
        case BC_TRANSACTION:
        case BC_REPLY: {
            out << ": " << indent;
            cmd = (const int32_t *)printBinderTransactionData(out, cmd);
            out << dedent;
        } break;
        
        case BC_ACQUIRE_RESULT: {
            const int32_t res = *cmd++;
            out << ": " << res << (res ? " (SUCCESS)" : " (FAILURE)");
        } break;
        
        case BC_FREE_BUFFER: {
            const int32_t buf = *cmd++;
            out << ": buffer=" << (void*)buf;
        } break;
        
        case BC_INCREFS:
        case BC_ACQUIRE:
        case BC_RELEASE:
        case BC_DECREFS: {
            const int32_t d = *cmd++;
            out << ": descriptor=" << (void*)d;
        } break;
    
        case BC_INCREFS_DONE:
        case BC_ACQUIRE_DONE: {
            const int32_t b = *cmd++;
            const int32_t c = *cmd++;
            out << ": target=" << (void*)b << " (cookie " << (void*)c << ")";
        } break;
        
        case BC_ATTEMPT_ACQUIRE: {
            const int32_t p = *cmd++;
            const int32_t d = *cmd++;
            out << ": decriptor=" << (void*)d << ", pri=" << p;
        } break;
        
        case BC_REQUEST_DEATH_NOTIFICATION:
        case BC_CLEAR_DEATH_NOTIFICATION: {
            const int32_t h = *cmd++;
            const int32_t c = *cmd++;
            out << ": handle=" << h << " (death cookie " << (void*)c << ")";
        } break;

        case BC_DEAD_BINDER_DONE: {
            const int32_t c = *cmd++;
            out << ": death cookie " << (void*)c;
        } break;
    }
    
    out << endl;
    return cmd;
}
#endif

static pthread_mutex_t gTLSMutex = PTHREAD_MUTEX_INITIALIZER;
static bool gHaveTLS = false;
static pthread_key_t gTLS = 0;
static bool gShutdown = false;
static bool gDisableBackgroundScheduling = false;

IPCThreadState* IPCThreadState::self()
{
    if (gHaveTLS) {
restart:
        const pthread_key_t k = gTLS;
        IPCThreadState* st = (IPCThreadState*)pthread_getspecific(k);
        if (st) return st;
        return new IPCThreadState;
    }
    
    if (gShutdown) return NULL;
    
    pthread_mutex_lock(&gTLSMutex);
    if (!gHaveTLS) {
        if (pthread_key_create(&gTLS, threadDestructor) != 0) {
            pthread_mutex_unlock(&gTLSMutex);
            return NULL;
        }
        gHaveTLS = true;
    }
    pthread_mutex_unlock(&gTLSMutex);
    goto restart;
}

void IPCThreadState::shutdown()
{
    gShutdown = true;
    
    if (gHaveTLS) {
        // XXX Need to wait for all thread pool threads to exit!
        IPCThreadState* st = (IPCThreadState*)pthread_getspecific(gTLS);
        if (st) {
            delete st;
            pthread_setspecific(gTLS, NULL);
        }
        gHaveTLS = false;
    }
}

void IPCThreadState::disableBackgroundScheduling(bool disable)
{
    gDisableBackgroundScheduling = disable;
}

sp<ProcessState> IPCThreadState::process()
{
    return mProcess;
}

status_t IPCThreadState::clearLastError()
{
    const status_t err = mLastError;
    mLastError = NO_ERROR;
    return err;
}

int IPCThreadState::getCallingPid()
{
    return mCallingPid;
}

int IPCThreadState::getCallingUid()
{
    return mCallingUid;
}

int64_t IPCThreadState::clearCallingIdentity()
{
    int64_t token = ((int64_t)mCallingUid<<32) | mCallingPid;
    clearCaller();
    return token;
}

void IPCThreadState::setStrictModePolicy(int32_t policy)
{
    mStrictModePolicy = policy;
}

int32_t IPCThreadState::getStrictModePolicy() const
{
    return mStrictModePolicy;
}

void IPCThreadState::setLastTransactionBinderFlags(int32_t flags)
{
    mLastTransactionBinderFlags = flags;
}

int32_t IPCThreadState::getLastTransactionBinderFlags() const
{
    return mLastTransactionBinderFlags;
}

void IPCThreadState::restoreCallingIdentity(int64_t token)
{
    mCallingUid = (int)(token>>32);
    mCallingPid = (int)token;
}

void IPCThreadState::clearCaller()
{
    mCallingPid = getpid();
    mCallingUid = getuid();
}

void IPCThreadState::flushCommands()
{
    if (mProcess->mDriverFD <= 0)
        return;
    talkWithDriver(false);
}

void IPCThreadState::joinThreadPool(bool isMain)
{
    LOG_THREADPOOL("**** THREAD %p (PID %d) IS JOINING THE THREAD POOL\n", (void*)pthread_self(), getpid());

    mOut.writeInt32(isMain ? BC_ENTER_LOOPER : BC_REGISTER_LOOPER);
    
    // This thread may have been spawned by a thread that was in the background
    // scheduling group, so first we will make sure it is in the default/foreground
    // one to avoid performing an initial transaction in the background.
    androidSetThreadSchedulingGroup(mMyThreadId, ANDROID_TGROUP_DEFAULT);
        
    status_t result;
    do {
        int32_t cmd;
        
        // When we've cleared the incoming command queue, process any pending derefs
        if (mIn.dataPosition() >= mIn.dataSize()) {
            size_t numPending = mPendingWeakDerefs.size();
            if (numPending > 0) {
                for (size_t i = 0; i < numPending; i++) {
                    RefBase::weakref_type* refs = mPendingWeakDerefs[i];
                    refs->decWeak(mProcess.get());
                }
                mPendingWeakDerefs.clear();
            }

            numPending = mPendingStrongDerefs.size();
            if (numPending > 0) {
                for (size_t i = 0; i < numPending; i++) {
                    BBinder* obj = mPendingStrongDerefs[i];
                    obj->decStrong(mProcess.get());
                }
                mPendingStrongDerefs.clear();
            }
        }

        // now get the next command to be processed, waiting if necessary
        result = talkWithDriver();
        if (result >= NO_ERROR) {
            size_t IN = mIn.dataAvail();
            if (IN < sizeof(int32_t)) continue;
            cmd = mIn.readInt32();
            IF_LOG_COMMANDS() {
                alog << "Processing top-level Command: "
                    << getReturnString(cmd) << endl;
            }


            result = executeCommand(cmd);
        }
        
        // After executing the command, ensure that the thread is returned to the
        // default cgroup before rejoining the pool.  The driver takes care of
        // restoring the priority, but doesn't do anything with cgroups so we
        // need to take care of that here in userspace.  Note that we do make
        // sure to go in the foreground after executing a transaction, but
        // there are other callbacks into user code that could have changed
        // our group so we want to make absolutely sure it is put back.
        androidSetThreadSchedulingGroup(mMyThreadId, ANDROID_TGROUP_DEFAULT);

        // Let this thread exit the thread pool if it is no longer
        // needed and it is not the main process thread.
        if(result == TIMED_OUT && !isMain) {
            break;
        }
    } while (result != -ECONNREFUSED && result != -EBADF);

    LOG_THREADPOOL("**** THREAD %p (PID %d) IS LEAVING THE THREAD POOL err=%p\n",
        (void*)pthread_self(), getpid(), (void*)result);
    
    mOut.writeInt32(BC_EXIT_LOOPER);
    talkWithDriver(false);
}

void IPCThreadState::stopProcess(bool immediate)
{
    //LOGI("**** STOPPING PROCESS");
    flushCommands();
    int fd = mProcess->mDriverFD;
    mProcess->mDriverFD = -1;
    close(fd);
    //kill(getpid(), SIGKILL);
}

status_t IPCThreadState::transact(int32_t handle,
                                  uint32_t code, const Parcel& data,
                                  Parcel* reply, uint32_t flags)
{
    // 检查 parcel 对象data中的进程间通信数据是否正确;
    status_t err = data.errorCheck();

    // 将参数 flags 的 TF_ACCEPT_FDS 位设置为1，表示允许Server进程在返回结果中携带文件描述符;
    flags |= TF_ACCEPT_FDS;

    IF_LOG_TRANSACTIONS() {
        TextOutput::Bundle _b(alog);
        alog << "BC_TRANSACTION thr " << (void*)pthread_self() << " / hand "
            << handle << " / code " << TypeCode(code) << ": "
            << indent << data << dedent << endl;
    }
    
    if (err == NO_ERROR) {
        LOG_ONEWAY(">>>> SEND from pid %d uid %d %s", getpid(), getuid(),
            (flags & TF_ONE_WAY) == 0 ? "READ REPLY" : "ONE WAY");
        // writeTransactionData 将Parcel内容写入到一个 binder_transaction_data 结构体中;
        err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL);
    }
    
    if (err != NO_ERROR) {
        if (reply) reply->setError(err);
        return (mLastError = err);
    }
    
    // 判断参数 flags 的 TF_ONE_WAY 是否为0，如果是，说明这是一个同步的进程间通信请求;
    // 这时候如果用来保存通信结果的 Parcel 对象 reply 不等于 NULL，
    // 那么就调用 waitForResponse 向 Binder 驱动程序发送一个 BC_TRANSACTION 命令协议;
    if ((flags & TF_ONE_WAY) == 0) {
        #if 0
        if (code == 4) { // relayout
            LOGI(">>>>>> CALLING transaction 4");
        } else {
            LOGI(">>>>>> CALLING transaction %d", code);
        }
        #endif
        if (reply) {
            // waitForResponse 向 Binder 驱动程序发送一个命令协议(eg: BC_TRANSACTION);
            err = waitForResponse(reply);
        } else {
            Parcel fakeReply;
            err = waitForResponse(&fakeReply);
        }
        #if 0
        if (code == 4) { // relayout
            LOGI("<<<<<< RETURNING transaction 4");
        } else {
            LOGI("<<<<<< RETURNING transaction %d", code);
        }
        #endif
        
        IF_LOG_TRANSACTIONS() {
            TextOutput::Bundle _b(alog);
            alog << "BR_REPLY thr " << (void*)pthread_self() << " / hand "
                << handle << ": ";
            if (reply) alog << indent << *reply << dedent << endl;
            else alog << "(none requested)" << endl;
        }
    } else {
        err = waitForResponse(NULL, NULL);
    }
    
    return err;
}

void IPCThreadState::incStrongHandle(int32_t handle)
{
    LOG_REMOTEREFS("IPCThreadState::incStrongHandle(%d)\n", handle);
    mOut.writeInt32(BC_ACQUIRE);
    mOut.writeInt32(handle);
}

void IPCThreadState::decStrongHandle(int32_t handle)
{
    LOG_REMOTEREFS("IPCThreadState::decStrongHandle(%d)\n", handle);
    mOut.writeInt32(BC_RELEASE);
    mOut.writeInt32(handle);
}

void IPCThreadState::incWeakHandle(int32_t handle)
{
    LOG_REMOTEREFS("IPCThreadState::incWeakHandle(%d)\n", handle);
    mOut.writeInt32(BC_INCREFS);
    mOut.writeInt32(handle);
}

void IPCThreadState::decWeakHandle(int32_t handle)
{
    LOG_REMOTEREFS("IPCThreadState::decWeakHandle(%d)\n", handle);
    mOut.writeInt32(BC_DECREFS);
    mOut.writeInt32(handle);
}

status_t IPCThreadState::attemptIncStrongHandle(int32_t handle)
{
    mOut.writeInt32(BC_ATTEMPT_ACQUIRE);
    mOut.writeInt32(0); // xxx was thread priority
    mOut.writeInt32(handle);
    status_t result = UNKNOWN_ERROR;
    
    waitForResponse(NULL, &result);
    
#if LOG_REFCOUNTS
    printf("IPCThreadState::attemptIncStrongHandle(%ld) = %s\n",
        handle, result == NO_ERROR ? "SUCCESS" : "FAILURE");
#endif
    
    return result;
}

void IPCThreadState::expungeHandle(int32_t handle, IBinder* binder)
{
#if LOG_REFCOUNTS
    printf("IPCThreadState::expungeHandle(%ld)\n", handle);
#endif
    self()->mProcess->expungeHandle(handle, binder);
}

status_t IPCThreadState::requestDeathNotification(int32_t handle, BpBinder* proxy)
{
    mOut.writeInt32(BC_REQUEST_DEATH_NOTIFICATION);
    mOut.writeInt32((int32_t)handle);
    mOut.writeInt32((int32_t)proxy);
    return NO_ERROR;
}

status_t IPCThreadState::clearDeathNotification(int32_t handle, BpBinder* proxy)
{
    mOut.writeInt32(BC_CLEAR_DEATH_NOTIFICATION);
    mOut.writeInt32((int32_t)handle);
    mOut.writeInt32((int32_t)proxy);
    return NO_ERROR;
}

IPCThreadState::IPCThreadState()
    : mProcess(ProcessState::self()),
      mMyThreadId(androidGetTid()),
      mStrictModePolicy(0),
      mLastTransactionBinderFlags(0)
{
    pthread_setspecific(gTLS, this);
    clearCaller();
    mIn.setDataCapacity(256);
    mOut.setDataCapacity(256);
}

IPCThreadState::~IPCThreadState()
{
}

status_t IPCThreadState::sendReply(const Parcel& reply, uint32_t flags)
{
    status_t err;
    status_t statusBuffer;
    err = writeTransactionData(BC_REPLY, flags, -1, 0, reply, &statusBuffer);
    if (err < NO_ERROR) return err;
    
    return waitForResponse(NULL, NULL);
}

/**
 * waitForResponse 向 Binder 驱动程序发送一个命令协议(eg: BC_TRANSACTION);
 */
status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
{
    int32_t cmd;
    int32_t err;

    while (1) {
        // 通过一个while循环不断地调用成员函数talkWithDriver来与Binder驱动程序进行交互，
        // 以便可以将前面准备好的BC_TRANSACTION命令协议发送给Binder驱动程序处理，
        // 并等待Binder驱动程序将进程间通信结果返回来。
        if ((err=talkWithDriver()) < NO_ERROR) break;
        err = mIn.errorCheck();
        if (err < NO_ERROR) break;
        if (mIn.dataAvail() == 0) continue;
        
        // IPCThreadState类的成员函数talkWithDriver已经将Binder驱动程序给进程发送的 BR_TRANSACTION_COMPLETE 返回协议
        // 保存在内部的返回协议缓冲区mIn中，因此，下面就可以通过返回协议缓冲区mIn来获得这个 BR_TRANSACTION_COMPLETE 返回协议。
        // 2.从返回协议缓冲区mIn中读出一个BR_REPLY返回协议代码。
        cmd = mIn.readInt32();
        
        IF_LOG_COMMANDS() {
            alog << "Processing waitForResponse Command: "
                << getReturnString(cmd) << endl;
        }

        switch (cmd) {
        case BR_TRANSACTION_COMPLETE:
            // IPCThreadState类的成员函数waitForResponse对BR_TRANSACTION_COMPLETE返回协议的处理很简单，
            // 它跳出了switch语句之后，就重新执行外层的while循环，
            // 即再次调用成员函数talkWithDriver来与Binder驱动程序交互。

            // 再次进入到IPCThreadState类的成员函数talkWithDriver中时，
            // 由于IPCThreadState类内部的命令协议缓冲区mOut中的命令协议，以及返回协议缓冲区mIn中的返回协议都已经处理完成了，
            // 因此，当它再次通过IO控制命令BINDER_WRITE_READ进入到Binder驱动程序的函数binder_ioctl中时，
            // 就会直接调用函数 binder_thread_read 等待目标进程将上次发出的进程间通信请求的结果返回来。
            if (!reply && !acquireResult) goto finish;
            break;
        
        case BR_DEAD_REPLY:
            err = DEAD_OBJECT;
            goto finish;

        case BR_FAILED_REPLY:
            err = FAILED_TRANSACTION;
            goto finish;
        
        case BR_ACQUIRE_RESULT:
            {
                LOG_ASSERT(acquireResult != NULL, "Unexpected brACQUIRE_RESULT");
                const int32_t result = mIn.readInt32();
                if (!acquireResult) continue;
                *acquireResult = result ? NO_ERROR : INVALID_OPERATION;
            }
            goto finish;
        
        case BR_REPLY:
            {
                binder_transaction_data tr;
                // 将返回协议缓冲区mIn的内容读到一个binder_transaction_data结构体tr中。
                err = mIn.read(&tr, sizeof(tr));
                LOG_ASSERT(err == NO_ERROR, "Not enough command data for brREPLY");
                if (err != NO_ERROR) goto finish;

                if (reply) {
                    if ((tr.flags & TF_STATUS_CODE) == 0) {
                        // 如果binder_transaction_data结构体tr的成员变量flags的TF_STATUS_CODE位等于0，
                        // 就说明当前线程之前所发出的一个进程间通信请求已经被成功地处理了。

                        // 下面就就将保存在binder_transaction_data结构体tr中的进程间通信结果保存在Parcel对象reply中，
                        // 这是通过调用Parcel对象reply的成员函数ipcSetDataReference来实现的。
                        reply->ipcSetDataReference(
                            reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                            tr.data_size,
                            reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
                            tr.offsets_size/sizeof(size_t),
                            freeBuffer, this);
                    } else {
                        err = *static_cast<const status_t*>(tr.data.ptr.buffer);
                        freeBuffer(NULL,
                            reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                            tr.data_size,
                            reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
                            tr.offsets_size/sizeof(size_t), this);
                    }
                } else {
                    freeBuffer(NULL,
                        reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                        tr.data_size,
                        reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
                        tr.offsets_size/sizeof(size_t), this);
                    continue;
                }
            }
            goto finish;

        default:
            err = executeCommand(cmd);
            if (err != NO_ERROR) goto finish;
            break;
        }
    }

finish:
    if (err != NO_ERROR) {
        if (acquireResult) *acquireResult = err;
        if (reply) reply->setError(err);
        mLastError = err;
    }
    
    return err;
}

/**
 * talkWithDriver是使用IO控制命令BINDER_WRITE_READ来与Binder驱动程序交互的，
 * 因此，它需要定义一个binder_write_read结构体来指定输入缓冲区和输出缓冲区。
 * 其中，输出缓冲区保存的是进程发送给Binder驱动程序的命令协议，
 * 而输入缓冲区保存的是Binder驱动程序发送给进程的返回协议，
 * 它们分别与IPCThreadState类内部的命令协议缓冲区mOut和返回协议缓冲区mIn对应。
 * 
 * 在IPCThreadState类内部，除了使用缓冲区 mOut 来保存即将要发送给Binder驱动程序的命令协议之外，
 * 还使用缓冲区 mIn 来保存那些从Binder驱动程序接收到的返回协议。
 * 
 * @doReceive: 用来描述调用者是否希望IPCThreadState类的成员函数talkWithDriver只接收Binder驱动程序发送给该进程的返回协议;(默认为true)
 * 一个进程使用IO控制命令BINDER_WRITE_READ进入到Binder驱动程序，当传递的binder_write_read结构体的输出缓冲区和输入缓冲区的长度分别等于0和大于0时，
 * Binder驱动程序就不会处理进程给它发送的命令协议，而只会向该进程发送返回协议，这样进程就达到了只接收返回协议的效果。
 * 
 * IPCThreadState类的成员函数talkWithDriver是否只接收Binder驱动程序发送给它的返回协议还受到返回协议缓冲区mIn的影响。
 * 如果上次Binder发送给进程的返回协议已经处理完成，即返回协议缓冲区mIn中的返回协议已经处理完成，
 * 那么即使参数doReceive的值为true，IPCThreadState类的成员函数talkWithDriver也会向Binder驱动程序发送命令协议。
 * 
 */
status_t IPCThreadState::talkWithDriver(bool doReceive)
{
    LOG_ASSERT(mProcess->mDriverFD >= 0, "Binder driver is not opened");
    
    binder_write_read bwr;
    
    // Is the read buffer empty?
    const bool needRead = mIn.dataPosition() >= mIn.dataSize();
    
    // We don't want to write anything if we are still reading
    // from data left in the input buffer and the caller
    // has requested to read the next data.
    // 如果返回协议缓冲区mIn的返回协议已经处理完成，即变量needRead的值为true，
    // 或者调用者不是只希望接收Binder驱动程序发送给进程的返回协议，即参数doReceive的值为false，
    // 那么将变量outAvail的值设置为IPCThreadState类内部的命令协议缓冲区的长度；否则，就将它的值设置为0。
    // 如果变量outAvail的值等于0，那么将IPCThreadState类内部的命令协议缓冲区mOut设置
    // 为binder_write_read结构体bwr的输出缓冲区write_buffer是起不到任何效果的。
    const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;
    
    // 将变量outAvail的值设置为binder_write_read结构体bwr的输出缓冲区的长度write_size;
    bwr.write_size = outAvail;
    // 将IPCThreadState类内部的命令协议缓冲区mOut设置为binder_write_read结构体bwr的输出缓冲区write_buffer;
    bwr.write_buffer = (long unsigned int)mOut.data();

    // This is what we'll read.
    if (doReceive && needRead) {
        bwr.read_size = mIn.dataCapacity();
        bwr.read_buffer = (long unsigned int)mIn.data();
    } else {
        bwr.read_size = 0;
    }
    
    IF_LOG_COMMANDS() {
        TextOutput::Bundle _b(alog);
        if (outAvail != 0) {
            alog << "Sending commands to driver: " << indent;
            const void* cmds = (const void*)bwr.write_buffer;
            const void* end = ((const uint8_t*)cmds)+bwr.write_size;
            alog << HexDump(cmds, bwr.write_size) << endl;
            while (cmds < end) cmds = printCommand(alog, cmds);
            alog << dedent;
        }
        alog << "Size of receive buffer: " << bwr.read_size
            << ", needRead: " << needRead << ", doReceive: " << doReceive << endl;
    }
    
    // Return immediately if there is nothing to do.
    // 判断binder_write_read结构体bwr的输出缓冲区的长度write_size和输入缓冲区的长度read_size的值是否都等于0。
    // 如果是，就说明IPCThreadState类的成员函数talkWithDriver根本就不需要进入到Binder驱动程序，
    // 因此，函数就直接返回了。
    if ((bwr.write_size == 0) && (bwr.read_size == 0)) return NO_ERROR;
    
    bwr.write_consumed = 0;
    bwr.read_consumed = 0;
    status_t err;

    // while循环使用IO控制命令BINDER_WRITE_READ来与Binder驱动程序进行交互。
    // 由于这时候传递给Binder驱动程序的binder_write_read结构体bwr的输出缓冲区的长度write_size和输入缓冲区的长度read_size均大于0，
    // 因此，Binder驱动程序在处理IO控制命令BINDER_WRITE_READ时，就会首先调用函数binder_thread_write来处理进程给它发送的BC_TRANSACTION命令协议，
    // 接着又会调用函数binder_thread_read来读取Binder驱动程序给进程发送的返回协议。
    do {
        IF_LOG_COMMANDS() {
            alog << "About to read/write, write size = " << mOut.dataSize() << endl;
        }
#if defined(HAVE_ANDROID_OS)
        // 调用 binder_ioctl 与驱动程序交互;
        if (ioctl(mProcess->mDriverFD, BINDER_WRITE_READ, &bwr) >= 0)
            err = NO_ERROR;
        else
            err = -errno;
#else
        err = INVALID_OPERATION;
#endif
        IF_LOG_COMMANDS() {
            alog << "Finished read/write, write size = " << mOut.dataSize() << endl;
        }
    } while (err == -EINTR);
    
    IF_LOG_COMMANDS() {
        alog << "Our err: " << (void*)err << ", write consumed: "
            << bwr.write_consumed << " (of " << mOut.dataSize()
			<< "), read consumed: " << bwr.read_consumed << endl;
    }

    // 从Binder驱动程序中返回来之后，将Binder驱动程序已经处理的命令协议从IPCThreadState类内部的命令协议缓冲区mOut中移除，
    // 接着将从Binder驱动程序中读取出来的返回协议保存在IPCThreadState类内部的返回协议缓冲区mIn中。
    if (err >= NO_ERROR) {
        if (bwr.write_consumed > 0) {
            if (bwr.write_consumed < (ssize_t)mOut.dataSize())
                mOut.remove(0, bwr.write_consumed);
            else
                mOut.setDataSize(0);
        }
        if (bwr.read_consumed > 0) {
            mIn.setDataSize(bwr.read_consumed);
            mIn.setDataPosition(0);
        }
        IF_LOG_COMMANDS() {
            TextOutput::Bundle _b(alog);
            alog << "Remaining data size: " << mOut.dataSize() << endl;
            alog << "Received commands from driver: " << indent;
            const void* cmds = mIn.data();
            const void* end = mIn.data() + mIn.dataSize();
            alog << HexDump(cmds, mIn.dataSize()) << endl;
            while (cmds < end) cmds = printReturnCommand(alog, cmds);
            alog << dedent;
        }
        return NO_ERROR;
    }
    
    return err;
}

/**
 * writeTransactionData 将Parcel内容写入到一个 binder_transaction_data 结构体中;
 */
status_t IPCThreadState::writeTransactionData(int32_t cmd, uint32_t binderFlags,
    int32_t handle, uint32_t code, const Parcel& data, status_t* statusBuffer)
{
    // 定义一个 binder_transaction_data 结构体;
    binder_transaction_data tr;

    // 初始化 binder_transaction_data 结构体; (eg: 0, ADD_SERVICE_TRANSACTION, TF_ACCEPT_FDS)
    tr.target.handle = handle;
    tr.code = code;
    tr.flags = binderFlags;
    
    // 确认Parcel对象data中的进程间通信数据的正确性;
    const status_t err = data.errorCheck();
    if (err == NO_ERROR) {
        // 将Parcel对象data内部的数据缓冲区和偏移数组设置为 binder_transaction_data 结构体 tr 的数据缓冲区和偏移数组;
        tr.data_size = data.ipcDataSize();
        tr.data.ptr.buffer = data.ipcData();
        tr.offsets_size = data.ipcObjectsCount()*sizeof(size_t);
        tr.data.ptr.offsets = data.ipcObjects();
    } else if (statusBuffer) {
        tr.flags |= TF_STATUS_CODE;
        *statusBuffer = err;
        tr.data_size = sizeof(status_t);
        tr.data.ptr.buffer = statusBuffer;
        tr.offsets_size = 0;
        tr.data.ptr.offsets = NULL;
    } else {
        return (mLastError = err);
    }
    
    // 将命令协议号cmd(eg:BC_TRANSACTION)写入到IPCThreadState类的成员变量mOut中;
    mOut.writeInt32(cmd);
    // 将binder_transaction_data 结构体tr写入到IPCThreadState类的成员变量mOut中;
    mOut.write(&tr, sizeof(tr));
    // 上面两行结合起来，表示它有一个cmd协议号的内容(tr)需要发送给Binder驱动程序处理;
    
    return NO_ERROR;
}

sp<BBinder> the_context_object;

void setTheContextObject(sp<BBinder> obj)
{
    the_context_object = obj;
}

status_t IPCThreadState::executeCommand(int32_t cmd)
{
    BBinder* obj;
    RefBase::weakref_type* refs;
    status_t result = NO_ERROR;
    
    switch (cmd) {
    case BR_ERROR:
        result = mIn.readInt32();
        break;
        
    case BR_OK:
        break;
        
    case BR_ACQUIRE:
        refs = (RefBase::weakref_type*)mIn.readInt32();
        obj = (BBinder*)mIn.readInt32();
        LOG_ASSERT(refs->refBase() == obj,
                   "BR_ACQUIRE: object %p does not match cookie %p (expected %p)",
                   refs, obj, refs->refBase());
        obj->incStrong(mProcess.get());
        IF_LOG_REMOTEREFS() {
            LOG_REMOTEREFS("BR_ACQUIRE from driver on %p", obj);
            obj->printRefs();
        }
        mOut.writeInt32(BC_ACQUIRE_DONE);
        mOut.writeInt32((int32_t)refs);
        mOut.writeInt32((int32_t)obj);
        break;
        
    case BR_RELEASE:
        refs = (RefBase::weakref_type*)mIn.readInt32();
        obj = (BBinder*)mIn.readInt32();
        LOG_ASSERT(refs->refBase() == obj,
                   "BR_RELEASE: object %p does not match cookie %p (expected %p)",
                   refs, obj, refs->refBase());
        IF_LOG_REMOTEREFS() {
            LOG_REMOTEREFS("BR_RELEASE from driver on %p", obj);
            obj->printRefs();
        }
        mPendingStrongDerefs.push(obj);
        break;
        
    case BR_INCREFS:
        refs = (RefBase::weakref_type*)mIn.readInt32();
        obj = (BBinder*)mIn.readInt32();
        refs->incWeak(mProcess.get());
        mOut.writeInt32(BC_INCREFS_DONE);
        mOut.writeInt32((int32_t)refs);
        mOut.writeInt32((int32_t)obj);
        break;
        
    case BR_DECREFS:
        refs = (RefBase::weakref_type*)mIn.readInt32();
        obj = (BBinder*)mIn.readInt32();
        // NOTE: This assertion is not valid, because the object may no
        // longer exist (thus the (BBinder*)cast above resulting in a different
        // memory address).
        //LOG_ASSERT(refs->refBase() == obj,
        //           "BR_DECREFS: object %p does not match cookie %p (expected %p)",
        //           refs, obj, refs->refBase());
        mPendingWeakDerefs.push(refs);
        break;
        
    case BR_ATTEMPT_ACQUIRE:
        refs = (RefBase::weakref_type*)mIn.readInt32();
        obj = (BBinder*)mIn.readInt32();
         
        {
            const bool success = refs->attemptIncStrong(mProcess.get());
            LOG_ASSERT(success && refs->refBase() == obj,
                       "BR_ATTEMPT_ACQUIRE: object %p does not match cookie %p (expected %p)",
                       refs, obj, refs->refBase());
            
            mOut.writeInt32(BC_ACQUIRE_RESULT);
            mOut.writeInt32((int32_t)success);
        }
        break;
    
    case BR_TRANSACTION:
        {
            binder_transaction_data tr;
            result = mIn.read(&tr, sizeof(tr));
            LOG_ASSERT(result == NO_ERROR,
                "Not enough command data for brTRANSACTION");
            if (result != NO_ERROR) break;
            
            Parcel buffer;
            buffer.ipcSetDataReference(
                reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                tr.data_size,
                reinterpret_cast<const size_t*>(tr.data.ptr.offsets),
                tr.offsets_size/sizeof(size_t), freeBuffer, this);
            
            const pid_t origPid = mCallingPid;
            const uid_t origUid = mCallingUid;
            
            mCallingPid = tr.sender_pid;
            mCallingUid = tr.sender_euid;
            
            int curPrio = getpriority(PRIO_PROCESS, mMyThreadId);
            if (gDisableBackgroundScheduling) {
                if (curPrio > ANDROID_PRIORITY_NORMAL) {
                    // We have inherited a reduced priority from the caller, but do not
                    // want to run in that state in this process.  The driver set our
                    // priority already (though not our scheduling class), so bounce
                    // it back to the default before invoking the transaction.
                    setpriority(PRIO_PROCESS, mMyThreadId, ANDROID_PRIORITY_NORMAL);
                }
            } else {
                if (curPrio >= ANDROID_PRIORITY_BACKGROUND) {
                    // We want to use the inherited priority from the caller.
                    // Ensure this thread is in the background scheduling class,
                    // since the driver won't modify scheduling classes for us.
                    // The scheduling group is reset to default by the caller
                    // once this method returns after the transaction is complete.
                    androidSetThreadSchedulingGroup(mMyThreadId,
                                                    ANDROID_TGROUP_BG_NONINTERACT);
                }
            }

            //LOGI(">>>> TRANSACT from pid %d uid %d\n", mCallingPid, mCallingUid);
            
            Parcel reply;
            IF_LOG_TRANSACTIONS() {
                TextOutput::Bundle _b(alog);
                alog << "BR_TRANSACTION thr " << (void*)pthread_self()
                    << " / obj " << tr.target.ptr << " / code "
                    << TypeCode(tr.code) << ": " << indent << buffer
                    << dedent << endl
                    << "Data addr = "
                    << reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer)
                    << ", offsets addr="
                    << reinterpret_cast<const size_t*>(tr.data.ptr.offsets) << endl;
            }
            if (tr.target.ptr) {
                sp<BBinder> b((BBinder*)tr.cookie);
                const status_t error = b->transact(tr.code, buffer, &reply, tr.flags);
                if (error < NO_ERROR) reply.setError(error);

            } else {
                const status_t error = the_context_object->transact(tr.code, buffer, &reply, tr.flags);
                if (error < NO_ERROR) reply.setError(error);
            }
            
            //LOGI("<<<< TRANSACT from pid %d restore pid %d uid %d\n",
            //     mCallingPid, origPid, origUid);
            
            if ((tr.flags & TF_ONE_WAY) == 0) {
                LOG_ONEWAY("Sending reply to %d!", mCallingPid);
                sendReply(reply, 0);
            } else {
                LOG_ONEWAY("NOT sending reply to %d!", mCallingPid);
            }
            
            mCallingPid = origPid;
            mCallingUid = origUid;

            IF_LOG_TRANSACTIONS() {
                TextOutput::Bundle _b(alog);
                alog << "BC_REPLY thr " << (void*)pthread_self() << " / obj "
                    << tr.target.ptr << ": " << indent << reply << dedent << endl;
            }
            
        }
        break;
    
    case BR_DEAD_BINDER:
        {
            BpBinder *proxy = (BpBinder*)mIn.readInt32();
            proxy->sendObituary();
            mOut.writeInt32(BC_DEAD_BINDER_DONE);
            mOut.writeInt32((int32_t)proxy);
        } break;
        
    case BR_CLEAR_DEATH_NOTIFICATION_DONE:
        {
            BpBinder *proxy = (BpBinder*)mIn.readInt32();
            proxy->getWeakRefs()->decWeak(proxy);
        } break;
        
    case BR_FINISHED:
        result = TIMED_OUT;
        break;
        
    case BR_NOOP:
        break;
        
    case BR_SPAWN_LOOPER:
        mProcess->spawnPooledThread(false);
        break;
        
    default:
        printf("*** BAD COMMAND %d received from Binder driver\n", cmd);
        result = UNKNOWN_ERROR;
        break;
    }

    if (result != NO_ERROR) {
        mLastError = result;
    }
    
    return result;
}

void IPCThreadState::threadDestructor(void *st)
{
	IPCThreadState* const self = static_cast<IPCThreadState*>(st);
	if (self) {
		self->flushCommands();
#if defined(HAVE_ANDROID_OS)
        ioctl(self->mProcess->mDriverFD, BINDER_THREAD_EXIT, 0);
#endif
		delete self;
	}
}


void IPCThreadState::freeBuffer(Parcel* parcel, const uint8_t* data, size_t dataSize,
                                const size_t* objects, size_t objectsSize,
                                void* cookie)
{
    //LOGI("Freeing parcel %p", &parcel);
    IF_LOG_COMMANDS() {
        alog << "Writing BC_FREE_BUFFER for " << data << endl;
    }
    LOG_ASSERT(data != NULL, "Called with NULL data");
    if (parcel != NULL) parcel->closeFileDescriptors();
    IPCThreadState* state = self();
    state->mOut.writeInt32(BC_FREE_BUFFER);
    state->mOut.writeInt32((int32_t)data);
}

}; // namespace android
