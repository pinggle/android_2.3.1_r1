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

#define LOG_TAG "Parcel"
//#define LOG_NDEBUG 0

#include <binder/Parcel.h>

#include <binder/IPCThreadState.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <utils/Debug.h>
#include <binder/ProcessState.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/String16.h>
#include <utils/TextOutput.h>
#include <utils/misc.h>
#include <utils/Flattenable.h>

#include <private/binder/binder_module.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef INT32_MAX
#define INT32_MAX ((int32_t)(2147483647))
#endif

#define LOG_REFS(...)
//#define LOG_REFS(...) LOG(LOG_DEBUG, "Parcel", __VA_ARGS__)

// ---------------------------------------------------------------------------

#define PAD_SIZE(s) (((s)+3)&~3)

// Note: must be kept in sync with android/os/StrictMode.java's PENALTY_GATHER
#define STRICT_MODE_PENALTY_GATHER 0x100

// Note: must be kept in sync with android/os/Parcel.java's EX_HAS_REPLY_HEADER
#define EX_HAS_REPLY_HEADER -128

// XXX This can be made public if we want to provide
// support for typed data.
struct small_flat_data
{
    uint32_t type;
    uint32_t data;
};

namespace android {

void acquire_object(const sp<ProcessState>& proc,
    const flat_binder_object& obj, const void* who)
{
    switch (obj.type) {
        case BINDER_TYPE_BINDER:
            if (obj.binder) {
                LOG_REFS("Parcel %p acquiring reference on local %p", who, obj.cookie);
                static_cast<IBinder*>(obj.cookie)->incStrong(who);
            }
            return;
        case BINDER_TYPE_WEAK_BINDER:
            if (obj.binder)
                static_cast<RefBase::weakref_type*>(obj.binder)->incWeak(who);
            return;
        case BINDER_TYPE_HANDLE: {
            const sp<IBinder> b = proc->getStrongProxyForHandle(obj.handle);
            if (b != NULL) {
                LOG_REFS("Parcel %p acquiring reference on remote %p", who, b.get());
                b->incStrong(who);
            }
            return;
        }
        case BINDER_TYPE_WEAK_HANDLE: {
            const wp<IBinder> b = proc->getWeakProxyForHandle(obj.handle);
            if (b != NULL) b.get_refs()->incWeak(who);
            return;
        }
        case BINDER_TYPE_FD: {
            // intentionally blank -- nothing to do to acquire this, but we do
            // recognize it as a legitimate object type.
            return;
        }
    }

    LOGD("Invalid object type 0x%08lx", obj.type);
}

void release_object(const sp<ProcessState>& proc,
    const flat_binder_object& obj, const void* who)
{
    switch (obj.type) {
        case BINDER_TYPE_BINDER:
            if (obj.binder) {
                LOG_REFS("Parcel %p releasing reference on local %p", who, obj.cookie);
                static_cast<IBinder*>(obj.cookie)->decStrong(who);
            }
            return;
        case BINDER_TYPE_WEAK_BINDER:
            if (obj.binder)
                static_cast<RefBase::weakref_type*>(obj.binder)->decWeak(who);
            return;
        case BINDER_TYPE_HANDLE: {
            const sp<IBinder> b = proc->getStrongProxyForHandle(obj.handle);
            if (b != NULL) {
                LOG_REFS("Parcel %p releasing reference on remote %p", who, b.get());
                b->decStrong(who);
            }
            return;
        }
        case BINDER_TYPE_WEAK_HANDLE: {
            const wp<IBinder> b = proc->getWeakProxyForHandle(obj.handle);
            if (b != NULL) b.get_refs()->decWeak(who);
            return;
        }
        case BINDER_TYPE_FD: {
            if (obj.cookie != (void*)0) close(obj.handle);
            return;
        }
    }

    LOGE("Invalid object type 0x%08lx", obj.type);
}

inline static status_t finish_flatten_binder(
    const sp<IBinder>& binder, const flat_binder_object& flat, Parcel* out)
{
    // 调用Parcel对象out的成员函数writeObject将flat_binder_object结构体flat写入到内部;
    return out->writeObject(flat, false);
}

// 函数 flatten_binder 将一个Service组件封装成一个flat_binder_object结构体
status_t flatten_binder(const sp<ProcessState>& proc,
    const sp<IBinder>& binder, Parcel* out)
{
    // 首先定义一个 flat_binder_object 结构体 obj;
    flat_binder_object obj;
    
    // 设置标志位;
    // 0x7f 用来描述将要注册的 Service 组件在处理一个进程间通信请求时，它所使用的 Service 线程的优先级不能低于 0x7f;
    // FLAT_BINDER_FLAG_ACCEPTS_FDS 表示可以将包含文件描述符的进程间通信数据传递给将要注册的 Service 组件处理.
    obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    if (binder != NULL) {
        // binder指向FregService组件，它继承了BBinder类，BBinder类的localBinder函数用来返回一个Binder本地对象接口;
        // 由于 FregService 组件是一个 Binder本地对象，因此得到 local 变量不为 NULL;
        IBinder *local = binder->localBinder();
        if (!local) {
            BpBinder *proxy = binder->remoteBinder();
            if (proxy == NULL) {
                LOGE("null proxy");
            }
            const int32_t handle = proxy ? proxy->handle() : 0;
            obj.type = BINDER_TYPE_HANDLE;
            obj.handle = handle;
            obj.cookie = NULL;
        } else {
            // 将 flat_binder_object 对象设置为 BINDER_TYPE_BINDER 类型的对象;
            obj.type = BINDER_TYPE_BINDER;
            // 将 flat_binder_object 对象的binder值设置为local内部的一个弱引用计数对象的地址值;
            obj.binder = local->getWeakRefs();
            // 将 flat_binder_object 对象的 cookie 对象设置为Binder本地对象local的地址值;
            obj.cookie = local;
        }
    } else {
        obj.type = BINDER_TYPE_BINDER;
        obj.binder = NULL;
        obj.cookie = NULL;
    }
    
    // 将 flat_binder_object 对象 obj 写入到 Parcel 对象 out 中;
    return finish_flatten_binder(binder, obj, out);
}

status_t flatten_binder(const sp<ProcessState>& proc,
    const wp<IBinder>& binder, Parcel* out)
{
    flat_binder_object obj;
    
    obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    if (binder != NULL) {
        sp<IBinder> real = binder.promote();
        if (real != NULL) {
            IBinder *local = real->localBinder();
            if (!local) {
                BpBinder *proxy = real->remoteBinder();
                if (proxy == NULL) {
                    LOGE("null proxy");
                }
                const int32_t handle = proxy ? proxy->handle() : 0;
                obj.type = BINDER_TYPE_WEAK_HANDLE;
                obj.handle = handle;
                obj.cookie = NULL;
            } else {
                obj.type = BINDER_TYPE_WEAK_BINDER;
                obj.binder = binder.get_refs();
                obj.cookie = binder.unsafe_get();
            }
            return finish_flatten_binder(real, obj, out);
        }
        
        // XXX How to deal?  In order to flatten the given binder,
        // we need to probe it for information, which requires a primary
        // reference...  but we don't have one.
        //
        // The OpenBinder implementation uses a dynamic_cast<> here,
        // but we can't do that with the different reference counting
        // implementation we are using.
        LOGE("Unable to unflatten Binder weak reference!");
        obj.type = BINDER_TYPE_BINDER;
        obj.binder = NULL;
        obj.cookie = NULL;
        return finish_flatten_binder(NULL, obj, out);
    
    } else {
        obj.type = BINDER_TYPE_BINDER;
        obj.binder = NULL;
        obj.cookie = NULL;
        return finish_flatten_binder(NULL, obj, out);
    }
}

inline static status_t finish_unflatten_binder(
    BpBinder* proxy, const flat_binder_object& flat, const Parcel& in)
{
    return NO_ERROR;
}
    
status_t unflatten_binder(const sp<ProcessState>& proc,
    const Parcel& in, sp<IBinder>* out)
{
    const flat_binder_object* flat = in.readObject(false);
    
    if (flat) {
        switch (flat->type) {
            case BINDER_TYPE_BINDER:
                *out = static_cast<IBinder*>(flat->cookie);
                return finish_unflatten_binder(NULL, *flat, in);
            case BINDER_TYPE_HANDLE:
                *out = proc->getStrongProxyForHandle(flat->handle);
                return finish_unflatten_binder(
                    static_cast<BpBinder*>(out->get()), *flat, in);
        }        
    }
    return BAD_TYPE;
}

status_t unflatten_binder(const sp<ProcessState>& proc,
    const Parcel& in, wp<IBinder>* out)
{
    const flat_binder_object* flat = in.readObject(false);
    
    if (flat) {
        switch (flat->type) {
            case BINDER_TYPE_BINDER:
                *out = static_cast<IBinder*>(flat->cookie);
                return finish_unflatten_binder(NULL, *flat, in);
            case BINDER_TYPE_WEAK_BINDER:
                if (flat->binder != NULL) {
                    out->set_object_and_refs(
                        static_cast<IBinder*>(flat->cookie),
                        static_cast<RefBase::weakref_type*>(flat->binder));
                } else {
                    *out = NULL;
                }
                return finish_unflatten_binder(NULL, *flat, in);
            case BINDER_TYPE_HANDLE:
            case BINDER_TYPE_WEAK_HANDLE:
                *out = proc->getWeakProxyForHandle(flat->handle);
                return finish_unflatten_binder(
                    static_cast<BpBinder*>(out->unsafe_get()), *flat, in);
        }
    }
    return BAD_TYPE;
}

// ---------------------------------------------------------------------------

Parcel::Parcel()
{
    initState();
}

Parcel::~Parcel()
{
    freeDataNoInit();
}

const uint8_t* Parcel::data() const
{
    return mData;
}

size_t Parcel::dataSize() const
{
    return (mDataSize > mDataPos ? mDataSize : mDataPos);
}

size_t Parcel::dataAvail() const
{
    // TODO: decide what to do about the possibility that this can
    // report an available-data size that exceeds a Java int's max
    // positive value, causing havoc.  Fortunately this will only
    // happen if someone constructs a Parcel containing more than two
    // gigabytes of data, which on typical phone hardware is simply
    // not possible.
    return dataSize() - dataPosition();
}

size_t Parcel::dataPosition() const
{
    return mDataPos;
}

size_t Parcel::dataCapacity() const
{
    return mDataCapacity;
}

status_t Parcel::setDataSize(size_t size)
{
    status_t err;
    err = continueWrite(size);
    if (err == NO_ERROR) {
        mDataSize = size;
        LOGV("setDataSize Setting data size of %p to %d\n", this, mDataSize);
    }
    return err;
}

void Parcel::setDataPosition(size_t pos) const
{
    mDataPos = pos;
    mNextObjectHint = 0;
}

status_t Parcel::setDataCapacity(size_t size)
{
    if (size > mDataSize) return continueWrite(size);
    return NO_ERROR;
}

status_t Parcel::setData(const uint8_t* buffer, size_t len)
{
    status_t err = restartWrite(len);
    if (err == NO_ERROR) {
        memcpy(const_cast<uint8_t*>(data()), buffer, len);
        mDataSize = len;
        mFdsKnown = false;
    }
    return err;
}

status_t Parcel::appendFrom(Parcel *parcel, size_t offset, size_t len)
{
    const sp<ProcessState> proc(ProcessState::self());
    status_t err;
    uint8_t *data = parcel->mData;
    size_t *objects = parcel->mObjects;
    size_t size = parcel->mObjectsSize;
    int startPos = mDataPos;
    int firstIndex = -1, lastIndex = -2;

    if (len == 0) {
        return NO_ERROR;
    }

    // range checks against the source parcel size
    if ((offset > parcel->mDataSize)
            || (len > parcel->mDataSize)
            || (offset + len > parcel->mDataSize)) {
        return BAD_VALUE;
    }

    // Count objects in range
    for (int i = 0; i < (int) size; i++) {
        size_t off = objects[i];
        if ((off >= offset) && (off < offset + len)) {
            if (firstIndex == -1) {
                firstIndex = i;
            }
            lastIndex = i;
        }
    }
    int numObjects = lastIndex - firstIndex + 1;

    // grow data
    err = growData(len);
    if (err != NO_ERROR) {
        return err;
    }

    // append data
    memcpy(mData + mDataPos, data + offset, len);
    mDataPos += len;
    mDataSize += len;

    if (numObjects > 0) {
        // grow objects
        if (mObjectsCapacity < mObjectsSize + numObjects) {
            int newSize = ((mObjectsSize + numObjects)*3)/2;
            size_t *objects =
                (size_t*)realloc(mObjects, newSize*sizeof(size_t));
            if (objects == (size_t*)0) {
                return NO_MEMORY;
            }
            mObjects = objects;
            mObjectsCapacity = newSize;
        }
        
        // append and acquire objects
        int idx = mObjectsSize;
        for (int i = firstIndex; i <= lastIndex; i++) {
            size_t off = objects[i] - offset + startPos;
            mObjects[idx++] = off;
            mObjectsSize++;

            flat_binder_object* flat
                = reinterpret_cast<flat_binder_object*>(mData + off);
            acquire_object(proc, *flat, this);

            if (flat->type == BINDER_TYPE_FD) {
                // If this is a file descriptor, we need to dup it so the
                // new Parcel now owns its own fd, and can declare that we
                // officially know we have fds.
                flat->handle = dup(flat->handle);
                flat->cookie = (void*)1;
                mHasFds = mFdsKnown = true;
            }
        }
    }

    return NO_ERROR;
}

bool Parcel::hasFileDescriptors() const
{
    if (!mFdsKnown) {
        scanForFds();
    }
    return mHasFds;
}

/**
 * 写入一个 Binder 进程间通信请求头;
 * Binder进程间通信请求头由两部分内容组成，第一部分是一个整数值，用来描述一个 Strict Mode Policy;
 * 第二部分内容是一个字符串，用来描述所请求服务的接口描述符。
 */
// Write RPC headers.  (previously just the interface token)
status_t Parcel::writeInterfaceToken(const String16& interface)
{
    // 首先获得当前线程的 Strict Mode Policy，然后将它与宏 STRICT_MODE_PENALTY_GATHER 执行一个按位或操作，
    // 最后将得到的结果写入到 Parcel 对象 data 中去传递给目标 Server 线程.
    // STRICT_MODE_PENALTY_GATHER:表示Service线程在处理进程间通信请求时，即使违反了预先设定的 Strict Mode Policy，
    // 系统也不发出警告，而是把这些警告收集起来，最后统一发送给Client线程来处理.
    writeInt32(IPCThreadState::self()->getStrictModePolicy() |
               STRICT_MODE_PENALTY_GATHER);
    // currently the interface identification token is just its name as a string
    // 将一个服务接口描述符写入到 Parcel 对象data中。Server 组件在处理一个进程间通信请求时，会将这个服务接口的描述符读取出来，
    // 并且验证它是否是一个合法的服务接口描述符，即是否是自己所实现的服务接口的描述符。如果不是，则说明这是一个非法的进程间通信请求。
    return writeString16(interface);
}

bool Parcel::checkInterface(IBinder* binder) const
{
    return enforceInterface(binder->getInterfaceDescriptor());
}

bool Parcel::enforceInterface(const String16& interface,
                              IPCThreadState* threadState) const
{
    int32_t strictPolicy = readInt32();
    if (threadState == NULL) {
        threadState = IPCThreadState::self();
    }
    if ((threadState->getLastTransactionBinderFlags() &
         IBinder::FLAG_ONEWAY) != 0) {
      // For one-way calls, the callee is running entirely
      // disconnected from the caller, so disable StrictMode entirely.
      // Not only does disk/network usage not impact the caller, but
      // there's no way to commuicate back any violations anyway.
      threadState->setStrictModePolicy(0);
    } else {
      threadState->setStrictModePolicy(strictPolicy);
    }
    const String16 str(readString16());
    if (str == interface) {
        return true;
    } else {
        LOGW("**** enforceInterface() expected '%s' but read '%s'\n",
                String8(interface).string(), String8(str).string());
        return false;
    }
}

const size_t* Parcel::objects() const
{
    return mObjects;
}

size_t Parcel::objectsCount() const
{
    return mObjectsSize;
}

status_t Parcel::errorCheck() const
{
    return mError;
}

void Parcel::setError(status_t err)
{
    mError = err;
}

status_t Parcel::finishWrite(size_t len)
{
    //printf("Finish write of %d\n", len);
    mDataPos += len;
    LOGV("finishWrite Setting data pos of %p to %d\n", this, mDataPos);
    if (mDataPos > mDataSize) {
        mDataSize = mDataPos;
        LOGV("finishWrite Setting data size of %p to %d\n", this, mDataSize);
    }
    //printf("New pos=%d, size=%d\n", mDataPos, mDataSize);
    return NO_ERROR;
}

status_t Parcel::writeUnpadded(const void* data, size_t len)
{
    size_t end = mDataPos + len;
    if (end < mDataPos) {
        // integer overflow
        return BAD_VALUE;
    }

    if (end <= mDataCapacity) {
restart_write:
        memcpy(mData+mDataPos, data, len);
        return finishWrite(len);
    }

    status_t err = growData(len);
    if (err == NO_ERROR) goto restart_write;
    return err;
}

status_t Parcel::write(const void* data, size_t len)
{
    void* const d = writeInplace(len);
    if (d) {
        memcpy(d, data, len);
        return NO_ERROR;
    }
    return mError;
}

void* Parcel::writeInplace(size_t len)
{
    const size_t padded = PAD_SIZE(len);

    // sanity check for integer overflow
    if (mDataPos+padded < mDataPos) {
        return NULL;
    }

    if ((mDataPos+padded) <= mDataCapacity) {
restart_write:
        //printf("Writing %ld bytes, padded to %ld\n", len, padded);
        uint8_t* const data = mData+mDataPos;

        // Need to pad at end?
        if (padded != len) {
#if BYTE_ORDER == BIG_ENDIAN
            static const uint32_t mask[4] = {
                0x00000000, 0xffffff00, 0xffff0000, 0xff000000
            };
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
            static const uint32_t mask[4] = {
                0x00000000, 0x00ffffff, 0x0000ffff, 0x000000ff
            };
#endif
            //printf("Applying pad mask: %p to %p\n", (void*)mask[padded-len],
            //    *reinterpret_cast<void**>(data+padded-4));
            *reinterpret_cast<uint32_t*>(data+padded-4) &= mask[padded-len];
        }

        finishWrite(padded);
        return data;
    }

    status_t err = growData(padded);
    if (err == NO_ERROR) goto restart_write;
    return NULL;
}

status_t Parcel::writeInt32(int32_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeInt64(int64_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeFloat(float val)
{
    return writeAligned(val);
}

status_t Parcel::writeDouble(double val)
{
    return writeAligned(val);
}

status_t Parcel::writeIntPtr(intptr_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeCString(const char* str)
{
    return write(str, strlen(str)+1);
}

status_t Parcel::writeString8(const String8& str)
{
    status_t err = writeInt32(str.bytes());
    if (err == NO_ERROR) {
        err = write(str.string(), str.bytes()+1);
    }
    return err;
}

status_t Parcel::writeString16(const String16& str)
{
    return writeString16(str.string(), str.size());
}

status_t Parcel::writeString16(const char16_t* str, size_t len)
{
    if (str == NULL) return writeInt32(-1);
    
    status_t err = writeInt32(len);
    if (err == NO_ERROR) {
        len *= sizeof(char16_t);
        uint8_t* data = (uint8_t*)writeInplace(len+sizeof(char16_t));
        if (data) {
            memcpy(data, str, len);
            *reinterpret_cast<char16_t*>(data+len) = 0;
            return NO_ERROR;
        }
        err = mError;
    }
    return err;
}

// 将要注册的Service组件封装成一个flat_binder_object结构体;
status_t Parcel::writeStrongBinder(const sp<IBinder>& val)
{
    return flatten_binder(ProcessState::self(), val, this);
}

status_t Parcel::writeWeakBinder(const wp<IBinder>& val)
{
    return flatten_binder(ProcessState::self(), val, this);
}

status_t Parcel::writeNativeHandle(const native_handle* handle)
{
    if (!handle || handle->version != sizeof(native_handle))
        return BAD_TYPE;

    status_t err;
    err = writeInt32(handle->numFds);
    if (err != NO_ERROR) return err;

    err = writeInt32(handle->numInts);
    if (err != NO_ERROR) return err;

    for (int i=0 ; err==NO_ERROR && i<handle->numFds ; i++)
        err = writeDupFileDescriptor(handle->data[i]);

    if (err != NO_ERROR) {
        LOGD("write native handle, write dup fd failed");
        return err;
    }
    err = write(handle->data + handle->numFds, sizeof(int)*handle->numInts);
    return err;
}

status_t Parcel::writeFileDescriptor(int fd)
{
    flat_binder_object obj;
    obj.type = BINDER_TYPE_FD;
    obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj.handle = fd;
    obj.cookie = (void*)0;
    return writeObject(obj, true);
}

status_t Parcel::writeDupFileDescriptor(int fd)
{
    flat_binder_object obj;
    obj.type = BINDER_TYPE_FD;
    obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj.handle = dup(fd);
    obj.cookie = (void*)1;
    return writeObject(obj, true);
}

status_t Parcel::write(const Flattenable& val)
{
    status_t err;

    // size if needed
    size_t len = val.getFlattenedSize();
    size_t fd_count = val.getFdCount();

    err = this->writeInt32(len);
    if (err) return err;

    err = this->writeInt32(fd_count);
    if (err) return err;

    // payload
    void* buf = this->writeInplace(PAD_SIZE(len));
    if (buf == NULL)
        return BAD_VALUE;

    int* fds = NULL;
    if (fd_count) {
        fds = new int[fd_count];
    }

    err = val.flatten(buf, len, fds, fd_count);
    for (size_t i=0 ; i<fd_count && err==NO_ERROR ; i++) {
        err = this->writeDupFileDescriptor( fds[i] );
    }

    if (fd_count) {
        delete [] fds;
    }

    return err;
}

/**
 * writeOjbect: 将 flat_binder_object 结构体写入到内部;
 * Parcel类内部有mData和mObjects两个缓冲区，
 * 其中，mData是一个数据缓冲区，它里面的内容可能包含有整数、字符串或者Binder对象，即flat_binder_object结构体；
 * mObjects是一个偏移数组，它保存了在数据缓冲区mData中的所有Binder对象的位置。
 * Binder驱动程序就是通过这个偏移数组找到进程间通信数据中的Binder对象的，以便对它们进行特殊处理。
 */
status_t Parcel::writeObject(const flat_binder_object& val, bool nullMetaData)
{
    // Parcel类的成员变量mDataPos记录了数据缓冲区mData下一个用来写入数据的位置，
    // 而成员变量mDataCapacity则记录了数据缓冲区mData的总大小；
    // 判断数据缓冲区mData是否还有足够的空间来写入一个Binder对象。
    const bool enoughData = (mDataPos+sizeof(val)) <= mDataCapacity;
    // Parcel类的成员变量mObjectsSize记录了偏移数组mObjects下一个用来写入数据的位置，
    // 而成员变量mObjectsCapacity则记录了偏移数组mObjects的总大小;
    // 下面一行代码用来判断偏移数组mObjects是否还有足够的空间来写入一个Binder对象的偏移位置。
    const bool enoughObjects = mObjectsSize < mObjectsCapacity;
    if (enoughData && enoughObjects) {
        // 下面的代码是将参数val所描述的Binder对象写入到数据缓冲区mData和偏移数组mObjects中;
restart_write:
        *reinterpret_cast<flat_binder_object*>(mData+mDataPos) = val;
        
        // Need to write meta-data?
        if (nullMetaData || val.binder != NULL) {
            mObjects[mObjectsSize] = mDataPos;
            acquire_object(ProcessState::self(), val, this);
            mObjectsSize++;
        }
        
        // remember if it's a file descriptor
        // 判断刚才写入的Binder对象的类型是否为 BINDER_TYPE_FD，如果是，
        // 那么就说明该Parcel对象的数据缓冲区中包含有文件描述符,于是将成员变量mHasFds 和mFdsKnown的值设置为true;
        if (val.type == BINDER_TYPE_FD) {
            mHasFds = mFdsKnown = true;
        }

        // 调用成员函数finishWrite来调整数据缓冲区mData下一个用来写入数据的位置，即调整成员变量mDataPos的值;
        return finishWrite(sizeof(flat_binder_object));
    }

    // 如果数据缓冲区mData或者偏移数组mObjects的空间不足以用来写入一个Binder对象，
    // 那么就会首先扩展它们的空间;
    if (!enoughData) {
        const status_t err = growData(sizeof(val));
        if (err != NO_ERROR) return err;
    }
    if (!enoughObjects) {
        size_t newSize = ((mObjectsSize+2)*3)/2;
        size_t* objects = (size_t*)realloc(mObjects, newSize*sizeof(size_t));
        if (objects == NULL) return NO_MEMORY;
        mObjects = objects;
        mObjectsCapacity = newSize;
    }
    
    goto restart_write;
}

status_t Parcel::writeNoException()
{
    return writeInt32(0);
}

void Parcel::remove(size_t start, size_t amt)
{
    LOG_ALWAYS_FATAL("Parcel::remove() not yet implemented!");
}

status_t Parcel::read(void* outData, size_t len) const
{
    if ((mDataPos+PAD_SIZE(len)) >= mDataPos && (mDataPos+PAD_SIZE(len)) <= mDataSize) {
        memcpy(outData, mData+mDataPos, len);
        mDataPos += PAD_SIZE(len);
        LOGV("read Setting data pos of %p to %d\n", this, mDataPos);
        return NO_ERROR;
    }
    return NOT_ENOUGH_DATA;
}

const void* Parcel::readInplace(size_t len) const
{
    if ((mDataPos+PAD_SIZE(len)) >= mDataPos && (mDataPos+PAD_SIZE(len)) <= mDataSize) {
        const void* data = mData+mDataPos;
        mDataPos += PAD_SIZE(len);
        LOGV("readInplace Setting data pos of %p to %d\n", this, mDataPos);
        return data;
    }
    return NULL;
}

template<class T>
status_t Parcel::readAligned(T *pArg) const {
    COMPILE_TIME_ASSERT_FUNCTION_SCOPE(PAD_SIZE(sizeof(T)) == sizeof(T));

    if ((mDataPos+sizeof(T)) <= mDataSize) {
        const void* data = mData+mDataPos;
        mDataPos += sizeof(T);
        *pArg =  *reinterpret_cast<const T*>(data);
        return NO_ERROR;
    } else {
        return NOT_ENOUGH_DATA;
    }
}

template<class T>
T Parcel::readAligned() const {
    T result;
    if (readAligned(&result) != NO_ERROR) {
        result = 0;
    }

    return result;
}

template<class T>
status_t Parcel::writeAligned(T val) {
    COMPILE_TIME_ASSERT_FUNCTION_SCOPE(PAD_SIZE(sizeof(T)) == sizeof(T));

    if ((mDataPos+sizeof(val)) <= mDataCapacity) {
restart_write:
        *reinterpret_cast<T*>(mData+mDataPos) = val;
        return finishWrite(sizeof(val));
    }

    status_t err = growData(sizeof(val));
    if (err == NO_ERROR) goto restart_write;
    return err;
}

status_t Parcel::readInt32(int32_t *pArg) const
{
    return readAligned(pArg);
}

int32_t Parcel::readInt32() const
{
    return readAligned<int32_t>();
}


status_t Parcel::readInt64(int64_t *pArg) const
{
    return readAligned(pArg);
}


int64_t Parcel::readInt64() const
{
    return readAligned<int64_t>();
}

status_t Parcel::readFloat(float *pArg) const
{
    return readAligned(pArg);
}


float Parcel::readFloat() const
{
    return readAligned<float>();
}

status_t Parcel::readDouble(double *pArg) const
{
    return readAligned(pArg);
}


double Parcel::readDouble() const
{
    return readAligned<double>();
}

status_t Parcel::readIntPtr(intptr_t *pArg) const
{
    return readAligned(pArg);
}


intptr_t Parcel::readIntPtr() const
{
    return readAligned<intptr_t>();
}


const char* Parcel::readCString() const
{
    const size_t avail = mDataSize-mDataPos;
    if (avail > 0) {
        const char* str = reinterpret_cast<const char*>(mData+mDataPos);
        // is the string's trailing NUL within the parcel's valid bounds?
        const char* eos = reinterpret_cast<const char*>(memchr(str, 0, avail));
        if (eos) {
            const size_t len = eos - str;
            mDataPos += PAD_SIZE(len+1);
            LOGV("readCString Setting data pos of %p to %d\n", this, mDataPos);
            return str;
        }
    }
    return NULL;
}

String8 Parcel::readString8() const
{
    int32_t size = readInt32();
    // watch for potential int overflow adding 1 for trailing NUL
    if (size > 0 && size < INT32_MAX) {
        const char* str = (const char*)readInplace(size+1);
        if (str) return String8(str, size);
    }
    return String8();
}

String16 Parcel::readString16() const
{
    size_t len;
    const char16_t* str = readString16Inplace(&len);
    if (str) return String16(str, len);
    LOGE("Reading a NULL string not supported here.");
    return String16();
}

const char16_t* Parcel::readString16Inplace(size_t* outLen) const
{
    int32_t size = readInt32();
    // watch for potential int overflow from size+1
    if (size >= 0 && size < INT32_MAX) {
        *outLen = size;
        const char16_t* str = (const char16_t*)readInplace((size+1)*sizeof(char16_t));
        if (str != NULL) {
            return str;
        }
    }
    *outLen = 0;
    return NULL;
}

sp<IBinder> Parcel::readStrongBinder() const
{
    sp<IBinder> val;
    unflatten_binder(ProcessState::self(), *this, &val);
    return val;
}

wp<IBinder> Parcel::readWeakBinder() const
{
    wp<IBinder> val;
    unflatten_binder(ProcessState::self(), *this, &val);
    return val;
}

int32_t Parcel::readExceptionCode() const
{
  int32_t exception_code = readAligned<int32_t>();
  if (exception_code == EX_HAS_REPLY_HEADER) {
    int32_t header_size = readAligned<int32_t>();
    // Skip over fat responses headers.  Not used (or propagated) in
    // native code
    setDataPosition(dataPosition() + header_size);
    // And fat response headers are currently only used when there are no
    // exceptions, so return no error:
    return 0;
  }
  return exception_code;
}

native_handle* Parcel::readNativeHandle() const
{
    int numFds, numInts;
    status_t err;
    err = readInt32(&numFds);
    if (err != NO_ERROR) return 0;
    err = readInt32(&numInts);
    if (err != NO_ERROR) return 0;

    native_handle* h = native_handle_create(numFds, numInts);
    for (int i=0 ; err==NO_ERROR && i<numFds ; i++) {
        h->data[i] = dup(readFileDescriptor());
        if (h->data[i] < 0) err = BAD_VALUE;
    }
    err = read(h->data + numFds, sizeof(int)*numInts);
    if (err != NO_ERROR) {
        native_handle_close(h);
        native_handle_delete(h);
        h = 0;
    }
    return h;
}


int Parcel::readFileDescriptor() const
{
    const flat_binder_object* flat = readObject(true);
    if (flat) {
        switch (flat->type) {
            case BINDER_TYPE_FD:
                //LOGI("Returning file descriptor %ld from parcel %p\n", flat->handle, this);
                return flat->handle;
        }        
    }
    return BAD_TYPE;
}

status_t Parcel::read(Flattenable& val) const
{
    // size
    const size_t len = this->readInt32();
    const size_t fd_count = this->readInt32();

    // payload
    void const* buf = this->readInplace(PAD_SIZE(len));
    if (buf == NULL)
        return BAD_VALUE;

    int* fds = NULL;
    if (fd_count) {
        fds = new int[fd_count];
    }

    status_t err = NO_ERROR;
    for (size_t i=0 ; i<fd_count && err==NO_ERROR ; i++) {
        fds[i] = dup(this->readFileDescriptor());
        if (fds[i] < 0) err = BAD_VALUE;
    }

    if (err == NO_ERROR) {
        err = val.unflatten(buf, len, fds, fd_count);
    }

    if (fd_count) {
        delete [] fds;
    }

    return err;
}
const flat_binder_object* Parcel::readObject(bool nullMetaData) const
{
    const size_t DPOS = mDataPos;
    if ((DPOS+sizeof(flat_binder_object)) <= mDataSize) {
        const flat_binder_object* obj
                = reinterpret_cast<const flat_binder_object*>(mData+DPOS);
        mDataPos = DPOS + sizeof(flat_binder_object);
        if (!nullMetaData && (obj->cookie == NULL && obj->binder == NULL)) {
            // When transferring a NULL object, we don't write it into
            // the object list, so we don't want to check for it when
            // reading.
            LOGV("readObject Setting data pos of %p to %d\n", this, mDataPos);
            return obj;
        }
        
        // Ensure that this object is valid...
        size_t* const OBJS = mObjects;
        const size_t N = mObjectsSize;
        size_t opos = mNextObjectHint;
        
        if (N > 0) {
            LOGV("Parcel %p looking for obj at %d, hint=%d\n",
                 this, DPOS, opos);
            
            // Start at the current hint position, looking for an object at
            // the current data position.
            if (opos < N) {
                while (opos < (N-1) && OBJS[opos] < DPOS) {
                    opos++;
                }
            } else {
                opos = N-1;
            }
            if (OBJS[opos] == DPOS) {
                // Found it!
                LOGV("Parcel found obj %d at index %d with forward search",
                     this, DPOS, opos);
                mNextObjectHint = opos+1;
                LOGV("readObject Setting data pos of %p to %d\n", this, mDataPos);
                return obj;
            }
        
            // Look backwards for it...
            while (opos > 0 && OBJS[opos] > DPOS) {
                opos--;
            }
            if (OBJS[opos] == DPOS) {
                // Found it!
                LOGV("Parcel found obj %d at index %d with backward search",
                     this, DPOS, opos);
                mNextObjectHint = opos+1;
                LOGV("readObject Setting data pos of %p to %d\n", this, mDataPos);
                return obj;
            }
        }
        LOGW("Attempt to read object from Parcel %p at offset %d that is not in the object list",
             this, DPOS);
    }
    return NULL;
}

void Parcel::closeFileDescriptors()
{
    size_t i = mObjectsSize;
    if (i > 0) {
        //LOGI("Closing file descriptors for %d objects...", mObjectsSize);
    }
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(mData+mObjects[i]);
        if (flat->type == BINDER_TYPE_FD) {
            //LOGI("Closing fd: %ld\n", flat->handle);
            close(flat->handle);
        }
    }
}

const uint8_t* Parcel::ipcData() const
{
    return mData;
}

size_t Parcel::ipcDataSize() const
{
    return (mDataSize > mDataPos ? mDataSize : mDataPos);
}

const size_t* Parcel::ipcObjects() const
{
    return mObjects;
}

size_t Parcel::ipcObjectsCount() const
{
    return mObjectsSize;
}

/**
 * Parcel::ipcSetDataReference
 * @data: 指向了用来保存进程间通信结果数据的缓冲区，它的大小由参数dataSize来描述;
 * @objects: 指向了一个Binder对象偏移数组，用来描述保存在进程间通信数据缓冲区中的Binder对象的位置，它的大小由参数objectsCount来描述;
 * @relFunc: 是一个函数指针，它指向了IPCThreadState类的成员函数freeBuffer；
 * @relCookie: 指向了当前线程的IPCThreadState对象;
 */
void Parcel::ipcSetDataReference(const uint8_t* data, size_t dataSize,
    const size_t* objects, size_t objectsCount, release_func relFunc, void* relCookie)
{
    // 调用函数freeDataNoInit来释放当前Parcel对象内部的数据缓冲区所占用的内存;
    freeDataNoInit();
    // 重新初始化当前Parcel对象内部所使用的数据缓冲区。
    mError = NO_ERROR;
    // 将该缓冲区作为当前Parcel对象内部使用的数据缓冲区。
    mData = const_cast<uint8_t*>(data);
    mDataSize = mDataCapacity = dataSize;
    //LOGI("setDataReference Setting data size of %p to %lu (pid=%d)\n", this, mDataSize, getpid());
    mDataPos = 0;
    LOGV("setDataReference Setting data pos of %p to %d\n", this, mDataPos);
    // 将该偏移数组作为当前Parcel对象内部使用的偏移数组;
    mObjects = const_cast<size_t*>(objects);
    mObjectsSize = mObjectsCapacity = objectsCount;
    mNextObjectHint = 0;
    // 将它们(relFunc和relCookie)保存在当前Parcel对象的成员变量mOwner和mOwnerCookie中
    mOwner = relFunc;
    mOwnerCookie = relCookie;
    scanForFds();
}

void Parcel::print(TextOutput& to, uint32_t flags) const
{
    to << "Parcel(";
    
    if (errorCheck() != NO_ERROR) {
        const status_t err = errorCheck();
        to << "Error: " << (void*)err << " \"" << strerror(-err) << "\"";
    } else if (dataSize() > 0) {
        const uint8_t* DATA = data();
        to << indent << HexDump(DATA, dataSize()) << dedent;
        const size_t* OBJS = objects();
        const size_t N = objectsCount();
        for (size_t i=0; i<N; i++) {
            const flat_binder_object* flat
                = reinterpret_cast<const flat_binder_object*>(DATA+OBJS[i]);
            to << endl << "Object #" << i << " @ " << (void*)OBJS[i] << ": "
                << TypeCode(flat->type & 0x7f7f7f00)
                << " = " << flat->binder;
        }
    } else {
        to << "NULL";
    }
    
    to << ")";
}

void Parcel::releaseObjects()
{
    const sp<ProcessState> proc(ProcessState::self());
    size_t i = mObjectsSize;
    uint8_t* const data = mData;
    size_t* const objects = mObjects;
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(data+objects[i]);
        release_object(proc, *flat, this);
    }
}

void Parcel::acquireObjects()
{
    const sp<ProcessState> proc(ProcessState::self());
    size_t i = mObjectsSize;
    uint8_t* const data = mData;
    size_t* const objects = mObjects;
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(data+objects[i]);
        acquire_object(proc, *flat, this);
    }
}

void Parcel::freeData()
{
    freeDataNoInit();
    initState();
}

void Parcel::freeDataNoInit()
{
    if (mOwner) {
        //LOGI("Freeing data ref of %p (pid=%d)\n", this, getpid());
        mOwner(this, mData, mDataSize, mObjects, mObjectsSize, mOwnerCookie);
    } else {
        releaseObjects();
        if (mData) free(mData);
        if (mObjects) free(mObjects);
    }
}

status_t Parcel::growData(size_t len)
{
    size_t newSize = ((mDataSize+len)*3)/2;
    return (newSize <= mDataSize)
            ? (status_t) NO_MEMORY
            : continueWrite(newSize);
}

status_t Parcel::restartWrite(size_t desired)
{
    if (mOwner) {
        freeData();
        return continueWrite(desired);
    }
    
    uint8_t* data = (uint8_t*)realloc(mData, desired);
    if (!data && desired > mDataCapacity) {
        mError = NO_MEMORY;
        return NO_MEMORY;
    }
    
    releaseObjects();
    
    if (data) {
        mData = data;
        mDataCapacity = desired;
    }
    
    mDataSize = mDataPos = 0;
    LOGV("restartWrite Setting data size of %p to %d\n", this, mDataSize);
    LOGV("restartWrite Setting data pos of %p to %d\n", this, mDataPos);
        
    free(mObjects);
    mObjects = NULL;
    mObjectsSize = mObjectsCapacity = 0;
    mNextObjectHint = 0;
    mHasFds = false;
    mFdsKnown = true;
    
    return NO_ERROR;
}

status_t Parcel::continueWrite(size_t desired)
{
    // If shrinking, first adjust for any objects that appear
    // after the new data size.
    size_t objectsSize = mObjectsSize;
    if (desired < mDataSize) {
        if (desired == 0) {
            objectsSize = 0;
        } else {
            while (objectsSize > 0) {
                if (mObjects[objectsSize-1] < desired)
                    break;
                objectsSize--;
            }
        }
    }
    
    if (mOwner) {
        // If the size is going to zero, just release the owner's data.
        if (desired == 0) {
            freeData();
            return NO_ERROR;
        }

        // If there is a different owner, we need to take
        // posession.
        uint8_t* data = (uint8_t*)malloc(desired);
        if (!data) {
            mError = NO_MEMORY;
            return NO_MEMORY;
        }
        size_t* objects = NULL;
        
        if (objectsSize) {
            objects = (size_t*)malloc(objectsSize*sizeof(size_t));
            if (!objects) {
                mError = NO_MEMORY;
                return NO_MEMORY;
            }

            // Little hack to only acquire references on objects
            // we will be keeping.
            size_t oldObjectsSize = mObjectsSize;
            mObjectsSize = objectsSize;
            acquireObjects();
            mObjectsSize = oldObjectsSize;
        }
        
        if (mData) {
            memcpy(data, mData, mDataSize < desired ? mDataSize : desired);
        }
        if (objects && mObjects) {
            memcpy(objects, mObjects, objectsSize*sizeof(size_t));
        }
        //LOGI("Freeing data ref of %p (pid=%d)\n", this, getpid());
        mOwner(this, mData, mDataSize, mObjects, mObjectsSize, mOwnerCookie);
        mOwner = NULL;

        mData = data;
        mObjects = objects;
        mDataSize = (mDataSize < desired) ? mDataSize : desired;
        LOGV("continueWrite Setting data size of %p to %d\n", this, mDataSize);
        mDataCapacity = desired;
        mObjectsSize = mObjectsCapacity = objectsSize;
        mNextObjectHint = 0;

    } else if (mData) {
        if (objectsSize < mObjectsSize) {
            // Need to release refs on any objects we are dropping.
            const sp<ProcessState> proc(ProcessState::self());
            for (size_t i=objectsSize; i<mObjectsSize; i++) {
                const flat_binder_object* flat
                    = reinterpret_cast<flat_binder_object*>(mData+mObjects[i]);
                if (flat->type == BINDER_TYPE_FD) {
                    // will need to rescan because we may have lopped off the only FDs
                    mFdsKnown = false;
                }
                release_object(proc, *flat, this);
            }
            size_t* objects =
                (size_t*)realloc(mObjects, objectsSize*sizeof(size_t));
            if (objects) {
                mObjects = objects;
            }
            mObjectsSize = objectsSize;
            mNextObjectHint = 0;
        }

        // We own the data, so we can just do a realloc().
        if (desired > mDataCapacity) {
            uint8_t* data = (uint8_t*)realloc(mData, desired);
            if (data) {
                mData = data;
                mDataCapacity = desired;
            } else if (desired > mDataCapacity) {
                mError = NO_MEMORY;
                return NO_MEMORY;
            }
        } else {
            mDataSize = desired;
            LOGV("continueWrite Setting data size of %p to %d\n", this, mDataSize);
            if (mDataPos > desired) {
                mDataPos = desired;
                LOGV("continueWrite Setting data pos of %p to %d\n", this, mDataPos);
            }
        }
        
    } else {
        // This is the first data.  Easy!
        uint8_t* data = (uint8_t*)malloc(desired);
        if (!data) {
            mError = NO_MEMORY;
            return NO_MEMORY;
        }
        
        if(!(mDataCapacity == 0 && mObjects == NULL
             && mObjectsCapacity == 0)) {
            LOGE("continueWrite: %d/%p/%d/%d", mDataCapacity, mObjects, mObjectsCapacity, desired);
        }
        
        mData = data;
        mDataSize = mDataPos = 0;
        LOGV("continueWrite Setting data size of %p to %d\n", this, mDataSize);
        LOGV("continueWrite Setting data pos of %p to %d\n", this, mDataPos);
        mDataCapacity = desired;
    }

    return NO_ERROR;
}

void Parcel::initState()
{
    mError = NO_ERROR;
    mData = 0;
    mDataSize = 0;
    mDataCapacity = 0;
    mDataPos = 0;
    LOGV("initState Setting data size of %p to %d\n", this, mDataSize);
    LOGV("initState Setting data pos of %p to %d\n", this, mDataPos);
    mObjects = NULL;
    mObjectsSize = 0;
    mObjectsCapacity = 0;
    mNextObjectHint = 0;
    mHasFds = false;
    mFdsKnown = true;
    mOwner = NULL;
}

void Parcel::scanForFds() const
{
    bool hasFds = false;
    for (size_t i=0; i<mObjectsSize; i++) {
        const flat_binder_object* flat
            = reinterpret_cast<const flat_binder_object*>(mData + mObjects[i]);
        if (flat->type == BINDER_TYPE_FD) {
            hasFds = true;
            break;
        }
    }
    mHasFds = hasFds;
    mFdsKnown = true;
}

}; // namespace android
