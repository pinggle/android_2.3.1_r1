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

#define LOG_TAG "ServiceManager"

#include <binder/IServiceManager.h>

#include <utils/Debug.h>
#include <utils/Log.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <utils/String8.h>
#include <utils/SystemClock.h>

#include <private/binder/Static.h>

#include <unistd.h>

namespace android {

sp<IServiceManager> defaultServiceManager()
{
    // 如果 gDefaultServiceManager 不为 NULL，说明Binder库已经为进程创建过一个 Service Manage 代理对象了。
    if (gDefaultServiceManager != NULL) return gDefaultServiceManager;
    
    {
        AutoMutex _l(gDefaultServiceManagerLock);
        if (gDefaultServiceManager == NULL) {
            // 创建一个 Service Manager 代理对象;
            // 1,调用 ProcessState 类的静态成员函数 self 获得进程内的一个 ProcessState 对象;
            // 2,调用前面获得的 ProcessState 对象的成员函数 getContextObject 创建一个 Binder 代理对象;
            // 3,调用模板函数 interface_cast<IServiceManager> 将前面获得的 Binder 代理对象封装成一个 Service Manager 代理对象;
            gDefaultServiceManager = interface_cast<IServiceManager>(
                ProcessState::self()->getContextObject(NULL));
        }
    }
    
    return gDefaultServiceManager;
}

bool checkCallingPermission(const String16& permission)
{
    return checkCallingPermission(permission, NULL, NULL);
}

static String16 _permission("permission");


bool checkCallingPermission(const String16& permission, int32_t* outPid, int32_t* outUid)
{
    IPCThreadState* ipcState = IPCThreadState::self();
    pid_t pid = ipcState->getCallingPid();
    uid_t uid = ipcState->getCallingUid();
    if (outPid) *outPid = pid;
    if (outUid) *outUid = uid;
    return checkPermission(permission, pid, uid);
}

bool checkPermission(const String16& permission, pid_t pid, uid_t uid)
{
    sp<IPermissionController> pc;
    gDefaultServiceManagerLock.lock();
    pc = gPermissionController;
    gDefaultServiceManagerLock.unlock();
    
    int64_t startTime = 0;

    while (true) {
        if (pc != NULL) {
            bool res = pc->checkPermission(permission, pid, uid);
            if (res) {
                if (startTime != 0) {
                    LOGI("Check passed after %d seconds for %s from uid=%d pid=%d",
                            (int)((uptimeMillis()-startTime)/1000),
                            String8(permission).string(), uid, pid);
                }
                return res;
            }
            
            // Is this a permission failure, or did the controller go away?
            if (pc->asBinder()->isBinderAlive()) {
                LOGW("Permission failure: %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
                return false;
            }
            
            // Object is dead!
            gDefaultServiceManagerLock.lock();
            if (gPermissionController == pc) {
                gPermissionController = NULL;
            }
            gDefaultServiceManagerLock.unlock();
        }
    
        // Need to retrieve the permission controller.
        sp<IBinder> binder = defaultServiceManager()->checkService(_permission);
        if (binder == NULL) {
            // Wait for the permission controller to come back...
            if (startTime == 0) {
                startTime = uptimeMillis();
                LOGI("Waiting to check permission %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
            }
            sleep(1);
        } else {
            pc = interface_cast<IPermissionController>(binder);
            // Install the new permission controller, and try again.        
            gDefaultServiceManagerLock.lock();
            gPermissionController = pc;
            gDefaultServiceManagerLock.unlock();
        }
    }
}

// ----------------------------------------------------------------------

class BpServiceManager : public BpInterface<IServiceManager>
{
public:
    BpServiceManager(const sp<IBinder>& impl)
        : BpInterface<IServiceManager>(impl)
    {
    }

    /**
     * getService:
     * 这个函数最多会尝试5次来获得一个名称为name的Service组件的代理对象。
     * 如果上一次获得失败，那么就调用函数sleep使得当前线程睡眠1毫秒，然后再重新去获取；
     * 否则，就直接将获得的Service组件的代理对象返回给调用者。
     * 
     * Service Manager代理对象的成员函数getService实现的是一个标准的Binder进程间通信过程，它可以划分为下面五个步骤。
     * （1）FregClient进程将进程间通信数据，即要获得其代理对象的Service组件FregService的名称，封装在一个Parcel对象中，用来传递给Binder驱动程序。
     * （2）FregClient进程向Binder驱动程序发送一个 BC_TRANSACTION 命令协议，Binder驱动程序根据协议内容找到Service Manager进程之后，
     *      就会向FregClient进程发送一个 BR_TRANSACTION_COMPLETE 返回协议，表示它的进程间通信请求已经被接受。
     *      FregClient进程接收到Binder驱动程序发送给它的 BR_TRANSACTION_COMPLETE 返回协议，并且对它进行处理之后，
     *      就会再次进入到Binder驱动程序中去等待Service Manager进程将它要获取的Binder代理对象的句柄值返回来。
     * （3）Binder驱动程序在向FregClient进程发送BR_TRANSACTION_COMPLETE返回协议的同时，
     *      也会向Service Manager进程发送一个 BR_TRANSACTION 返回协议，请求Service Manager进程执行一个 CHECK_SERVICE_TRANSACTION 操作。
     * （4）Service Manager进程执行完成FregClient进程请求的 CHECK_SERVICE_TRANSACTION 操作之后，
     *      就会向Binder驱动程序发送一个 BC_REPLY 命令协议，协议内容包含了Service组件FregService的信息。
     *      Binder驱动程序根据协议内容中的Service组件FregService的信息为FregClient进程创建一个Binder引用对象，
     *      接着就会向Service Manager进程发送一个 BR_TRANSACTION_COMPLETE 返回协议，
     *      表示它返回的Service组件FregService的信息已经收到了。
     *      Service Manager进程接收到Binder驱动程序发送给它的 BR_TRANSACTION_COMPLETE 返回协议，
     *      并且对它进行处理之后，一次进程间通信过程就结束了，接着它会再次进入到Binder驱动程序中去等待下一次进程间通信请求。
     * （5）Binder驱动程序在向 Service Manager 进程发送 BR_TRANSACTION_COMPLETE 返回协议的同时，
     *      也向 FregClient 进程发送一个 BR_REPLY 返回协议，协议内容包含了前面所创建的一个Binder引用对象的句柄值，
     *      这时候 FregClient 进程就可以通过这个句柄来创建一个Binder代理对象。
     */
    virtual sp<IBinder> getService(const String16& name) const
    {
        unsigned n;
        for (n = 0; n < 5; n++){
            // 调用成员函数checkService来获得一个名称为name的Service组件的代理对象
            sp<IBinder> svc = checkService(name);
            if (svc != NULL) return svc;
            LOGI("Waiting for service %s...\n", String8(name).string());
            sleep(1);
        }
        return NULL;
    }

    virtual sp<IBinder> checkService( const String16& name) const
    {
        Parcel data, reply;
        data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
        data.writeString16(name);
        // 请求 Service Manager 执行一个 CHECK_SERVICE_TRANSACTION 操作。
        remote()->transact(CHECK_SERVICE_TRANSACTION, data, &reply);
        // 当前线程从 IPCThreadState 类的成员函数 waitForResponse 返回到 Service Manager 代理对象的成员函数 checkService之后，
        // 就调用 Parcel 对象 reply 的成员函数 readStrongBinder 来获得一个 Binder 代理对象。
        return reply.readStrongBinder();
    }

    virtual status_t addService(const String16& name, const sp<IBinder>& service)
    {
        Parcel data, reply;
        // 将进程间通信数据写入到一个 Parcel对象 data 中;
        // 调用 data.writeInterfaceToken 写入一个 Binder 进程间通信请求头;
        data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
        // 调用 data.writeString16 写入将要注册的Service组件的名称;
        data.writeString16(name);
        // 调用 data.writeStrongBinder 将要注册的Service组件封装成一个flat_binder_object结构体;
        data.writeStrongBinder(service);
        // 调用内部的一个Binder代理对象的成员函数transact向Binder驱动程序发送一个BC_TRANSACTION命令协议;
        status_t err = remote()->transact(ADD_SERVICE_TRANSACTION, data, &reply);
        return err == NO_ERROR ? reply.readExceptionCode() : err;
    }

    virtual Vector<String16> listServices()
    {
        Vector<String16> res;
        int n = 0;

        for (;;) {
            Parcel data, reply;
            data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
            data.writeInt32(n++);
            status_t err = remote()->transact(LIST_SERVICES_TRANSACTION, data, &reply);
            if (err != NO_ERROR)
                break;
            res.add(reply.readString16());
        }
        return res;
    }
};

IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");

// ----------------------------------------------------------------------

status_t BnServiceManager::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    //printf("ServiceManager received: "); data.print();
    switch(code) {
        case GET_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = const_cast<BnServiceManager*>(this)->getService(which);
            reply->writeStrongBinder(b);
            return NO_ERROR;
        } break;
        case CHECK_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = const_cast<BnServiceManager*>(this)->checkService(which);
            reply->writeStrongBinder(b);
            return NO_ERROR;
        } break;
        case ADD_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = data.readStrongBinder();
            status_t err = addService(which, b);
            reply->writeInt32(err);
            return NO_ERROR;
        } break;
        case LIST_SERVICES_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            Vector<String16> list = listServices();
            const size_t N = list.size();
            reply->writeInt32(N);
            for (size_t i=0; i<N; i++) {
                reply->writeString16(list[i]);
            }
            return NO_ERROR;
        } break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

}; // namespace android
