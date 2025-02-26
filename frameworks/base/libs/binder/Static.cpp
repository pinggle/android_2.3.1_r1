/*
 * Copyright (C) 2008 The Android Open Source Project
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

// All static variables go here, to control initialization and
// destruction order in the library.

#include <private/binder/Static.h>

#include <binder/IPCThreadState.h>
#include <utils/Log.h>

namespace android {

// ------------ ProcessState.cpp

// gProcessMutex 是一个互斥锁，是用来保证一个进程至多只有一个 ProcessState 对象的，这同样是一个单例设计模式;
Mutex gProcessMutex;
// gProcess 是一个类型为 ProcessState 的强指针，它指向进程内的一个 ProcessState 对象;
sp<ProcessState> gProcess;

class LibUtilsIPCtStatics
{
public:
    LibUtilsIPCtStatics()
    {
    }
    
    ~LibUtilsIPCtStatics()
    {
        IPCThreadState::shutdown();
    }
};

static LibUtilsIPCtStatics gIPCStatics;

// ------------ ServiceManager.cpp

// 全局变量 gDefaultServiceManagerLock 是一个互斥锁，是用来保证一个进程至多只有一个 Service Manager 代理对象的。
// 结合锁机制来保证对象在进程中的唯一性，这是单例设计模式的经典实现;
Mutex gDefaultServiceManagerLock;
// 全局变量 gDefaultServiceManager 是一个类型为 IServiceManager 的强指针，它指向进程内的一个 BpServiceManager 对象，即一个 Service Manager 代理对象;
sp<IServiceManager> gDefaultServiceManager;
sp<IPermissionController> gPermissionController;

}   // namespace android
