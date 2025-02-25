#define LOG_TAG "IFregService"

#include <utils/Log.h>

#include "IFregService.h"

using namespace android;

enum 
{
	// 定义进程间通信代码，分别对应于 IFregService 接口中的两个成员函数 getVal 和 setVal;
	GET_VAL = IBinder::FIRST_CALL_TRANSACTION,
	SET_VAL
};

/**
 * BpFregService : 定义了一个Binder代理对象，它继承了模板类 BpInterface，并且实现了 IFregService 接口;
 */
class BpFregService: public BpInterface<IFregService>
{
public:
	BpFregService(const sp<IBinder>& impl) 
		: BpInterface<IFregService>(impl)
	{

	}

public:

	int32_t getVal()
	{
		// 将要传递的数据封装在一个 Parcel 对象 data 中;
		Parcel data;
		data.writeInterfaceToken(IFregService::getInterfaceDescriptor());
		
		Parcel reply;
		// 调用父类 BpRefBase 的成员函数 remote 来获得一个 BpBinder 代理对象;
		// 再调用这个 BpBinder 代理对象的成员函数 transact 来请求运行在 Server 进程中的一个 Binder 本地对象执行一个 GET_VAL 操作;
		remote()->transact(GET_VAL, data, &reply);
		// transact 函数调用的 GET_VAL 操作的返回结果是一个整数，封装在另外一个 Parcel 对象 reply 中；
		// 表示虚拟硬件设备 freg 的寄存器 val 的值；
		int32_t val = reply.readInt32();
	
		return val;
	}

	void setVal(int32_t val)
	{
		// 将要传递的数据封装在一个 Parcel 对象 data 中;
		Parcel data;
		data.writeInterfaceToken(IFregService::getInterfaceDescriptor());
		data.writeInt32(val);

		Parcel reply;
		// 使用其父类内部的一个 BpBinder 代理对象的成员函数 transact 来请求运行在 Server 进程中的一个 Binder 本地对象执行一个 SET_VAL 操作;
		// 该 SET_VAL 操作将一个整数写入到虚拟硬件设备 freg 的寄存器 val 中;
		remote()->transact(SET_VAL, data, &reply);
	}

};

// IFregService 类的元接口;
IMPLEMENT_META_INTERFACE(FregService, "shy.luo.IFregService");
/***
 * 将参数代入宏定义内，有如下代码: 

// 将 IFregService类的静态成员变量 descriptor 设置为: "shy.luo.IFregService";
const android::String16 IFregService::descriptor("shy.luo.IFregService");
// getInterfaceDescriptor 用来获取 IFregService 类的描述符，即静态成员变量 descriptor 的值;
const android::String16&IFregService::getInterfaceDescriptor() const {
    return IFregService::descriptor;
}
// asInterface 用来将一个 IBinder 对象转换为一个 IFregService 接口;
android::sp<IFregService> IFregService::asInterface(const android::sp<android::IBinder>& obj)
{
    android::sp<IFregService> intr;
    if (obj != NULL) {
		// 参数obj指向为 BnFregService 的 Binder 本地对象，则调用它的成员函数 queryLocalInterface 就可以直接返回一个 IFregService 接口;
        intr = static_cast<IFregService*>(obj->queryLocalInterface(IFregService::descriptor).get());
        if (intr == NULL) {
			// 参数obj指向为一个 BpBinder 代理对象，就将该 BpBinder 代理对象封装成一个 BpFregService 对象;
			// 并且将它的 IFregService 接口返回给调用者;
            intr = new BpFregService(obj);
        }
    }
    return intr;
}
// IFregService 类的构造函数和析构函数;(空实现)
IFregService::IFregService() { }
IFregService::~IFregService() { }

 */

 /**
  * onTransact 函数负责将 GET_VAL 和 SET_VAL 进程间通信请求分发给其子类(FregService)的成员函数 getVal 和 setVal 来处理。
  * FregService 的成员函数 getVal 和 setVal 分别用来读取和写入虚拟硬件设备 freg 的寄存器 val 的值;
  */
status_t BnFregService::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
	switch(code)
	{
		case GET_VAL:
		{
			// CHECK_INTERFACE 用来检查该进程间通信请求的合法性，即检查该请求是否是由 FregService 组件的代理对象发过来的。
			// 如果是，那么传递过来的 Parcel 对象 data 中的第一个数据应该是一个 IFregService 接口描述符，即"shy.luo.IFregService";
			// 如果不是，那么就认为这是一个非法的进程间通信请求，因此，就不会继续向下执行了。
			CHECK_INTERFACE(IFregService, data, reply);
			
			int32_t val = getVal();
			reply->writeInt32(val);
			
			return NO_ERROR;
		}
		case SET_VAL:
		{
			CHECK_INTERFACE(IFregService, data, reply);

			int32_t val = data.readInt32();
			setVal(val);

			return NO_ERROR;
		}
		default:
		{
			return BBinder::onTransact(code, data, reply, flags);
		}
	}
}
