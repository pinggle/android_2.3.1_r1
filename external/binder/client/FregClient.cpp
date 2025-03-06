#define LOG_TAG "FregClient"

#include <utils/Log.h>
#include <binder/IServiceManager.h>

#include "../common/IFregService.h"

int main()
{
	// 调用函数 defaultServiceManager 来获得 Service Manager 的一个代理对象;
	// 接着调用它的成员函数 getService 来获得一个名称为 "shy.luo.FregService" 的 Service 组件的一个类型为 BpBinder 的代理对象;
	// 从 service 模块的实现可以知道，名为 "shy.luo.FregService" 的 Service 组件正好是前面注册的一个 FregService 组件;
	sp<IBinder> binder = defaultServiceManager()->getService(String16(FREG_SERVICE));
	if(binder == NULL) {
		LOGE("Failed to get freg service: %s.\n", FREG_SERVICE);
		return -1;
	}

	// 将前面获得的 BpBinder 代理对象封装成一个 BpFregService 代理对象，并且取得它的 IFregService接口，保存在变量 service 中。
	// IFregService::asInterface 用来将一个 IBinder 对象转换为一个 IFregService 接口;
	// 通过IFregService类的静态成员函数asInterface将它封装成一个BpFregService类型的代理对象，
	// 并且获得它的一个IFregService接口，最后就可以通过这个接口来向运行在FregServer进程中的Service组件FregService发送进程间通信请求了。
	sp<IFregService> service = IFregService::asInterface(binder);
	if(service == NULL) {
		LOGE("Failed to get freg service interface.\n");
		return -2;
	}

	printf("Read original value from FregService:\n");

	// 调用 IFregService 接口 service 的成员函数 getVal 从运行在另外一个进程中的 FregService 组件获取虚拟硬件设备 freg 的寄存器 val 的值;
	int32_t val = service->getVal();
	printf(" %d.\n", val);

	printf("Add value 1 to FregService.\n");		

	val += 1;
	// 调用 IFregService 接口 service 的成员函数 setVal 来请求运行在另外一个进程中的 FregService 组件将虚拟硬件设备 freg 的寄存器 val 的值设置为指定的值;
	service->setVal(val);

	printf("Read the value from FregService again:\n");
	
	val = service->getVal();
	printf(" %d.\n", val); 

	return 0;
}
