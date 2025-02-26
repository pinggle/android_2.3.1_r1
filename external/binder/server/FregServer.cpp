#define LOG_TAG "FregServer"

#include <stdlib.h>
#include <fcntl.h>

#include <utils/Log.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>

#include "../common/IFregService.h"

#define FREG_DEVICE_NAME "/dev/freg"

/**
 * FregService: Service组件类,它继承了 BnFregService 类，并且实现了 IFregService 接口;
 */
class FregService : public BnFregService
{
public:
	/**
	 * FregService构造函数，调用open来打开设备文件 /dev/freg，并且将得到的文件描述符保存在成员变量 fd 中;
	 * 打开设备文件 /dev/freg 之后，成员函数 getVal 和 setVal 就可以读取和写入虚拟硬件设备 freg 的寄存器 val 的值了。
	 */
	FregService()
	{
		fd = open(FREG_DEVICE_NAME, O_RDWR);
		if(fd == -1) {
			LOGE("Failed to open device %s.\n", FREG_DEVICE_NAME);
		}
	}

	virtual ~FregService()
	{
		if(fd != -1) {
			close(fd);
		}
	}

public:
	/**
	 * 静态成员函数 instantiate 负责将一个 FregService 组件注册到 Service Manager 中，并且将它的注册名称设置为:"shy.luo.FregService";
	 * 这样，Client进程就可以通过名称 "shy.luo.FregService" 来获取这个 FregService 组件的一个代理对象了。
	 */
	static void instantiate()
	{
		defaultServiceManager()->addService(String16(FREG_SERVICE), new FregService());
	}

	int32_t getVal()
	{
		int32_t val = 0;

		if(fd != -1) {
			read(fd, &val, sizeof(val));
		}

		return val;
	}

	void setVal(int32_t val)
	{
		if(fd != -1) {
			write(fd, &val, sizeof(val));
		}
	}

private:
	int fd;
};

int main(int argc, char** argv)
{
	// 调用 instantiate 函数创建一个 FregService 组件，并将它注册到 Service Manager 中;
	FregService::instantiate();

	// 调用进程中的 ProcessState 对象的成员函数 startThreadPool 来启动一个 Binder 线程池;
	ProcessState::self()->startThreadPool();
	// 调用主线程的 IPCThreadState 对象的成员函数 joinThreadPool 将主线程添加到进程的 Binder 线程池中，用来处理来自 Client 进程的通信请求。
	IPCThreadState::self()->joinThreadPool();

	return 0;
}
