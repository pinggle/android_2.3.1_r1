#ifndef IFREGSERVICE_H_
#define IFREGSERVICE_H_

#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

// FREG_SERVICE 用来描述 Service 组件 FregService 注册到 Service Manager 的名称;
#define FREG_SERVICE "shy.luo.FregService"

using namespace android;

/**
 *  IFregService: 硬件访问服务接口;
 * 	成员函数 getVal 用来读取虚拟硬件设备freg中的寄存器val的值;
 * 	成员函数 setVal 用来写入虚拟硬件设备freg中的寄存器val的值;
 */ 
class IFregService: public IInterface
{
public:
	DECLARE_META_INTERFACE(FregService);
	virtual int32_t getVal() = 0;
	virtual void setVal(int32_t val) = 0;
};

/**
 * BnFregService: Binder本地对象类，实现了模板类 BnInterface 的成员函数 onTransact;
 */
class BnFregService: public BnInterface<IFregService>
{
public:
	virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

#endif
