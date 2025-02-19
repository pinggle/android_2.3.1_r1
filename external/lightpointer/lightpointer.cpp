#include <stdio.h>
#include <utils/RefBase.h>
      
using  namespace android;

/* LightClass 继承了 LightRefBase类 */
class LightClass : public LightRefBase<LightClass>
{
public:
	LightClass() 
	{
		printf("Construct LightClass Object.\n");
	}

	virtual ~LightClass() 
	{
		printf("Destory LightClass Object.\n");
	}
};

int main(int argc, char** argv) 
{
	LightClass* pLightClass = new LightClass();
	/* 创建轻量级指针 lpOut 引用 LightRefBase */
	sp<LightClass> lpOut = pLightClass;

	/* 经过构造函数的调用，引用计数值为1; */
	printf("Light Ref Count: %d.\n", pLightClass->getStrongCount());

	{
		/* 新建一个轻量级指针 lpInner 来引用 loOut 对象，引用计数增加1; */
		sp<LightClass> lpInner = lpOut;

		/* 经过构造函数和lpInner的指向，计数器为2; */
		printf("Light Ref Count: %d.\n", pLightClass->getStrongCount());
	} // 当走出括号，lpInner 被析构，引用计数减少1;

	/* 经过构造函数和lpInner的指向，然后lpInner被析构，计数器为1; */
	printf("Light Ref Count: %d.\n", pLightClass->getStrongCount());

	return 0;
}
