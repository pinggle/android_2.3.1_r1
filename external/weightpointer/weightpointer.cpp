#include <stdio.h>
#include <utils/RefBase.h>

#define INITIAL_STRONG_VALUE (1<<28)

using namespace android;

class WeightClass : public RefBase
{
public:
	void printRefCount() // 打印对象的引用计数，包括强引用计数和弱引用计数;
        {
		int32_t strong = getStrongCount();
                weakref_type* ref = getWeakRefs();

                printf("-----------------------\n");
                printf("Strong Ref Count: %d.\n", (strong  == INITIAL_STRONG_VALUE ? 0 : strong));
                printf("Weak Ref Count: %d.\n", ref->getWeakCount());
                printf("-----------------------\n");
        }
};

class StrongClass : public WeightClass
{
public:
	StrongClass() 
	{
		printf("Construct StrongClass Object.\n");
	}

	virtual ~StrongClass() 
	{
		printf("Destory StrongClass Object.\n");
	}
};

class WeakClass : public WeightClass
{
public:
        WeakClass()
        {
		extendObjectLifetime(OBJECT_LIFETIME_WEAK); // 对象的生命周期同时受到强引用计数和弱引用计数的影响;
                printf("Construct WeakClass Object.\n");
        }

        virtual ~WeakClass()
        {
                printf("Destory WeakClass Object.\n");
        }
};

class ForeverClass : public WeightClass
{
public:
        ForeverClass()
        {
		extendObjectLifetime(OBJECT_LIFETIME_FOREVER); // 对象的生命周期完全不受强引用计数和弱引用计数的影响;
                printf("Construct ForeverClass Object.\n");
        }

        virtual ~ForeverClass()
        {
                printf("Destory ForeverClass Object.\n");
        }
};


void TestStrongClass(StrongClass* pStrongClass)
{
	wp<StrongClass> wpOut = pStrongClass; // 将一个 StrongClass 对象赋值给一个弱指针 wpOut; 
	pStrongClass->printRefCount(); // 打印出该 StrongClass 对象的强引用计数值和弱引用计数值;（0和1）

	{
		sp<StrongClass> spInner = pStrongClass; // 将该 StrongClass对象赋值给一个强指针 spInner;
		pStrongClass->printRefCount(); // 打印出该 StrongClass 对象的强引用计数值和弱引用计数值;（1和2）
	}
	
	sp<StrongClass> spOut = wpOut.promote(); // spInner被析构,且由于对象 StrongClass 对象的生命周期只受强引用计数的影响，这里强引用计数为0，那么该StrongClass对象会自动被释放; 下面试图将弱指针 wpOut 升级为 强指针，但是由于弱指针 wpOut 所引用的 StrongClass 对象已经被释放，因此，弱指针 wpOut 升级为强指针就会失败;
	printf("spOut: %p.\n", spOut.get());
}

void TestWeakClass(WeakClass* pWeakClass)
{
        wp<WeakClass> wpOut = pWeakClass; // 将一个 WeakClass 对象赋值给一个弱指针，因此该 WeakClass 对象的强引用计数值和弱引用计数值应该分别为0和1；
        pWeakClass->printRefCount();

        {
                sp<WeakClass> spInner = pWeakClass; // 将该 WeakClass 对象赋值给一个强指针 spInner；
                pWeakClass->printRefCount(); // 该 WeakClass 对象的强引用计数值和弱引用计数值分别为1和2;
        }
        // spInner被析构，该 WeakClass 对象的强引用计数值和弱引用计数值应该分别为0和1；由于该 WeakClass 对象的生命周期同时受强引用计数和弱引用计数的影响，因此，此时该 WeakClass 对象不会被释放。
	pWeakClass->printRefCount();
        sp<WeakClass> spOut = wpOut.promote(); // 试图将弱指针 wpOut 升级为 强指针，由于弱指针 wpOut 所引用的 WeakClass 对象还存在，因此，弱指针 wpOut 就能够成功升级为强指针 spOut;
	printf("spOut: %p.\n", spOut.get()); // 该 WeakClass 对象的强引用计数值和弱引用计数值应该分别为1和2；
}

void TestForeverClass(ForeverClass* pForeverClass)
{
	wp<ForeverClass> wpOut = pForeverClass; // 将一个 ForeverClass 对象赋值给一个弱指针 wpOut，因此，该 ForeverClass 对象的强引用计数值和弱引用计数值分别为0和1;
        pForeverClass->printRefCount();

        {
                sp<ForeverClass> spInner = pForeverClass; // 将该 ForeverClass 对象赋值给一个强指针 spInner；
                pForeverClass->printRefCount(); // 该 ForeverClass 对象的强引用计数值和弱引用计数值分别为1和2;
        }
        // spInner被析构，该 ForeverClass 对象的强引用计数值和弱引用计数值应该分别为0和1；由于该 ForeverClass 对象的生命周期不受强引用计数和弱引用计数的影响，因此，此时该 ForeverClass 对象不会被释放。

        // 当 TestForeverClass 函数返回，wpOut被析构，该 ForeverClass 对象的强引用计数值和弱引用计数值应该分别为0和0；由于该 ForeverClass 对象的生命周期不受强引用计数和弱引用计数的影响，因此，此时该 ForeverClass 对象不会被释放。
}

int main(int argc, char** argv) 
{
	printf("Test Strong Class: \n");
	StrongClass* pStrongClass = new StrongClass();
	TestStrongClass(pStrongClass);

	printf("\nTest Weak Class: \n");
	WeakClass* pWeakClass = new WeakClass();
        TestWeakClass(pWeakClass);

	printf("\nTest Froever Class: \n");
	ForeverClass* pForeverClass = new ForeverClass();
        TestForeverClass(pForeverClass);
	pForeverClass->printRefCount();
	delete pForeverClass;

	return 0;
}
