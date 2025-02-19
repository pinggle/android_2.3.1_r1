package android.os;

interface IFregService {
	// setVal 用来往虚拟硬件设备freg的寄存器val中写入一个整数;
	void setVal(int val);
	// getVal 用来从虚拟硬件设备freg的寄存器val中读出一个整数;
	int getVal();
}

