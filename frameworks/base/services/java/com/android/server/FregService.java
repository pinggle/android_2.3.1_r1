package com.android.server;

import android.content.Context;
import android.os.IFregService;
import android.util.Slog;

public class FregService extends IFregService.Stub {
	private static final String TAG = "FregService";

	private int mPtr = 0;

	FregService() {
		// 调用 init_native 来打开虚拟硬件设备freg，并获得它的一个句柄值，保存在 mPtr 中;
		mPtr = init_native();

		if (mPtr == 0) {
			// 如果句柄值为0，则判定为打开虚拟硬件设备freg失败;
			Slog.e(TAG, "Failed to initialize freg service.");
		}
	}

	public void setVal(int val) {
		if (mPtr == 0) {
			Slog.e(TAG, "Freg service is not initialized.");
			return;
		}

		// 调用 JNI 方法 setVal_native 来写虚拟硬件设备 freg 的寄存器val;
		// 传入 mPtr，即虚拟硬件设备freg的句柄值，确认访问哪一个硬件设备;
		setVal_native(mPtr, val);
	}

	public int getVal() {
		if (mPtr == 0) {
			Slog.e(TAG, "Freg service is not initialized.");
			return 0;
		}

		// 调用 JNI 方法 getVal_native 来读虚拟硬件设备 freg 的寄存器val;
		// 传入 mPtr，即虚拟硬件设备freg的句柄值，确认访问哪一个硬件设备;
		return getVal_native(mPtr);
	}

	private static native int init_native();

	private static native void setVal_native(int ptr, int val);

	private static native int getVal_native(int ptr);
};
