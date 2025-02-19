// 文件路径: aosp/external/freg/freg.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#define FREG_DEVICE_NAME "/dev/freg"

int main(int argc, char** argv)
{
	int fd = -1;
	int val = 0;

	fd = open(FREG_DEVICE_NAME, O_RDWR);
	/* 调用 open 函数，以读写方式打开设备文件 /dev/freg; */
	if(fd == -1)
	{
		printf("Failed to open device %s.\n", FREG_DEVICE_NAME);
		return -1;
	}
	
	printf("Read original value:\n");
	read(fd, &val, sizeof(val));
	/* 调用 read 函数，读取虚拟硬件设备freg的寄存器val的内容; */
	printf("%d.\n\n", val);

	val = 5;
	printf("Write value %d to %s.\n\n", val, FREG_DEVICE_NAME);
    write(fd, &val, sizeof(val));
	/* 调用 write 函数，将整数 5 写入到虚拟硬件设备freg的寄存器val中; */
	
	printf("Read the value again:\n");
	read(fd, &val, sizeof(val));
	/* 读取刚才我们写入的值，并打印出来; */
	printf("%d.\n\n", val);

	close(fd);

	return 0;
}
