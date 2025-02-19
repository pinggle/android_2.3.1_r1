#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <asm/uaccess.h>

#include "freg.h"

/*

 freg模块的加载与卸载:
    freg_init: 加载，主要用来注册和初始化虚拟硬件设备freg;
    freg_exit: 卸载，主要用来反注册和释放虚拟硬件设备freg;

 传统设备文件系统接口:
    freg_open: 打开
    freg_release: 关闭
    freg_read: 读;
    freg_write: 写;

 devfs文件系统接口，将虚拟硬件设备freg的寄存器val当做设备的一个属性，通过读写这个属性就可以达到访问设备的目的。
    freg_val_show: 读设备属性val的值;
    freg_val_store: 写设备属性val的值;

 proc文件系统接口:
    freg_proc_read: 读;
    freg_proc_write: 写;
    freg_create_proc: 创建;
        create_proc_entry: 在/proc目录下创建一个文件 ，这种文件用户态将不支持file接口读写，只能用cat命令查看。
    freg_remove_proc: 删除;

问：这三种方式的接口，就读和写来说，有什么区别？为什么不是统一成一个函数进行读和写？
三种方式对应不同的硬件驱动设备不一样：
传统设备文件系统接口对应：/dev/freg;
devfs文件系统接口对应: /sys/class/freg/freg;
proc文件系统接口对应: /proc/freg;
因为设备不一样，在创建时对应linux底层接口也不一样，这样就导致了访问时的差异性，最终读写的函数实现也不一样。

**********************************/

/* 主设备号和从设备号变量 */
static int freg_major = 0;
static int freg_minor = 0;

/* 设备类别和设备变量 */
static struct class* freg_class = NULL;
static struct fake_reg_dev* freg_dev = NULL;

/* 传统的设备文件操作方法 */
static int freg_open(struct inode* inode, struct file* filp);
static int freg_release(struct inode* inode, struct file* filp);
static ssize_t freg_read(struct file* filp, char __user *buf, size_t count, loff_t* f_pos);
static ssize_t freg_write(struct file* filp, const char __user *buf, size_t count, loff_t* f_pos);

/* 传统的设备文件操作方法表 */
static struct file_operations freg_fops = {
        .owner = THIS_MODULE,
        .open = freg_open,
        .release = freg_release,
        .read = freg_read,
        .write = freg_write,
};

/* devfs 文件系统的设备属性操作方法 */
static ssize_t freg_val_show(struct device* dev, struct device_attribute* attr,  char* buf);
static ssize_t freg_val_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count);

/* devfs 文件系统的设备属性 */
static DEVICE_ATTR(val, S_IRUGO | S_IWUSR, freg_val_show, freg_val_store);

/* 打开设备方法 */
static int freg_open(struct inode* inode, struct file* filp) {
	struct fake_reg_dev* dev;
	
    /* 将自定义设备结构体保存在文件指针的私有数据域中，以便访问设备时可以直接拿来用 */
	dev = container_of(inode->i_cdev, struct fake_reg_dev, dev);
	filp->private_data = dev;
    /*  container_of是定义在linux内核kernel.h中的一个宏，
        它的作用是根据结构体中某个成员的地址反推出该结构体的地址。
        container_of之所以能做到这点，得归功于linux的内存管理方式在逻辑上是连续的这一特性。
    */

	return 0;
}

/* 设备文件释放时调用，空实现 */
static int freg_release(struct inode* inode, struct file* filp) {
	return 0;
}

/* 读取设备的寄存器val的值 */
static ssize_t freg_read(struct file* filp, char __user *buf, size_t count, loff_t* f_pos) {
	ssize_t err = 0;
	struct fake_reg_dev* dev = filp->private_data;

    /* 同步访问，获得信号量 */
	if(down_interruptible(&(dev->sem))) {	
		return -ERESTARTSYS;
	}
    /*  int down_interruptible(struct semaphore *sem)
        这个函数的功能就是获得信号量，如果得不到信号量就睡眠，此时没有信号打断，那么进入睡眠。
        但是在睡眠过程中可能被信号打断，打断之后返回-EINTR，主要用来进程间的互斥同步。
    */

	if(count < sizeof(dev->val)) {
		goto out;
	}

    /* 将寄存器val的值复制到用户提供的缓冲区中 */
	if(copy_to_user(buf, &(dev->val), sizeof(dev->val))) {
		err = -EFAULT;
		goto out;
	}
    /*  copy_to_user
        unsigned long copy_to_user(void *to, const void *from, unsigned long n);
        这个函数的作用是将内核空间的数据复制到用户空间。其中
            to：目标地址（用户空间）
            from：源地址（内核空间）
            n：将要拷贝数据的字节数
            返回：成功返回0，失败返回没有拷贝成功的数据字节数
    */

	err = sizeof(dev->val);

out:
	up(&(dev->sem));
    /*  对临界资源访问完毕后，可以调用原子操作up()来释放信号量，该操作会增加信号量的计数器。
        如果该信号量上的等待队列不为空，则唤醒阻塞在该信号量上的进程。
    */
	return err;
}

/* 写设备的寄存器val的值 */
static ssize_t freg_write(struct file* filp, const char __user *buf, size_t count, loff_t* f_pos) {
	struct fake_reg_dev* dev = filp->private_data;
	ssize_t err = 0;

    /* 同步访问，获得信号量 */
	if(down_interruptible(&(dev->sem))) {
            return -ERESTARTSYS;
    }

    if(count != sizeof(dev->val)) {
            goto out;
    }

    /* 将用户提供的缓存区的值写到设备寄存器中 */
	if(copy_from_user(&(dev->val), buf, count)) {
		err = -EFAULT;
		goto out;
	}
    /*  copy_from_user()这个函数的完整形态为
        unsigned long copy_from_user(void *to, const void *from, unsigned long n);
        这个函数的作用是将用户空间的数据复制到内核空间。其中
            to：目标地址（内核空间）
            from：源地址（用户空间）
            n：将要拷贝数据的字节数
            返回：成功返回0，失败返回没有拷贝成功的数据字节数
    */

	err = sizeof(dev->val);

out:
	up(&(dev->sem));
	return err;
}

/* 将寄存器val的值读取到缓冲区buf中，内部使用 */
static ssize_t __freg_get_val(struct fake_reg_dev* dev, char* buf) {
	int val = 0;

    /* 同步访问，获得信号量 */
	if(down_interruptible(&(dev->sem))) {
            return -ERESTARTSYS;
    }

    val = dev->val;
    /* 释放信号量 */
    up(&(dev->sem));

    return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

/* 将缓冲区buf的值写到设备寄存器val中，内部使用 */
static ssize_t __freg_set_val(struct fake_reg_dev* dev, const char* buf, size_t count) {
	int val = 0;

    /* 将字符串转换成数字 */
    val = simple_strtol(buf, NULL, 10);
    /* simple_strtol，把一个字符串转换为一个有符号长整数；*/

    /* 同步访问，获得信号量 */
    if(down_interruptible(&(dev->sem))) {
        return -ERESTARTSYS;
    }

    dev->val = val;
    /* 释放信号量 */
    up(&(dev->sem));

	return count;
}

/* 读设备属性val的值 */
static ssize_t freg_val_show(struct device* dev, struct device_attribute* attr, char* buf) {
	struct fake_reg_dev* hdev = (struct fake_reg_dev*)dev_get_drvdata(dev);
	
        return __freg_get_val(hdev, buf);
}

/* 写设备属性val的值 */
static ssize_t freg_val_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count) {
	 struct fake_reg_dev* hdev = (struct fake_reg_dev*)dev_get_drvdata(dev);

        return __freg_set_val(hdev, buf, count);
}

/* 读取设备寄存器val的值，保存到page缓冲区中 */
static ssize_t freg_proc_read(char* page, char** start, off_t off, int count, int* eof, void* data) {
	if(off > 0) {
		*eof = 1;
		return 0;
	}

	return __freg_get_val(freg_dev, page);	
}

/* 把缓冲区的值buff保存到设备寄存器中 */
static ssize_t freg_proc_write(struct file* filp, const char __user *buff, unsigned long len, void* data) {	
	int err = 0;
	char* page = NULL;

	if(len > PAGE_SIZE) {
		printk(KERN_ALERT"The buff is too large: %lu.\n", len);
		return -EFAULT;
	}

    /* __get_free_page() 分配连续的物理地址，用于整页分配。*/
	page = (char*)__get_free_page(GFP_KERNEL);
	if(!page) {
        printk(KERN_ALERT"Failed to alloc page.\n");
		return -ENOMEM;
	}
	
    /* 先把用户提供的缓冲区的值复制到内核缓冲区中 */
	if(copy_from_user(page, buff, len)) {
		printk(KERN_ALERT"Failed to copy buff from user.\n");
        err = -EFAULT;
		goto out;
	}

    /* 自定义函数，把缓冲区buf的值写到设备寄存器val中，内部使用 */
	err = __freg_set_val(freg_dev, page, len);

out:
    /* 释放内存页，与__get_free_page配对 */
	free_page((unsigned long)page);
	return err;	
}

/* 创建 /proc/freg 文件 */
static void freg_create_proc(void) {
	struct proc_dir_entry* entry;
	
	entry = create_proc_entry(FREG_DEVICE_PROC_NAME, 0, NULL);
	if(entry) {
		entry->owner = THIS_MODULE;
		entry->read_proc = freg_proc_read;
		entry->write_proc = freg_proc_write;
	}
    /*  create_proc_entry(在/proc目录下创建一个文件 ，
        这种文件用户态将不支持file接口读写，只能用cat命令查看) */
}

/* 删除 /proc/freg 文件 */
static void freg_remove_proc(void) {
	remove_proc_entry(FREG_DEVICE_PROC_NAME, NULL);
    /* remove_proc_entry() 是Linux 内核中用于删除proc 文件系统中某个进程文件的函数。*/
}

/* 初始化设备*/
static int  __freg_setup_dev(struct fake_reg_dev* dev) {
	int err;
	dev_t devno = MKDEV(freg_major, freg_minor);
    /* 宏 MKDEV 用于将给定的主设备号和次设备号的值组合成 dev_t 类型的设备号。*/

	memset(dev, 0, sizeof(struct fake_reg_dev));

    /* 初始化字符设备 */
	cdev_init(&(dev->dev), &freg_fops);
	dev->dev.owner = THIS_MODULE;
	dev->dev.ops = &freg_fops;
    /*  void cdev_init(struct cdev *cdev, const struct file_operations *fops)
        功能：用于初始化cdev结构体，并填充其成员ops 
        参数：cdev：字符设备；fops ：驱动操作函数集合
    */

    /* 注册字符设备 */
	err = cdev_add(&(dev->dev),devno, 1);
	if(err) {
		return err;
	}	
    /*  cdev_add函数主要是将cdev加入到cdev_map中，然后将cdev的kobject成员的parent对象的kref成员加1 */

    /* 初始化信号量和寄存器val的值 */
	init_MUTEX(&(dev->sem));
	dev->val = 0;
    /*  Init_MUTEX()函数初始化信号量为互斥量。 互斥量为信号量的特例，它可以防止数据被两个不同系统调用读写。 
        2.6.25及以后的linux内核版本废除了init_MUTEX函数,  新版本使用sema_init函数; */

	return 0;
}

/* 模块加载方法 */
static int __init freg_init(void) { 
	int err = -1;
	dev_t dev = 0;
	struct device* temp = NULL;

	printk(KERN_ALERT"Initializing freg device.\n");

    /* 动态分配主设备号和从设备号 */
	err = alloc_chrdev_region(&dev, 0, 1, FREG_DEVICE_NODE_NAME);
	if(err < 0) {
		printk(KERN_ALERT"Failed to alloc char dev region.\n");
		goto fail;
	}
    /* alloc_chrdev_region() 函数用于动态申请设备编号范围，这个函数好像并没有检查范围过大的情况，
    不过动态分配总是找个空的散列桶，所以问题也不大。通过指针参数返回实际获得的起始设备编号。*/

	freg_major = MAJOR(dev);
	freg_minor = MINOR(dev);
    /*  #define MINORBITS   20
        #define MINORMASK   ((1U << MINORBITS) - 1)
        #define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))
        #define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))
    */

    /* 分配 freg 设备结构体; */
	freg_dev = kmalloc(sizeof(struct fake_reg_dev), GFP_KERNEL);
	if(!freg_dev) {
		err = -ENOMEM;
		printk(KERN_ALERT"Failed to alloc freg device.\n");
		goto unregister;
	}

    /* 初始化设备，自定义函数 */
	err = __freg_setup_dev(freg_dev);
	if(err) {
		printk(KERN_ALERT"Failed to setup freg device: %d.\n", err);
		goto cleanup;
	}

    /* 在 /sys/class/ 目录下创建设备类别目录freg */
	freg_class = class_create(THIS_MODULE, FREG_DEVICE_CLASS_NAME);
	if(IS_ERR(freg_class)) {
		err = PTR_ERR(freg_class);
		printk(KERN_ALERT"Failed to create freg device class.\n");
		goto destroy_cdev;
	}
    /*  class_create动态创建设备的逻辑类，并完成部分字段的初始化，然后将其添加到内核中。
        创建的逻辑类位于/sys/class/。 */

    /* 在 /dev/ 目录和 /sys/class/freg 目录下分别创建设备文件freg */
	temp = device_create(freg_class, NULL, dev, "%s", FREG_DEVICE_FILE_NAME);
	if(IS_ERR(temp)) {
		err = PTR_ERR(temp);
		printk(KERN_ALERT"Failed to create freg device.\n");
		goto destroy_class;
	}
    /*  创建设备文件 device_create(); 
        device_create(led_class, NULL, dev, NULL, NAME); 
        这个函数用来给应用层mdev在/dev下创建设备节点。*/

    /* 在 /sys/class/freg/freg 目录下创建属性文件 val */
	err = device_create_file(temp, &dev_attr_val);
	if(err < 0) {
		printk(KERN_ALERT"Failed to create attribute val of freg device.\n");
                goto destroy_device;
	}
    /* device_create_file，使用这个函数时要引用 device_create 所返回的 device* 指针，
        作用是在 /sys/class/ 下创建一个属性文件，从而通过对这个属性文件进行读写就能完成对应的数据操作。
    */

	dev_set_drvdata(temp, freg_dev);
    /*  dev_set_drvdata函数用来设置 device 的私有数据，
        dev_get_drvdata函数用来获取 device 的私有数据。
    */

    /* 创建 /proc/freg 文件，自定义函数 */
	freg_create_proc();

	printk(KERN_ALERT"Succedded to initialize freg device.\n");

	return 0;

destroy_device:
	device_destroy(freg_class, dev); // 清除设备;
    /*  函数device_destroy()用于从linux内核系统设备驱动程序模型中移除一个设备，
        并删除/sys/devices/virtual目录下对应的设备目录及/dev/目录下对应的设备文件*/
destroy_class:
	class_destroy(freg_class);  // 清除类;
    /*  函数class_destroy()用于删除设备的逻辑类，即从Linux内核系统中删除设备的逻辑类。 */
destroy_cdev:
	cdev_del(&(freg_dev->dev)); // 清除设备号;
    /* 删除一个cdev，完成字符设备的注册和注销，释放 cdev 占用的内存。*/
cleanup:
	kfree(freg_dev);
unregister:
	unregister_chrdev_region(MKDEV(freg_major, freg_minor), 1);	    // 取消注册字符设备;
fail:
	return err;
}

/* 模块卸载方法 */
static void __exit freg_exit(void) {
	dev_t devno = MKDEV(freg_major, freg_minor);

	printk(KERN_ALERT"Destroy freg device.\n");
	
    /* 删除 /proc/freg 文件，自定义函数 */
	freg_remove_proc();

    /* 销毁设备类别和设备 */
	if(freg_class) {
		device_destroy(freg_class, MKDEV(freg_major, freg_minor));
		class_destroy(freg_class);
	}

    /* 删除字符设备和释放设备内存 */
	if(freg_dev) {
		cdev_del(&(freg_dev->dev));
		kfree(freg_dev);
	}

    /* 释放设备号资源 */
	unregister_chrdev_region(devno, 1);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fake Register Driver");

module_init(freg_init);
module_exit(freg_exit);

