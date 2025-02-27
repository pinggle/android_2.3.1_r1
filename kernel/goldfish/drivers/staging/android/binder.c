/* binder.c
 *
 * Android IPC Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "binder.h"

static DEFINE_MUTEX(binder_lock);
static HLIST_HEAD(binder_procs);
static struct binder_node *binder_context_mgr_node;
static uid_t binder_context_mgr_uid = -1;
static int binder_last_id;
static struct proc_dir_entry *binder_proc_dir_entry_root;
static struct proc_dir_entry *binder_proc_dir_entry_proc;
static struct hlist_head binder_dead_nodes;
static HLIST_HEAD(binder_deferred_list);
static DEFINE_MUTEX(binder_deferred_lock);

static int binder_read_proc_proc(
	char *page, char **start, off_t off, int count, int *eof, void *data);

/* This is only defined in include/asm-arm/sizes.h */
#ifndef SZ_1K
#define SZ_1K                               0x400
#endif

#ifndef SZ_4M
#define SZ_4M                               0x400000
#endif

#define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)

#define BINDER_SMALL_BUF_SIZE (PAGE_SIZE * 64)

enum {
	BINDER_DEBUG_USER_ERROR             = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION       = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER            = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION     = 1U << 5,
	BINDER_DEBUG_READ_WRITE             = 1U << 6,
	BINDER_DEBUG_USER_REFS              = 1U << 7,
	BINDER_DEBUG_THREADS                = 1U << 8,
	BINDER_DEBUG_TRANSACTION            = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE   = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER            = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS          = 1U << 12,
	BINDER_DEBUG_BUFFER_ALLOC           = 1U << 13,
	BINDER_DEBUG_PRIORITY_CAP           = 1U << 14,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC     = 1U << 15,
};
static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
	BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION;
module_param_named(debug_mask, binder_debug_mask, uint, S_IWUSR | S_IRUGO);
static int binder_debug_no_lock;
module_param_named(proc_no_lock, binder_debug_no_lock, bool, S_IWUSR | S_IRUGO);
static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);
static int binder_stop_on_user_error;
static int binder_set_stop_on_user_error(
	const char *val, struct kernel_param *kp)
{
	int ret;
	ret = param_set_int(val, kp);
	if (binder_stop_on_user_error < 2)
		wake_up(&binder_user_error_wait);
	return ret;
}
module_param_call(stop_on_user_error, binder_set_stop_on_user_error,
	param_get_int, &binder_stop_on_user_error, S_IWUSR | S_IRUGO);

#define binder_user_error(x...) \
	do { \
		if (binder_debug_mask & BINDER_DEBUG_USER_ERROR) \
			printk(KERN_INFO x); \
		if (binder_stop_on_user_error) \
			binder_stop_on_user_error = 2; \
	} while (0)

enum {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats {
	int br[_IOC_NR(BR_FAILED_REPLY) + 1];
	int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];
	int obj_created[BINDER_STAT_COUNT];
	int obj_deleted[BINDER_STAT_COUNT];
};

static struct binder_stats binder_stats;

struct binder_transaction_log_entry {
	int debug_id;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
};
struct binder_transaction_log {
	int next;
	int full;
	struct binder_transaction_log_entry entry[32];
};
struct binder_transaction_log binder_transaction_log;
struct binder_transaction_log binder_transaction_log_failed;

static struct binder_transaction_log_entry *binder_transaction_log_add(
	struct binder_transaction_log *log)
{
	struct binder_transaction_log_entry *e;
	e = &log->entry[log->next];
	memset(e, 0, sizeof(*e));
	log->next++;
	if (log->next == ARRAY_SIZE(log->entry)) {
		log->next = 0;
		log->full = 1;
	}
	return e;
}

// binder_work 用来描述待处理的工作项，这些工作项有可能属于一个进程，也有可能属于一个进程中的某一个线程。
struct binder_work {
	struct list_head entry; /* 用来将该结构体嵌入到一个宿主结构中; */
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type; /* 用来描述工作项的类型; Binder驱动程序根据 type 的值，可以判断出一个 binder_work 结构体嵌入到什么类型的宿主结构中. */
};

/* binder_node 用来描述一个 Binder 实体对象，每一个Service组件在Binder驱动中都对应有一个Binder实体对象，
 * 用来描述它在内核中的状态。Binder驱动程序通过强引用计数和弱引用计数来维护它们的生命周期。 */
struct binder_node {
	// debug_id 用来标志一个Binder实体对象的身份，用来帮助调试Binder驱动程序的;
	int debug_id;
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct hlist_node dead_node;
	};
	/* proc 指向一个Binder实体对象的宿主进程。*/
	struct binder_proc *proc;
	struct hlist_head refs;
	// 用来描述一个Binder实体对象的强引用计数;
	int internal_strong_refs;
	// 用来描述一个Binder实体对象的弱引用计数;
	int local_weak_refs;
	int local_strong_refs;
	// ptr和cookie分别指向一个用户空间地址，它们用来描述用户空间中的一个Service组件;
	// cookie 指向该Service组件的地址;
	// ptr 指向该 Service 组件内部的一个引用计数对象（类型为weakref_impl）的地址。
	void __user *ptr;
	void __user *cookie;
	unsigned has_strong_ref : 1;
	unsigned pending_strong_ref : 1;
	unsigned has_weak_ref : 1;
	unsigned pending_weak_ref : 1;
	// has_aync_transaction 用来描述一个Binder实体对象是否正在处理一个异步事务;(1:是;0:否)
	unsigned has_async_transaction : 1;
	// accept_fds 用来描述一个Binder实体对象是否可以接收包含有文件描述符的进程间通信数据.(1:可以接收;other:禁止接收)
	unsigned accept_fds : 1;
	// min_priority 表示一个Binder实体对象在处理一个来自Client进程的请求时，它所要求的处理线程，
	// 即Server进程中的一个线程，应该具备的最小线程优先级;
	int min_priority : 8;
	// 异步事务队列是由该目标Binder实体对象的成员变量async_todo描述的;
	// 异步事务定义的那些单向的进程间通信请求，即不需要等待应答的进程间通信请求，与此相对的便是同步事务。
	// 因为不需要等待应答，Binder驱动程序就认为异步事务的优先级低于同步事务，具体就表现为在同一时刻，
	// 一个Binder实体对象的所有异步事务至多只有一个会得到处理，其余的都等待在异步事务队列中;
	struct list_head async_todo;
};

// 用来描述一个Service组件的死亡接收通知;
// Binder驱动程序决定要向一个Client进程发送一个Service组件死亡通知时，会将一个 binder_ref_death 结构体封装成一个工作项，并且根据实际情况来设置该结构体的成员变量work的值,
// 最后将这个工作项添加到Client进程的todo队列中去等待处理;
// Binder驱动在下面两种情况下，会向一个Client进程发送一个Service组件的死亡通知;
// --> (1),当Binder驱动程序监测到一个Service组件死亡时，它就会找到该Service组件对应的Binder实体对象,然后通知Binder实体对象的成员refs就可以找到所有引用了它的Client进程,
//			最后就找到了这些Client进程所注册的死亡接收通知，即一个binder_ref_death结构体。这时候Binder驱动程序就会将该 binder_ref_death 结构体添加到 Client 进程的 todo
// 			队列中去等待处理。并将死亡通知的类型设置为: BINDER_WORK_DEAD_BINDER;
// --> (2),当Client进程向Binder驱动程序注册一个死亡接收通知时，如果它所引用的Service组件已经死亡，那么Binder驱动程序就会马上发送一个死亡通知给该Client进程。在这种情况下，
//			Binder驱动程序也会将死亡通知的类型设置为: BINDRE_WORK_DEAD_BINDER.
// --> (3),当Client进程向Binder驱动程序注销一个死亡通知时，Binder驱动程序也会向该Client进程的todo队列发送一个类型为 binder_ref_death 的工作项，用来表示注销结果。
struct binder_ref_death {
	// work的取值为: BINDER_WORK_DEAD_BINDER, BINDER_WORK_CLEAR_DEATH_NOTIFICATION, BINDER_WORKER_DEAD_BINDER_AND_CLEAR，用来标志一个具体的死亡通知类型。
	struct binder_work work;
	// cookie 保存负责接收死亡通知的对象的地址;
	void __user *cookie;
};

// binder_ref 用来描述一个Binder引用对象，每一个Client组件在Binder驱动程序中都对应有一个Binder引用对象，用来描述它在内核中的状态。
// Binder驱动程序通过强引用计数和弱引用计数来维护它们的生命周期;
struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	int debug_id;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	// proc 指向一个Binder引用对象的宿主进程;
	struct binder_proc *proc;
	// node 用来描述一个 Binder 引用对象所引用的 Binder 实体对象;
	struct binder_node *node;
	// desc是一个句柄值,描述一个Binder引用对象;
	uint32_t desc;
	// strong 描述一个Binder引用对象的强引用计数,Binder驱动通过它来维护一个Binder引用对象的生命周期;
	int strong;
	// weak 描述一个Binder引用对象的弱引用计数,Binder驱动通过它来维护一个Binder引用对象的生命周期;
	int weak;
	// death指向一个Service组件的死亡接收通知;
	struct binder_ref_death *death;
};

// binder_buffer 描述一个内核缓冲区,用来在进程间传输数据;
struct binder_buffer {
	struct list_head entry; /* free and allocated entries by addesss */
	struct rb_node rb_node; /* free entry by size or allocated entry */
				/* by address */
	// 如果一个内核缓冲区是空闲的，那free的值等于1;
	unsigned free : 1;
	// 在Service组件处理完成该事务之后，如果发现 allow_user_free 的值为1，那么该Service组件就会请求Binder驱动程序释放该内核缓冲区;
	unsigned allow_user_free : 1;
	// async_transaction 为1，则说明为一个异步事务;
	unsigned async_transaction : 1;
	unsigned debug_id : 29;

	// binder_transaction 和 binder_node 用来描述一个内核缓冲区正在交给哪一个事务以及哪一个Binder实体对象使用;
	struct binder_transaction *transaction;
	struct binder_node *target_node;

	size_t data_size;
	size_t offsets_size;
	// data 指向一块大小可变的数据缓冲区，它是真正用来保存通信数据的。
	// 数据缓冲区保存的数据分为两种: 一种是普通数据，另一种是Binder对象;
	uint8_t data[0];
};

enum {
	BINDER_DEFERRED_PUT_FILES    = 0x01,
	BINDER_DEFERRED_FLUSH        = 0x02,
	BINDER_DEFERRED_RELEASE      = 0x04,
};

// binder_proc 描述一个正在使用Binder进程间通信机制的进程;
// 当一个进程调用函数open来打开设备文件/dev/binder时，Binder驱动程序就会为它创建一个binder_proc结构体，
// 并且将它保存在一个全局的 hash 列表中，而成员变量 proc_node 就正好是该 hash 列表中的一个节点。
// 成员变量pid、tsk和files分别指向了进程的进程组ID、任务控制块和打开文件结构体数组;
struct binder_proc {
	struct hlist_node proc_node;
	// threads是一个红黑树的根节点,它以线程ID作为关键字来组织一个进程的Binder线程池;
	struct rb_root threads;
	// nodes 所描述的红黑树是用来组织Binder实体对象的，它以Binder实体对象的成员ptr作为关键字;
	struct rb_root nodes;
	// refs_by_desc 描述的红黑树用来组织Binder引用对象，它以Binder引用对象的成员desc作为关键字;
	struct rb_root refs_by_desc;
	// refs_by_node 描述的红黑树用来组织Binder引用对象，它以Binder引用对象的成员node作为关键字;
	struct rb_root refs_by_node;
	int pid;
	// 用户空间地址是在应用程序进程内部使用的，保存在成员变量vma中;
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct files_struct *files;
	// deferred_work_node 是一个hash列表，用来保存进程可以延迟执行的工作项;
	struct hlist_node deferred_work_node;
	// 描述延迟工作项的具体类型;
	int deferred_work;
	// buffer 保存内核空间地址，在Binder驱动程序内部使用;
	void *buffer;
	// 内核空间地址和用户空间地址的偏移值;
	ptrdiff_t user_buffer_offset;

	struct list_head buffers;
	struct rb_root free_buffers;
	struct rb_root allocated_buffers;
	// free_async_space 保存了当前可以用来保存异步事务数据的内核缓冲区的大小;
	size_t free_async_space;

	struct page **pages;
	// Binder驱动程序为进程分配的内核缓冲区的大小保存在成员变量buffer_size中;
	size_t buffer_size;
	// buffer_free 保存了空闲内核缓冲区的大小;
	uint32_t buffer_free;
	// 待处理工作项队列;
	struct list_head todo;
	wait_queue_head_t wait;
	// stats 用来统计进程数据，例如接收到的进程间通信请求的次数;
	struct binder_stats stats;
	// 死亡通知队列;
	struct list_head delivered_death;
	// Binder驱动程序最多可以主动请求进程注册的线程的数量保存在成员变量max_threads中;
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	// ready_threads 表示进程当前的空闲Binder线程数目;
	int ready_threads;
	long default_priority;
};

enum {
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_EXITED      = 0x04,
	BINDER_LOOPER_STATE_INVALID     = 0x08,
	BINDER_LOOPER_STATE_WAITING     = 0x10,
	BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

// binder_thread 用来描述Binder线程池中的一个线程;
// 一个线程注册到Binder驱动程序时，Binder驱动程序就会为它创建一个binder_thread结构体;
// 一个线程注册到Binder驱动程序后，它接着就会通过 BC_REGISTER_LOOPER（Binder驱动请求创建） 或者 BC_ENTER_LOOPER (主动注册) 协议来通知Binder驱动程序，
// 它可以处理进程间通信请求了，
// 当一个Binder线程退出时，它会通过 BC_EXIT_LOOPER 协议来通知Binder驱动程序;
struct binder_thread {
	// proc 指向其宿主进程；
	struct binder_proc *proc;
	// Binder线程池中的一个(红黑树)节点;
	struct rb_node rb_node;
	// Binder线程的ID;
	int pid;
	// Binder线程的状态;
	int looper;
	// 当Binder驱动程序决定将一个事务交给一个Binder线程处理时，它就会将该事务封装成一个 binder_transaction 结构体，并且
	// 将它添加到由线程结构体 binder_thread 的成员变量 transaction_stack 所描述的一个事务堆栈中;
	struct binder_transaction *transaction_stack;
	struct list_head todo;
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
		/* buffer. Used when sending a reply to a dead process that */
		/* we are also waiting on */
	// 当一个Binder线程在处理一个事务T1并需要依赖于其他的Binder线程来处理另一个事务T2时，
	// 它就会睡眠在由成员变量wait所描述的一个等待队列中，直到事务T2处理完成为止;
	wait_queue_head_t wait;
	struct binder_stats stats;
};

// binder_transaction 用来描述进程间通信过程，这个过程又称为一个事务;
struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply : 1;
	/*unsigned is_dead : 1;*/ /* not used at the moment */

	struct binder_buffer *buffer;
	unsigned int	code;
	unsigned int	flags;
	long	priority;
	long	saved_priority;
	uid_t	sender_euid;
};

static void binder_defer_work(struct binder_proc *proc, int defer);

/*
 * copied from get_unused_fd_flags
 */
int task_get_unused_fd_flags(struct binder_proc *proc, int flags)
{
	struct files_struct *files = proc->files;
	int fd, error;
	struct fdtable *fdt;
	unsigned long rlim_cur;
	unsigned long irqs;

	if (files == NULL)
		return -ESRCH;

	error = -EMFILE;
	spin_lock(&files->file_lock);

repeat:
	fdt = files_fdtable(files);
	fd = find_next_zero_bit(fdt->open_fds->fds_bits, fdt->max_fds,
				files->next_fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	rlim_cur = 0;
	if (lock_task_sighand(proc->tsk, &irqs)) {
		rlim_cur = proc->tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur;
		unlock_task_sighand(proc->tsk, &irqs);
	}
	if (fd >= rlim_cur)
		goto out;

	/* Do we need to expand the fd array or fd set?  */
	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	if (error) {
		/*
		 * If we needed to expand the fs array we
		 * might have blocked - try again.
		 */
		error = -EMFILE;
		goto repeat;
	}

	FD_SET(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	files->next_fd = fd + 1;
#if 1
	/* Sanity check */
	if (fdt->fd[fd] != NULL) {
		printk(KERN_WARNING "get_unused_fd: slot %d not NULL!\n", fd);
		fdt->fd[fd] = NULL;
	}
#endif
	error = fd;

out:
	spin_unlock(&files->file_lock);
	return error;
}

/*
 * copied from fd_install
 */
static void task_fd_install(
	struct binder_proc *proc, unsigned int fd, struct file *file)
{
	struct files_struct *files = proc->files;
	struct fdtable *fdt;

	if (files == NULL)
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	spin_unlock(&files->file_lock);
}

/*
 * copied from __put_unused_fd in open.c
 */
static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

/*
 * copied from sys_close
 */
static long task_close_fd(struct binder_proc *proc, unsigned int fd)
{
	struct file *filp;
	struct files_struct *files = proc->files;
	struct fdtable *fdt;
	int retval;

	if (files == NULL)
		return -ESRCH;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	retval = filp_close(filp, files);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

static void binder_set_nice(long nice)
{
	long min_nice;
	if (can_nice(current, nice)) {
		set_user_nice(current, nice);
		return;
	}
	min_nice = 20 - current->signal->rlim[RLIMIT_NICE].rlim_cur;
	if (binder_debug_mask & BINDER_DEBUG_PRIORITY_CAP)
		printk(KERN_INFO "binder: %d: nice value %ld not allowed use "
		       "%ld instead\n", current->pid, nice, min_nice);
	set_user_nice(current, min_nice);
	if (min_nice < 20)
		return;
	binder_user_error("binder: %d RLIMIT_NICE not set\n", current->pid);
}

static size_t binder_buffer_size(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	if (list_is_last(&buffer->entry, &proc->buffers))
		return proc->buffer + proc->buffer_size - (void *)buffer->data;
	else
		return (size_t)list_entry(buffer->entry.next,
			struct binder_buffer, entry) - (size_t)buffer->data;
}

static void binder_insert_free_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->free_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	size_t buffer_size;
	size_t new_buffer_size;

	BUG_ON(!new_buffer->free);

	new_buffer_size = binder_buffer_size(proc, new_buffer);

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: add free buffer, size %zd, "
		       "at %p\n", proc->pid, new_buffer_size, new_buffer);

	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);

		buffer_size = binder_buffer_size(proc, buffer);

		if (new_buffer_size < buffer_size)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
}

static void binder_insert_allocated_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->allocated_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;

	BUG_ON(new_buffer->free);

	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (new_buffer < buffer)
			p = &parent->rb_left;
		else if (new_buffer > buffer)
			p = &parent->rb_right;
		else
			BUG();
	}
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->allocated_buffers);
}

static struct binder_buffer *binder_buffer_lookup(
	struct binder_proc *proc, void __user *user_ptr)
{
	struct rb_node *n = proc->allocated_buffers.rb_node;
	struct binder_buffer *buffer;
	struct binder_buffer *kern_ptr;

	kern_ptr = user_ptr - proc->user_buffer_offset
		- offsetof(struct binder_buffer, data);

	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (kern_ptr < buffer)
			n = n->rb_left;
		else if (kern_ptr > buffer)
			n = n->rb_right;
		else
			return buffer;
	}
	return NULL;
}

static int binder_update_page_range(struct binder_proc *proc, int allocate,
	void *start, void *end, struct vm_area_struct *vma)
{
	void *page_addr;
	unsigned long user_page_addr;
	struct vm_struct tmp_area;
	struct page **page;
	struct mm_struct *mm;

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: %s pages %p-%p\n",
		       proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start)
		return 0;

	if (vma)
		mm = NULL;
	else
		mm = get_task_mm(proc->tsk);

	if (mm) {
		down_write(&mm->mmap_sem);
		vma = proc->vma;
	}

	if (allocate == 0)
		goto free_range;

	if (vma == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf failed to "
		       "map pages in userspace, no vma\n", proc->pid);
		goto err_no_vma;
	}

	for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
		int ret;
		struct page **page_array_ptr;
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

		BUG_ON(*page);
		*page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (*page == NULL) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		tmp_area.addr = page_addr;
		tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
		page_array_ptr = page;
		ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "to map page at %p in kernel\n",
			       proc->pid, page_addr);
			goto err_map_kernel_failed;
		}
		user_page_addr =
			(uintptr_t)page_addr + proc->user_buffer_offset;
		ret = vm_insert_page(vma, user_page_addr, page[0]);
		if (ret) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "to map page at %lx in userspace\n",
			       proc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		/* vm_insert_page does not seem to increment the refcount */
	}
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return 0;

free_range:
	for (page_addr = end - PAGE_SIZE; page_addr >= start;
	     page_addr -= PAGE_SIZE) {
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
		if (vma)
			zap_page_range(vma, (uintptr_t)page_addr +
				proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
		unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
		__free_page(*page);
		*page = NULL;
err_alloc_page_failed:
		;
	}
err_no_vma:
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return -ENOMEM;
}

static struct binder_buffer *binder_alloc_buf(struct binder_proc *proc,
	size_t data_size, size_t offsets_size, int is_async)
{
	struct rb_node *n = proc->free_buffers.rb_node;
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size;

	if (proc->vma == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf, no vma\n",
		       proc->pid);
		return NULL;
	}

	size = ALIGN(data_size, sizeof(void *)) +
		ALIGN(offsets_size, sizeof(void *));

	if (size < data_size || size < offsets_size) {
		binder_user_error("binder: %d: got transaction with invalid "
			"size %zd-%zd\n", proc->pid, data_size, offsets_size);
		return NULL;
	}

	if (is_async &&
	    proc->free_async_space < size + sizeof(struct binder_buffer)) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd f"
			       "ailed, no async space left\n", proc->pid, size);
		return NULL;
	}

	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_buffer_size(proc, buffer);

		if (size < buffer_size) {
			best_fit = n;
			n = n->rb_left;
		} else if (size > buffer_size)
			n = n->rb_right;
		else {
			best_fit = n;
			break;
		}
	}
	if (best_fit == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd failed, "
		       "no address space\n", proc->pid, size);
		return NULL;
	}
	if (n == NULL) {
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_buffer_size(proc, buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd got buff"
		       "er %p size %zd\n", proc->pid, size, buffer, buffer_size);

	has_page_addr =
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
	if (n == NULL) {
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			buffer_size = size; /* no room for other buffers */
		else
			buffer_size = size + sizeof(struct binder_buffer);
	}
	end_page_addr =
		(void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;
	if (binder_update_page_range(proc, 1,
	    (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;

	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	binder_insert_allocated_buffer(proc, buffer);
	if (buffer_size != size) {
		struct binder_buffer *new_buffer = (void *)buffer->data + size;
		list_add(&new_buffer->entry, &buffer->entry);
		new_buffer->free = 1;
		binder_insert_free_buffer(proc, new_buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd got "
		       "%p\n", proc->pid, size, buffer);
	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	buffer->async_transaction = is_async;
	if (is_async) {
		proc->free_async_space -= size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	return buffer;
}

static void *buffer_start_page(struct binder_buffer *buffer)
{
	return (void *)((uintptr_t)buffer & PAGE_MASK);
}

static void *buffer_end_page(struct binder_buffer *buffer)
{
	return (void *)(((uintptr_t)(buffer + 1) - 1) & PAGE_MASK);
}

static void binder_delete_free_buffer(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	struct binder_buffer *prev, *next = NULL;
	int free_page_end = 1;
	int free_page_start = 1;

	BUG_ON(proc->buffers.next == &buffer->entry);
	prev = list_entry(buffer->entry.prev, struct binder_buffer, entry);
	BUG_ON(!prev->free);
	if (buffer_end_page(prev) == buffer_start_page(buffer)) {
		free_page_start = 0;
		if (buffer_end_page(prev) == buffer_end_page(buffer))
			free_page_end = 0;
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_INFO "binder: %d: merge free, buffer %p "
			       "share page with %p\n", proc->pid, buffer, prev);
	}

	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		next = list_entry(buffer->entry.next,
				  struct binder_buffer, entry);
		if (buffer_start_page(next) == buffer_end_page(buffer)) {
			free_page_end = 0;
			if (buffer_start_page(next) ==
			    buffer_start_page(buffer))
				free_page_start = 0;
			if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
				printk(KERN_INFO "binder: %d: merge free, "
				       "buffer %p share page with %p\n",
				       proc->pid, buffer, prev);
		}
	}
	list_del(&buffer->entry);
	if (free_page_start || free_page_end) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_INFO "binder: %d: merge free, buffer %p do "
			       "not share page%s%s with with %p or %p\n",
			       proc->pid, buffer, free_page_start ? "" : " end",
			       free_page_end ? "" : " start", prev, next);
		binder_update_page_range(proc, 0, free_page_start ?
			buffer_start_page(buffer) : buffer_end_page(buffer),
			(free_page_end ? buffer_end_page(buffer) :
			buffer_start_page(buffer)) + PAGE_SIZE, NULL);
	}
}

static void binder_free_buf(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	size_t size, buffer_size;

	buffer_size = binder_buffer_size(proc, buffer);

	size = ALIGN(buffer->data_size, sizeof(void *)) +
		ALIGN(buffer->offsets_size, sizeof(void *));
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_free_buf %p size %zd buffer"
		       "_size %zd\n", proc->pid, buffer, size, buffer_size);

	BUG_ON(buffer->free);
	BUG_ON(size > buffer_size);
	BUG_ON(buffer->transaction != NULL);
	BUG_ON((void *)buffer < proc->buffer);
	BUG_ON((void *)buffer > proc->buffer + proc->buffer_size);

	if (buffer->async_transaction) {
		proc->free_async_space += size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printk(KERN_INFO "binder: %d: binder_free_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	binder_update_page_range(proc, 0,
		(void *)PAGE_ALIGN((uintptr_t)buffer->data),
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK),
		NULL);
	rb_erase(&buffer->rb_node, &proc->allocated_buffers);
	buffer->free = 1;
	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		struct binder_buffer *next = list_entry(buffer->entry.next,
						struct binder_buffer, entry);
		if (next->free) {
			rb_erase(&next->rb_node, &proc->free_buffers);
			binder_delete_free_buffer(proc, next);
		}
	}
	if (proc->buffers.next != &buffer->entry) {
		struct binder_buffer *prev = list_entry(buffer->entry.prev,
						struct binder_buffer, entry);
		if (prev->free) {
			binder_delete_free_buffer(proc, buffer);
			rb_erase(&prev->rb_node, &proc->free_buffers);
			buffer = prev;
		}
	}
	binder_insert_free_buffer(proc, buffer);
}

/**
 * 函数binder_get_node: 根据一个用户空间地址ptr在目标进程proc中找到一个对应的Binder实体对象。
 * 
 * 一个进程中的所有Binder实体对象都以它们的成员变量ptr作为关键字保存在进程内部的一个红黑树nodes中。
 * 因此，函数就在目标进程proc的Binder实体对象红黑树nodes中检查是否存在一个与参数ptr对应的Binder实体对象。
 * 如果存在，就将对应的Binder对象返回给调用者；否则，就返回一个NULL值给调用者。
 * 
 */
static struct binder_node *
binder_get_node(struct binder_proc *proc, void __user *ptr)
{
	struct rb_node *n = proc->nodes.rb_node;
	struct binder_node *node;

	while (n) {
		node = rb_entry(n, struct binder_node, rb_node);

		if (ptr < node->ptr)
			n = n->rb_left;
		else if (ptr > node->ptr)
			n = n->rb_right;
		else
			return node;
	}
	return NULL;
}

/* 函数 binder_new_node 为 Service Manager 创建一个 Binder 实体对象;
 * @proc : 用来描述 Service Manager 进程;
 * @ptr : 用来指向 Binder 本地对象内部的一个弱引用计数对象的地址值;
 * @cookie : 用来指向 Binder 本地对象的地址值;
 * 由于与 Service Manager 对象的Binder本地对象的地址值为0，因此 ptr 和 cookie 均被指定为 NULL; 
 */
static struct binder_node *
binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
	struct rb_node **p = &proc->nodes.rb_node;
	struct rb_node *parent = NULL;
	struct binder_node *node;

	// while 循环以参数 ptr 为关键字，在这个红黑树中检查前面是否已经为参数 ptr 和 cookie 所描述的 Binder 本地对象
	// 创建过 Binder 实体对象，如果已经创建过，则直接返回一个 NULL 值给调用者; 否则就创建一个新的 Binder 实体对象,
	// 并且对它进行初始化，最后将它加入到其宿主进程的成员变量 nodes 所描述的一个红黑树中;
	while (*p) {
		parent = *p;
		node = rb_entry(parent, struct binder_node, rb_node);

		if (ptr < node->ptr)
			p = &(*p)->rb_left;
		else if (ptr > node->ptr)
			p = &(*p)->rb_right;
		else
			return NULL;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;
	binder_stats.obj_created[BINDER_STAT_NODE]++;
	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &proc->nodes);
	node->debug_id = ++binder_last_id;
	node->proc = proc;
	node->ptr = ptr;
	node->cookie = cookie;
	node->work.type = BINDER_WORK_NODE;
	INIT_LIST_HEAD(&node->work.entry);
	INIT_LIST_HEAD(&node->async_todo);
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printk(KERN_INFO "binder: %d:%d node %d u%p c%p created\n",
		       proc->pid, current->pid, node->debug_id,
		       node->ptr, node->cookie);
	return node;
}

static int
binder_inc_node(struct binder_node *node, int strong, int internal,
		struct list_head *target_list)
{
	if (strong) {
		if (internal) {
			if (target_list == NULL &&
			    node->internal_strong_refs == 0 &&
			    !(node == binder_context_mgr_node &&
			    node->has_strong_ref)) {
				printk(KERN_ERR "binder: invalid inc strong "
					"node for %d\n", node->debug_id);
				return -EINVAL;
			}
			node->internal_strong_refs++;
		} else
			node->local_strong_refs++;
		if (!node->has_strong_ref && target_list) {
			list_del_init(&node->work.entry);
			list_add_tail(&node->work.entry, target_list);
		}
	} else {
		if (!internal)
			node->local_weak_refs++;
		if (!node->has_weak_ref && list_empty(&node->work.entry)) {
			if (target_list == NULL) {
				printk(KERN_ERR "binder: invalid inc weak node "
					"for %d\n", node->debug_id);
				return -EINVAL;
			}
			list_add_tail(&node->work.entry, target_list);
		}
	}
	return 0;
}

static int
binder_dec_node(struct binder_node *node, int strong, int internal)
{
	if (strong) {
		if (internal)
			node->internal_strong_refs--;
		else
			node->local_strong_refs--;
		if (node->local_strong_refs || node->internal_strong_refs)
			return 0;
	} else {
		if (!internal)
			node->local_weak_refs--;
		if (node->local_weak_refs || !hlist_empty(&node->refs))
			return 0;
	}
	if (node->proc && (node->has_strong_ref || node->has_weak_ref)) {
		if (list_empty(&node->work.entry)) {
			list_add_tail(&node->work.entry, &node->proc->todo);
			wake_up_interruptible(&node->proc->wait);
		}
	} else {
		if (hlist_empty(&node->refs) && !node->local_strong_refs &&
		    !node->local_weak_refs) {
			list_del_init(&node->work.entry);
			if (node->proc) {
				rb_erase(&node->rb_node, &node->proc->nodes);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printk(KERN_INFO "binder: refless node %d deleted\n", node->debug_id);
			} else {
				hlist_del(&node->dead_node);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printk(KERN_INFO "binder: dead node %d deleted\n", node->debug_id);
			}
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		}
	}

	return 0;
}


static struct binder_ref *
binder_get_ref(struct binder_proc *proc, uint32_t desc)
{
	struct rb_node *n = proc->refs_by_desc.rb_node;
	struct binder_ref *ref;

	while (n) {
		ref = rb_entry(n, struct binder_ref, rb_node_desc);

		if (desc < ref->desc)
			n = n->rb_left;
		else if (desc > ref->desc)
			n = n->rb_right;
		else
			return ref;
	}
	return NULL;
}

/**
 * 函数binder_get_ref_for_node: 在目标进程target_proc中创建一个Binder引用对象来引用该Service组件;
 */
static struct binder_ref *
binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node)
{
	struct rb_node *n;
	struct rb_node **p = &proc->refs_by_node.rb_node;
	struct rb_node *parent = NULL;
	struct binder_ref *ref, *new_ref;

	// 首先判断是否已经在目标进程proc中为Binder实体对象node创建过一个Binder引用对象。
	// 如果已经创建过，那么就会将对应的Binder引用对象返回给调用者；
	// 否则，就会首先创建一个Binder引用对象来引用该Binder实体对象node，然后再将它返回给调用者。

	// 一个进程中的所有Binder引用对象都以它们的成员变量node作为关键字保存在一个红黑树refs_by_node中。
	// 因此，下面的while循环就在目标进程proc的红黑树refs_by_node中检查是否已经存在一个与Binder实体对象node
	// 对应的Binder引用对象。如果存在，就直接将它返回给调用者；
	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_node);

		if (node < ref->node)
			p = &(*p)->rb_left;
		else if (node > ref->node)
			p = &(*p)->rb_right;
		else
			return ref;
	}

	// 如果不存在，接下来就会在目标进程proc中为Binder实体对象node创建一个Binder引用对象new_ref，
	// 并且将它添加到目标进程proc的红黑树refs_by_node中。
	new_ref = kzalloc(sizeof(*ref), GFP_KERNEL);
	if (new_ref == NULL)
		return NULL;
	binder_stats.obj_created[BINDER_STAT_REF]++;
	new_ref->debug_id = ++binder_last_id;
	new_ref->proc = proc;
	new_ref->node = node;
	rb_link_node(&new_ref->rb_node_node, parent, p);
	rb_insert_color(&new_ref->rb_node_node, &proc->refs_by_node);

	// 为新创建的Binder引用对象new_ref分配句柄值。
	// 检查Binder实体对象node是否引用了Service Manager的Binder实体对象binder_context_mgr_node。
	// 如果是，那么就将Binder引用对象new_ref的句柄值设置为0；否则，就先将Binder引用对象new_ref的句柄值设置为1.
	new_ref->desc = (node == binder_context_mgr_node) ? 0 : 1;
	// for循环实际上是在目标进程proc中找到一个【未使用的最小的句柄值】来作为新创建的Binder引用对象new_ref的句柄值。
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		ref = rb_entry(n, struct binder_ref, rb_node_desc);
		if (ref->desc > new_ref->desc)
			break;
		new_ref->desc = ref->desc + 1;
	}

	p = &proc->refs_by_desc.rb_node;
	// while循环再次确认前面为Binder引用对象new_ref分配的句柄值是有效的。
	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_desc);

		if (new_ref->desc < ref->desc)
			p = &(*p)->rb_left;
		else if (new_ref->desc > ref->desc)
			p = &(*p)->rb_right;
		else
			BUG();
	}
	// 将Binder引用对象new_ref添加到目标进程proc的红黑树refs_by_desc中。
	rb_link_node(&new_ref->rb_node_desc, parent, p);
	rb_insert_color(&new_ref->rb_node_desc, &proc->refs_by_desc);
	if (node) {
		// 将Binder引用对象new_ref添加到它所引用的Binder实体对象node的Binder引用对象列表中。
		hlist_add_head(&new_ref->node_entry, &node->refs);
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printk(KERN_INFO "binder: %d new ref %d desc %d for "
				"node %d\n", proc->pid, new_ref->debug_id,
				new_ref->desc, node->debug_id);
	} else {
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printk(KERN_INFO "binder: %d new ref %d desc %d for "
				"dead node\n", proc->pid, new_ref->debug_id,
				new_ref->desc);
	}
	return new_ref;
}

static void
binder_delete_ref(struct binder_ref *ref)
{
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printk(KERN_INFO "binder: %d delete ref %d desc %d for "
			"node %d\n", ref->proc->pid, ref->debug_id,
			ref->desc, ref->node->debug_id);
	rb_erase(&ref->rb_node_desc, &ref->proc->refs_by_desc);
	rb_erase(&ref->rb_node_node, &ref->proc->refs_by_node);
	if (ref->strong)
		binder_dec_node(ref->node, 1, 1);
	hlist_del(&ref->node_entry);
	binder_dec_node(ref->node, 0, 1);
	if (ref->death) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printk(KERN_INFO "binder: %d delete ref %d desc %d "
				"has death notification\n", ref->proc->pid,
				ref->debug_id, ref->desc);
		list_del(&ref->death->work.entry);
		kfree(ref->death);
		binder_stats.obj_deleted[BINDER_STAT_DEATH]++;
	}
	kfree(ref);
	binder_stats.obj_deleted[BINDER_STAT_REF]++;
}

static int
binder_inc_ref(
	struct binder_ref *ref, int strong, struct list_head *target_list)
{
	int ret;
	if (strong) {
		if (ref->strong == 0) {
			ret = binder_inc_node(ref->node, 1, 1, target_list);
			if (ret)
				return ret;
		}
		ref->strong++;
	} else {
		if (ref->weak == 0) {
			ret = binder_inc_node(ref->node, 0, 1, target_list);
			if (ret)
				return ret;
		}
		ref->weak++;
	}
	return 0;
}


static int
binder_dec_ref(struct binder_ref *ref, int strong)
{
	if (strong) {
		if (ref->strong == 0) {
			binder_user_error("binder: %d invalid dec strong, "
					  "ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id,
					  ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->strong--;
		if (ref->strong == 0) {
			int ret;
			ret = binder_dec_node(ref->node, strong, 1);
			if (ret)
				return ret;
		}
	} else {
		if (ref->weak == 0) {
			binder_user_error("binder: %d invalid dec weak, "
					  "ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id,
					  ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->weak--;
	}
	if (ref->strong == 0 && ref->weak == 0)
		binder_delete_ref(ref);
	return 0;
}

static void
binder_pop_transaction(
	struct binder_thread *target_thread, struct binder_transaction *t)
{
	if (target_thread) {
		// 验证要删除的binder_transaction结构体t是否位于目标线程target_thread的事务堆栈transaction_stack的顶端;
		BUG_ON(target_thread->transaction_stack != t);
		// 验证要删除的binder_transaction结构体t是否是由目标线程target_thread创建的，
		// 即binder_transaction结构体t所描述的事务是否是由目标线程target_thread发起的。
		BUG_ON(target_thread->transaction_stack->from != target_thread);
		// 将目标线程target_thread的事务堆栈transaction_stack中的下一个事务移到它的顶端，
		// 相当于将binder_transaction结构体t所描述的事务从目标线程target_thread的事务堆栈transaction_stack的顶端移除。
		target_thread->transaction_stack =
			target_thread->transaction_stack->from_parent;
		t->from = NULL;
	}
	t->need_reply = 0;
	if (t->buffer)
		t->buffer->transaction = NULL;
	// 将binder_transaction结构体t所占用的内存释放。
	kfree(t);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
}

static void
binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code)
{
	struct binder_thread *target_thread;
	BUG_ON(t->flags & TF_ONE_WAY);
	while (1) {
		target_thread = t->from;
		if (target_thread) {
			if (target_thread->return_error != BR_OK &&
			   target_thread->return_error2 == BR_OK) {
				target_thread->return_error2 =
					target_thread->return_error;
				target_thread->return_error = BR_OK;
			}
			if (target_thread->return_error == BR_OK) {
				if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
					printk(KERN_INFO "binder: send failed reply for transaction %d to %d:%d\n",
					       t->debug_id, target_thread->proc->pid, target_thread->pid);

				binder_pop_transaction(target_thread, t);
				target_thread->return_error = error_code;
				wake_up_interruptible(&target_thread->wait);
			} else {
				printk(KERN_ERR "binder: reply failed, target "
					"thread, %d:%d, has error code %d "
					"already\n", target_thread->proc->pid,
					target_thread->pid,
					target_thread->return_error);
			}
			return;
		} else {
			struct binder_transaction *next = t->from_parent;

			if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
				printk(KERN_INFO "binder: send failed reply "
					"for transaction %d, target dead\n",
					t->debug_id);

			binder_pop_transaction(target_thread, t);
			if (next == NULL) {
				if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
					printk(KERN_INFO "binder: reply failed,"
						" no target thread at root\n");
				return;
			}
			t = next;
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: reply failed, no targ"
					"et thread -- retry %d\n", t->debug_id);
		}
	}
}

static void
binder_transaction_buffer_release(struct binder_proc *proc,
			struct binder_buffer *buffer, size_t *failed_at);

/**
 * binder_transaction: 处理进程发送给它的命令协议;
 * @reply: 用来描述函数binder_transaction当前要处理的是一个BC_TRANSACTION命令协议，还是一个BC_REPLY命令协议;
 * 	(0:表示处理的是BC_TRANSACTION命令协议;否则,就表示处理的是BC_REPLY命令协议)
 * 
 * 发出该BC_TRANSACTION命令协议的源进程和源线程分别是FregServer应用程序进程及其主线程，
 * 它们分别使用binder_proc结构体proc和binder_thread结构体thread来描述。
 * 源进程proc发送BC_TRANSACTION命令协议给Binder驱动程序的目的是要将一个Service组件FregService注册
 * 到Service Manager中，因此，在binder_transaction_data结构体tr中，
 * 它指向的目标Binder对象是一个Binder引用对象，并且它的句柄值等于0。
 * 
 * 函数binder_transaction在处理BC_REPLY命令协议时，
 * 传进来的参数reply的值就等于1，以便可以区别于BC_TRANSACTION命令协议。
 * 
 */
static void
binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
	struct binder_transaction_data *tr, int reply)
{
	struct binder_transaction *t;
	struct binder_work *tcomplete;
	size_t *offp, *off_end;
	struct binder_proc *target_proc;
	struct binder_thread *target_thread = NULL;
	struct binder_node *target_node = NULL;
	struct list_head *target_list;
	wait_queue_head_t *target_wait;
	struct binder_transaction *in_reply_to = NULL;
	struct binder_transaction_log_entry *e;
	uint32_t return_error;

	e = binder_transaction_log_add(&binder_transaction_log);
	e->call_type = reply ? 2 : !!(tr->flags & TF_ONE_WAY);
	e->from_proc = proc->pid;
	e->from_thread = thread->pid;
	e->target_handle = tr->target.handle;
	e->data_size = tr->data_size;
	e->offsets_size = tr->offsets_size;

	if (reply) {
		// 用来找到之前请求与线程thread进行进程间通信的线程。找到了这个目标线程target_thread之后，
		// Binder驱动程序就可以向它发送一个BR_REPLY返回协议，以便将进程间通信结果返回给它。
		// 从线程thread的事务堆栈中将该binder_transaction结构体取出来，并且保存在变量in_reply_to中。
		// binder_transaction结构体in_reply_to的成员变量from指向了之前请求与线程thread进行进程间通信的线程;
		in_reply_to = thread->transaction_stack;
		if (in_reply_to == NULL) {
			binder_user_error("binder: %d:%d got reply transaction "
					  "with no transaction stack\n",
					  proc->pid, thread->pid);
			return_error = BR_FAILED_REPLY;
			goto err_empty_call_stack;
		}
		// 调用函数binder_set_nice来恢复它原来的线程优先级。
		binder_set_nice(in_reply_to->saved_priority);
		if (in_reply_to->to_thread != thread) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad transaction stack,"
				" transaction %d has target %d:%d\n",
				proc->pid, thread->pid, in_reply_to->debug_id,
				in_reply_to->to_proc ?
				in_reply_to->to_proc->pid : 0,
				in_reply_to->to_thread ?
				in_reply_to->to_thread->pid : 0);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			goto err_bad_call_stack;
		}
		// 将这个事务放在线程thread的事务堆栈transaction_stack的顶端，表示线程thread接下来要处理它。
		thread->transaction_stack = in_reply_to->to_parent;
		// 获得目标线程target_thread。
		target_thread = in_reply_to->from;
		if (target_thread == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (target_thread->transaction_stack != in_reply_to) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad target transaction stack %d, "
				"expected %d\n",
				proc->pid, thread->pid,
				target_thread->transaction_stack ?
				target_thread->transaction_stack->debug_id : 0,
				in_reply_to->debug_id);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
		}
		target_proc = target_thread->proc;
	} else {
		// 由于目标Binder引用对象的句柄值等于0，即 tr->target.handle 的值为 false;
		if (tr->target.handle) {
			struct binder_ref *ref;
			// 调用函数binder_get_ref来获得与句柄值tr-＞target.handle对应的Binder引用对象;
			ref = binder_get_ref(proc, tr->target.handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction to invalid handle\n",
					proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				goto err_invalid_target_handle;
			}
			// 再通过这个Binder引用对象的成员变量node来找到目标Binder实体对象target_node;
			target_node = ref->node;
		} else {
			// 将目标 Binder 实体对象 target_node 指向一个引用了 Service Manager 的 Binder 实体对象 binder_context_mgr_node;
			// binder_context_mgr_node是Binder驱动程序在Service Manager启动时创建的;
			target_node = binder_context_mgr_node;
			if (target_node == NULL) {
				return_error = BR_DEAD_REPLY;
				goto err_no_context_mgr_node;
			}
		}
		e->to_node = target_node->debug_id;
		// 找到了目标Binder实体对象之后，就可以根据它的成员变量proc来找到目标进程target_proc;
		target_proc = target_node->proc;
		if (target_proc == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		// 从理论上说，找到了目标进程target_proc之后，Binder驱动程序就可以向它发送一个BR_TRANSACTION返回协议，
		// 以便它可以处理注册Service组件FregService的进程间通信请求。
		// 发送给目标进程target_proc的BR_TRANSACTION返回协议最终是由它的空闲Binder线程来处理的。
		// 这些空闲的Binder线程可以划分为两种类型：第一种是因为无事可做而空闲；
		// 第二种不是真的空闲，而是它在处理某个事务的过程中，需要等待其他线程来完成另外一个事务。
		// 如果Binder驱动程序能够从目标进程target_proc中挑选出一个属于第二种类型的空闲Binder线程来处理 BR_TRANSACTION 返回协议，
		// 并且又不会影响该线程处理它原来的事务，那么Binder驱动程序就可以充分地利用目标进程target_proc的空闲Binder线程来处理进程间通信请求了。
		
		// 下面的代码，尝试在目标进程target_proc中找到一个属于第二种类型的Binder空闲线程target_thread来处理一个BR_TRANSACTION返回协议，
		// 以便可以提高目标进程target_proc的进程间通信并发处理能力。
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) {
				binder_user_error("binder: %d:%d got new "
					"transaction with bad transaction stack"
					", transaction %d has target %d:%d\n",
					proc->pid, thread->pid, tmp->debug_id,
					tmp->to_proc ? tmp->to_proc->pid : 0,
					tmp->to_thread ?
					tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			while (tmp) {
				if (tmp->from && tmp->from->proc == target_proc)
					target_thread = tmp->from;
				tmp = tmp->from_parent;
			}
		}
	}

	// 如果Binder驱动程序在目标进程target_proc中找到了一个最优的目标线程target_thread来接收BR_TRANSACTION返回协议;
	// 就将变量target_list和target_wait分别指向该目标线程target_thread的todo队列和wait等待队列；
	// 否则，就将变量target_list和target_wait分别指向该目标进程target_proc的todo队列和wait等待队列。
	if (target_thread) {
		e->to_thread = target_thread->pid;
		// 分别将它的todo队列和wait等待队列作为目标todo队列target_list和目标wait等待队列target_wait。
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait;
	} else {
		target_list = &target_proc->todo;
		target_wait = &target_proc->wait;
	}
	e->to_proc = target_proc->pid;
	// 有了目标todo队列target_list和目标wait等待队列target_wait之后，
	// 函数接下来就可以将一个与BR_TRANSACTION返回协议相关的待处理工作项加入到目标todo队列target_list中，
	// 以及通过目标wait等待队列target_wait将目标进程或者目标线程唤醒来处理这个工作项。

	/* TODO: reuse incoming transaction for reply */
	// 分配一个 binder_transaction 结构体 t;
	// 后面会将它封装为一个BINDER_WORK_TRANSACTION类型的工作项加入到目标todo队列target_list中，
	// 以便目标线程可以接收到一个BR_TRANSACTION返回协议。
	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (t == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_t_failed;
	}
	binder_stats.obj_created[BINDER_STAT_TRANSACTION]++;

	// 分配了一个binder_work结构体tcomplete，
	// 后面会将它封装成一个BINDER_WORK_TRANSACTION_COMPLETE类型的工作项加入到源线程thread的todo队列中，
	// 以便该线程知道可以马上返回用户空间，并且知道它之前给Binder驱动程序发送的BC_TRANSACTION命令协议已经被接收了。
	tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
	if (tcomplete == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_tcomplete_failed;
	}
	binder_stats.obj_created[BINDER_STAT_TRANSACTION_COMPLETE]++;

	// 开始初始化前面分配的binder_transaction结构体t;
	t->debug_id = ++binder_last_id;
	e->debug_id = t->debug_id;

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION) {
		if (reply)
			printk(KERN_INFO "binder: %d:%d BC_REPLY %d -> %d:%d, "
			       "data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, t->debug_id,
			       target_proc->pid, target_thread->pid,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
		else
			printk(KERN_INFO "binder: %d:%d BC_TRANSACTION %d -> "
			       "%d - node %d, data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, t->debug_id,
			       target_proc->pid, target_node->debug_id,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
	}

	if (!reply && !(tr->flags & TF_ONE_WAY))
		// 如果函数正在处理的是一个BC_TRANSACTION命令协议，并且它所描述的是一个同步的进程间通信请求，
		// 那么下面就会将binder_transaction结构体t的成员变量from指向源线程thread，
		// 以便目标进程target_proc或者目标线程target_thread处理完该进程间通信请求之后，
		// 能够找回发出该进程间通信请求的线程，最终将进程间通信结果返回给它。
		t->from = thread;
	else
		t->from = NULL;
	t->sender_euid = proc->tsk->cred->euid;
	t->to_proc = target_proc;
	t->to_thread = target_thread;
	t->code = tr->code;
	t->flags = tr->flags;
	t->priority = task_nice(current);
	// 为binder_transaction结构体t分配一个内核缓冲区，以便可以将进程间通信数据复制到它里面，
	// 最后传递给目标进程target_proc或者目标线程target_thread处理。
	// 这个内核缓冲区是在目标进程target_proc中分配的。
	t->buffer = binder_alloc_buf(target_proc, tr->data_size,
		tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
	if (t->buffer == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_binder_alloc_buf_failed;
	}
	t->buffer->allow_user_free = 0;
	t->buffer->debug_id = t->debug_id;
	t->buffer->transaction = t;
	t->buffer->target_node = target_node;
	if (target_node)
		// 调用函数binder_inc_node来增加目标Binder实体对象的强引用计数，
		// 因为binder_transaction结构体t通过成员变量target_node引用了它。
		binder_inc_node(target_node, 1, 0, NULL);

	// 计算分配给binder_transaction结构体t的内核缓冲区中用来保存偏移数组的开始位置offp;
	offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));

	// 将binder_transaction_data结构体tr的数据缓冲区，
	// 以及偏移数组的内容复制到分配给binder_transaction结构体t的内核缓冲区中。
	if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid "
			"data ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid "
			"offsets ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	if (!IS_ALIGNED(tr->offsets_size, sizeof(size_t))) {
		binder_user_error("binder: %d:%d got transaction with "
			"invalid offsets size, %zd\n",
			proc->pid, thread->pid, tr->offsets_size);
		return_error = BR_FAILED_REPLY;
		goto err_bad_offset;
	}

	// 计算分配给binder_transaction结构体t的内核缓冲区中用来保存偏移数组的结束位置off_end;
	off_end = (void *)offp + tr->offsets_size;

	// 接下来，函数就根据这两个位置(offp和off_end)来遍历进程间通信数据中的Binder对象，以便可以对它们进行处理。
	// for循环依次处理进程间通信数据中的Binder对象。如果Binder驱动程序是第一次碰到这些 Binder对象，
	// 那么Binder驱动程序就会根据它们的类型分别创建一个Binder实体对象或者一个Binder引用对象；
	// 否则，就会将之前为它们创建的Binder实体对象或者Binder引用对象获取回来，以便可以增加它们的引用计数，避免它们过早地被销毁。
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > t->buffer->data_size - sizeof(*fp) ||
		    t->buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, sizeof(void *))) {
			binder_user_error("binder: %d:%d got transaction with "
				"invalid offset, %zd\n",
				proc->pid, thread->pid, *offp);
			return_error = BR_FAILED_REPLY;
			goto err_bad_offset;
		}
		fp = (struct flat_binder_object *)(t->buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_ref *ref;
			// 调用函数binder_get_node就无法获得一个引用了它的Binder实体对象;
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				// 调用函数binder_new_node为它创建一个Binder实体对象node。
				// 在创建Binder实体对象node时，会根据从用户空间传递进来的flat_binder_object结构体的内容
				// 来设置它的最小线程优先级min_priority，以及是否接收文件描述符标志accept_fds。
				node = binder_new_node(proc, fp->binder, fp->cookie);
				if (node == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_new_node_failed;
				}
				node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
				node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
			}
			if (fp->cookie != node->cookie) {
				binder_user_error("binder: %d:%d sending u%p "
					"node %d, cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					fp->binder, node->debug_id,
					fp->cookie, node->cookie);
				goto err_binder_get_ref_for_node_failed;
			}
			// 接下来就要将即将要注册的Service组件FregService从源进程proc传递到目标进程target_proc中;
			// 调用函数binder_get_ref_for_node在目标进程target_proc中创建一个Binder引用对象来引用该Service组件FregService。
			ref = binder_get_ref_for_node(target_proc, node);
			if (ref == NULL) {
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_for_node_failed;
			}
			// 将flat_binder_object结构体fp的类型修改为BINDER_TYPE_HANDLE，并且设置好它的句柄值。
			// 这是因为当Binder驱动程序将进程间通信数据传递给目标进程target_proc时，
			// 进程间通信数据中的Binder实体对象就变成了Binder引用对象，因此，就需要修改flat_binder_object结构体fp的类型。
			if (fp->type == BINDER_TYPE_BINDER)
				fp->type = BINDER_TYPE_HANDLE;
			else
				fp->type = BINDER_TYPE_WEAK_HANDLE;
			fp->handle = ref->desc;

			// 调用函数binder_inc_ref来增加它的引用计数。
			// 在目标进程target_proc创建好一个Binder引用对象ref之后，接着就要将它传递给该目标进程了。
			// 在传递的过程中，必须要保证Binder引用对象ref不会被销毁.
			binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE, &thread->todo);
			// 前面在创建Binder引用对象ref时，尚未增加过与它所引用的Binder实体对象对应的Binder本地对象的引用计数，
			// 因此，在调用函数binder_inc_ref来增加Binder引用对象ref的引用计数时，
			// 需要将源线程thread的todo队列作为第三个参数传进去，以便Binder驱动程序可以将一个类型为BINDER_WORK_NODE的工作项添加到它里面。
			// 这样，当源线程thread从Binder驱动程序返回到用户空间时，就可以增加相应的Binder本地对象，
			// 即Service组件FregService的引用计数了。

			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        node %d u%p -> ref %d desc %d\n",
				       node->debug_id, node->ptr, ref->debug_id, ref->desc);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction with invalid "
					"handle, %ld\n", proc->pid,
					thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_failed;
			}
			if (ref->node->proc == target_proc) {
				if (fp->type == BINDER_TYPE_HANDLE)
					fp->type = BINDER_TYPE_BINDER;
				else
					fp->type = BINDER_TYPE_WEAK_BINDER;
				fp->binder = ref->node->ptr;
				fp->cookie = ref->node->cookie;
				binder_inc_node(ref->node, fp->type == BINDER_TYPE_BINDER, 0, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printk(KERN_INFO "        ref %d desc %d -> node %d u%p\n",
					       ref->debug_id, ref->desc, ref->node->debug_id, ref->node->ptr);
			} else {
				struct binder_ref *new_ref;
				new_ref = binder_get_ref_for_node(target_proc, ref->node);
				if (new_ref == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_get_ref_for_node_failed;
				}
				fp->handle = new_ref->desc;
				binder_inc_ref(new_ref, fp->type == BINDER_TYPE_HANDLE, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printk(KERN_INFO "        ref %d desc %d -> ref %d desc %d (node %d)\n",
					       ref->debug_id, ref->desc, new_ref->debug_id, new_ref->desc, ref->node->debug_id);
			}
		} break;

		case BINDER_TYPE_FD: {
			int target_fd;
			struct file *file;

			if (reply) {
				if (!(in_reply_to->flags & TF_ACCEPT_FDS)) {
					binder_user_error("binder: %d:%d got reply with fd, %ld, but target does not allow fds\n",
						proc->pid, thread->pid, fp->handle);
					return_error = BR_FAILED_REPLY;
					goto err_fd_not_allowed;
				}
			} else if (!target_node->accept_fds) {
				binder_user_error("binder: %d:%d got transaction with fd, %ld, but target does not allow fds\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fd_not_allowed;
			}

			file = fget(fp->handle);
			if (file == NULL) {
				binder_user_error("binder: %d:%d got transaction with invalid fd, %ld\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fget_failed;
			}
			target_fd = task_get_unused_fd_flags(target_proc, O_CLOEXEC);
			if (target_fd < 0) {
				fput(file);
				return_error = BR_FAILED_REPLY;
				goto err_get_unused_fd_failed;
			}
			task_fd_install(target_proc, target_fd, file);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        fd %ld -> %d\n", fp->handle, target_fd);
			/* TODO: fput? */
			fp->handle = target_fd;
		} break;

		default:
			binder_user_error("binder: %d:%d got transactio"
				"n with invalid object type, %lx\n",
				proc->pid, thread->pid, fp->type);
			return_error = BR_FAILED_REPLY;
			goto err_bad_object_type;
		}
	}
	if (reply) {
		BUG_ON(t->buffer->async_transaction != 0);
		// 调用函数binder_pop_transaction从目标线程target_thread的事务堆栈中删除binder_transaction结构体in_reply_to，
		// 因为它所描述的一个事务已经处理完成了，因此，目标线程target_thread就不需要再保存它了。
		binder_pop_transaction(target_thread, in_reply_to);
	} else if (!(t->flags & TF_ONE_WAY)) {
		// 如果函数binder_transaction正在处理的是一个同步的进程间通信请求，
		// 即binder_transaction结构体t的成员变量flags的TF_ONE_WAY位等于0，
		// 那么下面就设置它的成员变量need_reply的值为1，表示它需要等待回复。
		// 接着将事务t压入到源线程thread的事务堆栈transaction_stack中。
		BUG_ON(t->buffer->async_transaction != 0);
		t->need_reply = 1;
		t->from_parent = thread->transaction_stack;
		thread->transaction_stack = t;
	} else {
		BUG_ON(target_node == NULL);
		BUG_ON(t->buffer->async_transaction != 1);
		if (target_node->has_async_transaction) {
			// 如果函数binder_transaction正在处理的是一个异步的进程间通信请求，
			// 即binder_transaction结构体t的成员变量flags的TF_ONE_WAY位等于1，
			// 那么就会检查目标Binder实体对象target_node当前是否正在处理异步事务。
			// 如果是，那么它的成员变量has_async_transaction的值就会等于1。
			// 在这种情况下，Binder驱动程序就需要将binder_transaction结构体t封装成
			// 一个工作项添加到目标Binder实体对象target_node的async_todo队列中去等待处理，
			// 而不应该放到目标进程target_proc或者目标线程target_thread的todo队列中去等待处理。
			// 因此，就需要修改目标todo队列target_list和目标wait等待队列target_wait的值。
			target_list = &target_node->async_todo;
			target_wait = NULL;
		} else
			target_node->has_async_transaction = 1;
	}
	// 将 binder_transaction 结构体t封装成一个类型为 BINDER_WORK_TRANSACTION 的工作项
	// 添加到目标进程 target_proc 或者目标线程 target_thread的todo 队列中.
	t->work.type = BINDER_WORK_TRANSACTION;
	list_add_tail(&t->work.entry, target_list);
	// 将 binder_work 结构体 tcomplete 封装成一个类型为 BINDER_WORK_TRANSACTION_COMPLETE 的工作项
	// 添加到源线程 thread 的 todo 队列中，以便它从 Binder 驱动程序返回到用户空间之前，可以处理该工作项。
	tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
	list_add_tail(&tcomplete->entry, &thread->todo);
	if (target_wait)
		// 将目标进程target_proc或者目标线程target_thread唤醒，以便它们可以处理这个工作项。
		wake_up_interruptible(target_wait);
	// 如果目标todo队列target_list指向的是一个Binder实体对象的异步事务队列async_todo，
	// 那么目标wait等待队列target_wait就会等于NULL，
	// 这时候就不需要将目标进程target_proc或者目标线程target_thread唤醒了.
	return;

err_get_unused_fd_failed:
err_fget_failed:
err_fd_not_allowed:
err_binder_get_ref_for_node_failed:
err_binder_get_ref_failed:
err_binder_new_node_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
	binder_transaction_buffer_release(target_proc, t->buffer, offp);
	t->buffer->transaction = NULL;
	binder_free_buf(target_proc, t->buffer);
err_binder_alloc_buf_failed:
	kfree(tcomplete);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
err_alloc_tcomplete_failed:
	kfree(t);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
err_alloc_t_failed:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
err_no_context_mgr_node:
	if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
		printk(KERN_INFO "binder: %d:%d transaction failed %d, size"
				"%zd-%zd\n",
			   proc->pid, thread->pid, return_error,
			   tr->data_size, tr->offsets_size);

	{
		struct binder_transaction_log_entry *fe;
		fe = binder_transaction_log_add(&binder_transaction_log_failed);
		*fe = *e;
	}

	BUG_ON(thread->return_error != BR_OK);
	if (in_reply_to) {
		thread->return_error = BR_TRANSACTION_COMPLETE;
		binder_send_failed_reply(in_reply_to, return_error);
	} else
		thread->return_error = return_error;
}

static void
binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at)
{
	size_t *offp, *off_end;
	int debug_id = buffer->debug_id;

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
		printk(KERN_INFO "binder: %d buffer release %d, size %zd-%zd, failed at %p\n",
			   proc->pid, buffer->debug_id,
			   buffer->data_size, buffer->offsets_size, failed_at);

	// 检查即将要释放的内核缓冲区buffer是否是分配给一个Binder实体对象使用的，
	// 即它的成员变量target_node的值是否不等于NULL。如果是，那么就调用函数binder_dec_node来减少它的引用计数。
	if (buffer->target_node)
		binder_dec_node(buffer->target_node, 1, 0);

	offp = (size_t *)(buffer->data + ALIGN(buffer->data_size, sizeof(void *)));
	if (failed_at)
		off_end = failed_at;
	else
		off_end = (void *)offp + buffer->offsets_size;
	
	// for循环依次遍历即将要释放的内核缓冲区buffer中的Binder对象，
	// 并且减少它们所对应的Binder实体对象或者Binder引用对象的引用计数。
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > buffer->data_size - sizeof(*fp) ||
		    buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, sizeof(void *))) {
			printk(KERN_ERR "binder: transaction release %d bad"
					"offset %zd, size %zd\n", debug_id, *offp, buffer->data_size);
			continue;
		}
		fp = (struct flat_binder_object *)(buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				printk(KERN_ERR "binder: transaction release %d bad node %p\n", debug_id, fp->binder);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        node %d u%p\n",
				       node->debug_id, node->ptr);
			binder_dec_node(node, fp->type == BINDER_TYPE_BINDER, 0);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				printk(KERN_ERR "binder: transaction release %d bad handle %ld\n", debug_id, fp->handle);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        ref %d desc %d (node %d)\n",
				       ref->debug_id, ref->desc, ref->node->debug_id);
			binder_dec_ref(ref, fp->type == BINDER_TYPE_HANDLE);
		} break;

		case BINDER_TYPE_FD:
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        fd %ld\n", fp->handle);
			if (failed_at)
				task_close_fd(proc, fp->handle);
			break;

		default:
			printk(KERN_ERR "binder: transaction release %d bad object type %lx\n", debug_id, fp->type);
			break;
		}
	}
}

/* 函数 binder_thread_write 处理 BC_ENTER_LOOPER/BC_FREE_BUFFER 协议;
 * @buffer: 指向进程传递给Binder驱动程序的一个binder_read_write结构体的输出缓冲区write_buffer;
 */
int
binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
		    void __user *buffer, int size, signed long *consumed)
{
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	while (ptr < end && thread->return_error == BR_OK) {
		if (get_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}
		switch (cmd) {
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: {
			uint32_t target;
			struct binder_ref *ref;
			const char *debug_string;

			if (get_user(target, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (target == 0 && binder_context_mgr_node &&
			    (cmd == BC_INCREFS || cmd == BC_ACQUIRE)) {
				ref = binder_get_ref_for_node(proc,
					       binder_context_mgr_node);
				if (ref->desc != target) {
					binder_user_error("binder: %d:"
						"%d tried to acquire "
						"reference to desc 0, "
						"got %d instead\n",
						proc->pid, thread->pid,
						ref->desc);
				}
			} else
				ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d refcou"
					"nt change on invalid ref %d\n",
					proc->pid, thread->pid, target);
				break;
			}
			switch (cmd) {
			case BC_INCREFS:
				debug_string = "IncRefs";
				binder_inc_ref(ref, 0, NULL);
				break;
			case BC_ACQUIRE:
				debug_string = "Acquire";
				binder_inc_ref(ref, 1, NULL);
				break;
			case BC_RELEASE:
				debug_string = "Release";
				binder_dec_ref(ref, 1);
				break;
			case BC_DECREFS:
			default:
				debug_string = "DecRefs";
				binder_dec_ref(ref, 0);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printk(KERN_INFO "binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid, debug_string, ref->debug_id, ref->desc, ref->strong, ref->weak, ref->node->debug_id);
			break;
		}
		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: {
			void __user *node_ptr;
			void *cookie;
			struct binder_node *node;

			if (get_user(node_ptr, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			if (get_user(cookie, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			node = binder_get_node(proc, node_ptr);
			if (node == NULL) {
				binder_user_error("binder: %d:%d "
					"%s u%p no match\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" :
					"BC_ACQUIRE_DONE",
					node_ptr);
				break;
			}
			if (cookie != node->cookie) {
				binder_user_error("binder: %d:%d %s u%p node %d"
					" cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
					node_ptr, node->debug_id,
					cookie, node->cookie);
				break;
			}
			if (cmd == BC_ACQUIRE_DONE) {
				if (node->pending_strong_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_ACQUIRE_DONE node %d has "
						"no pending acquire request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_strong_ref = 0;
			} else {
				if (node->pending_weak_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_INCREFS_DONE node %d has "
						"no pending increfs request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_weak_ref = 0;
			}
			binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printk(KERN_INFO "binder: %d:%d %s node %d ls %d lw %d\n",
				       proc->pid, thread->pid, cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE", node->debug_id, node->local_strong_refs, node->local_weak_refs);
			break;
		}
		case BC_ATTEMPT_ACQUIRE:
			printk(KERN_ERR "binder: BC_ATTEMPT_ACQUIRE not supported\n");
			return -EINVAL;
		case BC_ACQUIRE_RESULT:
			printk(KERN_ERR "binder: BC_ACQUIRE_RESULT not supported\n");
			return -EINVAL;

		case BC_FREE_BUFFER: {
			void __user *data_ptr;
			struct binder_buffer *buffer;

			// 得到要释放的内核缓冲区的用户空间地址，保存在变量data_ptr中;
			if (get_user(data_ptr, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);

			// 调用函数 binder_buffer_lookup 在进程proc中找到与用户空间地址data_ptr对应的内核缓冲区buffer。
			// 如果找到的内核缓冲区buffer为NULL，或者它的成员变量allow_user_free的值等于0，
			// 即不允许进程从用户空间发送BC_FREE_BUFFER命令协议来释放，那么函数就不往下处理了。
			buffer = binder_buffer_lookup(proc, data_ptr);
			if (buffer == NULL) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p no match\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (!buffer->allow_user_free) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p matched "
					"unreturned buffer\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_FREE_BUFFER)
				printk(KERN_INFO "binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",
				       proc->pid, thread->pid, data_ptr, buffer->debug_id,
				       buffer->transaction ? "active" : "finished");

			// if语句检查内核缓冲区buffer的成员变量transaction是否不等于NULL。
			// 如果是，就说明该内核缓冲区是分配给一个binder_transaction结构体使用的。
			if (buffer->transaction) {
				// 将该binder_transaction结构体的成员变量buffer清空;
				buffer->transaction->buffer = NULL;
				// 将该内核缓冲区的成员变量transaction也清空;
				buffer->transaction = NULL;
			}
			// if语句检查内核缓冲区buffer是否是分配给一个Binder实体对象用来处理异步事务的。
			// 如果是，就需要对它的目标Binder实体对象的异步事务队列进行处理。
			// 因为当一个用于异步事务处理的内核缓冲区被用户空间通过BC_FREE_BUFFER命令协议释放时，
			// 就说明该异步事务已经处理完成了，因此，就需要着手处理下一个异步事务了
			if (buffer->async_transaction && buffer->target_node) {
				BUG_ON(!buffer->target_node->has_async_transaction);
				// 检查内核缓冲区buffer的目标Binder实体对象target_node的异步事务队列async_todo是否为空。
				// 如果是，就说明该Binder实体对象没有正在等待处理的异步事务;
				if (list_empty(&buffer->target_node->async_todo))
					buffer->target_node->has_async_transaction = 0;
				else
					// 将该异步事务队列async_todo中的下一个异步事务移至目标线程thread的todo队列中去等待处理。
					// 这样就可以保证一个Binder实体对象的所有异步事务都是串行处理的，
					// 相当于给予Binder实体对象更高的优先级来处理同步事务。
					list_move_tail(buffer->target_node->async_todo.next, &thread->todo);
			}
			// 调用函数binder_transaction_buffer_release来减少它里面的Binder实体对象或者Binder引用对象的引用计数。
			binder_transaction_buffer_release(proc, buffer, NULL);
			// 调用函数binder_free_buf来释放内核缓冲区buffer;
			binder_free_buf(proc, buffer);
			break;
		}

		case BC_TRANSACTION:
		case BC_REPLY: {
			struct binder_transaction_data tr;
			// 从用户空间读取传递的数据到 binder_transaction_data 结构体;
			if (copy_from_user(&tr, ptr, sizeof(tr)))
				return -EFAULT;
			ptr += sizeof(tr);
			// 调用函数binder_transaction来处理进程发送给它的命令协议(eg:BC_TRANSACTION);
			binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
			break;
		}

		case BC_REGISTER_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_REGISTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_ENTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"after BC_ENTER_LOOPER\n",
					proc->pid, thread->pid);
			} else if (proc->requested_threads == 0) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"without request\n",
					proc->pid, thread->pid);
			} else {
				proc->requested_threads--;
				proc->requested_threads_started++;
			}
			thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
			break;
		case BC_ENTER_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_ENTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_ENTER_LOOPER called after "
					"BC_REGISTER_LOOPER\n",
					proc->pid, thread->pid);
			}
			// 将目标线程 thread 的状态设置为 BINDER_LOOPER_STATE_ENTERED，
			// 以表明该线程是一个 Binder 线程，可以处理进程间通信请求;
			thread->looper |= BINDER_LOOPER_STATE_ENTERED;
			break;
		case BC_EXIT_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_EXIT_LOOPER\n",
				       proc->pid, thread->pid);
			thread->looper |= BINDER_LOOPER_STATE_EXITED;
			break;

		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION: {
			uint32_t target;
			void __user *cookie;
			struct binder_ref *ref;
			struct binder_ref_death *death;

			if (get_user(target, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (get_user(cookie, (void __user * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d %s "
					"invalid ref %d\n",
					proc->pid, thread->pid,
					cmd == BC_REQUEST_DEATH_NOTIFICATION ?
					"BC_REQUEST_DEATH_NOTIFICATION" :
					"BC_CLEAR_DEATH_NOTIFICATION",
					target);
				break;
			}

			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printk(KERN_INFO "binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid,
				       cmd == BC_REQUEST_DEATH_NOTIFICATION ?
				       "BC_REQUEST_DEATH_NOTIFICATION" :
				       "BC_CLEAR_DEATH_NOTIFICATION",
				       cookie, ref->debug_id, ref->desc,
				       ref->strong, ref->weak, ref->node->debug_id);

			if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
				if (ref->death) {
					binder_user_error("binder: %d:%"
						"d BC_REQUEST_DEATH_NOTI"
						"FICATION death notific"
						"ation already set\n",
						proc->pid, thread->pid);
					break;
				}
				death = kzalloc(sizeof(*death), GFP_KERNEL);
				if (death == NULL) {
					thread->return_error = BR_ERROR;
					if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
						printk(KERN_INFO "binder: %d:%d "
							"BC_REQUEST_DEATH_NOTIFICATION failed\n",
							proc->pid, thread->pid);
					break;
				}
				binder_stats.obj_created[BINDER_STAT_DEATH]++;
				INIT_LIST_HEAD(&death->work.entry);
				death->cookie = cookie;
				ref->death = death;
				if (ref->node->proc == NULL) {
					ref->death->work.type = BINDER_WORK_DEAD_BINDER;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						list_add_tail(&ref->death->work.entry, &thread->todo);
					} else {
						list_add_tail(&ref->death->work.entry, &proc->todo);
						wake_up_interruptible(&proc->wait);
					}
				}
			} else {
				if (ref->death == NULL) {
					binder_user_error("binder: %d:%"
						"d BC_CLEAR_DEATH_NOTIFI"
						"CATION death notificat"
						"ion not active\n",
						proc->pid, thread->pid);
					break;
				}
				death = ref->death;
				if (death->cookie != cookie) {
					binder_user_error("binder: %d:%"
						"d BC_CLEAR_DEATH_NOTIFI"
						"CATION death notificat"
						"ion cookie mismatch "
						"%p != %p\n",
						proc->pid, thread->pid,
						death->cookie, cookie);
					break;
				}
				ref->death = NULL;
				if (list_empty(&death->work.entry)) {
					death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						list_add_tail(&death->work.entry, &thread->todo);
					} else {
						list_add_tail(&death->work.entry, &proc->todo);
						wake_up_interruptible(&proc->wait);
					}
				} else {
					BUG_ON(death->work.type != BINDER_WORK_DEAD_BINDER);
					death->work.type = BINDER_WORK_DEAD_BINDER_AND_CLEAR;
				}
			}
		} break;
		case BC_DEAD_BINDER_DONE: {
			struct binder_work *w;
			void __user *cookie;
			struct binder_ref_death *death = NULL;
			if (get_user(cookie, (void __user * __user *)ptr))
				return -EFAULT;

			ptr += sizeof(void *);
			list_for_each_entry(w, &proc->delivered_death, entry) {
				struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
				if (tmp_death->cookie == cookie) {
					death = tmp_death;
					break;
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n",
				       proc->pid, thread->pid, cookie, death);
			if (death == NULL) {
				binder_user_error("binder: %d:%d BC_DEAD"
					"_BINDER_DONE %p not found\n",
					proc->pid, thread->pid, cookie);
				break;
			}

			list_del_init(&death->work.entry);
			if (death->work.type == BINDER_WORK_DEAD_BINDER_AND_CLEAR) {
				death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
				if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
					list_add_tail(&death->work.entry, &thread->todo);
				} else {
					list_add_tail(&death->work.entry, &proc->todo);
					wake_up_interruptible(&proc->wait);
				}
			}
		} break;

		default:
			printk(KERN_ERR "binder: %d:%d unknown command %d\n", proc->pid, thread->pid, cmd);
			return -EINVAL;
		}
		*consumed = ptr - buffer;
	}
	return 0;
}

void
binder_stat_br(struct binder_proc *proc, struct binder_thread *thread, uint32_t cmd)
{
	if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.br)) {
		binder_stats.br[_IOC_NR(cmd)]++;
		proc->stats.br[_IOC_NR(cmd)]++;
		thread->stats.br[_IOC_NR(cmd)]++;
	}
}

/* 
 * binder_has_proc_work 用来判断一个进程是否有未处理的工作项;
 */
static int
binder_has_proc_work(struct binder_proc *proc, struct binder_thread *thread)
{
	// 如果一个进程的 todo 队列不为空，那么就说明它有未处理的工作项，因此，函数的返回值就等于1;
	// 另外，如果当前线程的状态被设置为 BINDER_LOOPER_STATE_NEED_RETURN，那么就表示当前线程需要马上返回到用户空间;
	// 因此，这时候函数的返回值也会等于1，防止当期线程进入睡眠等待状态;
	return !list_empty(&proc->todo) || (thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

/*
 * binder_has_thread_work 用来判断一个线程是否有未处理的工作项;
 */
static int
binder_has_thread_work(struct binder_thread *thread)
{
	// 如果一个进程的 todo 队列不为空，那么就说明它有未处理的工作项，因此，函数的返回值就等于1;
	// 另外，如果当前线程的状态被设置为 BINDER_LOOPER_STATE_NEED_RETURN，那么就表示当前线程需要马上返回到用户空间;
	// 因此，这时候函数的返回值也会等于1，防止当期线程进入睡眠等待状态;
	// 还有一种情况，即它上次在 Binder 驱动程序中处理某一个工作项时出现了错误，这时候 Binder 驱动程序就会将相应的错误代码
	// (不等于BR_OK) 设置到对应的 binder_thread 结构体的成员变量 return_error 中，这种情况下，函数也会返回1，
	// 防止它进入睡眠等待状态;
	return !list_empty(&thread->todo) || thread->return_error != BR_OK ||
		(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

/**
 * 函数binder_thread_read: 负责处理一个线程或者一个进程的todo队列中的工作项。处理完成之后，它就会向目标进程发送一个返回协议。
 */
static int
binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
	void  __user *buffer, int size, signed long *consumed, int non_block)
{
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) {
		if (put_user(BR_NOOP, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
	}

retry:
	// 检查当前线程的事务堆栈 transaction_stack 是否为 NULL，以及 todo 队列是否为空。
	// 如果两个条件都成立，即两者都为空，就将变量 wait_for_proc_work 的值设置为 1;
	// 表示它接下来要检查它所属进程的 todo 队列中是否有未处理的工作项，否则，接下来就要优先处理自己的事务或工作项了。
	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);

	if (thread->return_error != BR_OK && ptr < end) {
		if (thread->return_error2 != BR_OK) {
			if (put_user(thread->return_error2, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (ptr == end)
				goto done;
			thread->return_error2 = BR_OK;
		}
		if (put_user(thread->return_error, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		thread->return_error = BR_OK;
		goto done;
	}

	// 先将当前线程的状态设置为 BINDER_LOOPER_STATE_WAITING，表示该线程正处于空闲状态;
	thread->looper |= BINDER_LOOPER_STATE_WAITING;
	// 如果 wait_for_proc_work 为 1，说明当期那线程所属的进程又多了一个空闲 Binder 线程;
	// 将该进程的空闲 Binder 线程数 ready_threads 加 1;
	if (wait_for_proc_work)
		proc->ready_threads++;
	mutex_unlock(&binder_lock);
	if (wait_for_proc_work) {
		if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
					BINDER_LOOPER_STATE_ENTERED))) {
			binder_user_error("binder: %d:%d ERROR: Thread waiting "
				"for process work before calling BC_REGISTER_"
				"LOOPER or BC_ENTER_LOOPER (state %x)\n",
				proc->pid, thread->pid, thread->looper);
			wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
		}
		// binder_set_nice 将当前线程的优先级设置为它所属进程的优先级;
		// 这是因为如果它所属的进程有未处理的工作项，它就需要代表该进程去处理这个工作项;
		binder_set_nice(proc->default_priority);
		// non_block 表示当前线程是否以非阻塞模式打开设备文件 /dev/binder;
		// 如果是，就表示当前线程不可以在 Binder 驱动程序中睡眠;
		// 即如果当前线程发现其所属进程的 todo 队列为空时，它不可以进入睡眠状态去等待该进程有新的未处理工作项;
		if (non_block) {
			// binder_has_proc_work 用来判断一个进程是否有未处理的工作项;
			if (!binder_has_proc_work(proc, thread))
				ret = -EAGAIN;
		} else
			// 调用 wait_event_interruptible_exclusive 来睡眠等待直到其所属的进程有新的未处理工作项为止;
			ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
	} else {
		if (non_block) {
			// binder_has_thread_work 判断一个线程是否有未处理的工作项;
			if (!binder_has_thread_work(thread))
				ret = -EAGAIN;
		} else
			ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
	}
	mutex_lock(&binder_lock);
	if (wait_for_proc_work)
		proc->ready_threads--;
	// 如果Binder驱动程序发现当前线程有新的工作项需要处理时，将它的状态位 BINDER_LOOPER_STATE_WAITING 清空;
	thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

	if (ret)
		return ret;

	// 当前线程被唤醒后，会调用下面 while 循环来处理它的工作项;
	while (1) {
		uint32_t cmd;
		struct binder_transaction_data tr;
		struct binder_work *w;
		struct binder_transaction *t = NULL;

		// 检查线程thread自己的todo队列中是否有工作项需要处理;
		if (!list_empty(&thread->todo))
			// 将线程 thread 的 todo 队列中类型为 BINDER_WORK_TRANSACTION_COMPLETE 的工作项取出来.
			w = list_first_entry(&thread->todo, struct binder_work, entry);
		// 检查它所属进程proc的todo队列中是否有工作项需要处理;
		// 只要其中的一个todo队列中有工作项需要处理，函数binder_thread_read就将它取出来处理，并且保存在binder_work结构体w中。
		else if (!list_empty(&proc->todo) && wait_for_proc_work)
			w = list_first_entry(&proc->todo, struct binder_work, entry);
		else {
			if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
				goto retry;
			break;
		}

		if (end - ptr < sizeof(tr) + 4)
			break;

		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			// 由于binder_work结构体w的类型为BINDER_WORK_TRANSACTION，即它是一个嵌入在一个binder_transaction结构体中的工作项，
			// 因此，下面就可以安全地将它转换为一个binder_transaction结构体t。
			// 将该工作项的宿主binder_transaction结构体取回来，并且保存在变量t中。
			t = container_of(w, struct binder_transaction, work);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			cmd = BR_TRANSACTION_COMPLETE;
			// 将一个BR_TRANSACTION_COMPLETE返回协议写入到用户空间提供的缓冲区中。
			// 从这里可以看出，Binder驱动程序处理类型为BINDER_WORK_TRANSACTION_COMPLETE的工作项的方式是
			// 向相应的进程发送一个BR_TRANSACTION_COMPLETE返回协议。
			if (put_user(cmd, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);

			binder_stat_br(proc, thread, cmd);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION_COMPLETE)
				printk(KERN_INFO "binder: %d:%d BR_TRANSACTION_COMPLETE\n",
				       proc->pid, thread->pid);

			list_del(&w->entry);
			kfree(w);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
		} break;
		case BINDER_WORK_NODE: {
			struct binder_node *node = container_of(w, struct binder_node, work);
			uint32_t cmd = BR_NOOP;
			const char *cmd_name;
			int strong = node->internal_strong_refs || node->local_strong_refs;
			int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
			if (weak && !node->has_weak_ref) {
				cmd = BR_INCREFS;
				cmd_name = "BR_INCREFS";
				node->has_weak_ref = 1;
				node->pending_weak_ref = 1;
				node->local_weak_refs++;
			} else if (strong && !node->has_strong_ref) {
				cmd = BR_ACQUIRE;
				cmd_name = "BR_ACQUIRE";
				node->has_strong_ref = 1;
				node->pending_strong_ref = 1;
				node->local_strong_refs++;
			} else if (!strong && node->has_strong_ref) {
				cmd = BR_RELEASE;
				cmd_name = "BR_RELEASE";
				node->has_strong_ref = 0;
			} else if (!weak && node->has_weak_ref) {
				cmd = BR_DECREFS;
				cmd_name = "BR_DECREFS";
				node->has_weak_ref = 0;
			}
			if (cmd != BR_NOOP) {
				if (put_user(cmd, (uint32_t __user *)ptr))
					return -EFAULT;
				ptr += sizeof(uint32_t);
				if (put_user(node->ptr, (void * __user *)ptr))
					return -EFAULT;
				ptr += sizeof(void *);
				if (put_user(node->cookie, (void * __user *)ptr))
					return -EFAULT;
				ptr += sizeof(void *);

				binder_stat_br(proc, thread, cmd);
				if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
					printk(KERN_INFO "binder: %d:%d %s %d u%p c%p\n",
					       proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
			} else {
				list_del_init(&w->entry);
				if (!weak && !strong) {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printk(KERN_INFO "binder: %d:%d node %d u%p c%p deleted\n",
						       proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
					rb_erase(&node->rb_node, &proc->nodes);
					kfree(node);
					binder_stats.obj_deleted[BINDER_STAT_NODE]++;
				} else {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printk(KERN_INFO "binder: %d:%d node %d u%p c%p state unchanged\n",
						       proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
				}
			}
		} break;
		case BINDER_WORK_DEAD_BINDER:
		case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
			struct binder_ref_death *death = container_of(w, struct binder_ref_death, work);
			uint32_t cmd;
			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
				cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
			else
				cmd = BR_DEAD_BINDER;
			if (put_user(cmd, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (put_user(death->cookie, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printk(KERN_INFO "binder: %d:%d %s %p\n",
				       proc->pid, thread->pid,
				       cmd == BR_DEAD_BINDER ?
				       "BR_DEAD_BINDER" :
				       "BR_CLEAR_DEATH_NOTIFICATION_DONE",
				       death->cookie);

			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION) {
				list_del(&w->entry);
				kfree(death);
				binder_stats.obj_deleted[BINDER_STAT_DEATH]++;
			} else
				list_move(&w->entry, &proc->delivered_death);
			if (cmd == BR_DEAD_BINDER)
				goto done; /* DEAD_BINDER notifications can cause transactions */
		} break;
		}

		if (!t)
			continue;

		BUG_ON(t->buffer == NULL);
		if (t->buffer->target_node) {
			struct binder_node *target_node = t->buffer->target_node;
			// 将目标Binder本地对象信息复制到binder_transaction_data结构体tr中，
			// 以便目标线程thread接收到Binder驱动程序给它发送的BR_TRANSACTION返回协议之后，
			// 可以将该返回协议交给指定的Binder本地对象来处理。
			tr.target.ptr = target_node->ptr;
			tr.cookie =  target_node->cookie;
			// 首先将它原来的线程优先级保存在binder_transaction结构体t的成员变量saved_priority中，
			// 以便它处理完成该进程间通信请求之后，Binder驱动程序可以恢复它原来的线程优先级。
			t->saved_priority = task_nice(current);
			// 如果binder_transaction结构体t描述的是一个同步的进程间通信请求，
			// 并且源线程的线程优先级 t-＞priority 高于目标 Binder 实体对象 target_node 所要求的最小线程优先级 min_priority;
			// 就将目标线程thread的线程优先级设置为源线程的线程优先级;
			if (t->priority < target_node->min_priority &&
			    !(t->flags & TF_ONE_WAY))
				binder_set_nice(t->priority);
			// 当binder_transaction结构体t描述的是一个异步的进程间通信请求时,
			// 那么Binder驱动程序在修改目标线程thread的线程优先级时，就不需要考虑源线程的线程优先级了。
			// 这是因为源线程不需要等待目标线程的进程间通信结果。因此，Binder驱动程序就不需要将目标线程模拟成源线程来执行。
			// 但是，需要进一步检查目标Binder实体对象target_node的最小线程优先级min_priority是否高于目标线程thread的线程优先级。
			// 如果是，那么就将目标线程thread的线程优先级设置为目标Binder实体对象target_node的最小线程优先级min_priority。
			else if (!(t->flags & TF_ONE_WAY) ||
				 t->saved_priority > target_node->min_priority)
				binder_set_nice(target_node->min_priority);
			cmd = BR_TRANSACTION;
		} else {
			tr.target.ptr = NULL;
			tr.cookie = NULL;
			// 将变量cmd的值设置为BR_REPLY，以便可以将进程间通信结果返回给它。
			cmd = BR_REPLY;
		}
		// 将binder_transaction结构体t中的进程间通信数据复制到binder_transaction_data结构体tr中。
		// eg: 复制到binder_transaction_data结构体tr中的成员变量code和flags的值分别为ADD_SERVICE_TRANSACTION和TF_ACCEPT_FDS。
		tr.code = t->code;
		tr.flags = t->flags;
		// 设置binder_transaction_data结构体tr的成员变量sender_euid和sender_pid，
		// 它们分别指向源线程的有效用户ID，以及线程组PID，这样目标线程thread在处理一个进程间通信请求时，
		// 就可以识别出源线程的身份，以便做一些安全性和合法性检查。
		tr.sender_euid = t->sender_euid;

		if (t->from) {
			struct task_struct *sender = t->from->proc->tsk;
			tr.sender_pid = task_tgid_nr_ns(sender, current->nsproxy->pid_ns);
		} else {
			tr.sender_pid = 0;
		}

		// 将binder_transaction结构体t中的数据缓冲区和偏移数组的内容复制到binder_transaction_data结构体tr中。
		// 返回给线程thread的进程间通信结果数据保存在binder_transaction结构体t的内核缓冲区buffer中，
		// 因此，下面的代码就将它们复制到binder_transaction_data结构体tr中。
		tr.data_size = t->buffer->data_size;
		tr.offsets_size = t->buffer->offsets_size;
		tr.data.ptr.buffer = (void *)t->buffer->data + proc->user_buffer_offset;
		tr.data.ptr.offsets = tr.data.ptr.buffer + ALIGN(t->buffer->data_size, sizeof(void *));

		// binder_transaction_data结构体tr的进程间通信数据设置完成之后，
		// 将它以及它所对应的返回协议 BR_TRANSACTION 复制到由目标线程 thread 提供的一个用户空间缓冲区中。
		// 分别将BR_REPLY返回协议代码和binder_transaction_data结构体tr的内容，复制到由线程thread提供的一个用户空间缓冲区中。
		if (put_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		if (copy_to_user(ptr, &tr, sizeof(tr)))
			return -EFAULT;
		ptr += sizeof(tr);

		binder_stat_br(proc, thread, cmd);
		if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
			printk(KERN_INFO "binder: %d:%d %s %d %d:%d, cmd %d"
				"size %zd-%zd ptr %p-%p\n",
			       proc->pid, thread->pid,
			       (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" : "BR_REPLY",
			       t->debug_id, t->from ? t->from->proc->pid : 0,
			       t->from ? t->from->pid : 0, cmd,
			       t->buffer->data_size, t->buffer->offsets_size,
			       tr.data.ptr.buffer, tr.data.ptr.offsets);

		// 将binder_work结构体w从目标线程thread或者目标进程的todo队列中删除，因为它所描述的工作项已经得到处理了。
		list_del(&t->work.entry);
		// 将binder_transaction结构体t的成员变量allow_user_free的值设置为1，
		// 表示Binder驱动程序为它所分配的内核缓冲区允许目标线程thread在用户空间中发出BC_FREE_BUFFER命令协议来释放。
		t->buffer->allow_user_free = 1;
		// 如果Binder驱动程序向目标线程thread发送的是一个BR_TRANSACTION返回协议，并且binder_transaction结构体t的成员变量flags的TF_ONE_WAY位等于0;
		// 那么就说明Binder驱动程序正在请求目标线程thread执行一个同步的进程间通信请求。
		if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
			// 将binder_transaction结构体t压入到目标线程thread的事务堆栈transaction_stack中，
			// 以便Binder驱动程序以后可以从目标线程thread所属进程的Binder线程池中选择一个最优的空闲Binder线程来处理其他的进程间通信请求。
			t->to_parent = thread->transaction_stack;
			t->to_thread = thread;
			thread->transaction_stack = t;
		} else {
			// 如果Binder驱动程序正在处理的不是一个同步的进程间通信请求，就释放binder_transaction结构体t所占用的内核空间；
			// 否则，就需要等到该同步的进程间通信请求处理完成之后，才可以释放binder_transaction结构体t所占用的内核空间。
			t->buffer->transaction = NULL;
			// 因为Binder驱动程序不需要等待目标线程将BR_REPLY返回协议的处理结果返回来。
			// 因此，就调用函数kfree来释放binder_transaction结构体t所占用的内存。
			kfree(t);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
		}
		break;
	}

done:

	// 检查是否需要请求当前线程所属的进程 proc 增加一个新的 Binder 线程来处理进程间通信请求。
	// 如果满足以下 4 个条件，就是将一个返回协议代码 BR_SPAWN_LOOPER 写入到用户空间缓冲区 buffer 中，
	// 以便进程 proc 可以创建一个新的线程加入到它的 Binder 线程池中。
	// (1) 进程 proc 的空闲线程数 ready_threads 等于0;
	// (2) Binder驱动程序当前不是正在请求进程proc增加一个新的Binder线程，即它的成员变量 requested_threads 的值等于0;

	*consumed = ptr - buffer;
	if (proc->requested_threads + proc->ready_threads == 0 &&
	    proc->requested_threads_started < proc->max_threads &&
	    (thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
	     BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */
	     /*spawn a new thread if we leave this out */) {
		proc->requested_threads++;
		if (binder_debug_mask & BINDER_DEBUG_THREADS)
			printk(KERN_INFO "binder: %d:%d BR_SPAWN_LOOPER\n",
			       proc->pid, thread->pid);
		if (put_user(BR_SPAWN_LOOPER, (uint32_t __user *)buffer))
			return -EFAULT;
	}
	return 0;
}

static void binder_release_work(struct list_head *list)
{
	struct binder_work *w;
	while (!list_empty(list)) {
		w = list_first_entry(list, struct binder_work, entry);
		list_del_init(&w->entry);
		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			struct binder_transaction *t = container_of(w, struct binder_transaction, work);
			if (t->buffer->target_node && !(t->flags & TF_ONE_WAY))
				binder_send_failed_reply(t, BR_DEAD_REPLY);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			kfree(w);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
		} break;
		default:
			break;
		}
	}

}

// 函数 binder_get_thread 在为一个线程创建一个 binder_thread 结构体之前，首先会检查与该线程所对应的
// binder_thread 结构体是否已经存在，如果存在，就不用创建了，可直接将该 binder_thread 结构体返回给调用者;
static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
	struct binder_thread *thread = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &proc->threads.rb_node;

	// 一个进程的所有 Binder 线程都保存在一个 binder_proc 结构体的成员变量 threads 所描述的一个红黑树中;
	// 由于这个红黑树是以线程的 PID 为关键字来组织的，因此下面的 while 循环就以当前线程的 pid 在这个红黑树中
	// 查找是否已经存在一个对应的 binder_thread 结构体。如果不存在，即最后得到的红黑树节点 p 为NULL，那么就为
	// 当前线程创建一个 binder_thread 结构体，并且对它进行初始化，然后再将它添加到其宿主进程的成员变量 threads
	// 所描述的一个红黑树中;
	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (current->pid < thread->pid)
			p = &(*p)->rb_left;
		else if (current->pid > thread->pid)
			p = &(*p)->rb_right;
		else
			break;
	}
	if (*p == NULL) {
		thread = kzalloc(sizeof(*thread), GFP_KERNEL);
		if (thread == NULL)
			return NULL;
		binder_stats.obj_created[BINDER_STAT_THREAD]++;
		thread->proc = proc;
		thread->pid = current->pid;
		init_waitqueue_head(&thread->wait);
		INIT_LIST_HEAD(&thread->todo);
		rb_link_node(&thread->rb_node, parent, p);
		rb_insert_color(&thread->rb_node, &proc->threads);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	return thread;
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;

	rb_erase(&thread->rb_node, &proc->threads);
	t = thread->transaction_stack;
	if (t && t->to_thread == thread)
		send_reply = t;
	while (t) {
		active_transactions++;
		if (binder_debug_mask & BINDER_DEBUG_DEAD_TRANSACTION)
			printk(KERN_INFO "binder: release %d:%d transaction %d %s, still active\n",
			       proc->pid, thread->pid, t->debug_id, (t->to_thread == thread) ? "in" : "out");
		if (t->to_thread == thread) {
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) {
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} else if (t->from == thread) {
			t->from = NULL;
			t = t->from_parent;
		} else
			BUG();
	}
	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	binder_release_work(&thread->todo);
	kfree(thread);
	binder_stats.obj_deleted[BINDER_STAT_THREAD]++;
	return active_transactions;
}

static unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread = NULL;
	int wait_for_proc_work;

	mutex_lock(&binder_lock);
	thread = binder_get_thread(proc);

	wait_for_proc_work = thread->transaction_stack == NULL &&
		list_empty(&thread->todo) && thread->return_error == BR_OK;
	mutex_unlock(&binder_lock);

	if (wait_for_proc_work) {
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
		poll_wait(filp, &proc->wait, wait);
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
	} else {
		if (binder_has_thread_work(thread))
			return POLLIN;
		poll_wait(filp, &thread->wait, wait);
		if (binder_has_thread_work(thread))
			return POLLIN;
	}
	return 0;
}

/**
 * 处理 IO 控制命令;
 */
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;
	// 获取前面Binder驱动程序为 Service Manager 进程创建的一个 binder_proc 结构体，保存到 proc 中;
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	/*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/

	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret)
		return ret;

	mutex_lock(&binder_lock);
	// 调用 binder_get_thread 为当前线程创建一个 binder_thread 结构体;
	// 当前线程即为 Service Manager 进程的主线程，同时它也是 Service Manager进程中的一个 Binder 线程。
	thread = binder_get_thread(proc);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	switch (cmd) {
	case BINDER_WRITE_READ: {
		struct binder_write_read bwr;
		if (size != sizeof(struct binder_write_read)) {
			ret = -EINVAL;
			goto err;
		}
		// 将从用户空间传进来的一个 binder_write_read 结构体复制出来，并且保存在变量 bwr 中;
		if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
			ret = -EFAULT;
			goto err;
		}
		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
			printk(KERN_INFO "binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
			       proc->pid, thread->pid, bwr.write_size, bwr.write_buffer, bwr.read_size, bwr.read_buffer);
		// 传递进来的输入缓冲区长度大于0,输出缓冲区等于0，因此下面的判断结果为 true;
		if (bwr.write_size > 0) {
			ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
			if (ret < 0) {
				bwr.read_consumed = 0;
				if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
					ret = -EFAULT;
				goto err;
			}
		}
		// 输出缓冲区为0，因此下面的判断结果为 false;
		if (bwr.read_size > 0) {
			ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
			if (!list_empty(&proc->todo))
				wake_up_interruptible(&proc->wait);
			if (ret < 0) {
				if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
					ret = -EFAULT;
				goto err;
			}
		}
		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
			printk(KERN_INFO "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
			       proc->pid, thread->pid, bwr.write_consumed, bwr.write_size, bwr.read_consumed, bwr.read_size);
		if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
			ret = -EFAULT;
			goto err;
		}
		break;
	}
	case BINDER_SET_MAX_THREADS:
		if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) {
			ret = -EINVAL;
			goto err;
		}
		break;
	case BINDER_SET_CONTEXT_MGR:
		// binder_context_mgr_node 用来描述与 Binder 进程间通信机制的上下文管理者相对应的一个Binder实体对象;
		// 如果它不为 NULL，说明前面已经有组件将自己注册为 Binder 进程间通信机制的上下文管理者了;
		if (binder_context_mgr_node != NULL) {
			printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
			ret = -EBUSY;
			goto err;
		}
		// binder_context_mgr_uid 用来描述注册了 Binder 进程通信机制的上下文管理者的进程的有效用户ID;
		// 如果它不等于 -1 , 说明前面已经有一个进程注册了 Binder 进程间通信机制的上下文管理者了;
		if (binder_context_mgr_uid != -1) {
			// 检查当前进程的有效用户ID是否等于全局变量 binder_context_mgr_uid;
			if (binder_context_mgr_uid != current->cred->euid) {
				printk(KERN_ERR "binder: BINDER_SET_"
				       "CONTEXT_MGR bad uid %d != %d\n",
				       current->cred->euid,
				       binder_context_mgr_uid);
				ret = -EPERM;
				goto err;
			}
		} else
			binder_context_mgr_uid = current->cred->euid;
		
		// 调用 binder_new_node 为 Service Manager 创建一个 Binder 实体对象,
		// 并将它保存在全局变量 binder_context_mgr_node 中;
		binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
		if (binder_context_mgr_node == NULL) {
			ret = -ENOMEM;
			goto err;
		}
		// 为刚创建的 Binder 实体对象的内部引用计数 local_weak_refs 和 local_strong_refs 自增为1，
		// 避免 Binder 驱动程序将其释放;
		binder_context_mgr_node->local_weak_refs++;
		binder_context_mgr_node->local_strong_refs++;
		// 将 Binder 实体对象的 has_strong_ref 和 has_weak_ref 设置为1，表示Binder驱动程序已经请求
		// Service Manager 进程增加 Service manager 组件的强引用计数和弱引用计数了;
		binder_context_mgr_node->has_strong_ref = 1;
		binder_context_mgr_node->has_weak_ref = 1;
		// 到这里, Service Manager 就成功地将自己注册为 Binder 进程间通信机制的上下文管理者了;
		break;
	case BINDER_THREAD_EXIT:
		if (binder_debug_mask & BINDER_DEBUG_THREADS)
			printk(KERN_INFO "binder: %d:%d exit\n",
			       proc->pid, thread->pid);
		binder_free_thread(proc, thread);
		thread = NULL;
		break;
	case BINDER_VERSION:
		if (size != sizeof(struct binder_version)) {
			ret = -EINVAL;
			goto err;
		}
		if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version)) {
			ret = -EINVAL;
			goto err;
		}
		break;
	default:
		ret = -EINVAL;
		goto err;
	}
	ret = 0;
err:
	if (thread)
		// 将 BINDER_LOOPER_STATE_NEED_RETURN 状态位清零，这样当该线程下次再进入到 Binder 驱动程序时，
		// Binder 驱动程序就可以将进程间通信请求分发给它处理了.
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret && ret != -ERESTARTSYS)
		printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
	return ret;
}

static void binder_vma_open(struct vm_area_struct *vma)
{
	struct binder_proc *proc = vma->vm_private_data;
	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder: %d open vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));
	dump_stack();
}

static void binder_vma_close(struct vm_area_struct *vma)
{
	struct binder_proc *proc = vma->vm_private_data;
	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder: %d close vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));
	proc->vma = NULL;
	binder_defer_work(proc, BINDER_DEFERRED_PUT_FILES);
}

static struct vm_operations_struct binder_vm_ops = {
	.open = binder_vma_open,
	.close = binder_vma_close,
};

/**
 * 当进程调用 mmap 将设备文件 /dev/binder 映射到自己的地址空间时，
 * Binder驱动程序中的函数 binder_mmap 就会被调用。
 */
static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	// vm_area_struct 和 vm_struct 都是用来描述虚拟地址空间;
	struct vm_struct *area;
	// filp->private_data 保存的是在 binder_open 函数中创建的 binder_proc;
	struct binder_proc *proc = filp->private_data;
	const char *failure_string;
	struct binder_buffer *buffer;

	// vma的成员变量vm_start和vm_end指定了要映射的用户地址空间范围;
	// binder驱动程序最多可以为进程分配4M内核缓冲区来传输进程间通信数据;
	if ((vma->vm_end - vma->vm_start) > SZ_4M)
		vma->vm_end = vma->vm_start + SZ_4M;

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));

	if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
		ret = -EPERM;
		failure_string = "bad vm_flags";
		goto err_bad_arg;
	}
	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

	if (proc->buffer) {
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}

	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
	if (area == NULL) {
		ret = -ENOMEM;
		failure_string = "get_vm_area";
		goto err_get_vm_area_failed;
	}
	proc->buffer = area->addr;
	proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;

#ifdef CONFIG_CPU_CACHE_VIPT
	if (cache_is_vipt_aliasing()) {
		while (CACHE_COLOUR((vma->vm_start ^ (uint32_t)proc->buffer))) {
			printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p bad alignment\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);
			vma->vm_start += PAGE_SIZE;
		}
	}
#endif
	proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
	if (proc->pages == NULL) {
		ret = -ENOMEM;
		failure_string = "alloc page array";
		goto err_alloc_pages_failed;
	}
	proc->buffer_size = vma->vm_end - vma->vm_start;

	vma->vm_ops = &binder_vm_ops;
	vma->vm_private_data = proc;

	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
		ret = -ENOMEM;
		failure_string = "alloc small buf";
		goto err_alloc_small_buf_failed;
	}
	buffer = proc->buffer;
	INIT_LIST_HEAD(&proc->buffers);
	list_add(&buffer->entry, &proc->buffers);
	buffer->free = 1;
	binder_insert_free_buffer(proc, buffer);
	proc->free_async_space = proc->buffer_size / 2;
	barrier();
	proc->files = get_files_struct(current);
	proc->vma = vma;

	/*printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);*/
	return 0;

err_alloc_small_buf_failed:
	kfree(proc->pages);
	proc->pages = NULL;
err_alloc_pages_failed:
	vfree(proc->buffer);
	proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
	printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n", proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
	return ret;
}

static int binder_open(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc;

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_open: %d:%d\n", current->group_leader->pid, current->pid);

	// 为进程创建一个 binder_proc 结构体 proc;
	proc = kzalloc(sizeof(*proc), GFP_KERNEL);
	if (proc == NULL)
		return -ENOMEM;
	// 对该 binder_proc 结构体 proc 进行初始化;
	get_task_struct(current);
	// tsk 用进程的任务控制块 current 初始化;
	proc->tsk = current;
	INIT_LIST_HEAD(&proc->todo);
	init_waitqueue_head(&proc->wait);
	// default_priority 用进程优先级 task_nice(current) 初始化;
	proc->default_priority = task_nice(current);
	mutex_lock(&binder_lock);
	binder_stats.obj_created[BINDER_STAT_PROC]++;
	// 将 binder_proc 结构体 proc 加入到一个全局 hash 队列 binder_procs 中;
	// Binder 驱动程序将所有打开了设备文件 /dev/binder 的进程都加入到全局 hash 队列 binder_procs 中;
	// 因此遍历这个hash队列就可以知道系统当前有多少个进程在使用 Binder 进程间通信机制;
	hlist_add_head(&proc->proc_node, &binder_procs);
	// pid 用进程组ID来初始化;
	proc->pid = current->group_leader->pid;
	INIT_LIST_HEAD(&proc->delivered_death);
	// 将初始化完成之后的 binder_proc 结构体 proc 保存在参数 filp 的成员变量 private_data 中。
	// 参数 filp 指向一个打开文件结构体，当进程调用函数 open 打开设备文件 /dev/binder 之后，内核就会返回一个文件描述符给进程,
	// 
	filp->private_data = proc;
	mutex_unlock(&binder_lock);

	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
		// 在目标设备上的 /proc/binder/proc 目录下创建一个以进程ID为名称的只读文件，并且以函数 binder_read_proc_proc 作为它的文件内容读取函数。
		// 通过读取文件 /proc/binder/proc/<PID> 的内容，我们就可以获得进程<PID>的Binder线程池、Binder实体对象、Binder引用对象以及内核缓冲区等信息;
		create_proc_read_entry(strbuf, S_IRUGO, binder_proc_dir_entry_proc, binder_read_proc_proc, proc);
	}

	return 0;
}

static int binder_flush(struct file *filp, fl_owner_t id)
{
	struct binder_proc *proc = filp->private_data;

	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}

static void binder_deferred_flush(struct binder_proc *proc)
{
	struct rb_node *n;
	int wake_count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		if (thread->looper & BINDER_LOOPER_STATE_WAITING) {
			wake_up_interruptible(&thread->wait);
			wake_count++;
		}
	}
	wake_up_interruptible_all(&proc->wait);

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_flush: %d woke %d threads\n", proc->pid, wake_count);
}

static int binder_release(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc = filp->private_data;
	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
	}

	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);
	
	return 0;
}

static void binder_deferred_release(struct binder_proc *proc)
{
	struct hlist_node *pos;
	struct binder_transaction *t;
	struct rb_node *n;
	int threads, nodes, incoming_refs, outgoing_refs, buffers, active_transactions, page_count;

	BUG_ON(proc->vma);
	BUG_ON(proc->files);

	hlist_del(&proc->proc_node);
	if (binder_context_mgr_node && binder_context_mgr_node->proc == proc) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printk(KERN_INFO "binder_release: %d context_mgr_node gone\n", proc->pid);
		binder_context_mgr_node = NULL;
	}

	threads = 0;
	active_transactions = 0;
	while ((n = rb_first(&proc->threads))) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		threads++;
		active_transactions += binder_free_thread(proc, thread);
	}
	nodes = 0;
	incoming_refs = 0;
	while ((n = rb_first(&proc->nodes))) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);

		nodes++;
		rb_erase(&node->rb_node, &proc->nodes);
		list_del_init(&node->work.entry);
		if (hlist_empty(&node->refs)) {
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		} else {
			struct binder_ref *ref;
			int death = 0;

			node->proc = NULL;
			node->local_strong_refs = 0;
			node->local_weak_refs = 0;
			hlist_add_head(&node->dead_node, &binder_dead_nodes);

			hlist_for_each_entry(ref, pos, &node->refs, node_entry) {
				incoming_refs++;
				if (ref->death) {
					death++;
					if (list_empty(&ref->death->work.entry)) {
						ref->death->work.type = BINDER_WORK_DEAD_BINDER;
						list_add_tail(&ref->death->work.entry, &ref->proc->todo);
						wake_up_interruptible(&ref->proc->wait);
					} else
						BUG();
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: node %d now dead, refs %d, death %d\n", node->debug_id, incoming_refs, death);
		}
	}
	outgoing_refs = 0;
	while ((n = rb_first(&proc->refs_by_desc))) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		outgoing_refs++;
		binder_delete_ref(ref);
	}
	binder_release_work(&proc->todo);
	buffers = 0;

	while ((n = rb_first(&proc->allocated_buffers))) {
		struct binder_buffer *buffer = rb_entry(n, struct binder_buffer, rb_node);
		t = buffer->transaction;
		if (t) {
			t->buffer = NULL;
			buffer->transaction = NULL;
			printk(KERN_ERR "binder: release proc %d, transaction %d, not freed\n", proc->pid, t->debug_id);
			/*BUG();*/
		}
		binder_free_buf(proc, buffer);
		buffers++;
	}

	binder_stats.obj_deleted[BINDER_STAT_PROC]++;

	page_count = 0;
	if (proc->pages) {
		int i;
		for (i = 0; i < proc->buffer_size / PAGE_SIZE; i++) {
			if (proc->pages[i]) {
				if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
					printk(KERN_INFO "binder_release: %d: page %d at %p not freed\n", proc->pid, i, proc->buffer + i * PAGE_SIZE);
				__free_page(proc->pages[i]);
				page_count++;
			}
		}
		kfree(proc->pages);
		vfree(proc->buffer);
	}

	put_task_struct(proc->tsk);

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_release: %d threads %d, nodes %d (ref %d), refs %d, active transactions %d, buffers %d, pages %d\n",
		       proc->pid, threads, nodes, incoming_refs, outgoing_refs, active_transactions, buffers, page_count);

	kfree(proc);
}

static void binder_deferred_func(struct work_struct *work)
{
	struct binder_proc *proc;
	struct files_struct *files;

	int defer;
	do {
		mutex_lock(&binder_lock);
		mutex_lock(&binder_deferred_lock);
		if (!hlist_empty(&binder_deferred_list)) {
			proc = hlist_entry(binder_deferred_list.first,
					struct binder_proc, deferred_work_node);
			hlist_del_init(&proc->deferred_work_node);
			defer = proc->deferred_work;
			proc->deferred_work = 0;
		} else {
			proc = NULL;
			defer = 0;
		}
		mutex_unlock(&binder_deferred_lock);

		files = NULL;
		if (defer & BINDER_DEFERRED_PUT_FILES)
			if ((files = proc->files))
				proc->files = NULL;

		if (defer & BINDER_DEFERRED_FLUSH)
			binder_deferred_flush(proc);

		if (defer & BINDER_DEFERRED_RELEASE)
			binder_deferred_release(proc); /* frees proc */
	
		mutex_unlock(&binder_lock);
		if (files)
			put_files_struct(files);
	} while (proc);
}
static DECLARE_WORK(binder_deferred_work, binder_deferred_func);

static void binder_defer_work(struct binder_proc *proc, int defer)
{
	mutex_lock(&binder_deferred_lock);
	proc->deferred_work |= defer;
	if (hlist_unhashed(&proc->deferred_work_node)) {
		hlist_add_head(&proc->deferred_work_node,
				&binder_deferred_list);
		schedule_work(&binder_deferred_work);
	}
	mutex_unlock(&binder_deferred_lock);
}

static char *print_binder_transaction(char *buf, char *end, const char *prefix, struct binder_transaction *t)
{
	buf += snprintf(buf, end - buf, "%s %d: %p from %d:%d to %d:%d code %x flags %x pri %ld r%d",
			prefix, t->debug_id, t, t->from ? t->from->proc->pid : 0,
			t->from ? t->from->pid : 0,
			t->to_proc ? t->to_proc->pid : 0,
			t->to_thread ? t->to_thread->pid : 0,
			t->code, t->flags, t->priority, t->need_reply);
	if (buf >= end)
		return buf;
	if (t->buffer == NULL) {
		buf += snprintf(buf, end - buf, " buffer free\n");
		return buf;
	}
	if (t->buffer->target_node) {
		buf += snprintf(buf, end - buf, " node %d",
				t->buffer->target_node->debug_id);
		if (buf >= end)
			return buf;
	}
	buf += snprintf(buf, end - buf, " size %zd:%zd data %p\n",
			t->buffer->data_size, t->buffer->offsets_size,
			t->buffer->data);
	return buf;
}

static char *print_binder_buffer(char *buf, char *end, const char *prefix, struct binder_buffer *buffer)
{
	buf += snprintf(buf, end - buf, "%s %d: %p size %zd:%zd %s\n",
			prefix, buffer->debug_id, buffer->data,
			buffer->data_size, buffer->offsets_size,
			buffer->transaction ? "active" : "delivered");
	return buf;
}

static char *print_binder_work(char *buf, char *end, const char *prefix,
	const char *transaction_prefix, struct binder_work *w)
{
	struct binder_node *node;
	struct binder_transaction *t;

	switch (w->type) {
	case BINDER_WORK_TRANSACTION:
		t = container_of(w, struct binder_transaction, work);
		buf = print_binder_transaction(buf, end, transaction_prefix, t);
		break;
	case BINDER_WORK_TRANSACTION_COMPLETE:
		buf += snprintf(buf, end - buf,
				"%stransaction complete\n", prefix);
		break;
	case BINDER_WORK_NODE:
		node = container_of(w, struct binder_node, work);
		buf += snprintf(buf, end - buf, "%snode work %d: u%p c%p\n",
				prefix, node->debug_id, node->ptr, node->cookie);
		break;
	case BINDER_WORK_DEAD_BINDER:
		buf += snprintf(buf, end - buf, "%shas dead binder\n", prefix);
		break;
	case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		buf += snprintf(buf, end - buf,
				"%shas cleared dead binder\n", prefix);
		break;
	case BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
		buf += snprintf(buf, end - buf,
				"%shas cleared death notification\n", prefix);
		break;
	default:
		buf += snprintf(buf, end - buf, "%sunknown work: type %d\n",
				prefix, w->type);
		break;
	}
	return buf;
}

static char *print_binder_thread(char *buf, char *end, struct binder_thread *thread, int print_always)
{
	struct binder_transaction *t;
	struct binder_work *w;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "  thread %d: l %02x\n", thread->pid, thread->looper);
	header_buf = buf;
	t = thread->transaction_stack;
	while (t) {
		if (buf >= end)
			break;
		if (t->from == thread) {
			buf = print_binder_transaction(buf, end, "    outgoing transaction", t);
			t = t->from_parent;
		} else if (t->to_thread == thread) {
			buf = print_binder_transaction(buf, end, "    incoming transaction", t);
			t = t->to_parent;
		} else {
			buf = print_binder_transaction(buf, end, "    bad transaction", t);
			t = NULL;
		}
	}
	list_for_each_entry(w, &thread->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
					"    pending transaction", w);
	}
	if (!print_always && buf == header_buf)
		buf = start_buf;
	return buf;
}

static char *print_binder_node(char *buf, char *end, struct binder_node *node)
{
	struct binder_ref *ref;
	struct hlist_node *pos;
	struct binder_work *w;
	int count;
	count = 0;
	hlist_for_each_entry(ref, pos, &node->refs, node_entry)
		count++;

	buf += snprintf(buf, end - buf, "  node %d: u%p c%p hs %d hw %d ls %d lw %d is %d iw %d",
			node->debug_id, node->ptr, node->cookie,
			node->has_strong_ref, node->has_weak_ref,
			node->local_strong_refs, node->local_weak_refs,
			node->internal_strong_refs, count);
	if (buf >= end)
		return buf;
	if (count) {
		buf += snprintf(buf, end - buf, " proc");
		if (buf >= end)
			return buf;
		hlist_for_each_entry(ref, pos, &node->refs, node_entry) {
			buf += snprintf(buf, end - buf, " %d", ref->proc->pid);
			if (buf >= end)
				return buf;
		}
	}
	buf += snprintf(buf, end - buf, "\n");
	list_for_each_entry(w, &node->async_todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
					"    pending async transaction", w);
	}
	return buf;
}

static char *print_binder_ref(char *buf, char *end, struct binder_ref *ref)
{
	buf += snprintf(buf, end - buf, "  ref %d: desc %d %snode %d s %d w %d d %p\n",
			ref->debug_id, ref->desc, ref->node->proc ? "" : "dead ",
			ref->node->debug_id, ref->strong, ref->weak, ref->death);
	return buf;
}

static char *print_binder_proc(char *buf, char *end, struct binder_proc *proc, int print_all)
{
	struct binder_work *w;
	struct rb_node *n;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	header_buf = buf;

	for (n = rb_first(&proc->threads); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_thread(buf, end, rb_entry(n, struct binder_thread, rb_node), print_all);
	for (n = rb_first(&proc->nodes); n != NULL && buf < end; n = rb_next(n)) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);
		if (print_all || node->has_async_transaction)
			buf = print_binder_node(buf, end, node);
	}
	if (print_all) {
		for (n = rb_first(&proc->refs_by_desc); n != NULL && buf < end; n = rb_next(n))
			buf = print_binder_ref(buf, end, rb_entry(n, struct binder_ref, rb_node_desc));
	}
	for (n = rb_first(&proc->allocated_buffers); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_buffer(buf, end, "  buffer", rb_entry(n, struct binder_buffer, rb_node));
	list_for_each_entry(w, &proc->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "  ",
					"  pending transaction", w);
	}
	list_for_each_entry(w, &proc->delivered_death, entry) {
		if (buf >= end)
			break;
		buf += snprintf(buf, end - buf, "  has delivered dead binder\n");
		break;
	}
	if (!print_all && buf == header_buf)
		buf = start_buf;
	return buf;
}

static const char *binder_return_strings[] = {
	"BR_ERROR",
	"BR_OK",
	"BR_TRANSACTION",
	"BR_REPLY",
	"BR_ACQUIRE_RESULT",
	"BR_DEAD_REPLY",
	"BR_TRANSACTION_COMPLETE",
	"BR_INCREFS",
	"BR_ACQUIRE",
	"BR_RELEASE",
	"BR_DECREFS",
	"BR_ATTEMPT_ACQUIRE",
	"BR_NOOP",
	"BR_SPAWN_LOOPER",
	"BR_FINISHED",
	"BR_DEAD_BINDER",
	"BR_CLEAR_DEATH_NOTIFICATION_DONE",
	"BR_FAILED_REPLY"
};

static const char *binder_command_strings[] = {
	"BC_TRANSACTION",
	"BC_REPLY",
	"BC_ACQUIRE_RESULT",
	"BC_FREE_BUFFER",
	"BC_INCREFS",
	"BC_ACQUIRE",
	"BC_RELEASE",
	"BC_DECREFS",
	"BC_INCREFS_DONE",
	"BC_ACQUIRE_DONE",
	"BC_ATTEMPT_ACQUIRE",
	"BC_REGISTER_LOOPER",
	"BC_ENTER_LOOPER",
	"BC_EXIT_LOOPER",
	"BC_REQUEST_DEATH_NOTIFICATION",
	"BC_CLEAR_DEATH_NOTIFICATION",
	"BC_DEAD_BINDER_DONE"
};

static const char *binder_objstat_strings[] = {
	"proc",
	"thread",
	"node",
	"ref",
	"death",
	"transaction",
	"transaction_complete"
};

static char *print_binder_stats(char *buf, char *end, const char *prefix, struct binder_stats *stats)
{
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(stats->bc) != ARRAY_SIZE(binder_command_strings));
	for (i = 0; i < ARRAY_SIZE(stats->bc); i++) {
		if (stats->bc[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
					binder_command_strings[i], stats->bc[i]);
		if (buf >= end)
			return buf;
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->br) != ARRAY_SIZE(binder_return_strings));
	for (i = 0; i < ARRAY_SIZE(stats->br); i++) {
		if (stats->br[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
					binder_return_strings[i], stats->br[i]);
		if (buf >= end)
			return buf;
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(binder_objstat_strings));
	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(stats->obj_deleted));
	for (i = 0; i < ARRAY_SIZE(stats->obj_created); i++) {
		if (stats->obj_created[i] || stats->obj_deleted[i])
			buf += snprintf(buf, end - buf, "%s%s: active %d total %d\n", prefix,
					binder_objstat_strings[i],
					stats->obj_created[i] - stats->obj_deleted[i],
					stats->obj_created[i]);
		if (buf >= end)
			return buf;
	}
	return buf;
}

static char *print_binder_proc_stats(char *buf, char *end, struct binder_proc *proc)
{
	struct binder_work *w;
	struct rb_node *n;
	int count, strong, weak;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  threads: %d\n", count);
	if (buf >= end)
		return buf;
	buf += snprintf(buf, end - buf, "  requested threads: %d+%d/%d\n"
			"  ready threads %d\n"
			"  free async space %zd\n", proc->requested_threads,
			proc->requested_threads_started, proc->max_threads,
			proc->ready_threads, proc->free_async_space);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->nodes); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  nodes: %d\n", count);
	if (buf >= end)
		return buf;
	count = 0;
	strong = 0;
	weak = 0;
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		count++;
		strong += ref->strong;
		weak += ref->weak;
	}
	buf += snprintf(buf, end - buf, "  refs: %d s %d w %d\n", count, strong, weak);
	if (buf >= end)
		return buf;

	count = 0;
	for (n = rb_first(&proc->allocated_buffers); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  buffers: %d\n", count);
	if (buf >= end)
		return buf;

	count = 0;
	list_for_each_entry(w, &proc->todo, entry) {
		switch (w->type) {
		case BINDER_WORK_TRANSACTION:
			count++;
			break;
		default:
			break;
		}
	}
	buf += snprintf(buf, end - buf, "  pending transactions: %d\n", count);
	if (buf >= end)
		return buf;

	buf = print_binder_stats(buf, end, "  ", &proc->stats);

	return buf;
}


static int binder_read_proc_state(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	struct binder_node *node;
	int len = 0;
	char *buf = page;
	char *end = page + PAGE_SIZE;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	buf += snprintf(buf, end - buf, "binder state:\n");

	if (!hlist_empty(&binder_dead_nodes))
		buf += snprintf(buf, end - buf, "dead nodes:\n");
	hlist_for_each_entry(node, pos, &binder_dead_nodes, dead_node) {
		if (buf >= end)
			break;
		buf = print_binder_node(buf, end, node);
	}

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (buf >= end)
			break;
		buf = print_binder_proc(buf, end, proc, 1);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (buf > page + PAGE_SIZE)
		buf = page + PAGE_SIZE;

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_stats(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	int len = 0;
	char *p = page;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	p += snprintf(p, PAGE_SIZE, "binder stats:\n");

	p = print_binder_stats(p, page + PAGE_SIZE, "", &binder_stats);

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (p >= page + PAGE_SIZE)
			break;
		p = print_binder_proc_stats(p, page + PAGE_SIZE, proc);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (p > page + PAGE_SIZE)
		p = page + PAGE_SIZE;

	*start = page + off;

	len = p - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_transactions(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	int len = 0;
	char *buf = page;
	char *end = page + PAGE_SIZE;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	buf += snprintf(buf, end - buf, "binder transactions:\n");
	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (buf >= end)
			break;
		buf = print_binder_proc(buf, end, proc, 0);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (buf > page + PAGE_SIZE)
		buf = page + PAGE_SIZE;

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_proc(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc = data;
	int len = 0;
	char *p = page;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);
	p += snprintf(p, PAGE_SIZE, "binder proc state:\n");
	p = print_binder_proc(p, page + PAGE_SIZE, proc, 1);
	if (do_lock)
		mutex_unlock(&binder_lock);

	if (p > page + PAGE_SIZE)
		p = page + PAGE_SIZE;
	*start = page + off;

	len = p - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static char *print_binder_transaction_log_entry(char *buf, char *end, struct binder_transaction_log_entry *e)
{
	buf += snprintf(buf, end - buf, "%d: %s from %d:%d to %d:%d node %d handle %d size %d:%d\n",
			e->debug_id, (e->call_type == 2) ? "reply" :
			((e->call_type == 1) ? "async" : "call "), e->from_proc,
			e->from_thread, e->to_proc, e->to_thread, e->to_node,
			e->target_handle, e->data_size, e->offsets_size);
	return buf;
}

static int binder_read_proc_transaction_log(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_transaction_log *log = data;
	int len = 0;
	int i;
	char *buf = page;
	char *end = page + PAGE_SIZE;

	if (off)
		return 0;

	if (log->full) {
		for (i = log->next; i < ARRAY_SIZE(log->entry); i++) {
			if (buf >= end)
				break;
			buf = print_binder_transaction_log_entry(buf, end, &log->entry[i]);
		}
	}
	for (i = 0; i < log->next; i++) {
		if (buf >= end)
			break;
		buf = print_binder_transaction_log_entry(buf, end, &log->entry[i]);
	}

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static struct file_operations binder_fops = {
	.owner = THIS_MODULE,
	.poll = binder_poll,
	.unlocked_ioctl = binder_ioctl,
	.mmap = binder_mmap,
	.open = binder_open,
	.flush = binder_flush,
	.release = binder_release,
};

static struct miscdevice binder_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "binder",
	.fops = &binder_fops
};

static int __init binder_init(void)
{
	int ret;

	// 在目标设备上创建了一个 /proc/binder/proc 目录，每一个使用了 Binder 进程间通信机制的进程在该目录下都对应有一个文件,
	// 这些文件是以进程ID来命名的,通过它们就可以读取到各个进程的Binder线程池、Binder实体对象、Binder引用对象以及内核缓冲区等信息.
	binder_proc_dir_entry_root = proc_mkdir("binder", NULL);
	if (binder_proc_dir_entry_root)
		binder_proc_dir_entry_proc = proc_mkdir("proc", binder_proc_dir_entry_root);
	// misc_register 来创建一个 Binder 设备;
	// Binder 驱动程序在目标设备上创建了一个 Binder 设备文件 /dev/binder，这个设备文件的操作方法列表是由全局变量 binder_fops 指定的;
	// 全局变量 binder_fops 为 Binder 设备文件 /dev/binder 指定文件打开、内存映射和IO控制函数分别为 binder_open,
	// binder_mmap 和 Binder_ioctl;
	ret = misc_register(&binder_miscdev);
	if (binder_proc_dir_entry_root) {
		// 在 /proc/binder 目录下创建了五个文件: state,stats,transactions,transaction_log,failed_transaction_log;
		// 通过读取这五个文件就可以读取Binder驱动程序的运行状况;
		// 例如,各个命令协议和返回协议的请求次数、日志记录信息，以及正在执行进程间通信过程的进程信息等。
		create_proc_read_entry("state", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_state, NULL);
		create_proc_read_entry("stats", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_stats, NULL);
		create_proc_read_entry("transactions", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transactions, NULL);
		create_proc_read_entry("transaction_log", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transaction_log, &binder_transaction_log);
		create_proc_read_entry("failed_transaction_log", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transaction_log, &binder_transaction_log_failed);
	}
	return ret;
}

device_initcall(binder_init);

MODULE_LICENSE("GPL v2");
