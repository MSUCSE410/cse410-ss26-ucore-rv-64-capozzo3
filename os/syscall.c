#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

int sys_task_info(uint64 ti_va) {
	struct proc *p = curr_proc();
	TaskInfo *ti = (TaskInfo* )useraddr(p->pagetable, ti_va);
	if (ti == 0) return -1;

	if (p->state == RUNNING) {
		ti->status = Running;
	}
	else if (p->state == RUNNABLE) {
		ti->status = Ready;
	}
	else if (p->state == UNUSED) {
		ti->status = UnInit;
	}
	else {
		ti->status = Exited;
	}

	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		ti->syscall_times[i] = p->syscall_times[i];
	}

	ti->time = (int)(get_time() - p->start_time);

	return 0;
}

uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	// return directly
	if (len == 0) return 0;

	// validate port
	if ((port & ~0x7) != 0) return -1;
	if ((port & 0x7) == 0) return -1;

	// validate start page alignment
	if (!PGALIGNED(start)) return -1;

	// round len up to next page boundary
	len = PGROUNDUP(len);

	// len upper limit 1 GiB
	if (len > (1UL << 30)) return -1;

	// port permission flags
	int perm = PTE_U;
	if (port & 1) perm |= PTE_R;
	if (port & 2) perm |= PTE_W;
	if (port & 4) perm |= PTE_X;

	struct proc *p = curr_proc();
	uint64 npages = len / PGSIZE;

	// iterate through associated pages
	for (uint64 i = 0; i < npages; i++) {
		uint64 va = start + i * PGSIZE;

		// check if not already mapped
		if (walkaddr(p->pagetable, va) != 0) {
			// if it is, undo our mapping
			for (uint64 j = 0; j < i; j++) {
				uint64 uva = start + j * PGSIZE;
				uint64 pa = walkaddr(p->pagetable, uva);
				uvmunmap(p->pagetable, uva, 1, 1);
				(void)pa;
			}
			return -1;
		}

		void *mem = kalloc();
		if (mem == 0) {
			// out of memory, undo our mapping
			for (uint64 j = 0; j < i; j++) {
				uvmunmap(p->pagetable, start + j * PGSIZE, 1, 1);
			}
			return -1;
		}

		memset(mem, 0, PGSIZE);

		if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) != 0) {
			kfree(mem);
			for (uint64 j = 0; j < i; j++) {
				uvmunmap(p->pagetable, start + j * PGSIZE, 1, 1);
			}
			return -1;
		}
	}

	return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	if (len == 0) return 0;

	// validate start and end page alignment
	if (!PGALIGNED(start)) return -1;

	// round len up to next page boundary
	len = PGROUNDUP(len);

	// len upper limit 1 GiB
	if (len > (1UL << 30)) return -1;

	struct proc *p = curr_proc();
	uint64 npages = len / PGSIZE;

	// verify pages are actually mapped
	for (uint64 i = 0; i < npages; i++) {
		if (walkaddr(p->pagetable, start + i * PGSIZE) == 0) return -1;
	}

	uvmunmap(p->pagetable, start, npages, 1);
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);

	// int id = get_id_by_name(name);
	// if (id < 0)	// invalid filename
	// 	return -1;

	struct inode *ip = namei(name);
	if (ip == 0) return -1;

	struct proc *child = allocproc();
	if (child == NULL) { // process pool is full
		iput(ip);
		return -1;
	}

	// program is loaded directly to the child
	if (bin_loader(ip, child) < 0) {
		iput(ip);
		freeproc(child); // if fails, freeproc to clean up
		return -1;
	}

	iput(ip);
	child->parent = p;
	add_task(child);
	return child->pid;
}

uint64 sys_set_priority(long long prio)
{
	if (prio < 2) // prio not within range [2, isize_max]
    	return -1;
	
	struct proc *p = curr_proc();
	p->priority = (uint32)prio;
	return prio;
}

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

int sys_fstat(int fd,uint64 stat){
	struct proc *p = curr_proc();
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct file *f = p->files[fd];
	if (f == 0 || f->type != FD_INODE)
		return -1;

	// translate user VA to kernel-accessible address
	Stat *st = (Stat *)useraddr(p->pagetable, stat);
	if (st == 0) return -1;

	ivalid(f->ip);
	st->dev = f->ip->dev;
	st->ino = f->ip->inum;
	st->mode = (f->ip->type == T_DIR) ? DIR : FILE;
	st->nlink = f->ip->nlink;
	return 0;
}

int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags) {
	struct proc *p = curr_proc();
	char old[MAXPATH], new[MAXPATH];
	copyinstr(p->pagetable, old, oldpath, MAXPATH);
	copyinstr(p->pagetable, new, newpath, MAXPATH);

	// find the inode the old path points to
	struct inode *ip = namei(old);
	if (ip == 0) return -1;
	ivalid(ip);

	// check if linking to itself
	if (strncmp(old, new, MAXPATH) == 0) {
		iput(ip);
		return -1;
	}
	ip->nlink++;
	iupdate(ip); // update the ip's nlink count

	// add new directory entry pointing to same inode
	struct inode *dp = root_dir();
	if (dirlink(dp, new, ip->inum) < 0) {
		ip->nlink--;
		iupdate(ip);
		iput(ip);
		iput(dp);
		return -1;
	}

	iput(ip);
	iput(dp);
	return 0;
}

int sys_unlinkat(int dirfd, uint64 name, uint64 flags){
	struct proc *p = curr_proc();
	char path[MAXPATH];
	copyinstr(p->pagetable, path, name, MAXPATH);

	struct inode *ip = namei(path);
	if (ip == 0) return -1;
	ivalid(ip);

	// remove directory entry
	struct inode *dp = root_dir();
	if (dirunlink(dp, path) < 0) {
		iput(dp);
		iput(ip);
		return -1;
	}
	iput(dp);

	// decrement nlink
	ip->nlink--;
	iupdate(ip);

	// iput will free if nlink == 0
	iput(ip);

	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
