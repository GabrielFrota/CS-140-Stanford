#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"


static void syscall_handler (struct intr_frame *);
static void halt(void) ;
static void exit(int status) ;
static pid_t exec(const char *file) ;
static int wait(pid_t pid) ;
static bool create(const char *file, unsigned initial_size) ;
static int open(const char *file) ;
static bool remove(const char *file) ;
static int filesize (int fd) ;
static unsigned tell (int fd) ;
static int read (int fd, void *buffer, unsigned size) ;
static int write(int fd, const void *buffer, unsigned size) ;
static void seek (int fd, unsigned position) ;
static void close(int fd) ;
static void validarPtrUsuario(const void *uAddr) ;

#ifdef VM
static mapid_t mmap (int fd, void *addr) ;
static void munmap (mapid_t mid) ;
#endif

#ifdef FILESYS
static bool chdir (const char *dir) ;
static bool mkdir (const char *dir) ;
static bool readdir (int fd, char *name) ;
static bool isdir (int fd) ;
static int inumber (int fd) ;
#endif


void syscall_init(void)
{
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall") ;
}


static void syscall_handler(struct intr_frame *f)
{
#ifdef VM
	thread_current()->espUsuario = f->esp ;
#endif
	int *esp = f->esp ;

	validarPtrUsuario(esp) ;

	int syscallNumber = *esp ;

	if (syscallNumber == SYS_HALT)
	{
		halt() ;
	}

	validarPtrUsuario(esp+1) ;

	switch (syscallNumber)
	{
	case SYS_EXIT:
	{
		exit(*(esp+1)) ;
		goto retornar ;
	}
	case SYS_EXEC:
	{
		f->eax = exec((char*)*(esp+1)) ;
		goto retornar ;
	}
	case SYS_WAIT:
	{
		f->eax = wait(*(esp+1)) ;
		goto retornar ;
	}
	case SYS_OPEN:
	{
		f->eax = open((char*)*(esp+1)) ;
		goto retornar ;
	}
	case SYS_FILESIZE:
	{
		f->eax = filesize(*(esp+1)) ;
		goto retornar ;
	}
	case SYS_TELL:
	{
		f->eax = tell(*(esp+1)) ;
		goto retornar ;
	}
	case SYS_REMOVE:
	{
		f->eax = remove((char*)*(esp+1)) ;
		goto retornar ;
	}
#ifdef VM
	case SYS_MUNMAP:
	{
		munmap(*(esp+1)) ;
		goto retornar ;
	}
#endif
#ifdef FILESYS
	case SYS_CHDIR:
	{
		f->eax = chdir((char*)*(esp+1)) ;
		goto retornar ;
	}
	case SYS_MKDIR:
	{
		f->eax = mkdir((char*)*(esp+1)) ;
		goto retornar ;
	}
	case SYS_ISDIR:
	{
		f->eax = isdir(*(esp+1)) ;
		goto retornar ;
	}
	case SYS_INUMBER:
	{
		f->eax = inumber(*(esp+1)) ;
		goto retornar ;
	}
#endif
	}

	validarPtrUsuario(esp+2) ;

	switch (syscallNumber)
	{
	case SYS_CREATE:
	{
		f->eax = create((char*)*(esp+1), *(esp+2)) ;
		goto retornar ;
	}
	case SYS_SEEK:
	{
		seek(*(esp+1), *(esp+2)) ;
		goto retornar ;
	}
#ifdef VM
	case SYS_MMAP:
	{
		f->eax = mmap(*(esp+1), (void*)*(esp+2)) ;
		goto retornar ;
	}
#endif
#ifdef FILESYS
	case SYS_READDIR:
	{
		f->eax = readdir(*(esp+1), (char*)*(esp+2)) ;
		goto retornar ;
	}
#endif
	}

	validarPtrUsuario(esp+3) ;

	switch (syscallNumber)
	{
	case SYS_READ:
	{
		f->eax = read(*(esp+1), (void*)*(esp+2), *(esp+3)) ;
		goto retornar ;
	}
	case SYS_WRITE:
	{
		f->eax = write(*(esp+1), (void*)*(esp+2), *(esp+3)) ;
		goto retornar ;
	}
	case SYS_CLOSE:
	{
		close(*(esp+1)) ;
		goto retornar ;
	}
	}

	/*
	 * Código syscall inválido, terminar processo
	 */
	thread_exit() ;

	retornar:
#ifdef VM
	thread_current()->espUsuario = NULL ;
#endif
	return ;
}

/*
 * Checa se uAddr é um endereço mapeado no mapeamento
 * virtual do processo em execução. A leitura de uAddr é para causar um
 * page fault em um momento seguro caso o endereço seja inválido.
 */
static int volatile aux ;
static void validarPtrUsuario(const void *uAddr)
{
	if (uAddr == NULL || !is_user_vaddr(uAddr))
		thread_exit() ;

	aux = *(char*)uAddr ;
}

/*
 * Syscall halt conforme especificado no documento.
 */
static void halt()
{
	shutdown_power_off() ;
}

/*
 * Syscall exit conforme especificado no documento.
 */
static void exit(int status)
{
	struct thread *cur = thread_current() ;
	struct statusFilho *s = cur->meuStatus ;

	lock_acquire(&s->lock) ;
	cur->meuStatus->flags |= STATUS_FLAG_EXIT_CHAMADO ;
	cur->meuStatus->status = status ;
	lock_release(&s->lock) ;

	thread_exit() ;
}

/*
 * Syscall exec conforme especificado no documento.
 */
static pid_t exec(const char *file)
{
	validarPtrUsuario(file) ;
	pid_t ret = process_execute(file) ;
	return ret ;
}

/*
 * Syscall wait conforme especificado no documento.
 */
static int wait(pid_t pid)
{
	return process_wait(pid) ;
}

/*
 * Syscall create conforme especificado no documento.
 */
static bool create(const char *file, unsigned initial_size)
{
	validarPtrUsuario(file) ;
	return process_create(file, initial_size) ;
}

/*
 * Syscall remove conforme especificado no documento.
 */
static bool remove(const char *file)
{
	validarPtrUsuario(file) ;
	return process_remove(file) ;
}

/*
 * Syscall open conforme especificado no documento.
 */
static int open(const char *file)
{
	validarPtrUsuario(file) ;
	return process_open(file) ;
}

/*
 * Syscall filesize conforme especificado no documento.
 */
static int filesize(int fd)
{
	return process_filesize(fd) ;
}

/*
 * Syscall read conforme especificado no documento.
 */
static int read (int fd, void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer+size))
		thread_exit() ;

	return process_read(fd, buffer, size) ;
}

/*
 * Syscall write conforme especificado no documento.
 */
static int write(int fd, const void *buffer, unsigned size)
{
	if (!is_user_vaddr(buffer+size))
		thread_exit() ;

	return process_write(fd, buffer, size) ;
}

/*
 * Syscall seek conforme especificado no documento.
 */
static void seek(int fd, unsigned position)
{
	process_seek(fd, position) ;
}

/*
 * Syscall tell conforme especificado no documento.
 */
static unsigned tell (int fd)
{
	return process_tell(fd) ;
}

/*
 * Syscall close conforme especificado no documento.
 */
static void close(int fd)
{
	process_close(fd) ;
}

#ifdef VM

/*
 * Sycall mmap conforme especificado no documento.
 */
static mapid_t mmap (int fd, void *addr)
{
	return process_mmap(fd, addr) ;
}

/*
 * Syscall munmap conforme especificado no documento.
 */
static void munmap (mapid_t mid)
{
	process_munmap(mid) ;
}

#endif

#ifdef FILESYS

static bool chdir (const char *dir)
{
	return process_chdir(dir) ;
}

static bool mkdir (const char *dir)
{
	return process_mkdir(dir) ;
}

static bool isdir (int fd)
{
	return process_isdir(fd) ;
}

static int inumber (int fd)
{
	return process_inumber(fd) ;
}

static bool readdir(int fd, char *name)
{
	return process_readdir(fd, name) ;
}

#endif
