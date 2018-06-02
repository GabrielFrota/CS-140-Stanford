#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "vm/frame.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"


/*
 * lock para garantir que apenas um processo execute código do file system, como
 * dito na especificação
 */
static struct lock fileSysLock ;


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct file *getDescritorArquivo(int fd) ;
static void validarRead(const void *uAddr) ;
static void validarWrite(void *uAddr) ;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
	char *fn_copy ;
	tid_t tid ;

	/* Make a copy of FILE_NAME.
	 Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0) ;
	if (fn_copy == NULL)
		return TID_ERROR ;
	strlcpy(fn_copy, file_name, PGSIZE) ;

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy) ;

	if (tid == TID_ERROR)
	{
		palloc_free_page(fn_copy) ;
		return TID_ERROR ;
	}

	struct thread *cur = thread_current() ;
	for (struct list_elem *e = list_begin(&cur->statusFilhos) ; e != list_end(&cur->statusFilhos) ;
		 e = list_next(e))
	{
		struct statusFilho *s = list_entry(e, struct statusFilho, elem) ;
		if (s->tid == tid)
		{
			sema_down(&s->semaphore) ;

			if ((s->flags & STATUS_FLAG_LOAD_SUCESSO) != 0)
				return tid ;
			else
				return TID_ERROR ;
		}
	}
	NOT_REACHED() ;
	return 0 ;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
	char *file_name = file_name_ ;
	struct intr_frame if_ ;
	bool success ;

	/* Initialize interrupt frame and load executable. */
	memset(&if_, 0, sizeof if_) ;
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG ;
	if_.cs = SEL_UCSEG ;
	if_.eflags = FLAG_IF | FLAG_MBS ;
	success = load(file_name, &if_.eip, &if_.esp) ;

	if (success)
		thread_current()->meuStatus->flags |= STATUS_FLAG_LOAD_SUCESSO ;

	sema_up(&thread_current()->meuStatus->semaphore) ;

	/* If load failed, quit. */
	palloc_free_page(file_name) ;
	if (!success)
		thread_exit() ;

	/* Start the user process by simulating a return from an
	 interrupt, implemented by intr_exit (in
	 threads/intr-stubs.S).  Because intr_exit takes all of its
	 arguments on the stack in the form of a `struct intr_frame',
	 we just point the stack pointer (%esp) to our stack frame
	 and jump to it. */
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory") ;
	NOT_REACHED () ;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	struct thread *cur = thread_current() ;
	struct statusFilho *s = NULL ;

	for (struct list_elem *e = list_begin(&cur->statusFilhos) ; e != list_end(&cur->statusFilhos) ;
		 e = list_next(e))
	{
		struct statusFilho *aux = list_entry(e, struct statusFilho, elem) ;
		if (aux->tid == child_tid)
			s = aux ;
	}

	if (s == NULL)
		return -1 ;

	sema_down(&s->semaphore) ;

	int ret = s->status ;
	list_remove(&s->elem) ;
	free(s) ;
	return ret ;
}

/* Free the current process's resources. */
void
process_exit (void)
{
	struct thread *cur = thread_current() ;
	uint32_t *pd ;

	/* Destroy the current process's page directory and switch back
	 to the kernel-only page directory. */
#ifdef VM
	lock_acquire(&cur->pageTableLock) ;
#endif
	pd = cur->pagedir ;
	if (pd != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		 cur->pagedir to NULL before switching page directories,
		 so that a timer interrupt can't switch back to the
		 process page directory.  We must activate the base page
		 directory before destroying the process's page
		 directory, or our active page directory will be one
		 that's been freed (and cleared). */
		cur->pagedir = NULL ;
		pagedir_activate(NULL) ;
		pagedir_destroy(pd) ;

		file_close(cur->executavel) ;
	}
#ifdef VM
	else
		lock_release(&cur->pageTableLock) ;
#endif
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *nomeArquivo, char **savePtr);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmdline, void (**eip) (void), void **esp)
{
	struct thread *t = thread_current() ;
	struct Elf32_Ehdr ehdr ;
	struct file *file = NULL ;
	off_t file_ofs ;
	bool success = false ;
	int i ;

	const char *fimCmd = strchr(cmdline, '\0') ;
	int tamanhoCmd = (fimCmd-cmdline)+1 ;
	char copiaCmd[tamanhoCmd] ;
	strlcpy(copiaCmd, cmdline, tamanhoCmd) ;
	char *savePtr ;
	char *nomeArquivo ;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create() ;
	if (t->pagedir == NULL)
		goto done ;
	process_activate() ;

	/* Open executable file. */
	nomeArquivo = strtok_r(copiaCmd, " ", &savePtr) ;
	if (nomeArquivo == NULL)
	{
		printf("strtok_r 1 falhou \n") ;
		goto done ;
	}

	//lock_acquire(&fileSysLock) ;
	file = filesys_open(nomeArquivo) ;
	//lock_release(&fileSysLock) ;

	if (file == NULL)
	{
		printf("load: %s: open failed\n", nomeArquivo) ;
		goto done ;
	}

	/* Read and verify executable header. */
	//lock_acquire(&fileSysLock) ;
	int ret = file_read(file, &ehdr, sizeof ehdr) ;
	//lock_release(&fileSysLock) ;

	if (ret != sizeof ehdr
		|| memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
		|| ehdr.e_type != 2
		|| ehdr.e_machine != 3
		|| ehdr.e_version != 1
		|| ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
		|| ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", nomeArquivo) ;
		goto done ;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff ;
	for (i = 0 ; i < ehdr.e_phnum; i++)
	{
		struct Elf32_Phdr phdr ;

		//lock_acquire(&fileSysLock) ;
		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done ;
		file_seek(file, file_ofs) ;

		int ret = file_read(file, &phdr, sizeof phdr) ;
		//lock_release(&fileSysLock) ;

		if (ret != sizeof phdr)
			goto done ;
		file_ofs += sizeof phdr ;
		switch (phdr.p_type)
		{
		case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
			/* Ignore this segment. */
			break ;
		case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
			goto done ;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0 ;
				uint32_t file_page = phdr.p_offset & ~PGMASK ;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK ;
				uint32_t page_offset = phdr.p_vaddr & PGMASK ;
				uint32_t read_bytes, zero_bytes ;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz ;
					zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
							- read_bytes) ;
				}
				else
				{
					/* Entirely zero.
					 Don't read anything from disk. */
					read_bytes = 0 ;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) ;
				}
				if (!load_segment(file, file_page, (void *) mem_page,
						read_bytes, zero_bytes, writable))
					goto done ;
			}
			else
				goto done ;
			break ;
		}
	}

	/* Set up stack. */
	if (!setup_stack(esp, nomeArquivo, &savePtr))
		goto done ;

	/* Start address. */
	*eip = (void (*)(void)) ehdr.e_entry ;

	success = true ;

	done:
	/* We arrive here whether the load is successful or not. */
	if (!success)
		file_close(file) ;
	else
	{
		file_deny_write(file) ;
		t->executavel = file ;
	}
	return success ;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);
	ASSERT (file != NULL);

#ifdef VM
	uint8_t *startAddr = upage ;
	uint8_t *endAddr = upage ;
#endif

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
#ifndef VM
	{
		/*
		 * Implementação antes do projeto 3.
		 * Executável é lido do disco por completo na
		 * inicialização do processo.
		 */

		/* Calculate how to fill this page.
		 We will read PAGE_READ_BYTES bytes from FILE
		 and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER) ;
		if (kpage == NULL)
			return false;

		/* Load this page. */
		//lock_acquire(&fileSysLock) ;
		int ret = file_read (file, kpage, page_read_bytes) ;
		//lock_release(&fileSysLock) ;

		if (ret != (int) page_read_bytes)
		{
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable))
		{
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
#else
	{
		/*
		 * Implementação a partir do projeto 3. Executável terá seus segmentos
		 * mapeados e será carregado em page faults, aqui apenas
		 * altera page table. Páginas que possuem page_read_bytes = PGSIZE são páginas idênticas
		 * aos bytes no arquivos, portanto estarão sempre mapeados através do bit PTE_M e a struct
		 * mapeamentoArquivo, e em caso de swap out não sao escritos na partição de swap.
		 * Páginas que possuem page_read_bytes < PGSIZE possuem 3 casos:
		 *
		 * - Página completa de zeros. Possui PTE_M setado e mid = 0 . No primero page fault receberá
		 * uma página zerada vinda de page_alloc(PAL_ZERO | PAL_USER) e em seguida o PTE_M é zerado, removendo
		 * o mapeamento. Essa é uma página de dados globais e em caso de swap-out será escrita na partição de swap.
		 *
		 * - Última página do segmento de código. Possui PTE_M setado e mid = algum id. A qualquer page fault
		 * recebera um read(page_read_bytes) em um página zerada vinda de page_alloc(PAL_ZERO | PAL_USER).
		 * O mapeamento não será removido, e em caso de swap a página é apenas desalocada, pois será lida do
		 * executável novamente em caso de page fault.
		 *
		 * - Páginas do segmento de dados, aonde existe um pedaço dos dados identicos ao executável, e um
		 * pedaço dos dados diferente do executável. O arquivo ELF guarda apenas os valores de inicialização
		 * diferentes de zero, e no caso de variáveis que serão inicializadas em zero, ele apenas guarda a
		 * quantidade de bytes do bloco. Portanto existirão alguns bytes no executavél que são as
		 * variáveis com valores diferentes de zero, e o resto da página será zeros, que será um bloco com
		 * a quantidade de bytes descrita no arquivo ELF. Possuem PTE_M setados e mid = algum id,
		 * no primeiro page fault serão lidos do disco por read(page_read_bytes) em um página previamente zerada,
		 * e logo em seguida terão o bit PTE_M colocado em zero, removendo o mapeamento. Se levarem swap-out
		 * serão escritos na partição de swap, pois essa é uma página de dados com "lazy load". O arquivo ELF
		 * não possui espaço suficiente para receber um write da página, alem do arquivo ELF não aceitar
		 * writes, pois é o executável do processo.
		 */

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		uint32_t *pte = pagedir_lookup_page(pagedir_active_pd(), upage, true) ;

		mapid_t mid ;
		if (page_read_bytes != 0)
			mid = (thread_current()->mapeamentosQuant + 1) ;
		else
			mid = 0 ;

		*pte = (mid << PTE_SHIFT_FLAGS) ;
		if (writable)
			*pte |= (PTE_U | PTE_M | PTE_W) ;
		else
			*pte |= (PTE_U | PTE_M) ;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		endAddr += page_read_bytes ;
	}

	if (startAddr != endAddr)
	{
		struct thread *cur = thread_current() ;
		struct mapeamentoArquivo *arq = malloc(sizeof(struct mapeamentoArquivo)) ;
		arq->mid = cur->mapeamentosQuant + 1 ;
		cur->mapeamentosQuant++ ;
		arq->f = file ;
		arq->off = ofs ;
		arq->startAddr = (void*)startAddr ;
		arq->endAddr = (void*)endAddr ;
		list_push_back(&cur->mapeamentos, &arq->elem) ;
	}

#endif

	return true ;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp, char *nomeArquivo, char **savePtr)
{
	uint8_t *kpage ;
	bool success = false ;
	struct thread *cur = thread_current() ;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO) ;
	if (kpage == NULL)
		goto fimFuncao ;

#ifdef VM
	lock_acquire(&cur->pageTableLock) ;
#endif
	bool b = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true) ;
#ifdef VM
	lock_release(&cur->pageTableLock) ;
#endif
	if (!b)
	{
		palloc_free_page(kpage) ;
		goto fimFuncao ;
	}

	int i = 0 ;
	char *topoPilha = (char*)PHYS_BASE ;
	char *argvs[32] ;

	int tamanho = strlen(nomeArquivo) ;
	topoPilha -= (tamanho+1) ;
	strlcpy(topoPilha, nomeArquivo, tamanho+1) ;
	argvs[i] = topoPilha ;
	i++ ;

	for (char *token = strtok_r(NULL, " ", savePtr) ; token != NULL ;
		 token = strtok_r(NULL, " ", savePtr))
	{
		int tamanho = strlen(token) ;
		topoPilha -= (tamanho+1) ;
		strlcpy(topoPilha, token, tamanho+1) ;
		argvs[i] = topoPilha ;
		i++ ;
		if (i == 32)
			goto fimFuncao ;
	}
	int argc = i ;

	int resto = (unsigned)topoPilha % 4 ;
	topoPilha -= resto ;

	topoPilha -= sizeof(char**) ;
	memset(topoPilha, 0, sizeof(char**)) ;

	for (i -= 1 ; i >= 0 ; i--)
	{
		topoPilha -= sizeof(char*) ;
		memcpy(topoPilha, argvs+i, sizeof(char*)) ;
	}

	void *baseArgv = topoPilha ;
	topoPilha -= sizeof(char**) ;
	memcpy(topoPilha, &baseArgv, sizeof(char**)) ;

	topoPilha -= sizeof(int) ;
	memcpy(topoPilha, &argc, sizeof(int)) ;

	topoPilha -= sizeof(void*) ;
	memset(topoPilha, 0, sizeof(void*)) ;

	*esp = topoPilha ;

	success = true ;

	fimFuncao:
	return success ;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
	struct thread *cur = thread_current() ;

	/* Verify that there's not already a page at that virtual
	 address, then map our page there. */
	if (pagedir_get_page(cur->pagedir, upage) == NULL)
	{
		if (pagedir_set_page(cur->pagedir, upage, kpage, writable))
		{
#ifdef VM
			frame_setDescritor(kpage, cur, upage) ;
#endif
			return true ;
		}
	}
	return false ;
}

void process_init(void)
{
	lock_init(&fileSysLock) ;
}

/*
 * Retorna o file* referente ao valor numérico fd. file* é uma struct do módulo filesys, que não
 * deve ficar sendo exposta para fora. As camadas de fora do filesys lidam com valores int fd,
 * que identificam um arquivoAberto do processo.
 */
static struct file *getDescritorArquivo(int fd)
{
	struct thread *cur = thread_current() ;

	for (struct list_elem *e = list_begin(&cur->arquivosAbertos) ; e != list_end(&cur->arquivosAbertos) ;
		 e = list_next(e))
	{
		struct arquivoAberto *arq = list_entry(e, struct arquivoAberto, elem) ;

		if (arq->fdNum == fd)
			return arq->f ;
	}

	return NULL ;
}

/*
 * Fecha todos os arquivo abertos do processo em execução, e da free nas structs arquivoAberto.
 * Chamada por thread_exit().
 */
void process_fecharArquivosAbertos(void)
{
	struct thread *cur = thread_current() ;

	for (struct list_elem *e = list_begin(&cur->arquivosAbertos) ; e != list_end(&cur->arquivosAbertos) ; )
	{
		struct arquivoAberto *arq = list_entry(e, struct arquivoAberto, elem) ;

		//lock_acquire(&fileSysLock) ;
		file_close(arq->f) ;
		//lock_release(&fileSysLock) ;

		e = list_remove(e) ;
		free(arq) ;
	}
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall create
 */
bool process_create(const char *file, unsigned initial_size)
{
	//lock_acquire(&fileSysLock) ;
	bool ret = filesys_create(file, initial_size) ;
	//lock_release(&fileSysLock) ;

	return ret ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall filesize
 */
int process_filesize(int fd)
{
	struct file *f = getDescritorArquivo(fd) ;

	if (f == NULL)
		return -1 ;
	if (inode_isDirectory(file_get_inode(f)))
		return -1 ;

	//lock_acquire(&fileSysLock) ;
	int ret = file_length(f) ;
	//lock_release(&fileSysLock) ;

	return ret ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall open
 */
int process_open(const char *file)
{
	struct thread *cur = thread_current() ;
	int fdNum ;

	//lock_acquire(&fileSysLock) ;
	struct file *f = filesys_open(file) ;
	if (f != NULL)
	{
		fdNum = cur->arquivosAbertosQuant + 2 ;
		cur->arquivosAbertosQuant++ ;
	}
	//lock_release(&fileSysLock) ;

	if (f == NULL)
		return -1 ;

	struct arquivoAberto *arq = malloc(sizeof(struct arquivoAberto)) ;
	arq->fdNum = fdNum ;
	arq->f = f ;
	list_push_front(&cur->arquivosAbertos, &arq->elem) ;

	return arq->fdNum ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall remove
 */
bool process_remove (const char *file)
{
	//lock_acquire(&fileSysLock) ;
	bool ret = filesys_remove(file) ;
	//lock_release(&fileSysLock) ;

	return ret ;
}

/*
 * Função interna do kernel que implementa funcionalidade da syscall close
 */
void process_close(int fd)
{
	struct thread *cur = thread_current() ;

	for (struct list_elem *e = list_begin(&cur->arquivosAbertos) ; e != list_end(&cur->arquivosAbertos) ;
		 e = list_next(e))
	{
		struct arquivoAberto *arq = list_entry(e, struct arquivoAberto, elem) ;
		if (arq->fdNum == fd)
		{
			//lock_acquire(&fileSysLock) ;
			file_close(arq->f) ;
			cur->arquivosAbertosQuant-- ;
			//lock_release(&fileSysLock) ;

			list_remove(e) ;
			free(arq) ;

			return ;
		}
	}
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall seek
 */
void process_seek (int fd, unsigned position)
{
	struct file *f = getDescritorArquivo(fd) ;

	if (f == NULL)
		return ;
	if (inode_isDirectory(file_get_inode(f)))
		return ;

	file_seek(f, position) ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall tell
 */
unsigned process_tell(int fd)
{
	struct file *f = getDescritorArquivo(fd) ;

	if (f == NULL)
		return 0 ;
	if (inode_isDirectory(file_get_inode(f)))
		return 0 ;

	return file_tell(f) ;
}

static int volatile aux ;

/*
 * Faz uma leitura do endereço uAddr para causar um page fault
 * em um momento seguro, caso uAddr seja um endereço inválido.
 */
static void validarRead(const void *uAddr)
{
	aux = *(char*)uAddr ;
}

/*
 * Faz uma escrita no endereço uAddr para causar um page fault
 * em um momento seguro, caso uAddr seja um endereço inválido
 */
static void validarWrite(void *uAddr)
{
	aux = *(char*)uAddr ;
	*(char*)uAddr = (char)aux ;
}

#ifndef VM

/*
 * Implementação das funções no projeto 2.
 */

/*
 * Função interna do kernel que implementa a funcionalidade da syscall write.
 * Função valida todo o intervalo de buffer a buffer+size antes de entrar
 * no código do filesys, pois um page fault dentro de um file_write() causa "resource leak".
 */
int process_write(int fd, const void *buffer, unsigned size)
{
	if (size < 1)
		return 0 ;

	if (pg_round_down(buffer) == pg_round_down(buffer+size))
	{
		validarRead(buffer) ;
	}
	else
	{
		if (size <= PGSIZE)
		{
			validarRead(buffer) ;
			validarRead(buffer+size) ;
		}
		else
		{
			void *pos = pg_round_down(buffer) ;
			void *pgLimite = pg_round_down(buffer+size) ;
			while (pos <= pgLimite)
			{
				validarRead(pos) ;
				pos += PGSIZE ;
			}
		}
	}

	if (fd == 1)
	{
		putbuf(buffer, size) ;
		return size ;
	}

	struct file *f = getDescritorArquivo(fd) ;
	if (f == NULL)
		return -1 ;
	if (inode_isDirectory(file_get_inode(f)))
		return -1 ;

	//lock_acquire(&fileSysLock) ;
	int ret = file_write(f, buffer, size) ;
	//lock_release(&fileSysLock) ;

	return ret ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall read.
 * Função valida todo o intervalo de buffer a buffer+size antes de entrar
 * no código do filesys, pois um page fault dentro de um file_read() causa "resource leak".
 */
int process_read(int fd, void *buffer, unsigned size)
{
	if (size < 1)
		return 0 ;

	if (pg_round_down(buffer) == pg_round_down(buffer+size))
	{
		validarWrite(buffer) ;
	}
	else
	{
		if (size <= PGSIZE)
		{
			validarWrite(buffer) ;
			validarWrite(buffer+size) ;
		}
		else
		{
			void *pos = pg_round_down(buffer) ;
			void *pgLimite = pg_round_down(buffer+size) ;
			while (pos <= pgLimite)
			{
				validarWrite(pos) ;
				pos += PGSIZE ;
			}
		}
	}

	if (fd == 0)
	{
		size_t cnt = size ;
		while (cnt > 0)
		{
			*(char*)buffer = input_getc() ;
			cnt -- ;
		}
		return size ;
	}

	struct file *f = getDescritorArquivo(fd) ;
	if (f == NULL)
		return -1 ;
	if (inode_isDirectory(file_get_inode(f)))
		return -1 ;

	//lock_acquire(&fileSysLock) ;
	int ret = file_read(f, buffer, size) ;
	//lock_release(&fileSysLock) ;

	return ret ;
}

#else

/*
 * Implementação das funções no projeto 3.
 */

/*
 * Função interna do kernel que implementa a funcionalidade da syscall write.
 * Função valida todo o intervalo de buffer a buffer+size antes de entrar
 * no código do filesys, pois um page fault dentro de um file_write() causa "resource leak".
 * Também seta a flag FRAME_PINNED do frame, para impedir que o frame leve swap-out durante a operação.
 */
int process_write(int fd, const void *buffer, unsigned size)
{
	if (size < 1)
		return 0 ;

	if (fd == STDIN_FILENO)
		return -1 ;

	struct file *f = NULL ;
	if (fd != STDOUT_FILENO)
	{
		f = getDescritorArquivo(fd) ;
		if (f == NULL)
			return -1 ;
	}

	if (f != NULL && inode_isDirectory(file_get_inode(f)))
		return -1 ;

	if (pg_round_down(buffer) == pg_round_down(buffer+size))
	{
		int ret ;
		validarRead(buffer) ;
		frame_pinUaddr(buffer) ;

		if (fd == STDOUT_FILENO)
		{
			putbuf(buffer, size) ;
			ret = size ;
		}
		else
		{
			//lock_acquire(&fileSysLock) ;
			ret = file_write(f, buffer, size) ;
			//lock_release(&fileSysLock) ;
		}

		frame_unpinUaddr(buffer) ;
		return ret ;
	}
	else
	{
		if (size <= PGSIZE)
		{
			int ret ;
			validarRead(buffer) ;
			validarRead(buffer+size) ;
			frame_pinUaddr(buffer) ;
			frame_pinUaddr(buffer+size) ;

			if (fd == STDOUT_FILENO)
			{
				putbuf(buffer, size) ;
				ret = size ;
			}
			else
			{
				//lock_acquire(&fileSysLock) ;
				ret = file_write(f, buffer, size) ;
				//lock_release(&fileSysLock) ;
			}

			frame_unpinUaddr(buffer) ;
			frame_unpinUaddr(buffer+size) ;
			return ret ;
		}
		else
		{
			unsigned ret ;
			size_t cnt = size ;
			validarRead(buffer) ;
			frame_pinUaddr(buffer) ;
			size_t bytes = pg_round_up(buffer) - buffer ;

			if (fd == STDOUT_FILENO)
			{
				putbuf(buffer, bytes) ;
				ret = bytes ;
			}
			else
			{
				//lock_acquire(&fileSysLock) ;
				ret = file_write(f, buffer, bytes) ;
				//lock_release(&fileSysLock) ;
			}

			frame_unpinUaddr(buffer) ;

			if (ret != bytes)
				return ret ;

			cnt -= bytes ;
			buffer += bytes ;

			while (cnt > 0)
			{
				unsigned ret ;
				size_t bytes ;
				if (cnt > PGSIZE)
					bytes = PGSIZE ;
				else
					bytes = cnt ;
				validarRead(buffer) ;
				frame_pinUaddr(buffer) ;

				if (fd == STDOUT_FILENO)
				{
					putbuf(buffer, bytes) ;
					ret = bytes ;
				}
				else
				{
					//lock_acquire(&fileSysLock) ;
					ret = file_write(f, buffer, bytes) ;
					//lock_release(&fileSysLock) ;
				}

				frame_unpinUaddr(buffer) ;

				if (ret != bytes)
				{
					return size - cnt + ret ;
				}

				cnt -= bytes ;
				buffer += bytes ;
			}

			if (cnt != 0)
				PANIC("cnt de process_write != 0") ;

			return size ;
		}
	}
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall read.
 * Função valida todo o intervalo de buffer a buffer+size antes de entrar
 * no código do filesys, pois um page fault dentro de um file_read() causa "resource leak".
 * Também seta a flag FRAME_PINNED do frame, para impedir que o frame leve swap-out durante a operação.
 */
int process_read(int fd, void *buffer, unsigned size)
{
	if (size < 1)
		return 0 ;

	if (fd == STDOUT_FILENO)
		return -1 ;

	struct file *f = NULL ;
	if (fd != STDIN_FILENO)
	{
		f = getDescritorArquivo(fd) ;
		if (f == NULL)
			return -1 ;
	}

	if (f != NULL && inode_isDirectory(file_get_inode(f)))
		return -1 ;

	if (pg_round_down(buffer) == pg_round_down(buffer+size))
	{
		int ret ;
		validarWrite(buffer) ;
		frame_pinUaddr(buffer) ;

		if (fd == STDIN_FILENO)
		{
			size_t cnt = size ;
			while (cnt > 0)
			{
				*(char*)buffer = input_getc() ;
				cnt-- ;
			}
			ret = size ;
		}
		else
		{
			//lock_acquire(&fileSysLock) ;
			ret = file_read(f, buffer, size) ;
			//lock_release(&fileSysLock) ;
		}

		frame_unpinUaddr(buffer) ;
		return ret ;
	}
	else
	{
		if (size <= PGSIZE)
		{
			int ret ;
			validarWrite(buffer) ;
			validarWrite(buffer+size) ;
			frame_pinUaddr(buffer) ;
			frame_pinUaddr(buffer+size) ;

			if (fd == STDIN_FILENO)
			{
				size_t cnt = size ;
				while (cnt > 0)
				{
					*(char*)buffer = input_getc() ;
					cnt-- ;
				}
				ret = size ;
			}
			else
			{
				//lock_acquire(&fileSysLock) ;
				ret = file_read(f, buffer, size) ;
				//lock_release(&fileSysLock) ;
			}

			frame_unpinUaddr(buffer) ;
			frame_unpinUaddr(buffer+size) ;
			return ret ;
		}
		else
		{
			unsigned ret ;
			size_t cnt = size ;
			validarWrite(buffer) ;
			frame_pinUaddr(buffer) ;
			size_t bytes = pg_round_up(buffer) - buffer ;

			if (fd == STDIN_FILENO)
			{
				size_t c = bytes ;
				while (c > 0)
				{
					*(char*)buffer = input_getc() ;
					c-- ;
				}
				ret = bytes ;
			}
			else
			{
				//lock_acquire(&fileSysLock) ;
				ret = file_read(f, buffer, bytes) ;
				//lock_release(&fileSysLock) ;
			}

			frame_unpinUaddr(buffer) ;

			if (ret != bytes)
				return ret ;

			cnt -= bytes ;
			buffer += bytes ;

			while (cnt > 0)
			{
				unsigned ret ;
				size_t bytes ;
				if (cnt > PGSIZE)
					bytes = PGSIZE ;
				else
					bytes = cnt ;
				validarWrite(buffer) ;
				frame_pinUaddr(buffer) ;

				if (fd == STDIN_FILENO)
				{
					size_t c = bytes ;
					while (c > 0)
					{
						*(char*)buffer = input_getc() ;
						c-- ;
					}
					ret = bytes ;
				}
				else
				{
					//lock_acquire(&fileSysLock) ;
					ret = file_read(f, buffer, bytes) ;
					//lock_release(&fileSysLock) ;
				}

				frame_unpinUaddr(buffer) ;

				if (ret != bytes)
				{
					return size - cnt + ret ;
				}

				cnt -= bytes ;
				buffer += bytes ;
			}

			if (cnt != 0)
				PANIC("cnt de process_read != 0") ;

			return size ;
		}
	}
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall mmap.
 */
mapid_t process_mmap(int fd, void *addr)
{
	if (fd == 0 || fd == 1
		|| addr == 0 || pg_ofs(addr) != 0)
	{
		return MAP_FAILED ;
	}

	int size = process_filesize(fd) ;
	if (size == -1 || size == 0)
	{
		return MAP_FAILED ;
	}

	struct thread *cur = thread_current() ;

	//lock_acquire(&fileSysLock) ;
	struct file *f = file_reopen(getDescritorArquivo(fd)) ;
	//lock_release(&fileSysLock) ;

	for (void *upage = addr ;
		 upage <= addr + size ;
		 upage += PGSIZE)
	{
		uint32_t *pte = pagedir_lookup_page(pagedir_active_pd(), upage, false) ;

		if (pte != NULL && *pte != 0)
			return MAP_FAILED ;
	}

	mapid_t mid = cur->mapeamentosQuant + 1 ;
	cur->mapeamentosQuant++ ;
	struct mapeamentoArquivo *arq = malloc(sizeof(struct mapeamentoArquivo)) ;
	arq->mid = mid ;
	arq->f = f ;
	arq->off = 0 ;
	arq->startAddr = addr ;
	arq->endAddr = addr + size ;

	for (void *upage = addr ;
		 upage <= addr + size ;
		 upage += PGSIZE)
	{
		uint32_t *pte = pagedir_lookup_page(pagedir_active_pd(), upage, true) ;

		*pte = (mid << PTE_SHIFT_FLAGS) ;
		*pte |= (PTE_U | PTE_W | PTE_M) ;
	}

	list_push_back(&cur->mapeamentos, &arq->elem) ;

	return mid ;
}

/*
 * Função interna do kernel que implementa a funcionalidade da syscall munmap.
 */
void process_munmap(mapid_t mid)
{
	struct mapeamentoArquivo *arq = process_getMapArqCur(mid) ;

	if (arq == NULL || arq->f == thread_current()->executavel)
		return ;

	struct thread *cur = thread_current() ;

	lock_acquire(&cur->pageTableLock) ;

	for (void *upage = arq->startAddr ;
		 upage <= arq->endAddr ;
		 upage += PGSIZE)
	{
		uint32_t *pte = pagedir_lookup_page(pagedir_active_pd(), upage, false) ;
		void *kernelAddr = pagedir_get_page(cur->pagedir, upage) ;

		if ((*pte & PTE_D) != 0)
		{
			*pte &= ~PTE_D ;
			file_write_at_semExtend(arq->f, kernelAddr, PGSIZE, arq->off + upage - arq->startAddr) ;
			lock_release(&cur->pageTableLock) ;
			palloc_free_page(kernelAddr) ;
			lock_acquire(&cur->pageTableLock) ;
			*pte = 0 ;
		}
		else
		{
			lock_release(&cur->pageTableLock) ;
			palloc_free_page(kernelAddr) ;
			lock_acquire(&cur->pageTableLock) ;
			*pte = 0 ;
		}
	}

	lock_release(&cur->pageTableLock) ;

	list_remove(&arq->elem) ;

	//lock_acquire(&fileSysLock) ;
	file_close(arq->f) ;
	//lock_release(&fileSysLock) ;

	free(arq) ;
}

/*
 * Retorna o mapeamentoArquivo* identificado por mid do processo em execução.
 */
struct mapeamentoArquivo *process_getMapArqCur(mapid_t mid)
{
	struct thread *cur = thread_current() ;

	for (struct list_elem *e = list_begin(&cur->mapeamentos) ; e != list_end(&cur->mapeamentos) ;
		 e = list_next(e))
	{
		struct mapeamentoArquivo *arq = list_entry(e, struct mapeamentoArquivo, elem) ;

		if (arq->mid == mid)
			return arq ;
	}

	return NULL ;
}

/*
 * Retorna o mapeamentoArquivo* que possui o endereço uAddr, do processo t.
 * Processo t pode ser qualquer processo, em execução ou não.
 */
struct mapeamentoArquivo *process_getMapArqAddr(struct thread *t, void *uAddr)
{
	for (struct list_elem *e = list_begin(&t->mapeamentos) ; e != list_end(&t->mapeamentos) ;
		 e = list_next(e))
	{
		struct mapeamentoArquivo *arq = list_entry(e, struct mapeamentoArquivo, elem) ;

		if (arq->startAddr <= uAddr && arq->endAddr >= uAddr)
			return arq ;
	}

	return NULL ;
}

/*
 * Desmapeia e retorna memória referente a todos os mapeamentos do processo.
 * Função chamada por thread_exit().
 */
void process_desmapearTodos(void)
{
	struct thread *cur = thread_current() ;

	for (struct list_elem *e = list_begin(&cur->mapeamentos) ; e != list_end(&cur->mapeamentos) ; )
	{
		struct mapeamentoArquivo *arq = list_entry(e, struct mapeamentoArquivo, elem) ;

		if (arq->f == cur->executavel)
			goto fim ;

		lock_acquire(&cur->pageTableLock) ;

		for (void *upage = arq->startAddr ;
			 upage <= arq->endAddr ;
			 upage += PGSIZE)
		{
			uint32_t *pte = pagedir_lookup_page(pagedir_active_pd(), upage, false) ;
			void *kernelAddr = pagedir_get_page(cur->pagedir, upage) ;

			if ((*pte & PTE_D) != 0)
			{
				*pte &= ~PTE_D ;
				file_write_at_semExtend(arq->f, kernelAddr, PGSIZE, arq->off + (upage - arq->startAddr)) ;
				lock_release(&cur->pageTableLock) ;
				palloc_free_page(kernelAddr) ;
				lock_acquire(&cur->pageTableLock) ;
				*pte = 0 ;
			}
			else
			{
				lock_release(&cur->pageTableLock) ;
				palloc_free_page(kernelAddr) ;
				lock_acquire(&cur->pageTableLock) ;
				*pte = 0 ;
			}
		}

		lock_release(&cur->pageTableLock) ;

		//lock_acquire(&fileSysLock) ;
		file_close(arq->f) ;
		//lock_release(&fileSysLock) ;

	fim:
		e = list_remove(&arq->elem) ;
		free(arq) ;
	}
}

/*
 * Aloca uma nova página e mapeia no endereço uAddr.
 * Função chamada pelo page fault handler caso a heuristica decida que a pilha do
 * processo deve crescer.
 */
void *process_crescerPilha(void *uAddr)
{
	void *kpage = palloc_get_page(PAL_USER) ;
	if (kpage == NULL)
		return NULL ;

	struct thread *cur = thread_current() ;

	if (pagedir_set_page(cur->pagedir, pg_round_down(uAddr), kpage, true))
		return kpage ;
	else
		return NULL ;
}

#endif

#ifdef FILESYS


bool process_chdir(const char *dir)
{
	char *resto ;
	struct dir *d = dir_processarCaminho(dir, &resto, NULL) ;
	if (d == NULL)
		return false ;

	if (resto == NULL)
	{
		dir_close(thread_current()->currentDir) ;
		thread_current()->currentDir = d ;
	}
	else
		free(resto) ;

	return resto == NULL ;
}


bool process_mkdir(const char *dir)
{
	struct thread *cur = thread_current() ;
	struct inode *ind ;
	bool sucesso = false ;
	struct dir *d ;
	char *resto ;

	d = dir_processarCaminho(dir, &resto, NULL) ;
	if (d == NULL)
		return false ;

	if (resto == NULL)
		goto saida ;

	if (!dir_lookup(d, resto, &ind))
	{
		block_sector_t b ;
		if (!free_map_allocate(1, &b))
			goto saida ;

		if (!dir_create(b, 0))
			goto saida ;

		char buf[512] ;
		memset(buf, 0 , 512) ;

		sucesso = dir_add(d, resto, b) ;
		if (!sucesso)
			goto saida ;

		struct dir *novoDir = dir_open(inode_open(b)) ;
		sucesso = dir_add(novoDir, ".", b) ;
		if (sucesso)
			sucesso = dir_add(novoDir, "..", inode_getSector(d->inode)) ;
		dir_close(novoDir) ;

		/*printf("\n=========\n") ;
		inode_read_at(d->inode, buf, 512, 0) ;
		hex_dump(0, buf, 512, true) ;*/
	}

saida:
	if (d != cur->currentDir)
		dir_close(d) ;
	free(resto) ;

	return sucesso ;
}


bool process_isdir(int fd)
{
	struct file *f = getDescritorArquivo(fd) ;
	if (f == NULL)
		return false ;

	return inode_isDirectory(file_get_inode(f)) ;
}


int process_inumber(int fd)
{
	struct file *f = getDescritorArquivo(fd) ;
	if (f == NULL)
		return false ;

	return inode_get_inumber(file_get_inode(f)) ;
}


bool process_readdir(int fd, char *name)
{
	struct file *f = getDescritorArquivo(fd) ;
	if (f == NULL)
		return false ;

	if (!inode_isDirectory(file_get_inode(f)))
		return false ;

	char n[READDIR_MAX_LEN + 1] ;
	while (dir_readdir((struct dir*)f, n))
	{
		if (strcmp(n, ".") == 0
			|| strcmp(n, "..") == 0)
		{
			continue ;
		}
		else
		{
			strlcpy(name, n, READDIR_MAX_LEN + 1) ;
			return true ;
		}
	}

	return false ;
}


#endif
