#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "vm/swap.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include <stdio.h>

#define MIN_PILHA (PHYS_BASE - (1024 * 1024 * 8))

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
	bool not_present ; /* True: not-present page, false: writing r/o page. */
	bool write ; /* True: access was write, false: access was read. */
	bool user ; /* True: access by user, false: access by kernel. */
	void *fault_addr ; /* Fault address. */

	/* Obtain faulting address, the virtual address that was
	 accessed to cause the fault.  It may point to code or to
	 data.  It is not necessarily the address of the instruction
	 that caused the fault (that's f->eip).
	 See [IA32-v2a] "MOV--Move to/from Control Registers" and
	 [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
	 (#PF)". */
	asm ("movl %%cr2, %0" : "=r" (fault_addr)) ;

	/* Turn interrupts back on (they were only off so that we could
	 be assured of reading CR2 before it changed). */
	intr_enable() ;

	/* Count page faults. */
	page_fault_cnt++ ;

#ifndef VM
	/*
	 * Page fault em builds antes do projeto 3 significa erro do processo
	 */
	thread_exit() ;

#else
	/*
	 * Page fault handler a partir do projeto 3
	 */

	not_present = (f->error_code & PF_P) == 0 ;
	write = (f->error_code & PF_W) != 0 ;
	user = (f->error_code & PF_U) != 0 ;

	if (user && !is_user_vaddr(fault_addr))
		thread_exit() ;

	uint32_t *pte ;
	int distanciaPilha ;
	void *kpage ;
	struct thread *cur = thread_current() ;

	if (is_user_vaddr(fault_addr) && cur->espUsuario != NULL)
		distanciaPilha = cur->espUsuario - fault_addr ;
	else
		distanciaPilha = f->esp - fault_addr ;

	lock_acquire(&cur->pageTableLock) ;

	if (distanciaPilha <= 32)
		pte = pagedir_lookup_page(pagedir_active_pd(), fault_addr, true) ;
	else
		pte = pagedir_lookup_page(pagedir_active_pd(), fault_addr, false) ;

	if (pte == NULL)
		goto saidaErro ;
	else if (*pte == 0 && (distanciaPilha > 32 || fault_addr < MIN_PILHA))
		goto saidaErro ;

	if (*pte == 0 && distanciaPilha <= 32)
	{
		kpage = process_crescerPilha(fault_addr) ;
		if (kpage == NULL)
			PANIC("Crescer pilha do processo %s endereço %p falhou",
				   thread_current()->name, fault_addr) ;
		else
			goto saidaSucesso ;
	}

	if (write && ((*pte & PTE_W) == 0))
		goto saidaErro ;

	if ((*pte & PTE_S) != 0)
	{
		kpage = palloc_get_page(PAL_USER) ;
		size_t idx = (*pte >> PTE_SHIFT_FLAGS) ;
		swap_swapIn(idx, kpage) ;
		*pte &= ~PTE_ADDR ;
		*pte |= vtop(kpage) ;
		*pte &= ~PTE_S ;
		*pte &= ~PTE_D ;
		*pte |= PTE_P ;
		goto saidaSucesso ;
	}

	if ((*pte & PTE_M) != 0)
	{
		struct mapeamentoArquivo *arq ;
		mapid_t mid = (*pte >> PTE_SHIFT_FLAGS) ;

		if (mid == 0)
		{
			/*
			 * Página zerada. Zerar bit PTE_M pois isso é página de dados.
			 */
			kpage = palloc_get_page(PAL_USER | PAL_ZERO) ;
			*pte &= ~PTE_M ;
			goto atualizarPTE ;
		}
		else
			arq = process_getMapArqCur(mid) ;

		off_t readBytes ;
		if (arq->endAddr - pg_round_down(fault_addr) >= PGSIZE)
			readBytes = PGSIZE ;
		else
			readBytes = arq->endAddr - pg_round_down(fault_addr) ;

		/*
		 * Se readBytes < PGSIZE necessário página zerada
		 */
		if (readBytes < PGSIZE)
		{
			kpage = palloc_get_page(PAL_USER | PAL_ZERO) ;

			/*
			 * Se f->eip == fault_addr o page fault foi causado por um acesso a
			 * ultima página do segmento de código do executável. Lê do executavel
			 * readBytes e escreve na página previamente zerada. O mapeamento ao
			 * arquivo continua.
			 *
			 * Se f->eip != fault_addr o page fault foi causado por
			 * um acesso no segmento de dados em uma página não alocada ainda. Lê
			 * do executavel readBytes e o mapeamento deve ser removido. Explicação
			 * mais detalhada em load_segment() em process.c
			 */
			if (f->eip != fault_addr)
			{
				arq->endAddr -= readBytes ;
				*pte &= ~PTE_M ;
			}
		}
		else
			kpage = palloc_get_page(PAL_USER) ;

		off_t offsetMapeamento = pg_round_down(fault_addr) - arq->startAddr ;
		file_read_at(arq->f, kpage, readBytes , arq->off + offsetMapeamento) ;

	atualizarPTE:
		*pte &= ~PTE_ADDR ;
		*pte |= vtop(kpage) ;
		*pte &= ~PTE_D ;
		*pte |= PTE_P ;
		goto saidaSucesso ;
	}

	printf("Page fault at %p: %s error %s page in %s context.\n",
			fault_addr,
			not_present ? "not present" : "rights violation",
			write ? "writing" : "reading",
			user ? "user" : "kernel") ;
	intr_dump_frame(f) ;

	PANIC("Page fault nao identificado") ;

saidaErro:
	lock_release(&cur->pageTableLock) ;
	thread_exit() ;

saidaSucesso:
	pagedir_invalidate_pd(thread_current()->pagedir) ;
	lock_release(&cur->pageTableLock) ;
	frame_setDescritor(kpage, thread_current(), pg_round_down(fault_addr)) ;

#endif
}

