#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/fixed-point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#ifdef FILESYS
#include "filesys/directory.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list ;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/*
 *  Lista de threads bloqueadas por um intervalo de tempo. Threads que
 *  chamaram timer_sleep(ticks) são encadeadas aqui.
 */
static struct list listaBloqueadosTimer ;

/*
 * Variaveis necessárias para o advanced scheduler
 */
static int readyThreads = 0 ;
static int64_t loadAvg = 0 ;


static void kernel_thread(thread_func *, void *aux) ;
static void idle(void *aux UNUSED) ;
static struct thread *running_thread(void) ;
static struct thread *next_thread_to_run(void) ;
static void init_thread(struct thread *, const char *name, int priority) ;
static bool is_thread(struct thread *) UNUSED ;
static void *alloc_frame(struct thread *, size_t size) ;
static void schedule(void) ;
void thread_schedule_tail(struct thread *prev) ;
static tid_t allocate_tid(void) ;
static int getPrioridadeCabecaFilaProntos(void) ;
static void atualizarPrioridade(struct thread *t) ;
static void checarAtualizarPrioridade(struct thread *t, void *aux) ;
static void atualizarPosicaoReadyList(struct thread *t) ;

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
	ASSERT(intr_get_level() == INTR_OFF) ;

	lock_init(&tid_lock) ;
	list_init(&ready_list) ;
	list_init(&all_list) ;
	list_init(&listaBloqueadosTimer) ;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread() ;
	init_thread(initial_thread, "main", PRI_DEFAULT) ;
	initial_thread->status = THREAD_RUNNING ;
	initial_thread->tid = allocate_tid() ;
	initial_thread->nice = 0 ;
	initial_thread->recentCpu = 0 ;
	initial_thread->recentCpuFlag = 0 ;

#ifdef USERPROG
	list_init(&initial_thread->statusFilhos) ;
	list_init(&initial_thread->arquivosAbertos) ;
#endif

#ifdef VM
	lock_init(&initial_thread->pageTableLock) ;
	list_init(&initial_thread->mapeamentos) ;
#endif

#ifdef FILESYS
	initial_thread->currentDir = NULL ;
#endif
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
	#ifdef USERPROG
	else if (t->pagedir != NULL)
		user_ticks++;
	#endif
	else
		kernel_ticks++;

	if (t != idle_thread)
	{
		t->recentCpu = addFixedPoint64Int(t->recentCpu, 1) ;
		t->recentCpuFlag = 1 ;
	}

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
	{
		if (thread_mlfqs)
			thread_foreach(checarAtualizarPrioridade, NULL) ;

		if (getPrioridadeCabecaFilaProntos() >= thread_getPrioridade(t))
			intr_yield_on_return() ;
	}
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority) ;
  tid = t->tid = allocate_tid() ;

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  t->nice = thread_current()->nice ;
  t->recentCpu = thread_current()->recentCpu ;

#ifdef USERPROG
	list_init(&t->statusFilhos) ;
	list_init(&t->arquivosAbertos) ;
	t->arquivosAbertosQuant = 0 ;
	struct statusFilho *s = malloc(sizeof(struct statusFilho)) ;
	s->flags = 0 ;
	s->status = 0 ;
	lock_init(&s->lock) ;
	sema_init(&s->semaphore, 0) ;
	s->tid = t->tid ;
	list_push_back(&thread_current()->statusFilhos, &s->elem) ;
	t->meuStatus = s ;
#endif

#ifdef VM
	lock_init(&t->pageTableLock) ;
	t->espUsuario = NULL ;
	list_init(&t->mapeamentos) ;
	t->mapeamentosQuant = 0 ;
#endif

#ifdef FILESYS
	if (thread_current()->currentDir != NULL)
		t->currentDir = dir_reopen(thread_current()->currentDir) ;
#endif

  /* Add to run queue. */
  thread_unblock (t);
  thread_checarPreempt(t, thread_current()) ;

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
	ASSERT (!intr_context());
	ASSERT (intr_get_level() == INTR_OFF);

	struct thread *t = thread_current() ;
	t->status = THREAD_BLOCKED ;
	if (t != idle_thread)
		readyThreads-- ;

	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
	enum intr_level old_level;

	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_BLOCKED);

	old_level = intr_disable ();

	if (thread_mlfqs)
		atualizarPrioridade(t) ;

	t->status = THREAD_READY ;
	list_insert_ordered(&ready_list, &t->elem, thread_compararPrioridadeMaior, 0) ;
	readyThreads++ ;

	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
	ASSERT(!intr_context()) ;

	struct thread *cur = thread_current() ;

#ifdef VM
	process_desmapearTodos() ;
#endif

#ifdef FILESYS
	dir_close(cur->currentDir) ;
#endif

#ifdef USERPROG
	struct statusFilho *s = cur->meuStatus ;

	if (cur == initial_thread)
		goto pularInformarPai ;

	lock_acquire(&s->lock) ;
	if ((s->flags & STATUS_FLAG_EXIT_CHAMADO) == 0)
	{
		s->status = STATUS_TERMINADO_KERNEL ;
		s->flags |= STATUS_FLAG_EXIT_CHAMADO ;
	}
	printf("%s: exit(%d)\n", cur->name, cur->meuStatus->status) ;

	if ((s->flags & STATUS_FLAG_PAI_FINALIZADO) != 0)
	{
		lock_release(&s->lock) ;
		free(s) ;
	}
	else
	{
		lock_release(&s->lock) ;
		sema_up(&s->semaphore) ;
	}

	pularInformarPai:

	for (struct list_elem *e = list_begin(&cur->statusFilhos) ; e != list_end(&cur->statusFilhos) ; )
	{
		struct statusFilho *s = list_entry(e, struct statusFilho, elem) ;

		lock_acquire(&s->lock) ;
		if ((s->flags & STATUS_FLAG_EXIT_CHAMADO) != 0)
		{
			e = list_remove(e) ;
			lock_release(&s->lock) ;
			free(s) ;
		}
		else
		{
			s->flags |= STATUS_FLAG_PAI_FINALIZADO ;
			e = list_remove(e) ;
			lock_release(&s->lock) ;
		}
	}

	process_fecharArquivosAbertos() ;
	process_exit () ;
#endif

	/* Remove thread from all threads list, set our status to dying,
	 and schedule another process.  That process will destroy us
	 when it calls thread_schedule_tail(). */
	intr_disable() ;

	list_remove(&cur->allelem) ;
	cur->status = THREAD_DYING ;
	readyThreads-- ;

	schedule() ;
	NOT_REACHED() ;
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
	struct thread *cur = thread_current() ;
	enum intr_level old_level ;

	ASSERT(!intr_context()) ;

	old_level = intr_disable() ;

	cur->status = THREAD_READY ;
	if (cur != idle_thread)
		list_insert_ordered(&ready_list, &cur->elem, thread_compararPrioridadeMaior, 0) ;

	schedule() ;

	intr_set_level(old_level) ;
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
	struct thread *t = thread_current() ;
	t->priority = new_priority ;

	if (getPrioridadeCabecaFilaProntos() > thread_getPrioridade(t))
		thread_yield() ;
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
	return thread_getPrioridade(thread_current()) ;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice)
{
	struct thread *t = thread_current() ;
	t->nice = nice ;
	atualizarPrioridade(t) ;

	if (getPrioridadeCabecaFilaProntos() > thread_getPrioridade(t))
		thread_yield() ;
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
	return thread_current()->nice ;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
	return fixedPoint64ToIntNearest(multFixedPoint64Int(loadAvg, 100)) ;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
	struct thread *t = thread_current() ;
	return fixedPoint64ToIntNearest(multFixedPoint64Int(t->recentCpu, 100)) ;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL) ;
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX) ;
	ASSERT(name != NULL) ;

	memset(t, 0, sizeof *t) ;
	t->status = THREAD_BLOCKED ;
	strlcpy(t->name, name, sizeof t->name) ;
#ifdef USERPROG
	char *savePtr ;
	strtok_r(t->name, " ", &savePtr) ;
#endif
	t->stack = (uint8_t *) t + PGSIZE ;
	t->priority = priority ;
	t->nice = 0 ;
	t->recentCpu = 0 ;
	t->recentCpuFlag = 0 ;
	t->prioridadeEmprestadaMax = NULL ;
	t->bloqueadoPor = NULL ;
	list_init(&t->prioridadesEmprestadas) ;
	t->magic = THREAD_MAGIC ;
	list_push_back(&all_list, &t->allelem) ;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem) ;
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule(void)
{
	struct thread *cur = running_thread() ;
	struct thread *next = next_thread_to_run() ;
	struct thread *prev = NULL ;

	ASSERT(intr_get_level() == INTR_OFF) ;
	ASSERT(cur->status != THREAD_RUNNING) ;
	ASSERT(is_thread(next)) ;

	if (cur != next)
	{
		prev = switch_threads(cur, next) ;
	}
	thread_schedule_tail(prev) ;
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

void thread_sleep(int64_t timerAcordar)
{
	struct thread *cur = thread_current() ;
	enum intr_level old_level ;

	ASSERT(!intr_context()) ;

	old_level = intr_disable() ;

	cur->timerTicks = timerAcordar ;
	list_push_back(&listaBloqueadosTimer, &cur->elem) ;
	thread_block() ;

	intr_set_level(old_level) ;
}

/*
 * função chamada em todo timer interrupt. Itera sobre a listaBloqueadosTimer comparando
 * o valor do timerAgora com o instante em que a thread deve voltar para a ready_list, e a desbloqueia caso
 * o instante já tenha acontecido ou seja agora.
 */
void thread_checarTimers(int64_t timerAgora)
{
	for (struct list_elem *e = list_begin(&listaBloqueadosTimer) ; e != list_end(&listaBloqueadosTimer) ; )
	{
		struct thread *t = list_entry(e, struct thread, elem) ;
		if (timerAgora >= t->timerTicks)
		{
			e = list_remove(e) ;
			thread_unblock(t) ;
		}
		else
			e = list_next(e) ;
	}
}

/*
 * Retorna a prioridade da thread na cabeça da ready_list, que está sempre ordenada.
 * Função interna usada para decidir se a thread em execução deve chamar thread_yield().
 */
static int getPrioridadeCabecaFilaProntos(void)
{
	if (list_empty(&ready_list))
		return PRI_MIN ;
	else
		return thread_getPrioridade(list_entry(list_front(&ready_list), struct thread, elem)) ;
}

/*
 * Retorna a prioridade da thread t, levando em conta a possível existência de doação de prioridades.
 */
int thread_getPrioridade(struct thread *t)
{
	if (t->prioridadeEmprestadaMax == NULL)
		return t->priority ;
	else
		return t->prioridadeEmprestadaMax->prio ;
}

/*
 * Funçao é um list_less_func usada no list.h nas operações de ordenação.
 * Retorna true se o A vem antes que B, falso se A é vem depois ou é igual a B.
 * Como uma thread com prioridade maior deve vir antes, a comparação "parece" estar invertida.
 */
bool thread_compararPrioridadeMaior(const struct list_elem *a,
						       	    const struct list_elem *b,
								    void *aux UNUSED)
{
	struct thread *ta = list_entry(a, struct thread, elem) ;
	struct thread *tb = list_entry(b, struct thread, elem) ;

	return thread_getPrioridade(ta) > thread_getPrioridade(tb) ;
}

bool thread_compararPrioridadeMaiorIgual(const struct list_elem *a,
										 const struct list_elem *b,
										 void *aux UNUSED)
{
	struct thread *ta = list_entry(a, struct thread, elem) ;
	struct thread *tb = list_entry(b, struct thread, elem) ;

	return thread_getPrioridade(ta) >= thread_getPrioridade(tb) ;
}

/*
 * Função chamada dentro de um lock_sema_down(). Checa se a prioridade da t1 é maior que a prioridade da t2,
 * e caso seja, cria uma doação de prioridade para a t2.
 */
void thread_checarEmprestarPrioridade(struct thread *t1, struct thread *t2, struct lock *lock)
{
	if (thread_getPrioridade(t1) > thread_getPrioridade(t2))
	{
		struct prioridadeEmprestada *p = malloc(sizeof(struct prioridadeEmprestada)) ;
		p->prio = thread_getPrioridade(t1) ;
		p->lock = lock ;
		list_push_front(&t2->prioridadesEmprestadas, &p->elem) ;
		t2->prioridadeEmprestadaMax = p ;

		if (t2->bloqueadoPor != NULL)
		{
			thread_checarEmprestarPrioridade(t2, t2->bloqueadoPor->holder, t2->bloqueadoPor) ;
		}
		else if (t2->status == THREAD_READY)
		{
			atualizarPosicaoReadyList(t2) ;
		}
	}
}

/*
 * Função chamada dentro de um lock_sema_up(). Checa se existem doações de prioridades referentes ao
 * lock que está prestes a ser liberado, e caso exista, remove-as.
 */
void thread_checarPrioridadesEmprestadas(struct lock *lock)
{
	struct thread *t = lock->holder ;

	for (struct list_elem *e = list_begin(&t->prioridadesEmprestadas) ; e != list_end(&t->prioridadesEmprestadas) ; )
	{
		struct prioridadeEmprestada *p = list_entry(e, struct prioridadeEmprestada, elem) ;
		if (p->lock == lock)
		{
			e = list_remove(e) ;
			if (p == t->prioridadeEmprestadaMax)
				t->prioridadeEmprestadaMax = NULL ;
			free(p) ;
		}
		else
			e = list_next(e) ;
	}

	if (t->prioridadeEmprestadaMax == NULL)
	{
		/*
		 * o lock que será devolvido é o lock que fornecia a prioridadeEmprestadaMax.
		 */
		if (!list_empty(&t->prioridadesEmprestadas))
		{
			t->prioridadeEmprestadaMax = list_entry(list_front(&t->prioridadesEmprestadas),
													struct prioridadeEmprestada, elem) ;
		}
		if (t->status == THREAD_READY)
			atualizarPosicaoReadyList(t) ;
	}
}

/*
 * Função checa se uma thread recém desbloqueada tem prioridade maior que a thread em execução, e caso tenha, chama thread_yield().
 * Função é chamada sempre que uma thread chama thread_unblock() fora de um interrupt handler. Isso acontece em diferentes partes do sistema.
 */
void thread_checarPreempt(struct thread *threadDesbloqueada, struct thread *current)
{
	if (thread_getPrioridade(threadDesbloqueada) > thread_getPrioridade(current))
		thread_yield() ;
}

/*
 * Função chamada sempre em um timer interrupt múltiplo de segundo. Faz todos os cálculos referentes ao advanced scheduler.
 */
void thread_timerInterruptSegundo(void)
{
	/*
	 * load_avg = (59/60)*load_avg + (1/60)*ready_threads
	 */
	int x = intToFixedPoint(59) ;
	int fracao = divFixedPointInt(x, 60) ;
	int64_t aux1 = multFixedPoint64(fracao, loadAvg) ;
	x = intToFixedPoint(1) ;
	fracao = divFixedPointInt(x, 60) ;
	int aux2 = multFixedPointInt(fracao, readyThreads) ;
	loadAvg = aux1 + aux2 ;

	for (struct list_elem *e = list_begin(&all_list) ; e != list_end(&all_list) ;
		 e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, allelem) ;
		/*
		 * recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice
		 */
		int64_t aux1 = multFixedPoint64Int(loadAvg, 2) ;
		int64_t aux2 = addFixedPoint64Int(aux1, 1) ;
		aux1 = divFixedPoint64(aux1, aux2) ;
		aux1 = multFixedPoint64(aux1, t->recentCpu) ;
		aux1 = addFixedPoint64Int(aux1, t->nice) ;

		if (aux1 != t->recentCpu)
		{
			t->recentCpu = aux1 ;
			t->recentCpuFlag = 1 ;
		}
	}
}

/*
 * Função chamada sempre que uma thread tem o valor de sua prioridade alterado. Isso mantém a ready_list sempre ordenada.
 */
static void atualizarPosicaoReadyList(struct thread *t)
{
	list_remove(&t->elem) ;
	list_insert_ordered(&ready_list, &t->elem, thread_compararPrioridadeMaior, NULL) ;
}

/*
 * Função chamada pelo timer interrupt handler. Atualiza o valor da prioridade de uma thread que teve o valor recent_cpu alterado.
 */
static void checarAtualizarPrioridade(struct thread *t, void *aux UNUSED)
{
	if (t->recentCpuFlag)
	{
		atualizarPrioridade(t) ;
		t->recentCpuFlag = 0 ;
		if (t->status == THREAD_READY)
			atualizarPosicaoReadyList(t) ;
	}
}

/*
 * Realiza os calculos referentes ao valor da prioridade da thread t.
 */
static void atualizarPrioridade(struct thread *t)
{
	/*
	 * priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
	 */
	int64_t aux1 = divFixedPoint64Int(t->recentCpu, 4) ;
	t->priority = PRI_MAX - fixedPoint64ToIntNearest(aux1) - (t->nice * 2) ;

	if (t->priority < PRI_MIN)
		t->priority = PRI_MIN ;
	else if (t->priority > PRI_MAX)
		t->priority = PRI_MAX ;
}

#ifdef FILESYS
void thread_setRootInit()
{
	initial_thread->currentDir = dir_open_root() ;
}
#endif
