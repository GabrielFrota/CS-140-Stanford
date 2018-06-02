#include "frame.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "vm/swap.h"
#include <stdio.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "stdio.h"
#include "userprog/process.h"
#include "filesys/file.h"

/*
 * array de descritores
 */
static struct frame *frames ;

/*
 * lock do ponteiro do relogio
 */
static struct lock lockContadorClockAlg ;

/*
 * ponteiro do relógio do clock algorithm
 */
static int contadorClockAlgorithm = 0 ;


void frame_init(void)
{
	frames = malloc(sizeof(struct frame) * user_pages) ;
	if (frames == NULL)
		PANIC("Malloc do array frames retornou NULL") ;

	lock_init(&lockContadorClockAlg) ;

	for (unsigned i = 0 ; i < user_pages ; i++)
	{
		lock_init(&frames[i].lock) ;
		frames[i].t = NULL ;
		frames[i].uAddr = NULL ;
	}
}

/*
 * Relaciona o descritor da pagina física referente ao endereço kpage,
 * ao endereço virtual uAddr do processo t. Isso significa que
 * essa página foi alocada ao processo t e está mapeada no endereço uAddr.
 */
void frame_setDescritor(void *kpage, struct thread *t, void *uAddr)
{
	ASSERT(kpage != NULL) ;
	ASSERT(uAddr != NULL) ;
	ASSERT(pg_ofs(kpage) == 0) ;
	ASSERT(pg_ofs(uAddr) == 0) ;

	int i = vtop(kpage) / PGSIZE - kernel_pages - 256 ;

	lock_acquire(&frames[i].lock) ;
	frames[i].t = t ;
	frames[i].uAddr = uAddr ;
	lock_release(&frames[i].lock) ;
}

/*
 * Limpa os campos do descritor. Função chamada por palloc_free_page() ao desalocar uma página.
 * Muito cuidado ao chamar palloc_free_page() sobre possíveis deadlocks, pois palloc_free_page()
 * irá tentar pegar o lock do descritor sendo desalocado. Em alguns momentos do código
 * frame_clearDescritor() é chamado em um trecho aonde se tem o thread_current()->pageTableLock, e o
 * thread_current()->pageTableLock sempre é devolvido antes de entrar aqui. Parece um código bobo
 * mas é para evitar um possivel deadlock entre o pageTableLock e o frame->lock. Processo Q
 * tem Q->pageTableLock e foi tirado de execução. Processo P está dentro de frame_freeFrames(), pegou
 * o frame->lock e foi bloqueado ao tentar pegar Q->pageTableLock. Processo Q volta para execução
 * e chama frame_clearDescritor(), e será bloqueado ao tentar pegar o frame->lock já possuído por P,
 * que está bloqueado esperando Q->pageTableLock.
 */
void frame_clearDescritor(void *kpage)
{
	ASSERT(pg_ofs(kpage) == 0) ;

	int i = vtop(kpage) / PGSIZE - kernel_pages - 256 ;

	lock_acquire(&frames[i].lock) ;
	frames[i].t = NULL ;
	frames[i].uAddr = NULL ;
	lock_release(&frames[i].lock) ;
}

/*
 * Trava o descritor referente ao endereço uAddr do processo em execução.
 */
void frame_pinUaddr(const void *uAddr)
{
	void *kAddr = pagedir_get_page(thread_current()->pagedir, uAddr) ;

	ASSERT(kAddr != NULL) ;

	int i = vtop(pg_round_down(kAddr)) / PGSIZE - kernel_pages - 256 ;
	lock_acquire(&frames[i].lock) ;
}

/*
 * Destrava o descritor referente ao endereço uAddr do processo em execução.
 */
void frame_unpinUaddr(const void *uAddr)
{
	void *kAddr = pagedir_get_page(thread_current()->pagedir, uAddr) ;

	ASSERT(kAddr != NULL) ;

	int i = vtop(pg_round_down(kAddr)) / PGSIZE - kernel_pages - 256 ;
	lock_release(&frames[i].lock) ;
}

/*
 * Trava o descritor referente ao endereço kpage.
 */
void frame_pinKaddr(const void *kpage)
{
	ASSERT(pg_ofs(kpage) == 0) ;
	ASSERT(!is_user_vaddr(kpage)) ;

	int i = vtop(kpage) / PGSIZE - kernel_pages - 256 ;
	lock_acquire(&frames[i].lock) ;
}

/*
 * Destrava o descritor referente ao endereço kpage.
 */
void frame_unpinKaddr(const void *kpage)
{
	ASSERT(pg_ofs(kpage) == 0) ;
	ASSERT(!is_user_vaddr(kpage)) ;

	int i = vtop(kpage) / PGSIZE - kernel_pages - 256 ;
	lock_release(&frames[i].lock) ;
}

/*
 * Implementação do clock algorithm. O algoritmo vai girando
 * pelos descritores de frames tentando achar um frame velho suficiente para
 * swap-out. Um frame velho suficiente é um frame aonde a page table entry do endereço
 * uAddr do processo t possui o bit PTE_A em zero. Existe aqui a noção de "pinnar" o frame,
 * aonde o algoritmo tenta adquirir o lock do frame, e caso o lock esteja indisponível,
 * o frame é ignorado no momento e o algoritmo segue para o próximo.
 * Um frame com o lock indisponível significa que esse frame está envolvido em uma operação read/write,
 * ou está sendo analisado por outra chamada freeFrames() de um outro processo, portanto não pode levar swap-out
 * por essa chamada freeFrames(). Na prática acho que isso é quase impossível de acontecer, mas teoricamente
 * é possível o algoritmo girar por todos os frames sem achar alguem para chutar,
 * e chegar a um frame em que outro processo estava analisando mas foi retirado de execução. Nesse caso
 * o outro processo já tem o lock do frame, o lock_try_acquire vai falhar e o frame será ignorado.
 */
void frame_freeFrames(size_t page_cnt)
{
	while (page_cnt > 0)
	{
		int i ;
		lock_acquire(&lockContadorClockAlg) ;
		i = contadorClockAlgorithm ;
		contadorClockAlgorithm = (contadorClockAlgorithm + 1) % user_pages ;
		lock_release(&lockContadorClockAlg) ;

		void *uAddr = NULL ;
		struct thread *t = NULL ;
		void *kernelAddr = NULL ;

		if (lock_try_acquire(&frames[i].lock))
		{
			if (frames[i].uAddr != 0)
			{
				uAddr = frames[i].uAddr ;
				t = frames[i].t ;
			}
			else
			{
				lock_release(&frames[i].lock) ;
				continue ;
			}
		}
		else
			continue ;

		struct thread *cur = thread_current() ;

		if (t != cur)
		{
			/*
			 * Se t != cur será preciso preciso alterar a PTE de uma thread diferente
			 * da em execução, portanto preciso pegar t->pageTableLock. Se possuo
			 * cur->pageTableLock, cheguei aki de dentro do page fault handler, e não
			 * posso bloquear no t->pageTableLock segurando cur->pageTableLock e frame->lock,
			 * pois pode acontecer deadlock. Também não posso soltar os locks e pegar depois
			 * pois existem races. lock_try_acquire() pega o lock caso disponível,
			 * e caso indisponível não bloqueia, desiste desse frame e vai para o próximo.
			 * Se não possuo cur->pageTableLock não estou dentro do page fault handler e posso
			 * bloquear no t->pageTableLock. Toda alocação de memória do user_pool que falhar
			 * vai chamar freeFrames(), portanto posso estar aqui vindo de diferentes pontos.
			 */
			if (lock_held_by_current_thread(&cur->pageTableLock))
			{
				if (!lock_try_acquire(&t->pageTableLock))
				{
					lock_release(&frames[i].lock) ;
					continue ;
				}
			}
			else
				lock_acquire(&t->pageTableLock) ;
		}

		/*
		 * t->pagedir == NULL o processo já terminou e está em processo de finalização,
		 * dentro de thread_exit(), limpando as estruturas de dados do kernel referentes ao processo.
		 * Pode acontecer do campo da struct thread já estar com valor NULL, mas pagedir_destroy() ainda
		 * não executou completamente, e o mapeamento do descritor do frame ainda não foi retirado.
		 * Nesse caso é preciso ignorar o frame pois não tem como conseguir *pte a partir
		 * de t->pagedir. O endereço t->pagedir está copiado em uma variável local da função pagedir_destroy(),
		 * e caso eu altere o frame daqui, a page table entry obtida em pagedir_destroy() continuará apontando
		 * para esse frame, que significa que palloc_free_page() será chamado nesse frame, portanto não posso
		 * usar esse frame nesse momento.
		 */
		if (t->pagedir == NULL)
		{
			lock_release(&frames[i].lock) ;
			lock_release(&t->pageTableLock) ;
			continue ;
		}
		uint32_t *pte = pagedir_lookup_page(t->pagedir, uAddr, false) ;

		if ((*pte & PTE_A) != 0)
		{
			*pte &= ~PTE_A ;
			if (t != cur)
			{
				lock_release(&t->pageTableLock) ;
			}
			lock_release(&frames[i].lock) ;
			continue ;
		}
		else
		{
			/*
			 * Frame velho suficiente encontrado, e será chutado. Importante que a
			 * primeira operação seja zerar bit PTE_P da page table entry. Os dados
			 * da pte serão alterados, e é necessário que o processo t não leia a pte
			 * em estado inconsistente. Após operação *pte &= ~PTE_P, qualquer acesso a
			 * página por t causará um page fault, e o início do page fault handler é
			 * lock_acquire(&thread_current()->pageTableLock), que bloqueará t pois o
			 * lock está comigo. Só libero o lock no fim do processo de evict, quando
			 * a pte está em estado consistente. Se vou chutar um frame que é meu,
			 * esse problema não existe pois eu estou executando dentro dessa função,
			 * e não acessarei a pte em estado inconsistente.
			 *
			 * Preferi colocar operação por operação nos bits para ficar mais fácil de ler
			 * e entender, se performance máxima fosse a intenção escreveria diferente.
			 * Talvez o compilador otimize as operações, não sei direito qual será o resultado
			 * das operações otimizadas, mas é garantido que ~PTE_P sempre estará
			 * na primeira operação.
			 */

			if ((*pte & PTE_M) != 0)
			{
				struct mapeamentoArquivo *arq = process_getMapArqAddr(t, uAddr) ;
				kernelAddr = pagedir_get_page(t->pagedir, uAddr) ;
				*pte &= ~PTE_P ;

				if ((*pte & PTE_D) != 0)
				{
					*pte &= ~PTE_D ;
					file_write_at_semExtend(arq->f, kernelAddr, PGSIZE, arq->off + (uAddr - arq->startAddr)) ;
				}
				*pte &= ~PTE_ADDR ;
				*pte |= (arq->mid << PTE_SHIFT_FLAGS) ;
				if (t == cur)
				{
					pagedir_invalidate_pd(t->pagedir) ;
				}
				page_cnt-- ;
			}
			else
			{
				kernelAddr = pagedir_get_page(t->pagedir, uAddr) ;
				*pte &= ~PTE_P ;
				size_t idx = swap_swapOut(kernelAddr) ;

				*pte |= PTE_S ;
				*pte &= ~PTE_D ;
				*pte &= ~PTE_ADDR ;
				*pte |= (idx << PTE_SHIFT_FLAGS) ;
				if (t == cur)
				{
					pagedir_invalidate_pd(t->pagedir) ;
				}
				page_cnt-- ;
			}
		}

		if (t != cur)
		{
			lock_release(&t->pageTableLock) ;
		}

		frames[i].t = NULL ;
		frames[i].uAddr = NULL ;
		lock_release(&frames[i].lock) ;

		palloc_free_page(kernelAddr) ;
	}
}

