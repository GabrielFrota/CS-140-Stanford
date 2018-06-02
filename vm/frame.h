#ifndef VM_FRAME_H_
#define VM_FRAME_H_

#include "threads/pte.h"
#include "threads/synch.h"
#include "threads/palloc.h"

/*
 * Descritor de uma página fisica disponível a processos usuários.
 * Existe 1 descritor para cada página do user_pool (do kernel_pool nenhum).
 * Esse descritor não é relacionado à alocação de memória, funcionalidade
 * que já existe em palloc.h. Esse descritor é relacionado ao swap de páginas
 * velhas, e páginas do kernel não podem levar swap.
 */
struct frame
{
	struct lock lock ;
	struct thread *t ;
	void *uAddr ;
} ;


void frame_init(void) ;
void frame_setDescritor(void *kpage, struct thread *t, void *uAddr) ;
void frame_clearDescritor(void *kpage) ;
void frame_freeFrames(size_t page_cnt) ;
void frame_pinUaddr(const void *uAddr) ;
void frame_unpinUaddr(const void *uAddr) ;
void frame_pinKaddr(const void *kpage) ;
void frame_unpinKaddr(const void *kpage) ;


#endif /* VM_FRAME_H_ */
