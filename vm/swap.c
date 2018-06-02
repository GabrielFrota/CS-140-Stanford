#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include <bitmap.h>
#include "vm/frame.h"

/*
 * quantidades de setores do disco necessários para salvar uma página
 */
#define SETORES_POR_PAGINA (PGSIZE/BLOCK_SECTOR_SIZE)

/*
 * endereço da struct para acesso da partição de swap
 */
static struct block *swapArea ;

/*
 * bitmap para gerenciar os slots de swap livres/em uso
 */
static struct bitmap *swapMap ;

/*
 * lock do bitmap swapMap
 */
static struct lock swapMapLock ;

/*
 * quantidade de slots para swap, valor depende do tamanho da partição de swap
 */
static size_t quantSlotsSwap ;


void swap_init(void)
{
	swapArea = block_get_role(BLOCK_SWAP) ;
	if (swapArea == NULL)
		PANIC("Disco para swap nao encontrado") ;

	quantSlotsSwap = block_size(swapArea) / SETORES_POR_PAGINA ;

	swapMap = bitmap_create(quantSlotsSwap) ;
	if (swapMap == NULL)
		PANIC("Bitmap_create do swapMap retornou NULL") ;
	bitmap_set_all(swapMap, true) ;

	lock_init(&swapMapLock) ;
}

/*
 * Escreve a pagina kpage em um slot livre da partição de swap.
 * Retorna o indice do slot.
 */
size_t swap_swapOut(void *kpage)
{
	lock_acquire(&swapMapLock) ;
	size_t idx = bitmap_scan_and_flip(swapMap, 0, 1, true) ;
	lock_release(&swapMapLock) ;

	if (idx == BITMAP_ERROR)
		PANIC("alocarSlotSwap falhou pois nao existem mais slots livres") ;

	for (int i = 0 ; i < SETORES_POR_PAGINA ; i++)
	{
		block_write(swapArea, idx * SETORES_POR_PAGINA + i, kpage + BLOCK_SECTOR_SIZE * i) ;
	}

	return idx ;
}

/*
 * Escreve no endereço kpage, a página previamente escrita no slot idx.
 */
void swap_swapIn(size_t idx, void *kpage)
{
	for (int i = 0 ; i < SETORES_POR_PAGINA ; i++)
	{
		block_read(swapArea, idx * SETORES_POR_PAGINA + i, kpage + BLOCK_SECTOR_SIZE * i) ;
	}

	lock_acquire(&swapMapLock) ;
	bitmap_flip(swapMap, idx) ;
	lock_release(&swapMapLock) ;
}

